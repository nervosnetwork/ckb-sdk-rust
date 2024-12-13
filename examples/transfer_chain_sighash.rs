use std::collections::HashMap;
use std::error::Error as StdErr;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        CellCollector, DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    Address, HumanCapacity, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};
use clap::Parser;

/// Transfer some CKB from sender address to receiver0 address, and
/// transfer from receiver0 to receiver1 address, after build the 2 transactions,
/// send the 2 transaction one by one.
///
/// Make sure receiver0 and receiver1 have no other capacity, and the capacity is bigger
/// enough to transfer 2 times with fee and minimum capacity to create a cell.
///
/// # Example:
///     ./target/debug/examples/transfer_from_sighash \
///       --sender-key <key-hex> \
///       --receiver0-key <key-hex>
///       --receiver0 <address> \
///       --receiver1 <address> \
///       --capacity 61.0
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    receiver0_key: H256,

    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver0: Address,
    #[clap(long, value_name = "ADDRESS")]
    receiver1: Address,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let args = Args::parse();
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let receiver0_key = secp256k1::SecretKey::from_slice(args.receiver0_key.as_bytes())
        .map_err(|err| format!("invalid receiver0 secret key: {}", err))?;
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let receiver0 = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &receiver0_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let mut tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);
    let tx = build_transfer_tx(
        &mut cell_collector,
        &tx_dep_provider,
        &args,
        sender,
        sender_key,
        &args.receiver0,
        args.capacity.0,
    )?;
    let ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let mut tip_num = ckb_client.get_tip_block_number().unwrap().value();
    cell_collector.apply_tx(tx.data(), tip_num)?;
    tx_dep_provider.apply_tx(tx.data(), tip_num)?;
    let tx1 = build_transfer_tx(
        &mut cell_collector,
        &tx_dep_provider,
        &args,
        receiver0,
        receiver0_key,
        &args.receiver1,
        args.capacity.0 - 100_000,
    )?;
    tip_num = ckb_client.get_tip_block_number().unwrap().value();
    cell_collector.apply_tx(tx1.data(), tip_num)?;
    tx_dep_provider.apply_tx(tx.data(), tip_num)?;

    // Send transaction
    let json_tx = json_types::TransactionView::from(tx);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let tx0_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator.clone())
        .expect("send transaction");
    println!(">>> tx {} sent! <<<", tx0_hash);

    let json_tx = json_types::TransactionView::from(tx1);
    println!("tx1: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let tx1_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    println!(">>> tx {} sent! <<<", tx1_hash);

    Ok(())
}

fn build_transfer_tx(
    cell_collector: &mut DefaultCellCollector,
    tx_dep_provider: &DefaultTransactionDependencyProvider,
    args: &Args,
    sender: Script,
    sender_key: secp256k1::SecretKey,
    receiver: &Address,
    capacity: u64,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let mut balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);
    balancer.set_max_fee(Some(100_000_000));

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());

    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(Script::from(receiver))
        .capacity(capacity.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let (tx, still_locked_groups) = builder.build_unlocked(
        cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}
