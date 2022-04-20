use std::collections::HashMap;
use std::error::Error as StdErr;
use std::str::FromStr;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashScriptSigner, SecpSighashUnlocker},
    Address, GenesisInfo, HumanCapacity, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
};
use clap::Parser;

/// Transfer some CKB from one sighash address to other address
/// # Example:
///     ./target/debug/examples/transfer --sender-key ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --receiver ckt1qyqgjagv5f8xq9syxd38v2ga3dczszqy67psu2y8r4 --capacity 61.0
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The sender private key (hex string, no '0x' prefix)
    #[clap(long, value_name = "KEY")]
    sender_key: String,
    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: String,
    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: String,
    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
    /// CKB indexer rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8116")]
    ckb_indexer: String,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let args = Args::parse();
    let sender_privkey = {
        let mut bin = vec![0u8; args.sender_key.len() / 2];
        faster_hex::hex_decode(args.sender_key.as_bytes(), &mut bin)
            .map_err(|err| format!("parse privkey hex: {}", err))?;
        secp256k1::SecretKey::from_slice(&bin)
            .map_err(|err| format!("parser secret key: {}", err))?
    };
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_privkey);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };
    let receiver = Script::from(
        &Address::from_str(args.receiver.as_str())
            .map_err(|err| format!("parse receiver address: {}", err))?,
    );
    let capacity = HumanCapacity::from_str(args.capacity.as_str())
        .map_err(|err| format!("parse capacity: {}", err))?
        .0;

    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_privkey]);
    let sighash_signer = SecpSighashScriptSigner::new(Box::new(signer));
    let sighash_unlocker = SecpSighashUnlocker::new(sighash_signer);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_withess = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build()
        .as_bytes();
    let balancer = CapacityBalancer::new_simple(sender, placeholder_withess, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        let info = GenesisInfo::from_block(&BlockView::from(genesis_block))?;
        DefaultCellDepResolver::new(&info)
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(receiver)
        .capacity(capacity.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let (tx, locked_groups) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(locked_groups.is_empty());

    // Send transaction
    let json_tx = json_types::TransactionView::from(tx);
    println!(
        "tx: {}",
        serde_json::to_string_pretty(&json_tx).expect("to json")
    );
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let _tx_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    println!(">>> tx sent! <<<");

    Ok(())
}
