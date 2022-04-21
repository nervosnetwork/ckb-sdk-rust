use std::collections::HashMap;
use std::error::Error as StdErr;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH},
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, unlock_tx, CapacityBalancer, TxBuilder},
    unlock::{MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker},
    Address, GenesisInfo, HumanCapacity, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{CellOutput, Script},
    prelude::*,
    H160, H256,
};
use clap::Parser;

/// Transfer some CKB from one multisig(without since) address to other address
/// # Example:
///     ./target/debug/examples/transfer_from_multisig \
///       --sender-key <key-hex> \
///       --sender-key <key-hex> \
///       --receiver <address> \
///       --capacity 120.0
///       --require-first-n 0
///       --threshold 2
///       --sighash-address <address>
///       --sighash-address <address>
///       --sighash-address <address>
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The sender private keys (hex string, must presented in `sighash_address`)
    #[clap(long, value_name = "KEY")]
    sender_key: Vec<H256>,

    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,

    /// Require first n signatures of corresponding pubkey
    #[clap(long, value_name = "NUM")]
    require_first_n: u8,

    /// Multisig threshold
    #[clap(long, value_name = "NUM")]
    threshold: u8,

    /// Normal sighash address
    #[clap(long, value_name = "ADDRESS")]
    sighash_address: Vec<Address>,

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
    let multisig_config = {
        if args.sighash_address.is_empty() {
            return Err("Must have at least one sighash_address".to_string().into());
        }
        let mut sighash_addresses = Vec::with_capacity(args.sighash_address.len());
        for addr in args.sighash_address.clone() {
            let args = addr.payload().args();
            if addr.payload().code_hash(None).as_slice() != SIGHASH_TYPE_HASH.as_bytes()
                || addr.payload().hash_type() != ScriptHashType::Type
                || args.len() != 20
            {
                return Err(format!("sighash_address {} is not sighash address", addr).into());
            }
            sighash_addresses.push(H160::from_slice(args.as_ref()).unwrap());
        }
        MultisigConfig::new_with(sighash_addresses, args.require_first_n, args.threshold)?
    };

    let mut sender_keys = Vec::with_capacity(args.sender_key.len());
    for key_bin in args.sender_key.clone() {
        let key = secp256k1::SecretKey::from_slice(key_bin.as_bytes())
            .map_err(|err| format!("invalid sender secret key: {}", err))?;
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
        let hash160 = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20]).unwrap();
        if !multisig_config.contains_address(&hash160) {
            return Err(format!("key {:#x} is not in multisig config", key_bin).into());
        }
        sender_keys.push(key);
    }

    let tx = build_transfer_tx(&args, multisig_config, sender_keys)?;

    // Send transaction
    let json_tx = json_types::TransactionView::from(tx);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let _tx_hash = CkbRpcClient::new(args.ckb_rpc.as_str())
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    println!(">>> tx sent! <<<");

    Ok(())
}

fn build_transfer_tx(
    args: &Args,
    multisig_config: MultisigConfig,
    sender_keys: Vec<secp256k1::SecretKey>,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(MULTISIG_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(multisig_config.hash160().as_bytes().to_vec()).pack())
        .build();
    let sender_addr = Address::new(args.receiver.network(), sender.clone().into(), true);
    println!("sender address: {}", sender_addr);
    let placeholder_withess = multisig_config.placeholder_withess();
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

    // Build base transaction
    let unlockers = build_multisig_unlockers(sender_keys[0], multisig_config.clone());
    let output = CellOutput::new_builder()
        .lock(Script::from(&args.receiver))
        .capacity(args.capacity.0.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let mut tx = builder.build_balanced(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;

    // Unlock transaction
    let mut locked_groups = None;
    for key in sender_keys {
        let unlockers = build_multisig_unlockers(key, multisig_config.clone());
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &tx_dep_provider, &unlockers)?;
        tx = new_tx;
        locked_groups = Some(new_locked_groups);
    }
    assert_eq!(locked_groups, Some(Vec::new()));
    Ok(tx)
}

fn build_multisig_unlockers(
    key: secp256k1::SecretKey,
    config: MultisigConfig,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![key]);
    let multisig_signer = SecpMultisigScriptSigner::new(Box::new(signer), config);
    let multisig_unlocker = SecpMultisigUnlocker::new(multisig_signer);
    let multisig_script_id = ScriptId::new_type(MULTISIG_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        multisig_script_id,
        Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}
