use std::collections::HashMap;
use std::error::Error as StdErr;
use std::fs;
use std::path::PathBuf;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::{MultisigScript, SIGHASH_TYPE_HASH},
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, unlock_tx, CapacityBalancer, TxBuilder},
    unlock::{MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker},
    Address, AddressPayload, HumanCapacity, NetworkType, ScriptGroup, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{CellOutput, Script, Transaction, WitnessArgs},
    prelude::*,
    H160, H256,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Transfer some CKB from one multisig(without since) address to other address
/// # Example:
///     ./target/debug/examples/transfer_from_multisig gen \
///       --receiver <address> \
///       --capacity 120.0 \
///       --require-first-n 0 \
///       --threshold 2 \
///       --sighash-address <address> \
///       --sighash-address <address> \
///       --sighash-address <address> \
///       --tx-file tx.json
///
///     ./target/debug/examples/transfer_from_multisig sign \
///       --sender-key <key-hex> \
///       --tx-file tx.json
///
///     ./target/debug/examples/transfer_from_multisig send --tx-file tx.json
///
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct GenTxArgs {
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

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}

#[derive(Args)]
struct SignTxArgs {
    /// The sender private keys (hex string, must presented in `sighash_address`)
    #[clap(long, value_name = "KEY")]
    sender_key: Vec<H256>,

    /// The transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate the transaction
    Gen(GenTxArgs),
    /// Sign the transaction
    Sign(SignTxArgs),
    /// Send the transaction
    Send {
        /// The transaction info file (.json)
        #[clap(long, value_name = "PATH")]
        tx_file: PathBuf,

        /// CKB rpc url
        #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
        ckb_rpc: String,
    },
}

#[derive(Serialize, Deserialize)]
struct TxInfo {
    tx: json_types::TransactionView,
    multisig_config: MultisigConfig,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let cli = Cli::parse();
    match cli.command {
        Commands::Gen(args) => {
            let multisig_config = {
                if args.sighash_address.is_empty() {
                    return Err("Must have at least one sighash_address".to_string().into());
                }
                let mut sighash_addresses = Vec::with_capacity(args.sighash_address.len());
                for addr in args.sighash_address.clone() {
                    let lock_args = addr.payload().args();
                    if addr.payload().code_hash(None).as_slice() != SIGHASH_TYPE_HASH.as_bytes()
                        || addr.payload().hash_type() != ScriptHashType::Type
                        || lock_args.len() != 20
                    {
                        return Err(
                            format!("sighash_address {} is not sighash address", addr).into()
                        );
                    }
                    sighash_addresses.push(H160::from_slice(lock_args.as_ref()).unwrap());
                }
                MultisigConfig::new_with(
                    ckb_sdk::constants::MultisigScript::V2,
                    sighash_addresses,
                    args.require_first_n,
                    args.threshold,
                )?
            };
            let tx = build_transfer_tx(&args, &multisig_config)?;
            let tx_info = TxInfo {
                tx: json_types::TransactionView::from(tx),
                multisig_config,
            };
            fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
        }
        Commands::Sign(args) => {
            if args.sender_key.is_empty() {
                return Err("sender key is missing".to_string().into());
            }
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&args.tx_file)?)?;
            let mut sender_keys = Vec::with_capacity(args.sender_key.len());
            for key_bin in args.sender_key.clone() {
                let key = secp256k1::SecretKey::from_slice(key_bin.as_bytes())
                    .map_err(|err| format!("invalid sender secret key: {}", err))?;
                let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
                let hash160 =
                    H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20]).unwrap();
                if !tx_info.multisig_config.contains_address(&hash160) {
                    return Err(format!("key {:#x} is not in multisig config", key_bin).into());
                }
                sender_keys.push(key);
                let address = Address::new(
                    NetworkType::Testnet,
                    AddressPayload::from_pubkey_hash(hash160),
                    true,
                );
                println!("> sign by address(testnet): {}", address);
            }
            let tx = Transaction::from(tx_info.tx.inner).into_view();
            let (tx, _) = sign_tx(&args, tx, &tx_info.multisig_config, sender_keys)?;
            let config_data_len = tx_info.multisig_config.to_witness_data().len();
            let lock_field =
                WitnessArgs::from_slice(tx.witnesses().get(0).unwrap().raw_data().as_ref())?
                    .lock()
                    .to_opt()
                    .unwrap()
                    .raw_data();
            if (0..tx_info.multisig_config.threshold() as usize).all(|i| {
                lock_field.as_ref()[config_data_len + i * 65..config_data_len + (i + 1) * 65]
                    != [0u8; 65]
            }) {
                println!("> transaction ready to send!");
            } else {
                println!("> need more keys to sign the transaction!");
            }
            let tx_info = TxInfo {
                tx: json_types::TransactionView::from(tx),
                multisig_config: tx_info.multisig_config,
            };
            fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
        }
        Commands::Send { tx_file, ckb_rpc } => {
            // Send transaction
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(tx_file)?)?;
            println!(
                "> tx: {}",
                serde_json::to_string_pretty(&tx_info.tx).unwrap()
            );
            let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
            let _tx_hash = CkbRpcClient::new(ckb_rpc.as_str())
                .send_transaction(tx_info.tx.inner, outputs_validator)
                .expect("send transaction");
            println!(">>> tx sent! <<<");
        }
    }
    Ok(())
}

fn build_transfer_tx(
    args: &GenTxArgs,
    multisig_config: &MultisigConfig,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(MultisigScript::V2.script_id().code_hash.pack())
        .hash_type(MultisigScript::V2.script_id().hash_type)
        .args(Bytes::from(multisig_config.hash160().as_bytes().to_vec()).pack())
        .build();
    let sender_addr = Address::new(args.receiver.network(), sender.clone().into(), true);
    println!("> sender address: {}", sender_addr);
    let placeholder_witness = multisig_config.placeholder_witness();
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

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
    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    // Build base transaction
    let unlockers = build_multisig_unlockers(Vec::new(), multisig_config.clone());
    let output = CellOutput::new_builder()
        .lock(Script::from(&args.receiver))
        .capacity(args.capacity.0)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let tx = builder.build_balanced(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    Ok(tx)
}

fn sign_tx(
    args: &SignTxArgs,
    mut tx: TransactionView,
    multisig_config: &MultisigConfig,
    sender_keys: Vec<secp256k1::SecretKey>,
) -> Result<(TransactionView, Vec<ScriptGroup>), Box<dyn StdErr>> {
    // Unlock transaction
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);
    let mut still_locked_groups = None;
    for key in sender_keys {
        let unlockers = build_multisig_unlockers(vec![key], multisig_config.clone());
        let (new_tx, new_still_locked_groups) =
            unlock_tx(tx.clone(), &tx_dep_provider, &unlockers)?;
        tx = new_tx;
        still_locked_groups = Some(new_still_locked_groups);
    }
    Ok((tx, still_locked_groups.unwrap_or_default()))
}

fn build_multisig_unlockers(
    keys: Vec<secp256k1::SecretKey>,
    config: MultisigConfig,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(keys);
    let multisig_signer = SecpMultisigScriptSigner::new(Box::new(signer), config);
    let multisig_unlocker = SecpMultisigUnlocker::new(multisig_signer);
    let multisig_script_id = MultisigScript::V2.script_id();
    let mut unlockers = HashMap::default();
    unlockers.insert(
        multisig_script_id,
        Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}
