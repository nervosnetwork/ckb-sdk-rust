use ckb_crypto::secp::Pubkey;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner, TransactionDependencyProvider,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses, transfer::CapacityTransferBuilder,
        unlock_tx, CapacityBalancer, TxBuilder,
    },
    types::NetworkType,
    unlock::{
        opentx::OpentxWitness, IdentityFlag, MultisigConfig, OmniLockConfig, OmniLockScriptSigner,
        SecpSighashUnlocker,
    },
    unlock::{OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker},
    util::{blake160, keccak160},
    Address, HumanCapacity, ScriptGroup, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction, WitnessArgs},
    prelude::*,
    H160, H256,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{collections::HashMap, error::Error as StdErr};
use std::{collections::HashSet, fs};

/*
# examples for the developer local node
########################### sighash opentx example #################################
# 1. build an opentx address
 ./target/debug/examples/transfer_from_opentx build --receiver ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024
{
  "lock-arg": "0x00b398368a8ed39448f95479c1178ff3fc5e31631810",
  "lock-hash": "0x3f54ccaf46b3472b55eaa2e2c0a5cae87575b3de90a81fe60206dd5c0951ffa8",
  "mainnet": "ckb1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqv8f7ak",
  "testnet": "ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7"
}
# 2. transfer capacity to the address
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
  --capacity 99 --skip-check-to-address
    # 0x937deeb989bbd7f4bd0273bf2049d7614615dd58a32090b0093f23a692715871
# 3. generate the transaction
./target/debug/examples/transfer_from_opentx gen-open-tx --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 98.0 --open-capacity 1.0\
            --tx-file tx.json
# 4. sign the transaction
./target/debug/examples/transfer_from_opentx sign-open-tx --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --tx-file tx.json
# add input, with capacity 98.99999588
./target/debug/examples/transfer_from_opentx add-input --tx-hash df85d2aaa44d50b1db286bdb2fbd8682cad12d6858b269d2531403ba5e63a2eb --index 0 --tx-file tx.json
# add output, capacity is 98.99999588(original) + 1(open capacity) - 0.001(fee)
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 99.99899588  --tx-file tx.json
# sighash sign the new input
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
# send the tx
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0xebb9d9ff39efbee5957d6f7d19a4a17f1ac2e69dbc9289e4931cef6b832f4d57

########################### ethereum opentx example #################################
# 1. build an opentx address
./target/debug/examples/transfer_from_opentx build --ethereum-receiver 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d                                                                                                                                                                                             14:03:11
pubkey:"038d3cfceea4f9c2e76c5c4f5e99aec74c26d6ac894648b5700a0b71f91f9b5c2a"
pubkey:"048d3cfceea4f9c2e76c5c4f5e99aec74c26d6ac894648b5700a0b71f91f9b5c2a26b16aac1d5753e56849ea83bf795eb8b06f0b6f4e5ed7b8caca720595458039"
{
  "lock-arg": "0x01cf2485c76aff1f2b4464edf04a1c8045068cf7e010",
  "lock-hash": "0x057dcd204f26621ef49346ed77d2bdbf3069b83a5ef0a2b52be5299a93507cf6",
  "mainnet": "ckb1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgpeujgt3m2lu0jk3ryahcy58yqg5rgealqzqjzc5z5",
  "testnet": "ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgpeujgt3m2lu0jk3ryahcy58yqg5rgealqzqf4vcru"
}
# 2. transfer capacity to the address
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgpeujgt3m2lu0jk3ryahcy58yqg5rgealqzqf4vcru \
  --capacity 99 --skip-check-to-address
    # 0xbd696b87629dfe38136c52e579800a432622baf5893b61365c7a18902a9ccd60
# 3. generate the transaction
./target/debug/examples/transfer_from_opentx gen-open-tx --ethereum-sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 98.0 --open-capacity 1.0\
            --tx-file tx.json
# 4. sign the transaction
./target/debug/examples/transfer_from_opentx sign-open-tx --sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --tx-file tx.json
# add input, with capacity 99.99899588
./target/debug/examples/transfer_from_opentx add-input --tx-hash ebb9d9ff39efbee5957d6f7d19a4a17f1ac2e69dbc9289e4931cef6b832f4d57 --index 1 --tx-file tx.json
# add output, capacity is 99.99899588(original) + 1(open capacity) - 0.001(fee)
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 100.99799588  --tx-file tx.json
# sighash sign the new input
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
# send the tx
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0x621077216f3bf7861beacd3cdda44f7a5854454fcd133922b89f0addd0330e6b

########################### multisig opentx example #################################
# 1. build an opentx address
./target/debug/examples/transfer_from_opentx build --require-first-n 0 \
  --threshold 2 \
  --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
  --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
  --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4                                                                                                                                                                                    14:03:11
{
  "lock-arg": "0x065d7d0128eeaa6f9656a229b42aadd0b177d387eb10",
  "lock-hash": "0xf5202949800af0b454b2e4806c57da1d0f3ae87f7b9f4b698d9f3b71162ec196",
  "mainnet": "ckb1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgxt47sz28w4fhev44z9x6z4twsk9ma8pltzqmtamce",
  "testnet": "ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgxt47sz28w4fhev44z9x6z4twsk9ma8pltzqqufhe3"
}
# 2. transfer capacity to the address
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgxt47sz28w4fhev44z9x6z4twsk9ma8pltzqqufhe3 \
  --capacity 99 --skip-check-to-address
    # 0xf993b27a0129f72ec0a889cb016987c3cef00f7819461e51d5755464da6adf1b
# 3. generate the transaction
./target/debug/examples/transfer_from_opentx gen-open-tx \
    --require-first-n 0 \
    --threshold 2 \
    --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
    --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
    --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4 \
    --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
    --capacity 98.0 --open-capacity 1.0 \
    --tx-file tx.json
# 4. sign the transaction
./target/debug/examples/transfer_from_opentx sign-open-tx \
    --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
    --sender-key d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc \
    --tx-file tx.json
# add input, with capacity 99.99899588
./target/debug/examples/transfer_from_opentx add-input --tx-hash ebb9d9ff39efbee5957d6f7d19a4a17f1ac2e69dbc9289e4931cef6b832f4d57 --index 1 --tx-file tx.json
# add output, capacity is 99.99899588(original) + 1(open capacity) - 0.001(fee)
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 100.99799588  --tx-file tx.json
# sighash sign the new input
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
# send the tx
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0x621077216f3bf7861beacd3cdda44f7a5854454fcd133922b89f0addd0330e6b
*/
const OPENTX_TX_HASH: &str = "d7697f6b3684d1451c42cc538b3789f13b01430007f65afe74834b6a28714a18";
const OPENTX_TX_IDX: &str = "0";

#[derive(Args)]
struct MultiSigArgs {
    /// Require first n signatures of corresponding pubkey
    #[clap(long, value_name = "NUM", default_value = "1")]
    require_first_n: u8,

    /// Multisig threshold
    #[clap(long, value_name = "NUM", default_value = "1")]
    threshold: u8,

    /// Normal sighash address
    #[clap(long, value_name = "ADDRESS")]
    sighash_address: Vec<Address>,
}
#[derive(Args)]
struct BuildOmniLockAddrArgs {
    /// The receiver address
    #[clap(long, value_name = "ADDRESS", group = "algorithm")]
    receiver: Option<Address>,

    /// The receiver's private key (hex string)
    #[clap(long, value_name = "KEY", group = "algorithm")]
    ethereum_receiver: Option<H256>,

    #[clap(flatten)]
    multis_args: MultiSigArgs,

    /// omnilock script deploy transaction hash
    #[clap(
        long,
        value_name = "H256",
        default_value = OPENTX_TX_HASH
    )]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER", default_value = OPENTX_TX_IDX)]
    omnilock_index: usize,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}
#[derive(Args)]
struct GenOpenTxArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: Option<H256>,
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    ethereum_sender_key: Option<H256>,

    #[clap(flatten)]
    multis_args: MultiSigArgs,

    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256", default_value = OPENTX_TX_HASH)]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER", default_value = OPENTX_TX_IDX)]
    omnilock_index: usize,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,
    /// The open transaction capacity not decided to whom (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    open_capacity: HumanCapacity,
    #[clap(long, value_name = "NUMBER", default_value = "0")]
    fee_rate: u64,
    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,

    /// CKB indexer rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8116")]
    ckb_indexer: String,
}

#[derive(Args)]
struct SignTxArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: Vec<H256>,

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256", default_value = OPENTX_TX_HASH)]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER", default_value = OPENTX_TX_IDX)]
    omnilock_index: usize,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}

#[derive(Args)]
struct AddInputArgs {
    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256")]
    tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER")]
    index: usize,

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256", default_value = OPENTX_TX_HASH)]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER", default_value = OPENTX_TX_IDX)]
    omnilock_index: usize,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}

#[derive(Args)]
struct AddOutputArgs {
    /// --to-sighash-address ckt1qyqg7zchpds6lv3v0nr36z2msu2x9a5lkhrq7kvyww --capacity 19999.9999 --tx-file tx.json
    #[clap(long, value_name = "ADDRESS")]
    to_address: Address,
    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,
}
#[derive(Subcommand)]
enum Commands {
    /// build omni lock address
    Build(BuildOmniLockAddrArgs),
    /// Generate the transaction
    GenOpenTx(GenOpenTxArgs),
    /// Sign the open transaction
    SignOpenTx(SignTxArgs),
    /// sign sighash input
    SighashSignTx(SignTxArgs),
    /// Add input
    AddInput(AddInputArgs),
    /// Add output
    AddOutput(AddOutputArgs),
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
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Serialize, Deserialize)]
struct TxInfo {
    tx: json_types::TransactionView,
    omnilock_config: OmniLockConfig,
}

struct OmniLockInfo {
    type_hash: H256,
    script_id: ScriptId,
    cell_dep: CellDep,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(build_args) => build_omnilock_addr(&build_args)?,
        Commands::GenOpenTx(gen_args) => {
            gen_open_tx(&gen_args)?;
        }
        Commands::SignOpenTx(args) => {
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&args.tx_file)?)?;
            let tx = Transaction::from(tx_info.tx.inner).into_view();
            let keys = args
                .sender_key
                .iter()
                .map(|sender_key| {
                    secp256k1::SecretKey::from_slice(sender_key.as_bytes())
                        .map_err(|err| format!("invalid sender secret key: {}", err))
                        .unwrap()
                })
                .collect();
            if tx_info.omnilock_config.is_pubkey_hash() || tx_info.omnilock_config.is_ethereum() {
                for key in &keys {
                    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, key);
                    let hash160 = match tx_info.omnilock_config.id().flag() {
                        IdentityFlag::PubkeyHash => {
                            blake2b_256(&pubkey.serialize()[..])[0..20].to_vec()
                        }
                        IdentityFlag::Ethereum => {
                            keccak160(Pubkey::from(pubkey).as_ref()).as_bytes().to_vec()
                        }
                        _ => unreachable!(),
                    };
                    if tx_info.omnilock_config.id().auth_content().as_bytes() != hash160 {
                        return Err(format!("key {:#x} is not in omnilock config", key).into());
                    }
                }
            }
            let (tx, _) = sign_tx(&args, tx, &tx_info.omnilock_config, keys)?;
            let witness_args =
                WitnessArgs::from_slice(tx.witnesses().get(0).unwrap().raw_data().as_ref())?;
            let lock_field = witness_args.lock().to_opt().unwrap().raw_data();
            if lock_field != tx_info.omnilock_config.zero_lock(OmniUnlockMode::Normal)? {
                println!("> transaction has been signed!");
            } else {
                println!("failed to sign tx");
            }
            let tx_info = TxInfo {
                tx: json_types::TransactionView::from(tx),
                omnilock_config: tx_info.omnilock_config,
            };
            fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
        }
        Commands::SighashSignTx(args) => {
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&args.tx_file)?)?;
            let tx = Transaction::from(tx_info.tx.inner).into_view();
            let (tx, _) = sighash_sign(&args, tx)?;
            let witness_args =
                WitnessArgs::from_slice(tx.witnesses().get(0).unwrap().raw_data().as_ref())?;
            let lock_field = witness_args.lock().to_opt().unwrap().raw_data();
            if lock_field != tx_info.omnilock_config.zero_lock(OmniUnlockMode::Normal)? {
                println!("> transaction ready to send!");
            } else {
                println!("failed to sign tx");
            }
            let tx_info = TxInfo {
                tx: json_types::TransactionView::from(tx),
                omnilock_config: tx_info.omnilock_config,
            };
            fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
        }
        Commands::AddInput(args) => {
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&args.tx_file)?)?;
            // println!("> tx: {}", serde_json::to_string_pretty(&tx_info.tx)?);
            let tx = Transaction::from(tx_info.tx.inner).into_view();
            let tx = add_live_cell(&args, tx)?;
            let tx_info = TxInfo {
                tx: json_types::TransactionView::from(tx),
                omnilock_config: tx_info.omnilock_config,
            };
            fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
        }
        Commands::AddOutput(args) => {
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&args.tx_file)?)?;
            // println!("> tx: {}", serde_json::to_string_pretty(&tx_info.tx)?);
            let tx = Transaction::from(tx_info.tx.inner).into_view();
            let lock_script = Script::from(args.to_address.payload());
            let output = CellOutput::new_builder()
                .capacity(Capacity::shannons(args.capacity.0).pack())
                .lock(lock_script)
                .build();
            let tx = tx
                .as_advanced_builder()
                .output(output)
                .output_data(Bytes::default().pack())
                .build();
            let tx_info = TxInfo {
                tx: json_types::TransactionView::from(tx),
                omnilock_config: tx_info.omnilock_config,
            };
            fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
        }
        Commands::Send { tx_file, ckb_rpc } => {
            // Send transaction
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&tx_file)?)?;
            println!("> tx: {}", serde_json::to_string_pretty(&tx_info.tx)?);
            let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
            let _tx_hash = CkbRpcClient::new(ckb_rpc.as_str())
                .send_transaction(tx_info.tx.inner, outputs_validator)
                .expect("send transaction");
            println!(">>> tx sent! <<<");
        }
    }

    Ok(())
}

fn build_multisig_config(
    sighash_address: &[Address],
    require_first_n: u8,
    threshold: u8,
) -> Result<MultisigConfig, Box<dyn StdErr>> {
    if sighash_address.is_empty() {
        return Err("Must have at least one sighash_address".to_string().into());
    }
    let mut sighash_addresses = Vec::with_capacity(sighash_address.len());
    for addr in sighash_address {
        let lock_args = addr.payload().args();
        if addr.payload().code_hash(None).as_slice() != SIGHASH_TYPE_HASH.as_bytes()
            || addr.payload().hash_type() != ScriptHashType::Type
            || lock_args.len() != 20
        {
            return Err(format!("sighash_address {} is not sighash address", addr).into());
        }
        sighash_addresses.push(H160::from_slice(lock_args.as_ref()).unwrap());
    }
    Ok(MultisigConfig::new_with(
        sighash_addresses,
        require_first_n,
        threshold,
    )?)
}

fn build_omnilock_addr(args: &BuildOmniLockAddrArgs) -> Result<(), Box<dyn StdErr>> {
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let mut config = if let Some(receiver) = args.receiver.as_ref() {
        let arg = H160::from_slice(&receiver.payload().args()).unwrap();
        OmniLockConfig::new_pubkey_hash(arg)
    } else if let Some(ethereum_receiver) = args.ethereum_receiver.as_ref() {
        let privkey = secp256k1::SecretKey::from_slice(ethereum_receiver.as_bytes()).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
        println!("pubkey:{:?}", hex_string(&pubkey.serialize()));
        println!("pubkey:{:?}", hex_string(&pubkey.serialize_uncompressed()));
        let addr = keccak160(Pubkey::from(pubkey).as_ref());
        OmniLockConfig::new_ethereum(addr)
    } else if !args.multis_args.sighash_address.is_empty() {
        let args = &args.multis_args;
        let multisig_config =
            build_multisig_config(&args.sighash_address, args.require_first_n, args.threshold)?;
        OmniLockConfig::new_multisig(multisig_config)
    } else {
        return Err("must provide a receiver or an ethereum_receiver".into());
    };
    config.set_opentx_mode();
    let address_payload = {
        let args = config.build_args();
        ckb_sdk::AddressPayload::new_full(ScriptHashType::Type, cell.type_hash.pack(), args)
    };
    let lock_script = Script::from(&address_payload);
    let resp = serde_json::json!({
        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone(), true).to_string(),
        "testnet": Address::new(NetworkType::Testnet, address_payload.clone(), true).to_string(),
        "lock-arg": format!("0x{}", hex_string(address_payload.args().as_ref())),
        "lock-hash": format!("{:#x}", lock_script.calc_script_hash())
    });
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

fn gen_open_tx(args: &GenOpenTxArgs) -> Result<(), Box<dyn StdErr>> {
    let (tx, omnilock_config) = build_open_tx(args)?;
    let tx_info = TxInfo {
        tx: json_types::TransactionView::from(tx),
        omnilock_config,
    };
    fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
    Ok(())
}

fn get_opentx_placeholder_hash() -> H256 {
    let mut ret = H256::default();
    let opentx = "opentx";
    let offset = ret.0.len() - opentx.len();
    ret.0[offset..].copy_from_slice(opentx.as_bytes());
    ret
}

fn get_opentx_tmp_script() -> Script {
    let tmp_locker = get_opentx_placeholder_hash();
    Script::new_builder()
        .code_hash(tmp_locker.pack())
        .hash_type(ScriptHashType::Type.into())
        .args([0u8; 65].pack())
        .build()
}

fn build_open_tx(
    args: &GenOpenTxArgs,
) -> Result<(TransactionView, OmniLockConfig), Box<dyn StdErr>> {
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;

    let mut omnilock_config = if let Some(sender_key) = args.sender_key.as_ref() {
        let sender_key = secp256k1::SecretKey::from_slice(sender_key.as_bytes())
            .map_err(|err| format!("invalid sender secret key: {}", err))?;
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let pubkey_hash = blake160(&pubkey.serialize());
        OmniLockConfig::new_pubkey_hash(pubkey_hash)
    } else if let Some(sender_key) = args.ethereum_sender_key.as_ref() {
        let sender_key = secp256k1::SecretKey::from_slice(sender_key.as_bytes())
            .map_err(|err| format!("invalid sender secret key: {}", err))?;
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        println!("pubkey:{:?}", hex_string(&pubkey.serialize()));
        println!("pubkey:{:?}", hex_string(&pubkey.serialize_uncompressed()));
        let addr = keccak160(Pubkey::from(pubkey).as_ref());
        OmniLockConfig::new_ethereum(addr)
    } else if !args.multis_args.sighash_address.is_empty() {
        let args = &args.multis_args;
        let multisig_config =
            build_multisig_config(&args.sighash_address, args.require_first_n, args.threshold)?;
        OmniLockConfig::new_multisig(multisig_config)
    } else {
        return Err("must provide a sender-key or an ethereum-sender-key".into());
    };
    omnilock_config.set_opentx_mode();
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(cell.type_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(omnilock_config.build_args().pack())
        .build();
    let placeholder_witness = omnilock_config.placeholder_witness(OmniUnlockMode::Normal)?;
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, args.fee_rate);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
    let genesis_block = BlockView::from(genesis_block);
    let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(&genesis_block)?;
    cell_dep_resolver.insert(cell.script_id, cell.cell_dep, "Omni Lock".to_string());
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    // Build base transaction
    let unlockers = build_omnilock_unlockers(Vec::new(), omnilock_config.clone(), cell.type_hash);
    let output = CellOutput::new_builder()
        .lock(sender.clone())
        .capacity(args.capacity.0.pack())
        .build();

    let tmp_locker = get_opentx_tmp_script();
    let output_tmp = CellOutput::new_builder()
        .lock(tmp_locker.clone())
        .capacity(args.open_capacity.0.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![
        (output, Bytes::default()),
        (output_tmp, Bytes::default()),
    ]);

    let base_tx = builder.build_base(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
    )?;

    let secp256k1_data_dep = {
        // pub const SECP256K1_DATA_OUTPUT_LOC: (usize, usize) = (0, 3);
        let tx_hash = genesis_block.transactions()[0].hash();
        let out_point = OutPoint::new(tx_hash, 3u32);
        CellDep::new_builder().out_point(out_point).build()
    };

    let base_tx = base_tx
        .as_advanced_builder()
        .cell_dep(secp256k1_data_dep)
        .build();
    let (tx, _) = fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;

    let tx = balance_tx_capacity(
        &tx,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;

    let tmp_idxes: HashSet<usize> = tx
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, out)| out.lock() == tmp_locker)
        .map(|(idx, _)| idx)
        .collect();
    let outputs: Vec<CellOutput> = tx
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| !tmp_idxes.contains(idx))
        .map(|(_, out)| out)
        .collect();
    let outputs_data: Vec<ckb_types::packed::Bytes> = tx
        .outputs_data()
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| !tmp_idxes.contains(idx))
        .map(|(_, out)| out)
        .collect();
    let tx = tx
        .as_advanced_builder()
        .set_outputs(outputs)
        .set_outputs_data(outputs_data)
        .build();

    let wit = OpentxWitness::new_sig_all_relative(&tx, Some(0xdeadbeef)).unwrap();
    omnilock_config.set_opentx_input(wit);
    // after set opentx config, need to update the witness field
    let placeholder_witness = omnilock_config.placeholder_witness(OmniUnlockMode::Normal)?;
    let tmp_idxes: Vec<_> = tx
        .input_pts_iter()
        .enumerate()
        .filter(|(_, output)| tx_dep_provider.get_cell(output).unwrap().lock() == sender)
        .map(|(idx, _)| idx)
        .collect();
    let witnesses: Vec<_> = tx
        .witnesses()
        .into_iter()
        .enumerate()
        .map(|(i, w)| {
            if tmp_idxes.contains(&i) {
                placeholder_witness.as_bytes().pack()
            } else {
                w
            }
        })
        .collect();
    let tx = tx.as_advanced_builder().set_witnesses(witnesses).build();
    Ok((tx, omnilock_config))
}

fn build_omnilock_cell_dep(
    ckb_client: &mut CkbRpcClient,
    tx_hash: &H256,
    index: usize,
) -> Result<OmniLockInfo, Box<dyn StdErr>> {
    let out_point_json = ckb_jsonrpc_types::OutPoint {
        tx_hash: tx_hash.clone(),
        index: ckb_jsonrpc_types::Uint32::from(index as u32),
    };
    let cell_status = ckb_client.get_live_cell(out_point_json, false)?;
    let script = Script::from(cell_status.cell.unwrap().output.type_.unwrap());

    let type_hash = script.calc_script_hash();
    let out_point = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes())?, index as u32);

    let cell_dep = CellDep::new_builder().out_point(out_point).build();
    Ok(OmniLockInfo {
        type_hash: H256::from_slice(type_hash.as_slice())?,
        script_id: ScriptId::new_type(type_hash.unpack()),
        cell_dep,
    })
}

fn add_live_cell(
    args: &AddInputArgs,
    tx: TransactionView,
) -> Result<TransactionView, Box<dyn StdErr>> {
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let out_point_json = ckb_jsonrpc_types::OutPoint {
        tx_hash: args.tx_hash.clone(),
        index: ckb_jsonrpc_types::Uint32::from(args.index as u32),
    };
    let cell_with_status = ckb_client.get_live_cell(out_point_json, false)?;
    let input_outpoint = OutPoint::new(
        Byte32::from_slice(args.tx_hash.as_bytes())?,
        args.index as u32,
    );
    // since value should be provided in args
    let input = ckb_types::packed::CellInput::new(input_outpoint, 0);
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let code_hash = cell_with_status.cell.unwrap().output.lock.code_hash;
    let script_id = ScriptId::new_type(code_hash);
    let dep = cell_dep_resolver
        .get(&script_id)
        .as_ref()
        .unwrap()
        .0
        .clone();

    Ok(tx.as_advanced_builder().input(input).cell_dep(dep).build())
}

fn build_omnilock_unlockers(
    keys: Vec<secp256k1::SecretKey>,
    config: OmniLockConfig,
    omni_lock_type_hash: H256,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = match config.id().flag() {
        IdentityFlag::PubkeyHash => SecpCkbRawKeySigner::new_with_secret_keys(keys),
        IdentityFlag::Ethereum => SecpCkbRawKeySigner::new_with_ethereum_secret_keys(keys),
        IdentityFlag::Multisig => SecpCkbRawKeySigner::new_with_secret_keys(keys),
        _ => unreachable!("should not reach here!"),
    };
    let omnilock_signer =
        OmniLockScriptSigner::new(Box::new(signer), config.clone(), OmniUnlockMode::Normal);
    let omnilock_unlocker = OmniLockUnlocker::new(omnilock_signer, config);
    let omnilock_script_id = ScriptId::new_type(omni_lock_type_hash);
    HashMap::from([(
        omnilock_script_id,
        Box::new(omnilock_unlocker) as Box<dyn ScriptUnlocker>,
    )])
}

fn sign_tx(
    args: &SignTxArgs,
    mut tx: TransactionView,
    omnilock_config: &OmniLockConfig,
    keys: Vec<secp256k1::SecretKey>,
) -> Result<(TransactionView, Vec<ScriptGroup>), Box<dyn StdErr>> {
    // Unlock transaction
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;

    let mut _still_locked_groups = None;
    let unlockers = build_omnilock_unlockers(keys, omnilock_config.clone(), cell.type_hash);
    let (new_tx, new_still_locked_groups) = unlock_tx(tx.clone(), &tx_dep_provider, &unlockers)?;
    tx = new_tx;
    _still_locked_groups = Some(new_still_locked_groups);
    Ok((tx, _still_locked_groups.unwrap_or_default()))
}

fn sighash_sign(
    args: &SignTxArgs,
    tx: TransactionView,
) -> Result<(TransactionView, Vec<ScriptGroup>), Box<dyn StdErr>> {
    if args.sender_key.is_empty() {
        return Err("must provide sender-key to sign".into());
    }
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key[0].as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build the transaction
    // let output = CellOutput::new_builder()
    //     .lock(Script::from(&args.receiver))
    //     .capacity(args.capacity.0.pack())
    //     .build();
    // let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    // let (tx, still_locked_groups) = builder.build_unlocked(
    //     &mut cell_collector,
    //     &cell_dep_resolver,
    //     &header_dep_resolver,
    //     &tx_dep_provider,
    //     &balancer,
    //     &unlockers,
    // )?;

    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);
    let (new_tx, new_still_locked_groups) = unlock_tx(tx, &tx_dep_provider, &unlockers)?;
    Ok((new_tx, new_still_locked_groups))
}
