use ckb_crypto::secp::Pubkey;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses, transfer::CapacityTransferBuilder,
        unlock_tx, CapacityBalancer, TxBuilder,
    },
    types::NetworkType,
    unlock::{OmniLockConfig, OmniLockScriptSigner, OmniUnlockMode},
    unlock::{OmniLockUnlocker, ScriptUnlocker},
    util::keccak160,
    Address, HumanCapacity, ScriptGroup, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction, WitnessArgs},
    prelude::*,
    H256,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::{collections::HashMap, error::Error as StdErr};

// https://github.com/XuJiandong/rfcs/blob/omnilock/rfcs/0042-omnilock/0042-omnilock.md
// pub const OMNILOCK_TYPE_HASH: H256 =
// h256!("0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb");

/*
# examples for the developer local node
########################### ethereum omnilock example #################################
# 1. build a omnilock address
./target/debug/examples/transfer_from_omnilock_ethereum build \
  --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
  --receiver 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d
# pubkey:"038d3cfceea4f9c2e76c5c4f5e99aec74c26d6ac894648b5700a0b71f91f9b5c2a"
# pubkey:"048d3cfceea4f9c2e76c5c4f5e99aec74c26d6ac894648b5700a0b71f91f9b5c2a26b16aac1d5753e56849ea83bf795eb8b06f0b6f4e5ed7b8caca720595458039"
# {
#   "lock-arg": "0x01cf2485c76aff1f2b4464edf04a1c8045068cf7e000",
#   "lock-hash": "0x04b791304bbd6287218acc9e4b0971789ea1ef52b758317481245913511c6159",
#   "mainnet": "ckb1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgpeujgt3m2lu0jk3ryahcy58yqg5rgealqqq5yzrqv",
#   "testnet": "ckt1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgpeujgt3m2lu0jk3ryahcy58yqg5rgealqqq0nk0py"
# }
# 2. transfer capacity to the address
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgpeujgt3m2lu0jk3ryahcy58yqg5rgealqqq0nk0py \
  --capacity 200 --tx-fee 0.001 --skip-check-to-address
# 0x27c1fc437cac0e45236e566a71c8b87d2f9cbf58d3bfce0be4dab12c57d9e217
# 3. generate the transaction
./target/debug/examples/transfer_from_omnilock_ethereum gen --sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
    --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
    --receiver ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug \
    --capacity 100.0 \
    --tx-file tx.json
# 4. sign the transaction
./target/debug/examples/transfer_from_omnilock_ethereum sign --sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
            --tx-file tx.json
# 5. send transaction
./target/debug/examples/transfer_from_omnilock_ethereum send --tx-file tx.json
*/

#[derive(Args)]
struct BuildOmniLockAddrArgs {
    /// The receiver's private key (hex string)
    #[clap(long, value_name = "KEY")]
    receiver: H256,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256")]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER")]
    omnilock_index: usize,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}
#[derive(Args)]
struct GenTxArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,
    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256")]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER")]
    omnilock_index: usize,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}
#[derive(Args)]
struct SignTxArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The output transaction info file (.json)
    #[clap(long, value_name = "PATH")]
    tx_file: PathBuf,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "H256")]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "NUMBER")]
    omnilock_index: usize,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,
}
#[derive(Subcommand)]
enum Commands {
    /// build omni lock address
    Build(BuildOmniLockAddrArgs),
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
        Commands::Gen(gen_args) => {
            gen_omnilock_tx(&gen_args)?;
        }
        Commands::Sign(args) => {
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(&args.tx_file)?)?;
            let tx = Transaction::from(tx_info.tx.inner).into_view();
            let key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
                .map_err(|err| format!("invalid sender secret key: {}", err))?;
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
            let pubkey = Pubkey::from(pubkey);
            let hash160 = keccak160(pubkey.as_ref());
            if tx_info.omnilock_config.id().auth_content().as_bytes() != hash160.as_bytes() {
                return Err(format!("key {:#x} is not in omnilock config", args.sender_key).into());
            }
            let (tx, _) = sign_tx(&args, tx, &tx_info.omnilock_config, key)?;
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
        Commands::Send { tx_file, ckb_rpc } => {
            // Send transaction
            let tx_info: TxInfo = serde_json::from_slice(&fs::read(tx_file)?)?;
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

fn build_omnilock_addr(args: &BuildOmniLockAddrArgs) -> Result<(), Box<dyn StdErr>> {
    let ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell = build_omnilock_cell_dep(&ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let privkey = secp256k1::SecretKey::from_slice(args.receiver.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
    println!("pubkey:{:?}", hex_string(&pubkey.serialize()));
    println!("pubkey:{:?}", hex_string(&pubkey.serialize_uncompressed()));
    let addr = keccak160(Pubkey::from(pubkey).as_ref());
    let config = OmniLockConfig::new_ethereum(addr);
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

fn gen_omnilock_tx(args: &GenTxArgs) -> Result<(), Box<dyn StdErr>> {
    let (tx, omnilock_config) = build_transfer_tx(args)?;
    let tx_info = TxInfo {
        tx: json_types::TransactionView::from(tx),
        omnilock_config,
    };
    fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
    Ok(())
}

fn build_transfer_tx(
    args: &GenTxArgs,
) -> Result<(TransactionView, OmniLockConfig), Box<dyn StdErr>> {
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    println!("pubkey:{:?}", hex_string(&pubkey.serialize()));
    println!("pubkey:{:?}", hex_string(&pubkey.serialize_uncompressed()));
    let ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell = build_omnilock_cell_dep(&ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let addr = keccak160(Pubkey::from(pubkey).as_ref());
    let omnilock_config = OmniLockConfig::new_ethereum(addr);
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(cell.type_hash.pack())
        .hash_type(ScriptHashType::Type)
        .args(omnilock_config.build_args().pack())
        .build();
    let placeholder_witness = omnilock_config.placeholder_witness(OmniUnlockMode::Normal)?;
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
    let genesis_block = BlockView::from(genesis_block);
    let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(&genesis_block)?;
    cell_dep_resolver.insert(cell.script_id, cell.cell_dep, "Omni Lock".to_string());
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector = DefaultCellCollector::new(args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    // Build base transaction
    let unlockers = build_omnilock_unlockers(Vec::new(), omnilock_config.clone(), cell.type_hash);
    let output = CellOutput::new_builder()
        .lock(Script::from(&args.receiver))
        .capacity(args.capacity.0)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);

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
    let (tx_filled_witnesses, _) =
        fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;

    let tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;
    Ok((tx, omnilock_config))
}

fn build_omnilock_cell_dep(
    ckb_client: &CkbRpcClient,
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

fn build_omnilock_unlockers(
    keys: Vec<secp256k1::SecretKey>,
    config: OmniLockConfig,
    omni_lock_type_hash: H256,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    // NOTE: this is the difference with sighash
    let signer = SecpCkbRawKeySigner::new_with_ethereum_secret_keys(keys);
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
    key: secp256k1::SecretKey,
) -> Result<(TransactionView, Vec<ScriptGroup>), Box<dyn StdErr>> {
    // Unlock transaction
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    let ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell = build_omnilock_cell_dep(&ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;

    let unlockers = build_omnilock_unlockers(vec![key], omnilock_config.clone(), cell.type_hash);
    let (new_tx, new_still_locked_groups) = unlock_tx(tx.clone(), &tx_dep_provider, &unlockers)?;
    tx = new_tx;
    assert!(new_still_locked_groups.is_empty());
    Ok((tx, new_still_locked_groups))
}
