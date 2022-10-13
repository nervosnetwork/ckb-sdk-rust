use ckb_hash::blake2b_256;
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
    unlock::{OmniLockConfig, OmniLockScriptSigner, opentx::OpentxWitness},
    unlock::{OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker},
    util::blake160,
    Address, HumanCapacity, ScriptGroup, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction, WitnessArgs},
    prelude::*,
    H160, H256,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::{collections::HashMap, error::Error as StdErr};

/*
# examples for the developer local node
########################### sighash omnilock example #################################
# 1. build a omnilock address
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
./target/debug/examples/transfer_from_opentx gen --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 98.0 \
            --tx-file tx.json
# 4. sign the transaction
./target/debug/examples/transfer_from_opentx sign --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
            --tx-file tx.json
# 5. send transaction
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
*/
const OPENTX_TX_HASH: &str = "d7697f6b3684d1451c42cc538b3789f13b01430007f65afe74834b6a28714a18";
const OPENTX_TX_IDX: &str = "0";

#[derive(Args)]
struct BuildOmniLockAddrArgs {
    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

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
    sender_key: H256,
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
    sender_key: H256,

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
#[derive(Subcommand)]
enum Commands {
    /// build omni lock address
    Build(BuildOmniLockAddrArgs),
    /// Generate the transaction
    Gen(GenOpenTxArgs),
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
            let hash160 = &blake2b_256(&pubkey.serialize()[..])[0..20];
            if tx_info.omnilock_config.id().auth_content().as_bytes() != hash160 {
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

fn build_omnilock_addr(args: &BuildOmniLockAddrArgs) -> Result<(), Box<dyn StdErr>> {
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let arg = H160::from_slice(&args.receiver.payload().args()).unwrap();
    let mut config = OmniLockConfig::new_pubkey_hash(arg);
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

fn gen_omnilock_tx(args: &GenOpenTxArgs) -> Result<(), Box<dyn StdErr>> {
    let (tx, omnilock_config) = build_transfer_tx(args)?;
    let tx_info = TxInfo {
        tx: json_types::TransactionView::from(tx),
        omnilock_config,
    };
    fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
    Ok(())
}

fn build_transfer_tx(
    args: &GenOpenTxArgs,
) -> Result<(TransactionView, OmniLockConfig), Box<dyn StdErr>> {
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;

    let pubkey_hash = blake160(&pubkey.serialize());
    let mut omnilock_config = OmniLockConfig::new_pubkey_hash(pubkey_hash);
    omnilock_config.set_opentx_mode();
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(cell.type_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(omnilock_config.build_args().pack())
        .build();
    let placeholder_witness = omnilock_config.placeholder_witness(OmniUnlockMode::Normal)?;
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, 0);

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
    let (tx, _) =
        fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;

    let tx = balance_tx_capacity(
        &tx,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;

    let outputs: Vec<CellOutput> = tx.outputs().into_iter().skip(1).collect();
    let outputs_data: Vec<ckb_types::packed::Bytes> =
        tx.outputs_data().into_iter().skip(1).collect();

    let tx = tx
        .as_advanced_builder()
        .set_outputs(outputs)
        .set_outputs_data(outputs_data)
        .build();

    let wit = OpentxWitness::new_sig_all_relative(&tx, Some(0xdeadbeef)).unwrap();
    omnilock_config.set_opentx_input(wit);
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

fn build_omnilock_unlockers(
    keys: Vec<secp256k1::SecretKey>,
    config: OmniLockConfig,
    omni_lock_type_hash: H256,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(keys);
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

    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;

    let mut _still_locked_groups = None;
    let unlockers = build_omnilock_unlockers(vec![key], omnilock_config.clone(), cell.type_hash);
    let (new_tx, new_still_locked_groups) = unlock_tx(tx.clone(), &tx_dep_provider, &unlockers)?;
    tx = new_tx;
    _still_locked_groups = Some(new_still_locked_groups);
    Ok((tx, _still_locked_groups.unwrap_or_default()))
}
