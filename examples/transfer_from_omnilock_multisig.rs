use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
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
    unlock::{MultisigConfig, OmniLockUnlocker, ScriptUnlocker},
    unlock::{OmniLockConfig, OmniLockScriptSigner, OmniUnlockMode},
    Address, HumanCapacity, ScriptGroup, ScriptId,
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

// https://github.com/XuJiandong/rfcs/blob/omnilock/rfcs/0042-omnilock/0042-omnilock.md
// pub const OMNILOCK_TYPE_HASH: H256 =
// h256!("0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb");

/*
# examples for the developer local node
* note: all the address and sender-key are all examples, so you should not send capacity to these address.
########################### mulitsig omnilock example #################################
# 1. build a omnilock address
 ./target/debug/examples/transfer_from_omnilock_multisig build \
  --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
  --require-first-n 0 \
  --threshold 2 \
  --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
  --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
  --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4
# {
#  "lock-arg": "0x065d7d0128eeaa6f9656a229b42aadd0b177d387eb00",
#  "lock-hash": "0xd93312782194cdb1a23dd73128795fd6a71ceb067ea9fd10546b95853d45f08e",
#  "mainnet": "ckb1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgxt47sz28w4fhev44z9x6z4twsk9ma8pltqqad8v6p",
#  "testnet": "ckt1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgxt47sz28w4fhev44z9x6z4twsk9ma8pltqqx6nqmf"
# }
# 2. transfer capacity to the address
ckb-cli wallet transfer --from-account 0xb398368a8ed39448f95479c1178ff3fc5e316318 \
  --to-address ckt1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgxt47sz28w4fhev44z9x6z4twsk9ma8pltqqx6nqmf \
  --capacity 200 --tx-fee 0.001 --skip-check-to-address
#    0x2eecdfc28b58dc8af81cee8c1de03d4ed3ee9dd179cf37ea91530f84046cd21f
# 3. generate the transaction
./target/debug/examples/transfer_from_omnilock_multisig gen \
  --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
  --receiver ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug \
  --capacity 120.0 \
  --require-first-n 0 \
  --threshold 2 \
  --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
  --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
  --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4 \
  --tx-file tx.json

# 4. sign the transaction
./target/debug/examples/transfer_from_omnilock_multisig sign \
  --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
  --sender-key d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc \
  --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
  --tx-file tx.json
# 5. send transaction
./target/debug/examples/transfer_from_omnilock send --tx-file tx.json
*/

#[derive(Args)]
struct BuildOmniLockAddrArgs {
    /// Require first n signatures of corresponding pubkey
    #[clap(long, value_name = "NUM")]
    require_first_n: u8,

    /// Multisig threshold
    #[clap(long, value_name = "NUM")]
    threshold: u8,

    /// Normal sighash address
    #[clap(long, value_name = "ADDRESS")]
    sighash_address: Vec<Address>,

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
    /// Require first n signatures of corresponding pubkey
    #[clap(long, value_name = "NUM")]
    require_first_n: u8,

    /// Multisig threshold
    #[clap(long, value_name = "NUM")]
    threshold: u8,

    /// Normal sighash address
    #[clap(long, value_name = "ADDRESS")]
    sighash_address: Vec<Address>,

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
            let keys: Vec<_> = args
                .sender_key
                .iter()
                .map(|sender_key| {
                    secp256k1::SecretKey::from_slice(sender_key.as_bytes())
                        .map_err(|err| format!("invalid sender secret key: {}", err))
                        .unwrap()
                })
                .collect();
            let (tx, _) = sign_tx(&args, tx, &tx_info.omnilock_config, keys)?;
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

    let multisig_config =
        build_multisig_config(&args.sighash_address, args.require_first_n, args.threshold)?;

    let config = OmniLockConfig::new_multisig(multisig_config);
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
    let multisig_config =
        build_multisig_config(&args.sighash_address, args.require_first_n, args.threshold)?;
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let omnilock_config = OmniLockConfig::new_multisig(multisig_config);
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(cell.type_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(omnilock_config.build_args().pack())
        .build();
    let placeholder_witness = omnilock_config.placeholder_witness(OmniUnlockMode::Normal)?;
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

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
        .lock(Script::from(&args.receiver))
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
