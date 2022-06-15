use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    rpc::CkbRpcClient,
    traits::{
        default_impls::ParseGenesisInfoError, CellCollector, CellDepResolver, DefaultCellCollector,
        DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider,
        HeaderDepResolver, SecpCkbRawKeySigner, TransactionDependencyProvider,
    },
    tx_builder::{
        transfer::CapacityTransferBuilder, unlock_tx, CapacityBalancer, TxBuilder, TxBuilderError,
    },
    types::NetworkType,
    unlock::{IdentityFlags, OmniLockUnlocker, ScriptUnlocker},
    unlock::{OmniLockConfig, OmniLockScriptSigner},
    Address, HumanCapacity, ScriptGroup, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, DepType, ScriptHashType, TransactionView},
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
########################### sighash omnilock example #################################
# 1. build a omnilock address
 ./target/debug/examples/transfer_from_omnilock build \
  --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
  --receiver ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024
    # receiver lock-arg:b398368a8ed39448f95479c1178ff3fc5e316318
    # {
    #   "lock-arg": "0x00b398368a8ed39448f95479c1178ff3fc5e31631800",
    #   "lock-hash": "0x6b845964aad7f568edf61a69d1c2278c68065dc91bad3c32234869aed86f7642",
    #   "mainnet": "ckb1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgqkwvrdz5w6w2y372508q30rlnl30rzcccqq2pnflw",
    #   "testnet": "ckt1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgqkwvrdz5w6w2y372508q30rlnl30rzcccqq3k897x"
    # }
# 2. transfer capacity to the address
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqklkz85v4xt39ws5dd2hdv8xsy4jnpe3envjzvddqecxr0mgvrksqgqkwvrdz5w6w2y372508q30rlnl30rzcccqq3k897x \
  --capacity 99 --tx-fee 0.001 --skip-check-to-address
    # 0x999479f890a65cb4c37660565daeb77adec30cf65862e8e1aece09993b6340fc
# 3. generate the transaction
./target/debug/examples/transfer_from_omnilock gen --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
            --receiver ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug \
            --capacity 100.0 \
            --tx-file tx.json
# 4. sign the transaction
./target/debug/examples/transfer_from_omnilock sign --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --omnilock-tx-hash 34e39e16a285d951b587e88f74286cbdb09c27a5c7e86aa1b1c92058a3cbcc52 --omnilock-index 0  \
            --tx-file tx.json
# 5. send transaction
./target/debug/examples/transfer_from_omnilock send --tx-file tx.json
*/

#[derive(Args)]
struct BuildOmniLockAddrArgs {
    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// omnilock script deploy transaction hash
    #[clap(long, value_name = "omnilock_tx_hash")]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "index")]
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
    #[clap(long, value_name = "omnilock_tx_hash")]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "index")]
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
    #[clap(long, value_name = "omnilock_tx_hash")]
    omnilock_tx_hash: H256,

    /// cell index of omnilock script deploy transaction's outputs
    #[clap(long, value_name = "index")]
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
    celldep: CellDep,
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
            let hash160 = Bytes::copy_from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20]);
            if tx_info.omnilock_config.id.blake160 != hash160 {
                return Err(format!("key {:#x} is not in multisig config", args.sender_key).into());
            }
            let (tx, _) = sign_tx(&args, tx, &tx_info.omnilock_config, key)?;
            let lock_field =
                WitnessArgs::from_slice(tx.witnesses().get(0).unwrap().raw_data().as_ref())?
                    .lock()
                    .to_opt()
                    .unwrap()
                    .raw_data();
            if lock_field != tx_info.omnilock_config.zero_lock() {
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

fn build_omnilock_addr(args: &BuildOmniLockAddrArgs) -> Result<(), Box<dyn StdErr>> {
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let config = OmniLockConfig::new_pubkey_hash_with_lockarg(args.receiver.payload().args());
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
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell =
        build_omnilock_cell_dep(&mut ckb_client, &args.omnilock_tx_hash, args.omnilock_index)?;
    let omnilock_config = OmniLockConfig::new_pubkey_hash(&pubkey.into());
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(cell.type_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(omnilock_config.build_args().pack())
        .build();
    let sender_addr = Address::new(args.receiver.network(), sender.clone().into(), true);
    println!("> sender address: {}", sender_addr);
    let placeholder_witness = omnilock_config.placeholder_witness();

    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
    let genesis_block = BlockView::from(genesis_block);
    let cell_dep_resolver = {
        let mut res = DefaultCellDepResolver::from_genesis(&genesis_block)?;
        res.insert(cell.script_id, cell.celldep, "Omni Lock".to_string());
        res
    };
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
    let secp256k1_data_dep = build_seckp256k1_data_dep(&genesis_block).unwrap();
    let builder = OmniLockTransferBuilder::new(
        Box::new(builder),
        omnilock_config.id.flags,
        secp256k1_data_dep,
    );
    let tx = builder.build_balanced(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    Ok((tx, omnilock_config))
}

fn build_omnilock_cell_dep(
    ckb_client: &mut CkbRpcClient,
    tx_hash: &H256,
    index: usize,
) -> Result<OmniLockInfo, Box<dyn StdErr>> {
    let tx = ckb_client
        .get_transaction(tx_hash.clone())
        .unwrap()
        .unwrap();
    let cell = tx
        .transaction
        .unwrap()
        .inner
        .outputs
        .into_iter()
        .nth(index)
        .unwrap();
    let script = Script::from(cell.type_.unwrap());

    let type_hash = script.calc_script_hash();
    let script_id = ScriptId::new_type(type_hash.unpack());
    let type_hash = H256::from_slice(type_hash.as_slice())?;
    let out_point = OutPoint::new(
        Byte32::from_slice(tx_hash.as_bytes()).unwrap(),
        index as u32,
    );

    let celldep = CellDep::new_builder().out_point(out_point).build();
    Ok(OmniLockInfo {
        type_hash,
        script_id,
        celldep,
    })
}

fn build_seckp256k1_data_dep(genesis_block: &BlockView) -> Option<CellDep> {
    let mut out_point = None;
    // pub const SECP256K1_DATA_OUTPUT_LOC: (usize, usize) = (0, 3);
    genesis_block
        .transactions()
        .iter()
        .enumerate()
        .for_each(|(tx_index, tx)| {
            if tx_index == 0 {
                out_point = Some(OutPoint::new(tx.hash(), 3u32));
            }
        });
    if let Some(out) = out_point {
        let dao_dep = CellDep::new_builder().out_point(out).build();
        return Some(dao_dep);
    }
    None
}

fn build_omnilock_unlockers(
    keys: Vec<secp256k1::SecretKey>,
    config: OmniLockConfig,
    omni_lock_type_hash: H256,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(keys);
    let omnilock_signer = OmniLockScriptSigner::new(Box::new(signer), config);
    let multisig_unlocker = OmniLockUnlocker::new(omnilock_signer);
    let omnilock_script_id = ScriptId::new_type(omni_lock_type_hash);
    let mut unlockers = HashMap::default();
    unlockers.insert(
        omnilock_script_id,
        Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}

#[derive(Clone)]
pub struct OmniLockDepResolver {
    default_resolver: DefaultCellDepResolver,
}
impl OmniLockDepResolver {
    pub fn from_genesis(
        genesis_block: &BlockView,
    ) -> Result<OmniLockDepResolver, ParseGenesisInfoError> {
        let default_resolver = DefaultCellDepResolver::from_genesis(genesis_block)?;
        Ok(OmniLockDepResolver { default_resolver })
    }
    pub fn extend_block(
        &mut self,
        block: &BlockView,
        target_data_hash: &H256,
    ) -> Result<(), ParseGenesisInfoError> {
        // this scan operations can be done with command `ckb-cli util cell-meta`
        let mut omnilock_data_hash = None;
        let mut omnilock_type_hash = None;
        let mut outpoint = None;
        block
            .transactions()
            .iter()
            .skip(1) // the skip block build transaction
            .for_each(|tx| {
                tx.outputs()
                    .into_iter()
                    .zip(tx.outputs_data().into_iter())
                    .enumerate()
                    .for_each(|(index, (output, data))| {
                        let type_hash = output
                            .type_()
                            .to_opt()
                            .map(|script| script.calc_script_hash());
                        let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                        if data_hash == target_data_hash.pack() {
                            omnilock_type_hash = type_hash;
                            omnilock_data_hash = Some(data_hash);

                            outpoint = Some(OutPoint::new(tx.hash(), index as u32));
                        }
                    });
            });
        if outpoint.is_none() {
            log::error!("can't find omnilock code hash from block",);
        }

        let omnilock_type_hash = omnilock_type_hash
            .ok_or_else(|| "No type hash(sighash) found in txs[0][1]".to_owned())
            .map_err(ParseGenesisInfoError::TypeHashNotFound)?;
        let omnilock_dep = CellDep::new_builder()
            .out_point(outpoint.unwrap())
            .dep_type(DepType::Code.into())
            .build();
        self.default_resolver.insert(
            ScriptId::new_type(omnilock_type_hash.unpack()),
            omnilock_dep,
            "Omni Lock".to_string(),
        );
        Ok(())
    }

    pub fn insert(
        &mut self,
        script_id: ScriptId,
        cell_dep: CellDep,
        name: String,
    ) -> Option<(CellDep, String)> {
        self.default_resolver.insert(script_id, cell_dep, name)
    }
    pub fn remove(&mut self, script_id: &ScriptId) -> Option<(CellDep, String)> {
        self.default_resolver.remove(script_id)
    }
    pub fn contains(&self, script_id: &ScriptId) -> bool {
        self.default_resolver.contains(script_id)
    }
    pub fn get(&self, script_id: &ScriptId) -> Option<&(CellDep, String)> {
        self.default_resolver.get(script_id)
    }
    pub fn sighash_dep(&self) -> Option<&(CellDep, String)> {
        self.default_resolver.sighash_dep()
    }
    pub fn multisig_dep(&self) -> Option<&(CellDep, String)> {
        self.default_resolver.multisig_dep()
    }
    pub fn dao_dep(&self) -> Option<&(CellDep, String)> {
        self.default_resolver.multisig_dep()
    }
}

impl CellDepResolver for OmniLockDepResolver {
    fn resolve(&self, script: &Script) -> Option<CellDep> {
        self.default_resolver.resolve(script)
    }
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

/// A builder to build a transaction simply transfer capcity to an address. It
/// will resolve the type script's cell_dep if given.
pub struct OmniLockTransferBuilder {
    pub tx_builder: Box<dyn TxBuilder>,
    pub id_flags: IdentityFlags,
    pub secp256k1_data_dep: CellDep,
}

impl OmniLockTransferBuilder {
    pub fn new(
        tx_builder: Box<dyn TxBuilder>,
        id_flags: IdentityFlags,
        secp256k1_data_dep: CellDep,
    ) -> OmniLockTransferBuilder {
        OmniLockTransferBuilder {
            tx_builder,
            id_flags,
            secp256k1_data_dep,
        }
    }
}

impl TxBuilder for OmniLockTransferBuilder {
    fn build_base(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        let mut tx = self.tx_builder.build_base(
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
        )?;

        if self.id_flags == IdentityFlags::PubkeyHash {
            let cell_deps = tx
                .cell_deps()
                .as_builder()
                .push(self.secp256k1_data_dep.clone())
                .build();
            tx = tx.as_advanced_builder().cell_deps(cell_deps).build();
        }

        Ok(tx)
    }
}
