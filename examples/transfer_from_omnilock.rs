use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::OMNILOCK_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        default_impls::ParseGenesisInfoError, CellDepResolver, DefaultCellCollector,
        DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider,
        SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    types::NetworkType,
    unlock::{OmniLockConfig, OmniLockScriptSigner},
    unlock::{OmniLockUnlocker, ScriptUnlocker, SecpSighashUnlocker},
    Address, HumanCapacity, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, DepType, ScriptHashType, TransactionView},
    h256,
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::{collections::HashMap, error::Error as StdErr};

#[derive(Args)]
struct BuildOmniLockAddrArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,

    /// CKB indexer rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8116")]
    ckb_indexer: String,
}
#[derive(Args)]
struct GenTxArgs {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,
    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

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
struct SignTxArgs {}
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

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(build_args) => build_omnilock_addr(&build_args)?,
        Commands::Gen(gen_args) => {
            gen_omnilock_tx(&gen_args)?;
        }
        Commands::Sign(sig_args) => {}
        Commands::Send { tx_file, ckb_rpc } => {}
    }

    Ok(())
}

fn build_omnilock_addr(args: &BuildOmniLockAddrArgs) -> Result<(), Box<dyn StdErr>> {
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);

    let config = OmniLockConfig::new_pubkey_hash(&pubkey.into());
    let address_payload = config.to_address_payload();
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
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);

    let omnilock_config = OmniLockConfig::new_pubkey_hash(&pubkey.into());

    let tx = build_transfer_tx(&args, &omnilock_config)?;
    let tx_info = TxInfo {
        tx: json_types::TransactionView::from(tx),
        omnilock_config,
    };
    fs::write(&args.tx_file, serde_json::to_string_pretty(&tx_info)?)?;
    Ok(())
}

fn build_transfer_tx(
    args: &GenTxArgs,
    omnilock_config: &OmniLockConfig,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build CapacityBalancer
    let sender = Script::new_builder()
        .code_hash(OMNILOCK_TYPE_HASH.pack())
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
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        let mut res = OmniLockDepResolver::from_genesis(&BlockView::from(genesis_block))?;
        let omnilock_block = ckb_client
            .get_block(h256!(
                "0xc334b5f392c0065848bf09f1ccad5050644260f1fe1002d9adfcb2cbbb64faf6"
            ))?
            .unwrap();
        res.extend_block(&BlockView::from(omnilock_block), &h256!("0x635f78eba450cb2f73f113022ff62e4bbfb5a39b7368c375c6a731ba4c85c59e"))?;
        res
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    // Build base transaction
    let unlockers = build_omnilock_unlockers(Vec::new(), omnilock_config.clone());
    let output = CellOutput::new_builder()
        .lock(Script::from(&args.receiver))
        .capacity(args.capacity.0.pack())
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

fn build_omnilock_unlockers(
    keys: Vec<secp256k1::SecretKey>,
    config: OmniLockConfig,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(keys);
    let omnilock_signer = OmniLockScriptSigner::new(Box::new(signer), config);
    let multisig_unlocker = OmniLockUnlocker::new(omnilock_signer);
    let omnilock_script_id = ScriptId::new_type(OMNILOCK_TYPE_HASH.clone());
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
                        println!(
                            "type hash:{:?} data_hash:{:?} code_hash_pack: {:?}",
                            type_hash,
                            data_hash,
                            target_data_hash.pack()
                        );
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
            .dep_type(DepType::DepGroup.into())
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
