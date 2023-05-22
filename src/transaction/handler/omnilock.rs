use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
};

use super::{cell_dep, HandlerContext, ScriptHandler};
use crate::{
    core::TransactionBuilder,
    traits::DefaultTransactionDependencyProvider,
    transaction::{builder::PrepareTransactionViewer, input::TransactionInput},
    tx_builder::TxBuilderError,
    unlock::{OmniLockConfig, OmniUnlockMode},
    NetworkInfo, NetworkType, ScriptGroup, ScriptId,
};
use lazy_static::lazy_static;

pub struct OmnilockScriptHandler {
    cell_deps: Vec<CellDep>,
    sighash_dep: CellDep,
    multisig_dep: CellDep,
    lock_script_id: ScriptId,
}

pub struct OmnilockScriptContext {
    pub cfg: OmniLockConfig,
    pub rce_cells: Option<Vec<OutPoint>>,
    pub unlock_mode: OmniUnlockMode,
    pub rpc_url: String,
}

impl OmnilockScriptContext {
    pub fn new(cfg: OmniLockConfig, rpc_url: String) -> Self {
        Self {
            cfg,
            rce_cells: None,
            unlock_mode: OmniUnlockMode::Normal,
            rpc_url,
        }
    }
}

impl HandlerContext for OmnilockScriptContext {}

impl OmnilockScriptHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        ScriptId::from(script) == self.lock_script_id
    }

    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let mut ret = Self {
            cell_deps: vec![],
            sighash_dep: Default::default(),
            multisig_dep: Default::default(),
            lock_script_id: ScriptId::default(),
        };
        ret.init(network)?;
        Ok(ret)
    }

    pub fn set_cell_deps(&mut self, cell_deps: Vec<CellDep>) {
        self.cell_deps = cell_deps;
    }

    pub fn set_lock_script_id(&mut self, lock_script_id: ScriptId) {
        self.lock_script_id = lock_script_id;
    }

    fn build_base(
        &self,
        viewer: &mut PrepareTransactionViewer,
        context: &OmnilockScriptContext,
    ) -> Result<(), TxBuilderError> {
        if let Some(admin_cfg) = context.cfg.get_admin_config() {
            if let Some(rce_cells) = context.rce_cells.as_ref() {
                if admin_cfg.rce_in_input() {
                    let tx_dep_provider =
                        DefaultTransactionDependencyProvider::new(&context.rpc_url, 10);
                    for cell in rce_cells {
                        let (input_cell, data) = tx_dep_provider.get_cell_with_data(cell)?;
                        let transaction_input =
                            TransactionInput::new(input_cell, data, cell.clone());
                        viewer.transaction_inputs.push(transaction_input);
                    }
                } else {
                    for cell in rce_cells {
                        let cell_dep = CellDep::new_builder()
                            .out_point(cell.clone())
                            .dep_type(DepType::Code.into())
                            .build();
                        viewer.tx.dedup_cell_dep(cell_dep);
                    }
                }
            }
        }
        let id_flag = if let Some(admin_cfg) = context.cfg.get_admin_config() {
            admin_cfg.get_auth().flag()
        } else {
            context.cfg.id().flag()
        };
        match id_flag {
            crate::unlock::IdentityFlag::PubkeyHash |
            // ethereum only need secp256k1_data, and sighash group_dep contains it.
            crate::unlock::IdentityFlag::Ethereum => {
                    viewer.tx.dedup_cell_dep(self.sighash_dep.clone());
            },
            crate::unlock::IdentityFlag::Multisig => {
                   viewer.tx.dedup_cell_dep(self.multisig_dep.clone());
            },
            crate::unlock::IdentityFlag::OwnerLock => {},
            _ => todo!(),
        }
        Ok(())
    }
}

impl ScriptHandler for OmnilockScriptHandler {
    fn prepare_transaction(
        &self,
        viewer: &mut PrepareTransactionViewer,
        context: &mut dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if let Some(args) = context.as_any().downcast_ref::<OmnilockScriptContext>() {
            self.build_base(viewer, args)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if !self.is_match(&script_group.script) {
            return Ok(false);
        }
        if let Some(args) = context.as_any().downcast_ref::<OmnilockScriptContext>() {
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            let index = script_group.input_indices.first().unwrap();
            let placeholder_witness = args.cfg.placeholder_witness(args.unlock_mode)?;
            if let Some(lock) = placeholder_witness.lock().to_opt() {
                tx_builder.set_witness_lock(*index, Some(lock.raw_data()));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        if network.network_type == NetworkType::Mainnet {
            self.cell_deps.push(cell_dep!(
                "0xdfdb40f5d229536915f2d5403c66047e162e25dedd70a79ef5164356e1facdc8",
                0u32,
                DepType::Code
            ));
            self.lock_script_id = MAINNET_OMNILOCK_SCRIPT_ID.clone();

            self.sighash_dep = cell_dep!(
                "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
                0u32,
                DepType::DepGroup
            );
            self.multisig_dep = cell_dep!(
                "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
                1u32,
                DepType::DepGroup
            );
        } else if network.network_type == NetworkType::Testnet {
            self.cell_deps.push(cell_dep!(
                "0x27b62d8be8ed80b9f56ee0fe41355becdb6f6a40aeba82d3900434f43b1c8b60",
                0u32,
                DepType::Code
            ));
            self.lock_script_id = TESTNET_OMNILOCK_SCRIPT_ID.clone();
            self.sighash_dep = cell_dep!(
                "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
                0u32,
                DepType::DepGroup
            );
            self.multisig_dep = cell_dep!(
                "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
                1u32,
                DepType::DepGroup
            );
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };
        Ok(())
    }
}

lazy_static! {
    pub static ref MAINNET_OMNILOCK_SCRIPT_ID: ScriptId = ScriptId::new_type(h256!(
        "0x9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26"
    ));
    pub static ref TESTNET_OMNILOCK_SCRIPT_ID: ScriptId = ScriptId::new_type(h256!(
        "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb"
    ));
}
