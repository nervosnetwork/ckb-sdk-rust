use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
};

use super::{cell_dep, HandlerContext, ScriptHandler};
use crate::{
    core::TransactionBuilder,
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
}

impl ScriptHandler for OmnilockScriptHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
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
            self.cell_deps.push(self.sighash_dep.clone());
            self.cell_deps.push(cell_dep!(
                "0xc76edf469816aa22f416503c38d0b533d2a018e253e379f134c3985b3472c842",
                0u32,
                DepType::Code
            ));
            self.lock_script_id = MAINNET_OMNILOCK_SCRIPT_ID.clone();
        } else if network.network_type == NetworkType::Testnet {
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
            self.cell_deps.push(self.sighash_dep.clone());
            self.cell_deps.push(cell_dep!(
                "0x3d4296df1bd2cc2bd3f483f61ab7ebeac462a2f336f2b944168fe6ba5d81c014",
                0u32,
                DepType::Code
            ));
            self.lock_script_id = get_testnet_omnilock_script_id().clone();
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
}

#[cfg(not(feature = "test"))]
pub fn get_testnet_omnilock_script_id() -> ScriptId {
    ScriptId::new_type(h256!(
        "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb"
    ))
}

// for unit test
#[cfg(feature = "test")]
pub fn get_testnet_omnilock_script_id() -> ScriptId {
    ScriptId::new_data1(h256!(
        "0xce6b8f2ba48b3ed6d84a851daad2c0bd28a084c6c31a6943a3f39cbb4d48df10"
    ))
}
