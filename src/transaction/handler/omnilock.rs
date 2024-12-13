use ckb_types::{
    h256,
    packed::{CellDep, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
};

use super::{HandlerContext, ScriptHandler};
use crate::{
    core::TransactionBuilder,
    tx_builder::TxBuilderError,
    types::cobuild::{
        basic::{Message, SighashAll, SighashAllOnly},
        top_level::WitnessLayout,
    },
    unlock::{OmniLockConfig, OmniUnlockMode},
    NetworkInfo, NetworkType, ScriptGroup, ScriptId,
};
use lazy_static::lazy_static;

pub struct OmnilockScriptHandler {
    cell_deps: Vec<CellDep>,
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

    pub fn unlock_mode(mut self, unlock_mode: OmniUnlockMode) -> Self {
        self.unlock_mode = unlock_mode;
        self
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
            lock_script_id: ScriptId::default(),
        };
        ret.init(network)?;
        Ok(ret)
    }

    pub fn set_cell_deps(&mut self, cell_deps: Vec<CellDep>) {
        self.cell_deps = cell_deps;
    }

    pub fn insert_cell_dep(&mut self, cell_dep: CellDep) {
        self.cell_deps.push(cell_dep)
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
            if args.cfg.enable_cobuild {
                let lock_field = args.cfg.placeholder_witness_lock(args.unlock_mode)?;

                let witness = match &args.cfg.cobuild_message {
                    None => {
                        let sighash_all_only = SighashAllOnly::new_builder()
                            .seal(
                                [bytes::Bytes::copy_from_slice(&[0x00u8]), lock_field]
                                    .concat()
                                    .pack(),
                            )
                            .build();
                        let sighash_all_only =
                            WitnessLayout::new_builder().set(sighash_all_only).build();
                        sighash_all_only.as_bytes().pack()
                    }
                    Some(msg) => {
                        let sighash_all = SighashAll::new_builder()
                            .message(Message::new_unchecked(msg.clone()))
                            .seal(
                                [bytes::Bytes::copy_from_slice(&[0x00u8]), lock_field]
                                    .concat()
                                    .pack(),
                            )
                            .build();
                        let sighash_all = WitnessLayout::new_builder().set(sighash_all).build();
                        sighash_all.as_bytes().pack()
                    }
                };
                tx_builder.set_witness(*index, witness);
            } else {
                let placeholder_witness = args.cfg.placeholder_witness(args.unlock_mode)?;
                if let Some(lock) = placeholder_witness.lock().to_opt() {
                    tx_builder.set_witness_lock(*index, Some(lock.raw_data()));
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        if network.network_type == NetworkType::Mainnet {
            self.lock_script_id = MAINNET_OMNILOCK_SCRIPT_ID.clone();
        } else if network.network_type == NetworkType::Testnet {
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

pub fn get_testnet_omnilock_script_id() -> ScriptId {
    ScriptId::new_type(h256!(
        "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb"
    ))
}
