use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
};

use crate::{
    constants::MultisigScript, core::TransactionBuilder, tx_builder::TxBuilderError,
    unlock::MultisigConfig, NetworkInfo, NetworkType, ScriptGroup,
};

use super::{HandlerContext, ScriptHandler};
use anyhow::anyhow;

pub struct Secp256k1Blake160MultisigAllScriptContext {
    multisig_config: MultisigConfig,
}
impl HandlerContext for Secp256k1Blake160MultisigAllScriptContext {}
impl Secp256k1Blake160MultisigAllScriptContext {
    pub fn new(config: MultisigConfig) -> Self {
        Self {
            multisig_config: config,
        }
    }
}

pub struct Secp256k1Blake160MultisigAllScriptHandler {
    multisig_script: MultisigScript,
    cell_deps: Vec<CellDep>,
}

impl Secp256k1Blake160MultisigAllScriptHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        let multisig_script_id = self.multisig_script.script_id();
        script.code_hash() == multisig_script_id.code_hash.pack()
            && script.hash_type() == multisig_script_id.hash_type.into()
    }

    pub fn new(
        network: &NetworkInfo,
        multisig_script: MultisigScript,
    ) -> Result<Self, TxBuilderError> {
        let mut ret = Self {
            multisig_script,
            cell_deps: vec![],
        };
        ret.init(network)?;
        Ok(ret)
    }

    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        Self::new(network, MultisigScript::Legacy)
    }

    pub fn new_with_customize(multisig_script: MultisigScript, cell_deps: Vec<CellDep>) -> Self {
        Self {
            multisig_script,
            cell_deps,
        }
    }
}

impl ScriptHandler for Secp256k1Blake160MultisigAllScriptHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if !self.is_match(&script_group.script) {
            return Ok(false);
        }
        if let Some(args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160MultisigAllScriptContext>()
        {
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            let index = script_group.input_indices.first().unwrap();
            let witness = args.multisig_config.placeholder_witness();
            tx_builder.set_witness(*index, witness.as_bytes().pack());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[allow(clippy::if_same_then_else)]
    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let out_point =
            if network.network_type == NetworkType::Mainnet {
                let dep_group = self.multisig_script.dep_group(network.to_owned()).ok_or(
                    TxBuilderError::Other(anyhow!("not found multisig dep on mainnet")),
                )?;
                OutPoint::new_builder()
                    .tx_hash(dep_group.0.pack())
                    .index(dep_group.1.pack())
                    .build()
            } else if network.network_type == NetworkType::Testnet {
                let dep_group = self.multisig_script.dep_group(network.to_owned()).ok_or(
                    TxBuilderError::Other(anyhow!("not found multisig dep on testnet")),
                )?;
                OutPoint::new_builder()
                    .tx_hash(dep_group.0.pack())
                    .index(dep_group.1.pack())
                    .build()
            } else if network.network_type == NetworkType::Preview {
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0x0fab65924f2784f17ad7f86d6aef4b04ca1ca237102a68961594acebc5c77816")
                            .pack(),
                    )
                    .index(1u32.pack())
                    .build()
            } else if network.network_type == NetworkType::Dev {
                let dep_group = self.multisig_script.dep_group(network.to_owned()).ok_or(
                    TxBuilderError::Other(anyhow!("not found multisig dep on devnet")),
                )?;
                OutPoint::new_builder()
                    .tx_hash(dep_group.0.pack())
                    .index(dep_group.1.pack())
                    .build()
            } else {
                return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
            };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::DepGroup.into())
            .build();
        self.cell_deps.push(cell_dep);
        Ok(())
    }
}
