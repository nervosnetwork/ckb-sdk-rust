use ckb_types::{
    core::DepType,
    packed::{CellDep, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
};

use crate::{
    constants::MultisigScript, core::TransactionBuilder, tx_builder::TxBuilderError,
    unlock::MultisigConfig, NetworkInfo, ScriptGroup,
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

    #[cfg(not(target_arch = "wasm32"))]
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

    pub async fn new_async(
        network: &NetworkInfo,
        multisig_script: MultisigScript,
    ) -> Result<Self, TxBuilderError> {
        let mut ret = Self {
            multisig_script,
            cell_deps: vec![],
        };
        ret.init_async(network).await?;
        Ok(ret)
    }

    pub fn new_with_customize(multisig_script: MultisigScript, cell_deps: Vec<CellDep>) -> Self {
        Self {
            multisig_script,
            cell_deps,
        }
    }
}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::if_same_then_else)]
    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let dep_group = self
            .multisig_script
            .dep_group(network.to_owned(), None)
            .ok_or(TxBuilderError::Other(anyhow!(
                "not found multisig dep on network: {:?}",
                network
            )))?;
        let out_point = OutPoint::new_builder()
            .tx_hash(dep_group.0.pack())
            .index(dep_group.1.pack())
            .build();

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::DepGroup.into())
            .build();
        self.cell_deps.push(cell_dep);
        Ok(())
    }
    async fn init_async(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let dep_group = self
            .multisig_script
            .dep_group_async(network.to_owned(), None)
            .await
            .ok_or(TxBuilderError::Other(anyhow!(
                "not found multisig dep on network: {:?}",
                network
            )))?;
        let out_point = OutPoint::new_builder()
            .tx_hash(dep_group.0.pack())
            .index(dep_group.1.pack())
            .build();

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::DepGroup.into())
            .build();
        self.cell_deps.push(cell_dep);
        Ok(())
    }
}
