use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
};

use crate::{
    constants, core::TransactionBuilder, tx_builder::TxBuilderError, NetworkInfo, NetworkType,
    ScriptGroup,
};

use super::{HandlerContext, ScriptHandler};

pub struct Secp256k1Blake160SighashAllScriptHandler {
    cell_deps: Vec<CellDep>,
}

pub struct Secp256k1Blake160SighashAllScriptContext {}

impl HandlerContext for Secp256k1Blake160SighashAllScriptContext {}

impl Secp256k1Blake160SighashAllScriptHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        script.code_hash() == constants::SIGHASH_TYPE_HASH.pack()
    }
    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let mut ret = Self { cell_deps: vec![] };
        ret.init(network)?;
        Ok(ret)
    }
}

impl ScriptHandler for Secp256k1Blake160SighashAllScriptHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if !self.is_match(&script_group.script) {
            return Ok(false);
        }
        if let Some(_args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160SighashAllScriptContext>()
        {
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            let index = script_group.input_indices.first().unwrap();
            tx_builder.set_witness_lock(*index, Some(bytes::Bytes::from(vec![0u8; 65])));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let out_point = if network.network_type == NetworkType::Mainnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c")
                        .pack(),
                )
                .index(0u32.pack())
                .build()
        } else if network.network_type == NetworkType::Testnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
                        .pack(),
                )
                .index(0u32.pack())
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
