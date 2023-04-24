use ckb_types::packed::Script;

use crate::{transaction::builder::tx_data::TxData, NetworkInfo, NetworkType, ScriptGroup};

use super::{HandlerContext, ScriptHandler};

pub struct Secp256k1Blake160SighashAllScriptHandler {}

pub struct Secp256k1Blake160SighashAllScriptContext {}

impl HandlerContext for Secp256k1Blake160SighashAllScriptContext {}

impl Secp256k1Blake160SighashAllScriptHandler {
    pub fn is_match(&self, _script: &Script) -> bool {
        true
    }
    pub fn new_with_network(_network: &NetworkInfo) -> Self {
        Self {}
    }
}

impl ScriptHandler for Secp256k1Blake160SighashAllScriptHandler {
    fn build_transaction(
        &self,
        _tx_data: &mut TxData,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, String> {
        if self.is_match(&script_group.script) {
            return Ok(false);
        }
        if let Some(_args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160SighashAllScriptHandler>()
        {
        } else {
            return Ok(false);
        }
        todo!()
    }

    fn init(&mut self, _network: NetworkType) {
        // init code hash and cell deps
    }
}
