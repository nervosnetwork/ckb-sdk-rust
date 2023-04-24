use std::any::Any;

use crate::{tx_builder::TxBuilderError, NetworkInfo, ScriptGroup};

use self::sighash::Secp256k1Blake160SighashAllScriptContext;

use super::builder::tx_data::TxData;

pub mod sighash;

pub trait ScriptHandler {
    fn build_transaction(
        &self,
        tx_data: &mut TxData,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError>;

    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError>;
}

pub trait Type2Any: 'static {
    fn as_any(&self) -> &dyn Any;
}

impl<T: 'static> Type2Any for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait HandlerContext: Type2Any {}

pub struct HandlerContexts {
    pub contexts: Vec<Box<dyn HandlerContext>>,
}

impl Default for HandlerContexts {
    fn default() -> Self {
        Self {
            contexts: vec![Box::new(Secp256k1Blake160SighashAllScriptContext {})],
        }
    }
}
