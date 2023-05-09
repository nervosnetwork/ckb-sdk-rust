use std::any::Any;

use crate::{core::TransactionBuilder, tx_builder::TxBuilderError, NetworkInfo, ScriptGroup};

use self::sighash::Secp256k1Blake160SighashAllScriptContext;

pub mod sighash;

pub trait ScriptHandler {
    /// Try to build transaction with the given script_group and context.
    ///
    /// Return true if script in script_group is matched and context with correct concrete type,
    /// so the work try to match handler and according context will be done,
    /// and the out side loop can be stopped, or return false to indicate try next match.
    fn build_transaction(
        &self,
        tx_data: &mut TransactionBuilder,
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
