use std::any::Any;

use crate::{
    core::TransactionBuilder, tx_builder::TxBuilderError, unlock::MultisigConfig, NetworkInfo,
    ScriptGroup,
};

use self::sighash::Secp256k1Blake160SighashAllScriptContext;

pub mod multisig;
pub mod sighash;
pub mod typeid;

pub trait ScriptHandler {
    /// Try to build transaction with the given script_group and context.
    ///
    /// Return true if script_group and context are matched, otherwise return false.
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
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
            contexts: vec![
                Box::new(Secp256k1Blake160SighashAllScriptContext),
                Box::new(typeid::TypeIdContext),
            ],
        }
    }
}

impl HandlerContexts {
    pub fn new_sighash() -> Self {
        Self {
            contexts: vec![Box::new(Secp256k1Blake160SighashAllScriptContext)],
        }
    }

    pub fn new_multisig(config: MultisigConfig) -> Self {
        Self {
            contexts: vec![Box::new(
                multisig::Secp256k1Blake160MultisigAllScriptContext::new(config),
            )],
        }
    }

    pub fn add_context(mut self, context: Box<dyn HandlerContext>) {
        self.contexts.push(context);
    }
}
