use std::any::Any;

use crate::{
    core::TransactionBuilder, tx_builder::TxBuilderError, unlock::MultisigConfig, NetworkInfo,
    ScriptGroup,
};

use self::{
    sighash::Secp256k1Blake160SighashAllScriptContext, sudt::SudtContext, typeid::TypeIdContext,
};

pub mod multisig;
pub mod sighash;
pub mod sudt;
pub mod typeid;

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ScriptHandler: Send + Sync {
    /// Try to build transaction with the given script_group and context.
    ///
    /// Return true if script_group and context are matched, otherwise return false.
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError>;
    #[cfg(not(target_arch = "wasm32"))]
    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError>;
    async fn init_async(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError>;
    
}

pub trait Type2Any: 'static {
    fn as_any(&self) -> &dyn Any;
}

impl<T: 'static> Type2Any for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait HandlerContext: Type2Any + Send + Sync {}

pub struct HandlerContexts {
    pub contexts: Vec<Box<dyn HandlerContext>>,
}

impl Default for HandlerContexts {
    fn default() -> Self {
        Self {
            contexts: vec![
                Box::new(Secp256k1Blake160SighashAllScriptContext),
                Box::new(SudtContext),
                Box::new(TypeIdContext),
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

    pub fn add_context(&mut self, context: Box<dyn HandlerContext>) {
        self.contexts.push(context);
    }
}
