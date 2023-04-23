use std::any::Any;

use crate::{NetworkType, ScriptGroup};

use super::builder::tx_data::TxData;

pub mod sighash;

pub trait ScriptHandler {
    fn build_transaction(
        &self,
        tx_data: &mut TxData,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, String>;

    fn init(&mut self, network: NetworkType);
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

#[derive(Default)]
pub struct HandlerContexts {
    pub contexts: Vec<Box<dyn HandlerContext>>,
}
