use std::any::Any;

use crate::{
    core::TransactionBuilder, tx_builder::TxBuilderError, unlock::MultisigConfig, NetworkInfo,
    ScriptGroup,
};

use self::{
    sighash::Secp256k1Blake160SighashAllScriptContext, sudt::SudtContext, typeid::TypeIdContext,
};

pub mod multisig;
pub mod omnilock;
pub mod sighash;
pub mod sudt;
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

macro_rules! cell_dep {
    ($hash: literal, $idx: expr, $dep_type: expr) => {{
        let out_point = ckb_types::packed::OutPoint::new_builder()
            .tx_hash(ckb_types::h256!($hash).pack())
            .index($idx.pack())
            .build();
        ckb_types::packed::CellDep::new_builder()
            .out_point(out_point)
            .dep_type($dep_type.into())
            .build()
    }};
}

pub(crate) use cell_dep;
