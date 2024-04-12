use alloc::{boxed::Box, vec::Vec};
use ckb_types::core;

use crate::{
    traits::{dummy_impls::DummyTransactionDependencyProvider, SecpCkbRawKeySigner},
    unlock::{ScriptUnlocker, SecpSighashUnlocker, UnlockError},
};

use super::{CKBScriptSigner, SignContext};

pub struct Secp256k1Blake160SighashAllSigner {}

pub struct Secp256k1Blake160SighashAllSignerContext {
    keys: Vec<secp256k1::SecretKey>,
}

impl Secp256k1Blake160SighashAllSignerContext {
    pub fn new(keys: Vec<secp256k1::SecretKey>) -> Self {
        Self { keys }
    }
}

impl SignContext for Secp256k1Blake160SighashAllSignerContext {}

impl CKBScriptSigner for Secp256k1Blake160SighashAllSigner {
    fn match_context(&self, context: &dyn SignContext) -> bool {
        context
            .as_any()
            .is::<Secp256k1Blake160SighashAllSignerContext>()
    }
    fn sign_transaction(
        &self,
        transaction: &core::TransactionView,
        script_group: &crate::ScriptGroup,
        context: &dyn super::SignContext,
    ) -> Result<core::TransactionView, UnlockError> {
        if let Some(args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160SighashAllSignerContext>()
        {
            let signer = SecpCkbRawKeySigner::new_with_secret_keys(args.keys.clone());
            let unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
            let tx = unlocker.unlock(
                transaction,
                script_group,
                &DummyTransactionDependencyProvider {},
            )?;
            Ok(tx)
        } else {
            Err(UnlockError::SignContextTypeIncorrect)
        }
    }
}
