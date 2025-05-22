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

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl CKBScriptSigner for Secp256k1Blake160SighashAllSigner {
    fn match_context(&self, context: &dyn SignContext) -> bool {
        context
            .as_any()
            .is::<Secp256k1Blake160SighashAllSignerContext>()
    }
    #[cfg(target_arch = "wasm32")]
    async fn sign_transaction_async(
        &self,
        tx_view: &core::TransactionView,
        script_group: &crate::ScriptGroup,
        context: &dyn super::SignContext,
    ) -> Result<core::TransactionView, UnlockError> {
        if let Some(args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160SighashAllSignerContext>()
        {
            let signer = SecpCkbRawKeySigner::new_with_secret_keys(args.keys.clone());
            let unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
            let tx = unlocker
                .unlock_async(
                    tx_view,
                    script_group,
                    &DummyTransactionDependencyProvider {},
                )
                .await?;
            Ok(tx)
        } else {
            Err(UnlockError::SignContextTypeIncorrect)
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
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
