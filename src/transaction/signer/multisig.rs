use ckb_types::core;

use crate::{
    traits::{dummy_impls::DummyTransactionDependencyProvider, SecpCkbRawKeySigner},
    unlock::{
        MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker, UnlockError,
    },
};

use super::{CKBScriptSigner, SignContext};

pub struct Secp256k1Blake160MultisigAllSigner {}

pub struct Secp256k1Blake160MultisigAllSignerContext {
    keys: Vec<secp256k1::SecretKey>,
    multisig_config: MultisigConfig,
}

impl Secp256k1Blake160MultisigAllSignerContext {
    pub fn new(keys: Vec<secp256k1::SecretKey>, multisig_config: MultisigConfig) -> Self {
        Self {
            keys,
            multisig_config,
        }
    }

    pub fn build_multisig_unlocker(&self) -> SecpMultisigUnlocker {
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(self.keys.clone());
        let multisig_signer =
            SecpMultisigScriptSigner::new(Box::new(signer), self.multisig_config.clone());
        SecpMultisigUnlocker::new(multisig_signer)
    }
}

impl SignContext for Secp256k1Blake160MultisigAllSignerContext {}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl CKBScriptSigner for Secp256k1Blake160MultisigAllSigner {
    fn match_context(&self, context: &dyn SignContext) -> bool {
        context
            .as_any()
            .is::<Secp256k1Blake160MultisigAllSignerContext>()
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
            .downcast_ref::<Secp256k1Blake160MultisigAllSignerContext>()
        {
            let unlocker = args.build_multisig_unlocker();
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
    #[cfg(target_arch = "wasm32")]
    async fn sign_transaction_async(
        &self,
        transaction: &core::TransactionView,
        script_group: &crate::ScriptGroup,
        context: &dyn super::SignContext,
    ) -> Result<core::TransactionView, UnlockError> {
        let unlocker = if let Some(args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160MultisigAllSignerContext>()
        {
            args.build_multisig_unlocker()
        } else {
            return Err(UnlockError::SignContextTypeIncorrect);
        };

        let tx = unlocker
            .unlock_async(
                transaction,
                script_group,
                &DummyTransactionDependencyProvider {},
            )
            .await?;
        Ok(tx)
    }
}
