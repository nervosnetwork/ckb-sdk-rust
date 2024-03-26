use ckb_types::core;

use crate::{
    traits::{dummy_impls::DummyTransactionDependencyProvider, SecpCkbRawKeySigner},
    unlock::{
        OmniLockConfig, OmniLockScriptSigner, OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker,
        UnlockError,
    },
};

use super::{CKBScriptSigner, SignContext};

pub struct OmnilockSigner {}

pub struct OmnilockSignerContext {
    keys: Vec<secp256k1::SecretKey>,
    cfg: OmniLockConfig,
    unlock_mode: OmniUnlockMode,
}

impl OmnilockSignerContext {
    pub fn new(keys: Vec<secp256k1::SecretKey>, cfg: OmniLockConfig) -> Self {
        Self {
            keys,
            cfg,
            unlock_mode: OmniUnlockMode::Normal,
        }
    }

    pub fn build_omnilock_unlocker(&self) -> OmniLockUnlocker {
        let signer = if self.cfg.is_ethereum() {
            SecpCkbRawKeySigner::new_with_ethereum_secret_keys(self.keys.clone())
        } else {
            SecpCkbRawKeySigner::new_with_secret_keys(self.keys.clone())
        };
        let omnilock_signer =
            OmniLockScriptSigner::new(Box::new(signer), self.cfg.clone(), self.unlock_mode);
        OmniLockUnlocker::new(omnilock_signer, self.cfg.clone())
    }
}

impl SignContext for OmnilockSignerContext {}

impl CKBScriptSigner for OmnilockSigner {
    fn match_context(&self, context: &dyn SignContext) -> bool {
        context.as_any().is::<OmnilockSignerContext>()
    }
    fn sign_transaction(
        &self,
        transaction: &core::TransactionView,
        script_group: &crate::ScriptGroup,
        context: &dyn super::SignContext,
    ) -> Result<core::TransactionView, UnlockError> {
        if let Some(args) = context.as_any().downcast_ref::<OmnilockSignerContext>() {
            let unlocker = args.build_omnilock_unlocker();
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
