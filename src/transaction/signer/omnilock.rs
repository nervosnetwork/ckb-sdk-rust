use ckb_types::core;

use crate::{
    traits::{
        default_impls::Ed25519Signer, SecpCkbRawKeySigner, Signer, TransactionDependencyProvider,
    },
    unlock::{
        IdentityFlag, OmniLockConfig, OmniLockScriptSigner, OmniLockUnlocker, OmniUnlockMode,
        ScriptUnlocker, UnlockError,
    },
};

use super::{CKBScriptSigner, SignContext};

pub struct OmnilockSigner {}

pub struct OmnilockSignerContext {
    keys: Vec<secp256k1::SecretKey>,
    ed25519_key: Vec<ed25519_dalek::SigningKey>,
    custom_signer: Option<Box<dyn Signer>>,
    cfg: OmniLockConfig,
    unlock_mode: OmniUnlockMode,
}

impl OmnilockSignerContext {
    pub fn new(keys: Vec<secp256k1::SecretKey>, cfg: OmniLockConfig) -> Self {
        Self {
            keys,
            ed25519_key: Default::default(),
            custom_signer: None,
            cfg,
            unlock_mode: OmniUnlockMode::Normal,
        }
    }

    pub fn new_with_ed25519_key(key: Vec<ed25519_dalek::SigningKey>, cfg: OmniLockConfig) -> Self {
        Self {
            keys: Default::default(),
            ed25519_key: key,
            custom_signer: None,
            cfg,
            unlock_mode: OmniUnlockMode::Normal,
        }
    }

    pub fn new_with_dl_exec_signer<T: Signer + 'static>(signer: T, cfg: OmniLockConfig) -> Self {
        Self {
            keys: Default::default(),
            ed25519_key: Default::default(),
            custom_signer: Some(Box::new(signer)),
            cfg,
            unlock_mode: OmniUnlockMode::Normal,
        }
    }

    /// Default is Normal
    pub fn unlock_mode(mut self, unlock_mode: OmniUnlockMode) -> Self {
        self.unlock_mode = unlock_mode;
        self
    }

    pub fn build_omnilock_unlocker(&self) -> OmniLockUnlocker {
        let signer: Box<dyn Signer> = match self.cfg.id().flag() {
            IdentityFlag::Ethereum | IdentityFlag::EthereumDisplaying | IdentityFlag::Tron => {
                Box::new(SecpCkbRawKeySigner::new_with_ethereum_secret_keys(
                    self.keys.clone(),
                ))
            }
            IdentityFlag::Bitcoin | IdentityFlag::Dogecoin => {
                Box::new(SecpCkbRawKeySigner::new_with_btc_secret_key(
                    self.keys.clone(),
                    self.cfg.btc_sign_vtype,
                ))
            }
            IdentityFlag::Eos => Box::new(SecpCkbRawKeySigner::new_with_eos_secret_key(
                self.keys.clone(),
                self.cfg.btc_sign_vtype,
            )),
            IdentityFlag::Solana => Box::new(Ed25519Signer::new(self.ed25519_key.clone())),
            IdentityFlag::Dl | IdentityFlag::Exec => {
                let signer = self
                    .custom_signer
                    .as_ref()
                    .expect("must have custom signer");
                dyn_clone::clone_box(&**signer)
            }
            IdentityFlag::Multisig | IdentityFlag::PubkeyHash | IdentityFlag::OwnerLock => {
                Box::new(SecpCkbRawKeySigner::new_with_secret_keys(self.keys.clone()))
            }
        };
        let omnilock_signer = OmniLockScriptSigner::new(signer, self.cfg.clone(), self.unlock_mode);
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
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<core::TransactionView, UnlockError> {
        if let Some(args) = context.as_any().downcast_ref::<OmnilockSignerContext>() {
            let unlocker = args.build_omnilock_unlocker();
            let tx = unlocker.unlock(transaction, script_group, tx_dep_provider)?;
            Ok(tx)
        } else {
            Err(UnlockError::SignContextTypeIncorrect)
        }
    }
}
