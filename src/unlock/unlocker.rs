use std::collections::HashMap;

use ckb_script::ScriptGroup;
use ckb_types::core::TransactionView;
use thiserror::Error;

use super::signer::{ScriptSigner, Secp256k1MultisigSigner, Secp256k1SighashSigner, SignError};
use crate::traits::{TransactionDependencyProvider, TxDepProviderError};
use crate::types::ScriptId;

#[derive(Error, Debug)]
pub enum UnlockError {
    #[error("sign script error: `{0}`")]
    Signer(#[from] SignError),
    #[error("transaction dependency error: `{0}`")]
    TxDep(#[from] TxDepProviderError),
    #[error("other error: `{0}`")]
    Other(#[from] Box<dyn std::error::Error>),
}

/// Script unlock logic:
///   * Parse the script.args
///   * Sign the transaction
///   * Put extra unlock information into transaction (e.g. SMT proof in omni-lock case)
pub trait ScriptUnlocker {
    fn match_args(&self, args: &[u8]) -> bool;
    // Add signature or other information to witnesses
    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &mut dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError>;
}

#[derive(Default)]
pub struct ScriptUnlockerManager {
    items: HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
}

impl ScriptUnlockerManager {
    pub fn register(&mut self, script_id: ScriptId, unlocker: Box<dyn ScriptUnlocker>) {
        self.items.insert(script_id, unlocker);
    }
}

pub struct Secp256k1SighashUnlocker {
    signer: Secp256k1SighashSigner,
}
impl ScriptUnlocker for Secp256k1SighashUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        args.len() == 20 && self.signer.match_args(args.as_ref())
    }

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &mut dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group, tx_dep_provider)?)
    }
}

struct Secp256k1MultisigUnlocker {
    signer: Secp256k1MultisigSigner,
}
impl ScriptUnlocker for Secp256k1MultisigUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        (args.len() == 20 || args.len() == 28) && self.signer.match_args(args)
    }

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &mut dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group, tx_dep_provider)?)
    }
}
