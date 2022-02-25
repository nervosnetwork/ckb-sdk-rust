use ckb_script::ScriptGroup;
use ckb_types::{bytes::Bytes, core::TransactionView};
use thiserror::Error;

use super::signer::SignError;
use crate::traits::{TransactionDependencyProvider, TxDepProviderError};

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
    fn match_args(&self, args: Bytes) -> bool;
    // Add signature or other information to witnesses
    fn unlock(
        &self,
        tx: TransactionView,
        script_group: ScriptGroup,
        tx_dep_provider: &mut dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError>;
}
