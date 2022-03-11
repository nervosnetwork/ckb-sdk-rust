
use thiserror::Error;

use crate::traits::{TransactionDependencyError, WalletError};
use crate::unlock::{SignError, UnlockError};
use crate::chain::ParseGenesisInfoError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("parse GenesisInfo error: `{0}`")]
    ParseGenesisInfo(#[from] ParseGenesisInfo),
    #[error("sign error: `{0}`")]
    Sign(#[from] SignError),
    #[error("unlock error: `{0}`")]
    Unlock(#[from] UnlockError),
    #[error("wallet error: `{0}`")]
    Wallet(#[from] WalletError),
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),
}
