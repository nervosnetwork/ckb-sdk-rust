pub mod assembler;
pub mod hasher;
pub mod reader;

pub use hasher::OpentxWitness;

use crate::traits::TransactionDependencyError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenTxError {
    #[error("Transaction read error, index out of bound.")]
    OutOfBound,
    #[error("Item not exist")]
    ItemMissing,
    #[error("Fail to get cell `{0}`")]
    CellNotExist(#[from] TransactionDependencyError),
    #[error("Unsupport data source")]
    UnsupportSource,
    #[error("usize(`{0}`) to u64 overflow.")]
    LenOverflow(usize),

    #[error("arg1(`{0}`) out of range")]
    Arg1OutOfRange(u16),
    #[error("arg2(`{0}`) out of range")]
    Arg2OutOfRange(u16),
    #[error("base index(`{0}) bigger than end index(`{1}`)")]
    BaseIndexOverFlow(usize, usize),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
