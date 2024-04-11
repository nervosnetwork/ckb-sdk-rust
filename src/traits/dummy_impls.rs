use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellOutput, OutPoint},
};

use crate::traits::{
    TransactionDependencyError, TransactionDependencyProvider,
};
use anyhow::anyhow;

/// A dummy HeaderDepResolver. All methods will return error if possible.
#[derive(Default)]
pub struct DummyTransactionDependencyProvider;

impl TransactionDependencyProvider for DummyTransactionDependencyProvider {
    // For verify certain cell belong to certain transaction
    fn get_transaction(
        &self,
        _tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!(
            "dummy get_transaction"
        )))
    }
    // For get the output information of inputs or cell_deps, those cell should be live cell
    fn get_cell(&self, _out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!("dummy get_cell")))
    }
    // For get the output data information of inputs or cell_deps
    fn get_cell_data(&self, _out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!(
            "dummy get_cell_data"
        )))
    }
    // For get the header information of header_deps
    fn get_header(&self, _block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!(
            "dummy get_header"
        )))
    }
    fn get_block_extension(
        &self,
        _block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!(
            "dummy get_block_extension"
        )))
    }
}
