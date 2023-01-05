use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Transaction},
};

use crate::traits::{
    CellCollector, CellCollectorError, CellQueryOptions, HeaderDepResolver, LiveCell,
    TransactionDependencyError, TransactionDependencyProvider,
};
use anyhow::anyhow;

/// A dummy CellCollector. All methods will return error if possible.
#[derive(Default)]
pub struct DummyCellCollector;

impl CellCollector for DummyCellCollector {
    fn collect_live_cells(
        &mut self,
        _query: &CellQueryOptions,
        _apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        Err(CellCollectorError::Other(anyhow!(
            "dummy collect_live_cells"
        )))
    }

    fn lock_cell(
        &mut self,
        _out_point: OutPoint,
        _tip_block_num: u64,
    ) -> Result<(), CellCollectorError> {
        Err(CellCollectorError::Other(anyhow!("dummy lock_cell")))
    }

    fn apply_tx(
        &mut self,
        _tx: Transaction,
        _tip_block_num: u64,
    ) -> Result<(), CellCollectorError> {
        Err(CellCollectorError::Other(anyhow!("dummy apply_tx")))
    }
    fn reset(&mut self) {}
}

/// A dummy HeaderDepResolver. All methods will return error if possible.
#[derive(Default)]
pub struct DummyHeaderDepResolver;

impl HeaderDepResolver for DummyHeaderDepResolver {
    fn resolve_by_tx(&self, _tx_hash: &Byte32) -> Result<Option<HeaderView>, anyhow::Error> {
        Err(anyhow!("dummy resolve_by_tx"))
    }
    fn resolve_by_number(&self, _number: u64) -> Result<Option<HeaderView>, anyhow::Error> {
        Err(anyhow!("dummy resolve_by_number"))
    }
}

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
}
