//! For for implement offchain operations or for testing purpose

use std::collections::HashMap;

use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction},
    prelude::*,
    H256,
};

use crate::traits::{
    CellCollectorError, CellDepResolver, CellQueryOptions, HeaderDepResolver, LiveCell,
    TransactionDependencyError, TransactionDependencyProvider,
};
use crate::types::ScriptId;
use anyhow::anyhow;

/// A offchain cell_dep resolver
#[derive(Default, Clone)]
pub struct OffchainCellDepResolver {
    pub items: HashMap<ScriptId, (CellDep, String)>,
}
impl CellDepResolver for OffchainCellDepResolver {
    fn resolve(&self, script: &Script) -> Option<CellDep> {
        let script_id = ScriptId::from(script);
        self.items
            .get(&script_id)
            .map(|(cell_dep, _)| cell_dep.clone())
    }
}

#[derive(Default, Clone)]
pub struct OffchainHeaderDepResolver {
    pub by_tx_hash: HashMap<H256, HeaderView>,
    pub by_number: HashMap<u64, HeaderView>,
}

#[async_trait::async_trait]
impl HeaderDepResolver for OffchainHeaderDepResolver {
    async fn resolve_by_tx_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<Option<HeaderView>, anyhow::Error> {
        let tx_hash: H256 = tx_hash.unpack();
        let header = self.by_tx_hash.get(&tx_hash).cloned();
        Ok(header)
    }
    async fn resolve_by_number_async(
        &self,
        number: u64,
    ) -> Result<Option<HeaderView>, anyhow::Error> {
        let header = self.by_number.get(&number).cloned();

        Ok(header)
    }
}

const KEEP_BLOCK_PERIOD: u64 = 13;
/// A cell collector only use offchain data
#[derive(Default, Clone)]
pub struct OffchainCellCollector {
    // (block_hash, index) => tip_block_number
    pub locked_cells: HashMap<(H256, u32), u64>,
    // (live_cell, tip_block_number)
    pub live_cells: Vec<(LiveCell, u64)>,
    pub max_mature_number: u64,
}

pub(crate) struct CollectResult {
    pub(crate) cells: Vec<(LiveCell, u64)>,
    pub(crate) rest_cells: Vec<(LiveCell, u64)>,
    pub(crate) total_capacity: u64,
}
impl OffchainCellCollector {
    fn truncate(&mut self, current_tip_block_number: u64) {
        self.live_cells = self
            .live_cells
            .clone()
            .into_iter()
            .filter(|(_cell, block_num)| {
                *block_num >= current_tip_block_number
                    || (current_tip_block_number - block_num) <= KEEP_BLOCK_PERIOD
            })
            .collect();
        self.locked_cells = self
            .locked_cells
            .clone()
            .into_iter()
            .filter(|(_k, block_num)| {
                *block_num >= current_tip_block_number
                    || (current_tip_block_number - block_num) <= KEEP_BLOCK_PERIOD
            })
            .collect();
    }

    pub(crate) fn collect(
        &mut self,
        query: &CellQueryOptions,
        tip_block_number: u64,
    ) -> CollectResult {
        self.truncate(tip_block_number);
        let mut total_capacity = 0;
        let (cells, rest_cells): (Vec<_>, Vec<_>) =
            self.live_cells
                .clone()
                .into_iter()
                .partition(|(cell, _tip_num)| {
                    if total_capacity < query.min_total_capacity
                        && query.match_cell(cell, self.max_mature_number)
                    {
                        let capacity: u64 = cell.output.capacity().unpack();
                        total_capacity += capacity;
                        true
                    } else {
                        false
                    }
                });
        CollectResult {
            cells,
            rest_cells,
            total_capacity,
        }
    }

    pub(crate) fn lock_cell(
        &mut self,
        out_point: OutPoint,
        tip_blocknumber: u64,
    ) -> Result<(), CellCollectorError> {
        self.locked_cells.insert(
            (out_point.tx_hash().unpack(), out_point.index().unpack()),
            tip_blocknumber,
        );
        Ok(())
    }
    pub(crate) fn apply_tx(
        &mut self,
        tx: Transaction,
        tip_blocknumber: u64,
    ) -> Result<(), CellCollectorError> {
        let tx_view = tx.into_view();
        let tx_hash = tx_view.hash();
        for out_point in tx_view.input_pts_iter() {
            self.lock_cell(out_point, tip_blocknumber)?;
        }
        for (output_index, (output, data)) in tx_view.outputs_with_data_iter().enumerate() {
            let out_point = OutPoint::new(tx_hash.clone(), output_index as u32);
            let info = LiveCell {
                output: output.clone(),
                output_data: data.clone(),
                out_point,
                block_number: 0,
                tx_index: 0,
            };
            self.live_cells.push((info, tip_blocknumber));
        }
        Ok(())
    }

    pub(crate) fn reset(&mut self) {
        self.locked_cells.clear();
        self.live_cells.clear();
    }
}

/// offchain transaction dependency provider
#[derive(Default, Clone)]
pub struct OffchainTransactionDependencyProvider {
    pub tx_tip_num_map: HashMap<H256, u64>,
    pub txs: HashMap<H256, TransactionView>,
    pub cells: HashMap<(H256, u32), (CellOutput, Bytes)>,
}

impl OffchainTransactionDependencyProvider {
    /// create a new OffchainTransactionDependencyProvider
    pub(crate) fn new() -> Self {
        OffchainTransactionDependencyProvider {
            tx_tip_num_map: HashMap::new(),
            txs: HashMap::new(),
            cells: HashMap::new(),
        }
    }
    /// Add newly create transaction, so it can get transaction offchain
    pub(crate) fn apply_tx(
        &mut self,
        tx: Transaction,
        tip_blocknumber: u64,
    ) -> Result<(), TransactionDependencyError> {
        self.truncate(tip_blocknumber);
        let tx_view = tx.into_view();
        let tx_hash: H256 = tx_view.hash().unpack();
        self.tx_tip_num_map.insert(tx_hash.clone(), tip_blocknumber);
        self.txs.insert(tx_hash.clone(), tx_view.clone());

        for (idx, (cell_output, output_data)) in tx_view.outputs_with_data_iter().enumerate() {
            self.cells
                .insert((tx_hash.clone(), idx as u32), (cell_output, output_data));
        }
        Ok(())
    }

    /// Remove offchain data
    pub(crate) fn truncate(&mut self, current_tip_block_number: u64) {
        let (keep, removed) = self
            .tx_tip_num_map
            .clone()
            .into_iter()
            .partition(|(_k, v)| {
                *v >= current_tip_block_number
                    || (current_tip_block_number - v) >= KEEP_BLOCK_PERIOD
            });
        self.tx_tip_num_map = keep;
        self.txs = self
            .txs
            .clone()
            .into_iter()
            .filter(|(k, _v)| !removed.contains_key(k))
            .collect();
        self.cells = self
            .cells
            .clone()
            .into_iter()
            .filter(|(k, _v)| !removed.contains_key(&k.0))
            .collect();
        // self.headers =self.headers.clone().into_iter().filter(|(k,_v)|!removed.contains(&k)).collect();
    }
}

#[async_trait::async_trait]
impl TransactionDependencyProvider for OffchainTransactionDependencyProvider {
    // For verify certain cell belong to certain transaction
    async fn get_transaction_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        let tx_hash: H256 = tx_hash.unpack();
        self.txs
            .get(&tx_hash)
            .cloned()
            .ok_or_else(|| TransactionDependencyError::Other(anyhow!("offchain get_transaction")))
    }
    // For get the output information of inputs or cell_deps, those cell should be live cell
    async fn get_cell_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<CellOutput, TransactionDependencyError> {
        let tx_hash: H256 = out_point.tx_hash().unpack();
        let index: u32 = out_point.index().unpack();
        self.cells
            .get(&(tx_hash, index))
            .map(|(output, _)| output.clone())
            .ok_or_else(|| TransactionDependencyError::Other(anyhow!("offchain get_cell")))
    }
    // For get the output data information of inputs or cell_deps
    async fn get_cell_data_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<Bytes, TransactionDependencyError> {
        let tx_hash: H256 = out_point.tx_hash().unpack();
        let index: u32 = out_point.index().unpack();
        self.cells
            .get(&(tx_hash, index))
            .map(|(_, data)| data.clone())
            .ok_or_else(|| TransactionDependencyError::Other(anyhow!("offchain get_cell_data")))
    }
    // For get the header information of header_deps
    async fn get_header_async(
        &self,
        _block_hash: &Byte32,
    ) -> Result<HeaderView, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!(
            "get_header not supported"
        )))
    }

    async fn get_block_extension_async(
        &self,
        _block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError> {
        Err(TransactionDependencyError::Other(anyhow!(
            "get_block_extension not supported"
        )))
    }
}
