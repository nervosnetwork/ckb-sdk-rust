use anyhow::anyhow;
use dashmap::DashMap;
use parking_lot::Mutex;

use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Transaction},
    prelude::*,
};

use super::OffchainCellCollector;
use crate::rpc::ckb_indexer::Order;
use crate::rpc::{
    ckb_light_client::{FetchStatus, SearchKey},
    CkbRpcClient, LightClientRpcClient,
};
use crate::traits::{
    CellCollector, CellCollectorError, CellQueryOptions, LiveCell, QueryOrder,
    TransactionDependencyError, TransactionDependencyProvider,
};
use crate::util::get_max_mature_number;

pub struct LightClientTransactionDependencyProvider {
    client: Mutex<LightClientRpcClient>,
    // headers to load
    headers: DashMap<Byte32, Option<HeaderView>>,
    // transactions to load
    txs: DashMap<Byte32, Option<TransactionView>>,
}

impl LightClientTransactionDependencyProvider {
    pub fn new(url: &str) -> LightClientTransactionDependencyProvider {
        LightClientTransactionDependencyProvider {
            client: Mutex::new(LightClientRpcClient::new(url)),
            headers: DashMap::new(),
            txs: DashMap::new(),
        }
    }

    /// Check if headers and transactions all fetched
    pub fn is_ready(&self) -> bool {
        self.headers.iter().all(|pair| pair.value().is_some())
            && self.txs.iter().all(|pair| pair.value().is_some())
    }
}

impl TransactionDependencyProvider for LightClientTransactionDependencyProvider {
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        if let Some(Some(tx)) = self.txs.get(tx_hash).as_ref().map(|pair| pair.value()) {
            return Ok(tx.clone());
        }
        match self
            .client
            .lock()
            .fetch_transaction(tx_hash.unpack())
            .map_err(|err| TransactionDependencyError::Other(anyhow!(err)))?
        {
            FetchStatus::Fetched { data } => {
                let header: HeaderView = data.header.into();
                let tx: TransactionView = Transaction::from(data.transaction.inner).into_view();
                self.headers.insert(header.hash(), Some(header));
                self.txs.insert(tx_hash.clone(), Some(tx.clone()));
                Ok(tx)
            }
            status => {
                self.txs.insert(tx_hash.clone(), None);
                Err(TransactionDependencyError::NotFound(format!(
                    "fetching transaction: {:?}",
                    status
                )))
            }
        }
    }

    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError> {
        let tx = self.get_transaction(&out_point.tx_hash())?;
        let output_index: u32 = out_point.index().unpack();
        tx.outputs().get(output_index as usize).ok_or_else(|| {
            TransactionDependencyError::NotFound(format!("invalid output index: {}", output_index))
        })
    }
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError> {
        let tx = self.get_transaction(&out_point.tx_hash())?;
        let output_index: u32 = out_point.index().unpack();
        tx.outputs_data()
            .get(output_index as usize)
            .map(|packed_bytes| packed_bytes.raw_data())
            .ok_or_else(|| {
                TransactionDependencyError::NotFound(format!(
                    "invalid output index: {}",
                    output_index
                ))
            })
    }
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError> {
        if let Some(Some(header)) = self
            .headers
            .get(block_hash)
            .as_ref()
            .map(|pair| pair.value())
        {
            return Ok(header.clone());
        }
        match self
            .client
            .lock()
            .fetch_header(block_hash.unpack())
            .map_err(|err| TransactionDependencyError::Other(anyhow!(err)))?
        {
            FetchStatus::Fetched { data } => {
                let header: HeaderView = data.into();
                self.headers
                    .insert(block_hash.clone(), Some(header.clone()));
                Ok(header)
            }
            status => {
                self.headers.insert(block_hash.clone(), None);
                Err(TransactionDependencyError::NotFound(format!(
                    "fetching header: {:?}",
                    status
                )))
            }
        }
    }
}

pub struct LightClientCellCollector {
    ckb_client: CkbRpcClient,
    light_client: LightClientRpcClient,
    offchain: OffchainCellCollector,
}

impl LightClientCellCollector {
    pub fn new(ckb_client: &str, light_client: &str) -> LightClientCellCollector {
        let ckb_client = CkbRpcClient::new(ckb_client);
        let light_client = LightClientRpcClient::new(light_client);
        LightClientCellCollector {
            ckb_client,
            light_client,
            offchain: OffchainCellCollector::default(),
        }
    }
}

impl CellCollector for LightClientCellCollector {
    fn collect_live_cells(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        let max_mature_number = get_max_mature_number(&mut self.ckb_client)
            .map_err(|err| CellCollectorError::Internal(anyhow!(err)))?;

        self.offchain.max_mature_number = max_mature_number;
        let (mut cells, rest_cells, mut total_capacity) = self.offchain.collect(query);

        if total_capacity < query.min_total_capacity {
            let order = match query.order {
                QueryOrder::Asc => Order::Asc,
                QueryOrder::Desc => Order::Desc,
            };
            let locked_cells = self.offchain.locked_cells.clone();
            let search_key = SearchKey::from(query.clone());
            const MAX_LIMIT: u32 = 4096;
            let mut limit: u32 = query.limit.unwrap_or(128);
            let mut last_cursor: Option<json_types::JsonBytes> = None;
            while total_capacity < query.min_total_capacity {
                let page = self
                    .light_client
                    .get_cells(search_key.clone(), order.clone(), limit.into(), last_cursor)
                    .map_err(|err| CellCollectorError::Internal(err.into()))?;
                if page.objects.is_empty() {
                    break;
                }
                for cell in page.objects {
                    let live_cell = LiveCell::from(cell);
                    if !query.match_cell(&live_cell, max_mature_number)
                        || locked_cells.contains(&(
                            live_cell.out_point.tx_hash().unpack(),
                            live_cell.out_point.index().unpack(),
                        ))
                    {
                        continue;
                    }
                    let capacity: u64 = live_cell.output.capacity().unpack();
                    total_capacity += capacity;
                    cells.push(live_cell);
                    if total_capacity >= query.min_total_capacity {
                        break;
                    }
                }
                last_cursor = Some(page.last_cursor);
                if limit < MAX_LIMIT {
                    limit *= 2;
                }
            }
        }
        if apply_changes {
            self.offchain.live_cells = rest_cells;
            for cell in &cells {
                self.lock_cell(cell.out_point.clone())?;
            }
        }
        Ok((cells, total_capacity))
    }

    fn lock_cell(&mut self, out_point: OutPoint) -> Result<(), CellCollectorError> {
        self.offchain.lock_cell(out_point)
    }
    fn apply_tx(&mut self, tx: Transaction) -> Result<(), CellCollectorError> {
        self.offchain.apply_tx(tx)
    }
    fn reset(&mut self) {
        self.offchain.reset();
    }
}
