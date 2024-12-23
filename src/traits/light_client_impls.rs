use std::collections::HashMap;

use anyhow::anyhow;
use dashmap::DashMap;

use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Transaction},
    prelude::*,
};

use super::{offchain_impls::CollectResult, OffchainCellCollector};
use crate::rpc::{
    ckb_light_client::{FetchStatus, Order, SearchKey},
    LightClientRpcAsyncClient,
};
use crate::traits::{
    CellCollector, CellCollectorError, CellQueryOptions, HeaderDepResolver, LiveCell, QueryOrder,
    TransactionDependencyError, TransactionDependencyProvider,
};

pub struct LightClientHeaderDepResolver {
    client: LightClientRpcAsyncClient,
    // tx_hash => HeaderView
    headers: DashMap<Byte32, Option<HeaderView>>,
}

impl LightClientHeaderDepResolver {
    pub fn new(url: &str) -> LightClientHeaderDepResolver {
        let client = LightClientRpcAsyncClient::new(url);
        LightClientHeaderDepResolver {
            client,
            headers: DashMap::new(),
        }
    }

    /// Check if headers all fetched
    pub fn is_ready(&self) -> bool {
        self.headers.is_empty() || self.headers.iter().all(|pair| pair.value().is_some())
    }
}

#[async_trait::async_trait]
impl HeaderDepResolver for LightClientHeaderDepResolver {
    async fn resolve_by_tx_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<Option<HeaderView>, anyhow::Error> {
        if let Some(Some(header)) = self.headers.get(tx_hash).as_ref().map(|pair| pair.value()) {
            return Ok(Some(header.clone()));
        }
        match self.client.fetch_transaction(tx_hash.unpack()).await? {
            FetchStatus::Fetched { data } => {
                if let Some(block_hash) = data.tx_status.block_hash {
                    match self.client.fetch_header(block_hash).await? {
                        FetchStatus::Fetched { data } => {
                            let header: HeaderView = data.into();
                            self.headers.insert(tx_hash.clone(), Some(header.clone()));
                            Ok(Some(header))
                        }
                        status => {
                            self.headers.insert(tx_hash.clone(), None);
                            Err(anyhow!("fetching header by transaction: {:?}", status))
                        }
                    }
                } else {
                    self.headers.insert(tx_hash.clone(), None);
                    Err(anyhow!("fetching transaction: {:?}", data))
                }
            }
            status => {
                self.headers.insert(tx_hash.clone(), None);
                Err(anyhow!("fetching header by transaction: {:?}", status))
            }
        }
    }

    async fn resolve_by_number_async(
        &self,
        number: u64,
    ) -> Result<Option<HeaderView>, anyhow::Error> {
        for pair in self.headers.iter() {
            if let Some(header) = pair.value() {
                if header.number() == number {
                    return Ok(Some(header.clone()));
                }
            }
        }
        Err(anyhow!(
                "unable to resolver header by number directly when use light client as backend, you can call resolve_by_tx(tx_hash) to load the header first."
            ))
    }
}

pub struct LightClientTransactionDependencyProvider {
    client: LightClientRpcAsyncClient,
    // headers to load
    headers: DashMap<Byte32, Option<HeaderView>>,
    // transactions to load
    txs: DashMap<Byte32, Option<TransactionView>>,
}

impl LightClientTransactionDependencyProvider {
    pub fn new(url: &str) -> LightClientTransactionDependencyProvider {
        LightClientTransactionDependencyProvider {
            client: LightClientRpcAsyncClient::new(url),
            headers: DashMap::new(),
            txs: DashMap::new(),
        }
    }

    /// Check if headers and transactions all fetched
    pub fn is_ready(&self) -> bool {
        (self.headers.is_empty() && self.txs.is_empty())
            || (self.headers.iter().all(|pair| pair.value().is_some())
                && self.txs.iter().all(|pair| pair.value().is_some()))
    }
}

#[async_trait::async_trait]
impl TransactionDependencyProvider for LightClientTransactionDependencyProvider {
    async fn get_transaction_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        if let Some(Some(tx)) = self.txs.get(tx_hash).as_ref().map(|pair| pair.value()) {
            return Ok(tx.clone());
        }
        match self
            .client
            .fetch_transaction(tx_hash.unpack())
            .await
            .map_err(|err| TransactionDependencyError::Other(anyhow!(err)))?
        {
            FetchStatus::Fetched { data } => {
                if let Some(block_hash) = data.tx_status.block_hash {
                    match self
                        .client
                        .fetch_header(block_hash)
                        .await
                        .map_err(|err| TransactionDependencyError::Other(anyhow!(err)))?
                    {
                        FetchStatus::Fetched { data: header_view } => {
                            let header: HeaderView = header_view.into();
                            if let Some(transaction_view) = data.transaction {
                                let tx: TransactionView =
                                    Transaction::from(transaction_view.inner).into_view();
                                self.headers.insert(header.hash(), Some(header));
                                self.txs.insert(tx_hash.clone(), Some(tx.clone()));
                                Ok(tx)
                            } else {
                                self.txs.insert(tx_hash.clone(), None);
                                Err(TransactionDependencyError::NotFound(format!(
                                    "fetching transaction: {:?}",
                                    header
                                )))
                            }
                        }
                        status => {
                            self.txs.insert(tx_hash.clone(), None);
                            Err(TransactionDependencyError::NotFound(format!(
                                "fetching transaction: {:?}",
                                status
                            )))
                        }
                    }
                } else {
                    self.txs.insert(tx_hash.clone(), None);
                    Err(TransactionDependencyError::NotFound(format!(
                        "fetching transaction: {:?}",
                        data
                    )))
                }
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

    async fn get_cell_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<CellOutput, TransactionDependencyError> {
        let tx = self.get_transaction_async(&out_point.tx_hash()).await?;
        let output_index: u32 = out_point.index().unpack();
        tx.outputs().get(output_index as usize).ok_or_else(|| {
            TransactionDependencyError::NotFound(format!("invalid output index: {}", output_index))
        })
    }
    async fn get_cell_data_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<Bytes, TransactionDependencyError> {
        let tx = self.get_transaction_async(&out_point.tx_hash()).await?;
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
    async fn get_header_async(
        &self,
        block_hash: &Byte32,
    ) -> Result<HeaderView, TransactionDependencyError> {
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
            .fetch_header(block_hash.unpack())
            .await
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

    async fn get_block_extension_async(
        &self,
        _block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError> {
        Err(TransactionDependencyError::NotFound(
            "get_block_extension not supported".to_string(),
        ))
    }
}

#[derive(Clone)]
pub struct LightClientCellCollector {
    light_client: LightClientRpcAsyncClient,
    offchain: OffchainCellCollector,
}

impl LightClientCellCollector {
    pub fn new(url: &str) -> LightClientCellCollector {
        let light_client = LightClientRpcAsyncClient::new(url);
        LightClientCellCollector {
            light_client,
            offchain: OffchainCellCollector::default(),
        }
    }
}

#[async_trait::async_trait]
impl CellCollector for LightClientCellCollector {
    async fn collect_live_cells_async(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        let max_mature_number = 0;
        self.offchain.max_mature_number = max_mature_number;
        let tip_num = self
            .light_client
            .get_tip_header()
            .await
            .map_err(|err| CellCollectorError::Internal(anyhow!(err)))?
            .inner
            .number
            .value();
        let CollectResult {
            cells,
            rest_cells,
            mut total_capacity,
        } = self.offchain.collect(query, tip_num);
        let mut cells: Vec<_> = cells.into_iter().map(|c| c.0).collect();

        if total_capacity < query.min_total_capacity {
            let order = match query.order {
                QueryOrder::Asc => Order::Asc,
                QueryOrder::Desc => Order::Desc,
            };
            let mut ret_cells: HashMap<_, _> = cells
                .into_iter()
                .map(|c| (c.out_point.clone(), c))
                .collect();
            let locked_cells = self.offchain.locked_cells.clone();
            let search_key = SearchKey::from(query.clone());
            const MAX_LIMIT: u32 = 4096;
            let mut limit: u32 = query.limit.unwrap_or(16);
            let mut last_cursor: Option<json_types::JsonBytes> = None;
            while total_capacity < query.min_total_capacity {
                let page = self
                    .light_client
                    .get_cells(search_key.clone(), order.clone(), limit.into(), last_cursor)
                    .await
                    .map_err(|err| CellCollectorError::Internal(err.into()))?;
                if page.objects.is_empty() {
                    break;
                }
                for cell in page.objects {
                    let live_cell = LiveCell::from(cell);
                    if !query.match_cell(&live_cell, max_mature_number)
                        || locked_cells.contains_key(&(
                            live_cell.out_point.tx_hash().unpack(),
                            live_cell.out_point.index().unpack(),
                        ))
                    {
                        continue;
                    }
                    let capacity: u64 = live_cell.output.capacity().unpack();
                    if ret_cells
                        .insert(live_cell.out_point.clone(), live_cell)
                        .is_none()
                    {
                        total_capacity += capacity;
                    }
                    if total_capacity >= query.min_total_capacity {
                        break;
                    }
                }
                last_cursor = Some(page.last_cursor);
                if limit < MAX_LIMIT {
                    limit *= 2;
                }
            }
            cells = ret_cells.into_values().collect();
        }
        if apply_changes {
            self.offchain.live_cells = rest_cells;
            for cell in &cells {
                self.lock_cell(cell.out_point.clone(), tip_num)?;
            }
        }
        Ok((cells, total_capacity))
    }

    fn lock_cell(
        &mut self,
        out_point: OutPoint,
        tip_number: u64,
    ) -> Result<(), CellCollectorError> {
        self.offchain.lock_cell(out_point, tip_number)
    }
    fn apply_tx(&mut self, tx: Transaction, tip_number: u64) -> Result<(), CellCollectorError> {
        self.offchain.apply_tx(tx, tip_number)
    }
    fn reset(&mut self) {
        self.offchain.reset();
    }
}
