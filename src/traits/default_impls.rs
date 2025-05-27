use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use ckb_crypto::secp::Pubkey;
use lru::LruCache;
use thiserror::Error;
use tokio::sync::Mutex;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{self as json_types, Either};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, DepType, HeaderView, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction, TransactionReader},
    prelude::*,
    H160,
};

use super::{
    offchain_impls::CollectResult, OffchainCellCollector, OffchainCellDepResolver,
    OffchainTransactionDependencyProvider,
};
use crate::{constants::MULTISIG_LEGACY_GROUP_OUTPUT_LOC, types::ScriptId};
use crate::{constants::MULTISIG_LEGACY_OUTPUT_LOC, SECP256K1};
use crate::{
    constants::{MultisigScript, GENESIS_BLOCK_HASH_MAINNET, GENESIS_BLOCK_HASH_TESTNET},
    rpc::ckb_indexer::{Order, SearchKey, Tip},
};
use crate::{
    constants::{
        DAO_OUTPUT_LOC, DAO_TYPE_HASH, SIGHASH_GROUP_OUTPUT_LOC, SIGHASH_OUTPUT_LOC,
        SIGHASH_TYPE_HASH,
    },
    util::keccak160,
};
use crate::{
    rpc::{CkbRpcAsyncClient, IndexerRpcAsyncClient},
    traits::{
        CellCollector, CellCollectorError, CellDepResolver, CellQueryOptions, HeaderDepResolver,
        LiveCell, QueryOrder, Signer, SignerError, TransactionDependencyError,
        TransactionDependencyProvider,
    },
};
use crate::{
    util::{get_max_mature_number_async, serialize_signature, zeroize_privkey},
    NetworkInfo,
};
use ckb_resource::{
    CODE_HASH_DAO, CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL,
    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
};

/// Parse Genesis Info errors
#[derive(Error, Debug)]
pub enum ParseGenesisInfoError {
    #[error("invalid block number, expected: 0, got: `{0}`")]
    InvalidBlockNumber(u64),
    #[error("data not found: `{0}`")]
    DataHashNotFound(String),
    #[error("type not found: `{0}`")]
    TypeHashNotFound(String),
}

/// A cell_dep resolver use genesis info resolve system scripts and can register more cell_dep info.
#[derive(Clone)]
pub struct DefaultCellDepResolver {
    offchain: OffchainCellDepResolver,
}
impl DefaultCellDepResolver {
    /// You can customize the multisig script's depgroup by these two env variables, for example:
    /// 1. MULTISIG_LEGACY_DEP_GROUP=0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c,1
    /// 2. MULTISIG_V2_DEP_GROUP=0x6888aa39ab30c570c2c30d9d5684d3769bf77265a7973211a3c087fe8efbf738,2
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_genesis(
        genesis_block: &BlockView,
    ) -> Result<DefaultCellDepResolver, ParseGenesisInfoError> {
        crate::rpc::block_on(Self::from_genesis_async(genesis_block))
    }
    /// You can customize the multisig script's depgroup by these two env variables, for example:
    /// 1. MULTISIG_LEGACY_DEP_GROUP=0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c,1
    /// 2. MULTISIG_V2_DEP_GROUP=0x6888aa39ab30c570c2c30d9d5684d3769bf77265a7973211a3c087fe8efbf738,2
    pub async fn from_genesis_async(
        genesis_block: &BlockView,
    ) -> Result<DefaultCellDepResolver, ParseGenesisInfoError> {
        let header = genesis_block.header();
        if header.number() != 0 {
            return Err(ParseGenesisInfoError::InvalidBlockNumber(header.number()));
        }
        let mut sighash_type_hash = None;
        let mut multisig_legacy_type_hash = None;
        let mut dao_type_hash = None;
        let out_points = genesis_block
            .transactions()
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                tx.outputs()
                    .into_iter()
                    .zip(tx.outputs_data())
                    .enumerate()
                    .map(|(index, (output, data))| {
                        if tx_index == SIGHASH_OUTPUT_LOC.0 && index == SIGHASH_OUTPUT_LOC.1 {
                            sighash_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL.pack() {
                                log::error!(
                                    "System sighash script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
                                );
                            }
                        }
                        if tx_index == MULTISIG_LEGACY_OUTPUT_LOC.0 && index == MULTISIG_LEGACY_OUTPUT_LOC.1 {
                            multisig_legacy_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL.pack() {
                                log::error!(
                                    "System multisig script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL,
                                );
                            }
                        }
                        if tx_index == DAO_OUTPUT_LOC.0 && index == DAO_OUTPUT_LOC.1 {
                            dao_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_DAO.pack() {
                                log::error!(
                                    "System dao script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_DAO,
                                );
                            }
                        }
                        OutPoint::new(tx.hash(), index as u32)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let sighash_type_hash = sighash_type_hash
            .ok_or_else(|| "No type hash(sighash) found in txs[0][1]".to_owned())
            .map_err(ParseGenesisInfoError::TypeHashNotFound)?;
        let dao_type_hash = dao_type_hash
            .ok_or_else(|| "No type hash(dao) found in txs[0][2]".to_owned())
            .map_err(ParseGenesisInfoError::TypeHashNotFound)?;

        let sighash_dep = CellDep::new_builder()
            .out_point(out_points[SIGHASH_GROUP_OUTPUT_LOC.0][SIGHASH_GROUP_OUTPUT_LOC.1].clone())
            .dep_type(DepType::DepGroup.into())
            .build();

        let multisig_legacy_dep = CellDep::new_builder()
            .out_point(
                out_points[MULTISIG_LEGACY_GROUP_OUTPUT_LOC.0][MULTISIG_LEGACY_GROUP_OUTPUT_LOC.1]
                    .clone(),
            )
            .dep_type(DepType::DepGroup.into())
            .build();

        let dao_dep = CellDep::new_builder()
            .out_point(out_points[DAO_OUTPUT_LOC.0][DAO_OUTPUT_LOC.1].clone())
            .build();

        let mut items = HashMap::default();
        items.insert(
            ScriptId::new_type(sighash_type_hash.unpack()),
            (sighash_dep, "Secp256k1 blake160 sighash all".to_string()),
        );

        {
            let network_info: NetworkInfo =
                if genesis_block.hash().eq(&GENESIS_BLOCK_HASH_MAINNET.pack()) {
                    NetworkInfo::mainnet()
                } else if genesis_block.hash().eq(&GENESIS_BLOCK_HASH_TESTNET.pack()) {
                    NetworkInfo::testnet()
                } else {
                    NetworkInfo::devnet()
                };

            if let Some((v2_dep_hash, v2_dep_index)) =
                MultisigScript::V2.dep_group_async(network_info).await
            {
                let multisig_v2_dep = CellDep::new_builder()
                    .out_point(OutPoint::new(v2_dep_hash.pack(), v2_dep_index))
                    .dep_type(DepType::DepGroup.into())
                    .build();

                items.insert(
                    MultisigScript::V2.script_id(),
                    (
                        multisig_v2_dep,
                        "Secp256k1 blake160 multisig(v2) all".to_string(),
                    ),
                );
            }
        }

        items.insert(
            MultisigScript::Legacy.script_id(),
            (
                multisig_legacy_dep,
                "Secp256k1 blake160 multisig(legacy) all".to_string(),
            ),
        );
        items.insert(
            ScriptId::new_type(dao_type_hash.unpack()),
            (dao_dep, "Nervos DAO".to_string()),
        );
        let offchain = OffchainCellDepResolver { items };
        Ok(DefaultCellDepResolver { offchain })
    }

    pub fn insert(
        &mut self,
        script_id: ScriptId,
        cell_dep: CellDep,
        name: String,
    ) -> Option<(CellDep, String)> {
        self.offchain.items.insert(script_id, (cell_dep, name))
    }
    pub fn remove(&mut self, script_id: &ScriptId) -> Option<(CellDep, String)> {
        self.offchain.items.remove(script_id)
    }
    pub fn contains(&self, script_id: &ScriptId) -> bool {
        self.offchain.items.contains_key(script_id)
    }
    pub fn get(&self, script_id: &ScriptId) -> Option<&(CellDep, String)> {
        self.offchain.items.get(script_id)
    }
    pub fn sighash_dep(&self) -> Option<&(CellDep, String)> {
        self.get(&ScriptId::new_type(SIGHASH_TYPE_HASH))
    }
    /// TODO: We have found MultisigScript::Legacy's dep from genesis block.
    /// TODO: then need manually insert MultisigScript::V1's deps to self.
    pub fn multisig_dep(&self, multisig_script: MultisigScript) -> Option<&(CellDep, String)> {
        self.get(&multisig_script.script_id())
    }
    pub fn dao_dep(&self) -> Option<&(CellDep, String)> {
        self.get(&ScriptId::new_type(DAO_TYPE_HASH))
    }
}

impl CellDepResolver for DefaultCellDepResolver {
    fn resolve(&self, script: &Script) -> Option<CellDep> {
        self.offchain.resolve(script)
    }
}

/// A header_dep resolver use ckb jsonrpc client as backend
pub struct DefaultHeaderDepResolver {
    ckb_client: CkbRpcAsyncClient,
}
impl DefaultHeaderDepResolver {
    pub fn new(ckb_client: &str) -> DefaultHeaderDepResolver {
        let ckb_client = CkbRpcAsyncClient::new(ckb_client);
        DefaultHeaderDepResolver { ckb_client }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl HeaderDepResolver for DefaultHeaderDepResolver {
    async fn resolve_by_tx_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<Option<HeaderView>, anyhow::Error> {
        if let Some(block_hash) = self
            .ckb_client
            .get_transaction(tx_hash.unpack())
            .await
            .map_err(|e| anyhow!(e))?
            .and_then(|tx_with_status| tx_with_status.tx_status.block_hash)
        {
            Ok(self
                .ckb_client
                .get_header(block_hash)
                .await
                .map_err(Box::new)?
                .map(Into::into))
        } else {
            Ok(None)
        }
    }
    async fn resolve_by_number_async(
        &self,
        number: u64,
    ) -> Result<Option<HeaderView>, anyhow::Error> {
        Ok(self
            .ckb_client
            .get_header_by_number(number.into())
            .await
            .map_err(|e| anyhow!(e))?
            .map(Into::into))
    }
}

/// A cell collector use ckb-indexer as backend
#[derive(Clone)]
pub struct DefaultCellCollector {
    indexer_client: IndexerRpcAsyncClient,
    ckb_client: CkbRpcAsyncClient,
    offchain: OffchainCellCollector,
    acceptable_indexer_leftbehind: u64,
}

impl DefaultCellCollector {
    pub fn new(ckb_client: &str) -> DefaultCellCollector {
        let indexer_client = IndexerRpcAsyncClient::new(ckb_client);
        let ckb_client = CkbRpcAsyncClient::new(ckb_client);
        DefaultCellCollector {
            indexer_client,
            ckb_client,
            offchain: OffchainCellCollector::default(),
            acceptable_indexer_leftbehind: 1,
        }
    }

    /// THe acceptable ckb-indexer leftbehind block number (default = 1)
    pub fn acceptable_indexer_leftbehind(&self) -> u64 {
        self.acceptable_indexer_leftbehind
    }
    /// Set the acceptable ckb-indexer leftbehind block number
    pub fn set_acceptable_indexer_leftbehind(&mut self, value: u64) {
        self.acceptable_indexer_leftbehind = value;
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// wrapper check_ckb_chain_async future
    pub fn check_ckb_chain(&mut self) -> Result<(), CellCollectorError> {
        crate::rpc::block_on(self.check_ckb_chain_async())
    }
    /// Check if ckb-indexer synced with ckb node. This will check every 50ms for 100 times (more than 5s in total, since ckb-indexer's poll interval is 2.0s).
    pub async fn check_ckb_chain_async(&mut self) -> Result<(), CellCollectorError> {
        let tip_number = self
            .ckb_client
            .get_tip_block_number()
            .await
            .map_err(|err| CellCollectorError::Internal(err.into()))?;

        for _ in 0..100 {
            match self
                .indexer_client
                .get_indexer_tip()
                .await
                .map_err(|err| CellCollectorError::Internal(err.into()))?
            {
                Some(Tip { block_number, .. }) => {
                    if tip_number.value()
                        > block_number.value() + self.acceptable_indexer_leftbehind
                    {
                        #[cfg(not(target_arch = "wasm32"))]
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        #[cfg(target_arch = "wasm32")]
                        tokio_with_wasm::time::sleep(Duration::from_millis(50)).await;
                    } else {
                        return Ok(());
                    }
                }
                None => {
                    return Err(CellCollectorError::Other(anyhow!(
                        "ckb-indexer server not synced"
                    )));
                }
            }
        }
        Err(CellCollectorError::Other(anyhow!(
            "ckb-indexer server inconsistent with currently connected ckb node or not synced!"
        )))
    }
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl CellCollector for DefaultCellCollector {
    async fn collect_live_cells_async(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        let max_mature_number = get_max_mature_number_async(&self.ckb_client)
            .await
            .map_err(|err| CellCollectorError::Internal(anyhow!(err)))?;
        self.offchain.max_mature_number = max_mature_number;
        let tip_num = self
            .ckb_client
            .get_tip_block_number()
            .await
            .map_err(|err| CellCollectorError::Internal(anyhow!(err)))?
            .value();
        let CollectResult {
            cells,
            rest_cells,
            mut total_capacity,
        } = self.offchain.collect(query, tip_num);
        let mut cells: Vec<_> = cells.into_iter().map(|c| c.0).collect();
        if total_capacity < query.min_total_capacity {
            self.check_ckb_chain_async().await?;
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
                    .indexer_client
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
                    // use cell from indexer to replace offchain cell
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
        tip_block_number: u64,
    ) -> Result<(), CellCollectorError> {
        self.offchain.lock_cell(out_point, tip_block_number)
    }
    fn apply_tx(
        &mut self,
        tx: Transaction,
        tip_block_number: u64,
    ) -> Result<(), CellCollectorError> {
        self.offchain.apply_tx(tx, tip_block_number)
    }
    fn reset(&mut self) {
        self.offchain.reset();
    }
}

struct DefaultTxDepProviderInner {
    rpc_client: CkbRpcAsyncClient,
    tx_cache: LruCache<Byte32, TransactionView>,
    cell_cache: LruCache<OutPoint, (CellOutput, Bytes)>,
    header_cache: LruCache<Byte32, HeaderView>,
    offchain_cache: OffchainTransactionDependencyProvider,
}

/// A transaction dependency provider use ckb rpc client as backend, and with LRU cache supported
pub struct DefaultTransactionDependencyProvider {
    // since we will mainly deal with LruCache, so use Mutex here
    inner: Arc<Mutex<DefaultTxDepProviderInner>>,
}

impl Clone for DefaultTransactionDependencyProvider {
    fn clone(&self) -> DefaultTransactionDependencyProvider {
        let inner = Arc::clone(&self.inner);
        DefaultTransactionDependencyProvider { inner }
    }
}

impl DefaultTransactionDependencyProvider {
    /// Arguments:
    ///   * `url` is the ckb http jsonrpc server url
    ///   * When `cache_capacity` is 0 for not using cache.
    pub fn new(url: &str, cache_capacity: usize) -> DefaultTransactionDependencyProvider {
        let rpc_client = CkbRpcAsyncClient::new(url);
        let inner = DefaultTxDepProviderInner {
            rpc_client,
            tx_cache: LruCache::new(cache_capacity),
            cell_cache: LruCache::new(cache_capacity),
            header_cache: LruCache::new(cache_capacity),
            offchain_cache: OffchainTransactionDependencyProvider::new(),
        };
        DefaultTransactionDependencyProvider {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn apply_tx(
        &mut self,
        tx: Transaction,
        tip_block_number: u64,
    ) -> Result<(), TransactionDependencyError> {
        crate::rpc::block_on(self.apply_tx_async(tx, tip_block_number))
    }

    pub async fn apply_tx_async(
        &mut self,
        tx: Transaction,
        tip_block_number: u64,
    ) -> Result<(), TransactionDependencyError> {
        let mut inner = self.inner.lock().await;
        inner.offchain_cache.apply_tx(tx, tip_block_number)?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_cell_with_data(
        &self,
        out_point: &OutPoint,
    ) -> Result<(CellOutput, Bytes), TransactionDependencyError> {
        crate::rpc::block_on(self.get_cell_with_data_async(out_point))
    }

    pub async fn get_cell_with_data_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<(CellOutput, Bytes), TransactionDependencyError> {
        let mut inner = self.inner.lock().await;
        if let Some(pair) = inner.cell_cache.get(out_point) {
            return Ok(pair.clone());
        }

        let cell_with_status = inner
            .rpc_client
            .get_live_cell(out_point.clone().into(), true)
            .await
            .map_err(|err| TransactionDependencyError::Other(err.into()))?;
        if cell_with_status.status != "live" {
            return Err(TransactionDependencyError::Other(anyhow!(
                "invalid cell status: {:?}",
                cell_with_status.status
            )));
        }
        let cell = cell_with_status.cell.unwrap();
        let output = CellOutput::from(cell.output);
        let output_data = cell.data.unwrap().content.into_bytes();
        inner
            .cell_cache
            .put(out_point.clone(), (output.clone(), output_data.clone()));
        Ok((output, output_data))
    }
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TransactionDependencyProvider for DefaultTransactionDependencyProvider {
    async fn get_transaction_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        let mut inner = self.inner.lock().await;
        if let Some(tx) = inner.tx_cache.get(tx_hash) {
            return Ok(tx.clone());
        }
        let ret: Result<TransactionView, TransactionDependencyError> =
            inner.offchain_cache.get_transaction_async(tx_hash).await;
        if ret.is_ok() {
            return ret;
        }
        let tx_with_status = inner
            .rpc_client
            .get_transaction(tx_hash.unpack())
            .await
            .map_err(|err| TransactionDependencyError::Other(err.into()))?
            .ok_or_else(|| TransactionDependencyError::NotFound("transaction".to_string()))?;
        if tx_with_status.tx_status.status != json_types::Status::Committed {
            return Err(TransactionDependencyError::Other(anyhow!(
                "invalid transaction status: {:?}",
                tx_with_status.tx_status
            )));
        }
        let tx = match tx_with_status.transaction.unwrap().inner {
            Either::Left(t) => Transaction::from(t.inner).into_view(),
            Either::Right(bytes) => TransactionReader::from_slice(bytes.as_bytes())
                .map(|reader| reader.to_entity().into_view())
                .map_err(|err| anyhow!("invalid molecule encoded TransactionView: {}", err))?,
        };
        inner.tx_cache.put(tx_hash.clone(), tx.clone());
        Ok(tx)
    }
    async fn get_cell_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<CellOutput, TransactionDependencyError> {
        {
            let inner = self.inner.lock().await;
            let ret = inner.offchain_cache.get_cell_async(out_point).await;
            if ret.is_ok() {
                return ret;
            }
        }
        self.get_cell_with_data_async(out_point)
            .await
            .map(|(output, _)| output)
    }
    async fn get_cell_data_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<Bytes, TransactionDependencyError> {
        {
            let inner = self.inner.lock().await;
            let ret = inner.offchain_cache.get_cell_data_async(out_point).await;
            if ret.is_ok() {
                return ret;
            }
        }
        self.get_cell_with_data_async(out_point)
            .await
            .map(|(_, output_data)| output_data)
    }
    async fn get_header_async(
        &self,
        block_hash: &Byte32,
    ) -> Result<HeaderView, TransactionDependencyError> {
        let mut inner = self.inner.lock().await;
        if let Some(header) = inner.header_cache.get(block_hash) {
            return Ok(header.clone());
        }
        let header = inner
            .rpc_client
            .get_header(block_hash.unpack())
            .await
            .map_err(|err| TransactionDependencyError::Other(err.into()))?
            .map(HeaderView::from)
            .ok_or_else(|| TransactionDependencyError::NotFound("header".to_string()))?;
        inner.header_cache.put(block_hash.clone(), header.clone());
        Ok(header)
    }

    async fn get_block_extension_async(
        &self,
        block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError> {
        let inner = self.inner.lock().await;

        let block = inner
            .rpc_client
            .get_block(block_hash.unpack())
            .await
            .map_err(|err| TransactionDependencyError::Other(err.into()))?;
        match block {
            Some(block) => Ok(block.extension.map(ckb_types::packed::Bytes::from)),
            None => Ok(None),
        }
    }
}

/// A signer use secp256k1 raw key, the id is `blake160(pubkey)`.
#[derive(Default, Clone)]
pub struct SecpCkbRawKeySigner {
    keys: HashMap<H160, secp256k1::SecretKey>,
}

impl SecpCkbRawKeySigner {
    pub fn new(keys: HashMap<H160, secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        SecpCkbRawKeySigner { keys }
    }
    pub fn new_with_secret_keys(keys: Vec<secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        let mut signer = SecpCkbRawKeySigner::default();
        for key in keys {
            signer.add_secret_key(key);
        }
        signer
    }
    pub fn add_secret_key(&mut self, key: secp256k1::SecretKey) {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
        let hash160 = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        self.keys.insert(hash160, key);
    }

    /// Create SecpkRawKeySigner from secret keys for ethereum algorithm.
    pub fn new_with_ethereum_secret_keys(keys: Vec<secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        let mut signer = SecpCkbRawKeySigner::default();
        for key in keys {
            signer.add_ethereum_secret_key(key);
        }
        signer
    }
    /// Add a ethereum secret key
    pub fn add_ethereum_secret_key(&mut self, key: secp256k1::SecretKey) {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
        let hash160 = keccak160(Pubkey::from(pubkey).as_ref());
        self.keys.insert(hash160, key);
    }
}

impl Signer for SecpCkbRawKeySigner {
    fn match_id(&self, id: &[u8]) -> bool {
        id.len() == 20 && self.keys.contains_key(&H160::from_slice(id).unwrap())
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        _tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        if !self.match_id(id) {
            return Err(SignerError::IdNotFound);
        }
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg =
            secp256k1::Message::from_digest_slice(message).expect("Convert to message failed");
        let key = self.keys.get(&H160::from_slice(id).unwrap()).unwrap();
        if recoverable {
            let sig = SECP256K1.sign_ecdsa_recoverable(&msg, key);
            Ok(Bytes::from(serialize_signature(&sig).to_vec()))
        } else {
            let sig = SECP256K1.sign_ecdsa(&msg, key);
            Ok(Bytes::from(sig.serialize_compact().to_vec()))
        }
    }
}

impl Drop for SecpCkbRawKeySigner {
    fn drop(&mut self) {
        for (_, mut secret_key) in self.keys.drain() {
            zeroize_privkey(&mut secret_key);
        }
    }
}
#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_parse_genesis_info_error() {
        let error = super::ParseGenesisInfoError::DataHashNotFound("DataHashNotFound".to_string());
        let error = anyhow!(error);
        assert_eq!("data not found: `DataHashNotFound`", error.to_string());
    }
}
