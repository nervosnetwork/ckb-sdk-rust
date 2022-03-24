use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lru::LruCache;
use parking_lot::Mutex;

use ckb_chain_spec::consensus::Consensus;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, ScriptHashType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Transaction},
    prelude::*,
    H160, H256,
};

use crate::rpc::ckb_indexer::{Order, SearchKey, Tip};
use crate::rpc::{CkbRpcClient, IndexerRpcClient};
use crate::traits::{
    CellCollector, CellCollectorError, CellDepResolver, CellQueryOptions, HeaderDepResolver,
    LiveCell, Signer, SignerError, TransactionDependencyError, TransactionDependencyProvider,
};
use crate::types::ScriptId;
use crate::util::{
    get_max_mature_number, serialize_signature, to_consensus_struct, zeroize_privkey,
};
use crate::GenesisInfo;
use crate::SECP256K1;

/// A cell_dep resolver use genesis info resolve system scripts and can register more cell_dep info.
#[derive(Default, Clone)]
pub struct DefaultCellDepResolver {
    items: HashMap<ScriptId, (CellDep, String)>,
}
impl DefaultCellDepResolver {
    pub fn new(info: &GenesisInfo) -> DefaultCellDepResolver {
        let mut items = HashMap::default();
        items.insert(
            ScriptId::new(info.sighash_type_hash().unpack(), ScriptHashType::Type),
            (
                info.sighash_dep(),
                "Secp256k1 blake160 sighash all".to_string(),
            ),
        );
        items.insert(
            ScriptId::new(info.multisig_type_hash().unpack(), ScriptHashType::Type),
            (
                info.multisig_dep(),
                "Secp256k1 blake160 multisig all".to_string(),
            ),
        );
        items.insert(
            ScriptId::new(info.dao_type_hash().unpack(), ScriptHashType::Type),
            (info.dao_dep(), "Nervos DAO".to_string()),
        );
        DefaultCellDepResolver { items }
    }
    pub fn insert(
        &mut self,
        script_id: ScriptId,
        cell_dep: CellDep,
        name: String,
    ) -> Option<(CellDep, String)> {
        self.items.insert(script_id, (cell_dep, name))
    }
    pub fn remove(&mut self, script_id: &ScriptId) -> Option<(CellDep, String)> {
        self.items.remove(script_id)
    }
    pub fn contains(&self, script_id: &ScriptId) -> bool {
        self.items.contains_key(script_id)
    }
    pub fn get(&self, script_id: &ScriptId) -> Option<&(CellDep, String)> {
        self.items.get(script_id)
    }
}
impl CellDepResolver for DefaultCellDepResolver {
    fn resolve(&self, script_id: &ScriptId) -> Option<CellDep> {
        self.get(script_id).map(|(cell_dep, _)| cell_dep.clone())
    }
}

/// A header_dep resolver use ckb jsonrpc client as backend
pub struct DefaultHeaderDepResolver {
    ckb_client: Arc<Mutex<CkbRpcClient>>,
}
impl DefaultHeaderDepResolver {
    pub fn new(ckb_client: CkbRpcClient) -> DefaultHeaderDepResolver {
        let ckb_client = Arc::new(Mutex::new(ckb_client));
        DefaultHeaderDepResolver { ckb_client }
    }
}
impl HeaderDepResolver for DefaultHeaderDepResolver {
    fn resolve_by_tx(
        &self,
        tx_hash: &Byte32,
    ) -> Result<Option<HeaderView>, Box<dyn std::error::Error>> {
        let mut client = self.ckb_client.lock();
        if let Some(block_hash) = client
            .get_transaction(tx_hash.unpack())
            .map_err(Box::new)?
            .and_then(|tx_with_status| tx_with_status.tx_status.block_hash)
        {
            Ok(client
                .get_header(block_hash)
                .map_err(Box::new)?
                .map(Into::into))
        } else {
            Ok(None)
        }
    }
    fn resolve_by_number(
        &self,
        number: u64,
    ) -> Result<Option<HeaderView>, Box<dyn std::error::Error>> {
        Ok(self
            .ckb_client
            .lock()
            .get_header_by_number(number.into())
            .map_err(Box::new)?
            .map(Into::into))
    }
}

/// A cell collector use ckb-indexer as backend
pub struct DefaultCellCollector {
    indexer_client: IndexerRpcClient,
    ckb_client: CkbRpcClient,
    locked_cells: HashSet<(H256, u32)>,
    offchain_live_cells: Vec<LiveCell>,
}

impl DefaultCellCollector {
    pub fn new(indexer_client: IndexerRpcClient, ckb_client: CkbRpcClient) -> DefaultCellCollector {
        DefaultCellCollector {
            indexer_client,
            ckb_client,
            locked_cells: Default::default(),
            offchain_live_cells: Default::default(),
        }
    }

    /// Check if ckb-indexer synced with ckb node. This will check every 50ms for 10 times (500ms in total).
    pub fn check_ckb_chain(&mut self) -> Result<(), CellCollectorError> {
        let tip_header = self
            .ckb_client
            .get_tip_header()
            .map_err(|err| CellCollectorError::Internal(err.into()))?;
        let tip_hash = tip_header.hash;
        let tip_number = tip_header.inner.number;
        let mut retry = 10;
        while retry > 0 {
            match self
                .indexer_client
                .get_tip()
                .map_err(|err| CellCollectorError::Internal(err.into()))?
            {
                Some(Tip {
                    block_hash,
                    block_number,
                }) => {
                    if tip_number.value() > block_number.value() {
                        thread::sleep(Duration::from_millis(50));
                        retry -= 1;
                        continue;
                    } else if tip_hash == block_hash && tip_number == block_number {
                        return Ok(());
                    } else {
                        return Err(CellCollectorError::Other("ckb-indexer server inconsistent with currently connected ckb node or not synced!".to_owned().into()));
                    }
                }
                None => {
                    return Err(CellCollectorError::Other(
                        "ckb-indexer server not synced".to_owned().into(),
                    ));
                }
            }
        }
        Err(CellCollectorError::Other(
            "ckb-indexer server inconsistent with currently connected ckb node or not synced!"
                .to_owned()
                .into(),
        ))
    }
}

impl CellCollector for DefaultCellCollector {
    fn collect_live_cells(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        let max_mature_number = get_max_mature_number(&mut self.ckb_client)
            .map_err(|err| CellCollectorError::Internal(err.into()))?;
        let mut total_capacity = 0;
        let (mut cells, rest_cells): (Vec<_>, Vec<_>) = self
            .offchain_live_cells
            .clone()
            .into_iter()
            .partition(|cell| {
                if total_capacity < query.min_total_capacity
                    && query.match_cell(cell, Some(max_mature_number))
                {
                    let capacity: u64 = cell.output.capacity().unpack();
                    total_capacity += capacity;
                    true
                } else {
                    false
                }
            });
        if apply_changes {
            self.offchain_live_cells = rest_cells;
        }
        if total_capacity < query.min_total_capacity {
            self.check_ckb_chain()?;
            let locked_cells = self.locked_cells.clone();
            let search_key = SearchKey::from(query.clone());
            let max_limit = 4096;
            let mut limit: u32 = 128;
            let mut last_cursor: Option<json_types::JsonBytes> = None;
            while total_capacity < query.min_total_capacity {
                let page = self
                    .indexer_client
                    .get_cells(search_key.clone(), Order::Asc, limit.into(), last_cursor)
                    .map_err(|err| CellCollectorError::Internal(err.into()))?;
                if page.objects.is_empty() {
                    break;
                }
                for cell in page.objects {
                    let live_cell = LiveCell::from(cell);
                    if !query.match_cell(&live_cell, Some(max_mature_number))
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
                if limit < max_limit {
                    limit *= 2;
                }
            }
        }
        if apply_changes {
            for cell in &cells {
                self.lock_cell(cell.out_point.clone())?;
            }
        }

        Ok((cells, total_capacity))
    }

    fn lock_cell(&mut self, out_point: OutPoint) -> Result<(), CellCollectorError> {
        self.locked_cells
            .insert((out_point.tx_hash().unpack(), out_point.index().unpack()));
        Ok(())
    }
    fn apply_tx(&mut self, tx: Transaction) -> Result<(), CellCollectorError> {
        let tx_view = tx.into_view();
        let tx_hash = tx_view.hash();
        for out_point in tx_view.input_pts_iter() {
            self.lock_cell(out_point)?;
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
            self.offchain_live_cells.push(info);
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.locked_cells.clear();
        self.offchain_live_cells.clear();
    }
}

struct DefaultTxDepProviderInner {
    rpc_client: CkbRpcClient,
    consensus: Option<Consensus>,
    tx_cache: LruCache<Byte32, TransactionView>,
    cell_cache: LruCache<OutPoint, (CellOutput, Bytes)>,
    header_cache: LruCache<Byte32, HeaderView>,
}

/// A transaction dependency provider use ckb rpc client as backend, and with LRU cache supported
pub struct DefaultTransactionDependencyProvider {
    // since we will mainly deal with LruCache, so use Mutex here
    inner: Arc<Mutex<DefaultTxDepProviderInner>>,
}

impl DefaultTransactionDependencyProvider {
    /// Arguments:
    ///   * `url` is the ckb http jsonrpc server url
    ///   * When `cache_capacity` is 0 for not using cache.
    pub fn new(url: &str, cache_capacity: usize) -> DefaultTransactionDependencyProvider {
        let rpc_client = CkbRpcClient::new(url);
        let inner = DefaultTxDepProviderInner {
            rpc_client,
            consensus: None,
            tx_cache: LruCache::new(cache_capacity),
            cell_cache: LruCache::new(cache_capacity),
            header_cache: LruCache::new(cache_capacity),
        };
        DefaultTransactionDependencyProvider {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn get_cell_with_data(
        &self,
        out_point: &OutPoint,
    ) -> Result<(CellOutput, Bytes), TransactionDependencyError> {
        let mut inner = self.inner.lock();
        if let Some(pair) = inner.cell_cache.get(out_point) {
            return Ok(pair.clone());
        }
        // TODO: handle proposed/pending transactions
        let cell_with_status = inner
            .rpc_client
            .get_live_cell(out_point.clone().into(), true)
            .map_err(|err| TransactionDependencyError::Other(err.into()))?;
        if cell_with_status.status != "live" {
            return Err(TransactionDependencyError::Other(
                format!("invalid cell status: {:?}", cell_with_status.status).into(),
            ));
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

impl TransactionDependencyProvider for DefaultTransactionDependencyProvider {
    fn get_consensus(&self) -> Result<Consensus, TransactionDependencyError> {
        let mut inner = self.inner.lock();
        if let Some(consensus) = inner.consensus.as_ref() {
            return Ok(consensus.clone());
        }
        let consensus = inner
            .rpc_client
            .get_consensus()
            .map(to_consensus_struct)
            .map_err(|err| TransactionDependencyError::Other(err.into()))?;
        inner.consensus = Some(consensus.clone());
        Ok(consensus)
    }
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        let mut inner = self.inner.lock();
        if let Some(tx) = inner.tx_cache.get(tx_hash) {
            return Ok(tx.clone());
        }
        // TODO: handle proposed/pending transactions
        let tx_with_status = inner
            .rpc_client
            .get_transaction(tx_hash.unpack())
            .map_err(|err| TransactionDependencyError::Other(err.into()))?
            .ok_or_else(|| TransactionDependencyError::NotFound("transaction".to_string()))?;
        if tx_with_status.tx_status.status != json_types::Status::Committed {
            return Err(TransactionDependencyError::Other(
                format!("invalid transaction status: {:?}", tx_with_status.tx_status).into(),
            ));
        }
        let tx = Transaction::from(tx_with_status.transaction.unwrap().inner).into_view();
        inner.tx_cache.put(tx_hash.clone(), tx.clone());
        Ok(tx)
    }
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError> {
        self.get_cell_with_data(out_point).map(|(output, _)| output)
    }
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError> {
        self.get_cell_with_data(out_point)
            .map(|(_, output_data)| output_data)
    }
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError> {
        let mut inner = self.inner.lock();
        if let Some(header) = inner.header_cache.get(block_hash) {
            return Ok(header.clone());
        }
        let header = inner
            .rpc_client
            .get_header(block_hash.unpack())
            .map_err(|err| TransactionDependencyError::Other(err.into()))?
            .map(HeaderView::from)
            .ok_or_else(|| TransactionDependencyError::NotFound("header".to_string()))?;
        inner.header_cache.put(block_hash.clone(), header.clone());
        Ok(header)
    }
}

/// A signer use secp256k1 raw key, the id is `blake160(pubkey)`.
#[derive(Default)]
pub struct SecpCkbRawKeySigner {
    keys: HashMap<H160, secp256k1::SecretKey>,
}

impl SecpCkbRawKeySigner {
    pub fn new(keys: HashMap<H160, secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        SecpCkbRawKeySigner { keys }
    }
    pub fn add_secret_key(&mut self, key: secp256k1::SecretKey) {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
        let hash160 = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
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
        let msg = secp256k1::Message::from_slice(message).expect("Convert to message failed");
        let key = self.keys.get(&H160::from_slice(id).unwrap()).unwrap();
        if recoverable {
            let sig = SECP256K1.sign_recoverable(&msg, key);
            Ok(Bytes::from(serialize_signature(&sig).to_vec()))
        } else {
            let sig = SECP256K1.sign(&msg, key);
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
