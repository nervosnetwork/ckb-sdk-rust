use anyhow::anyhow;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashMap;
use thiserror::Error;

use crate::constants::{
    DAO_OUTPUT_LOC, DAO_TYPE_HASH, MULTISIG_GROUP_OUTPUT_LOC, MULTISIG_OUTPUT_LOC,
    MULTISIG_TYPE_HASH, SIGHASH_GROUP_OUTPUT_LOC, SIGHASH_OUTPUT_LOC, SIGHASH_TYPE_HASH,
};
use ckb_jsonrpc_types as json_types;
use ckb_resource::{
    CODE_HASH_DAO, CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL,
    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
};
use ckb_types::{
    bytes::Bytes,
    core::{DepType, HeaderView, ScriptHashType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction},
    prelude::*,
    H256,
};

use super::OffchainCellCollector;
use crate::rpc::{
    ckb_light_client::{Cell, FetchStatus, Order, ScriptType, SearchKey},
    CkbRpcClient, LightClientRpcClient, RpcError,
};
use crate::traits::{
    CellCollector, CellCollectorError, CellDepResolver, CellQueryOptions, HeaderDepResolver,
    LiveCell, OffchainCellDepResolver, QueryOrder, TransactionDependencyError,
    TransactionDependencyProvider,
};
use crate::types::ScriptId;
use crate::util::get_max_mature_number;

/// Query Genesis Info errors
#[derive(Error, Debug)]
pub enum GetGenesisInfoError {
    #[error("fetch genesis info rpc error `{0}`")]
    Rpc(#[from] RpcError),
    #[error("data not found: `{0}`")]
    DataHashNotFound(String),
    #[error("type not found: `{0}`")]
    TypeHashNotFound(String),
    #[error("dep group not found: `{0}`")]
    DepGroupNotFound(String),
}

pub struct LightClientCellDepResolver {
    offchain: OffchainCellDepResolver,
}

impl LightClientCellDepResolver {
    pub fn from_rpc(url: &str) -> Result<LightClientCellDepResolver, GetGenesisInfoError> {
        let mut client = LightClientRpcClient::new(url);
        let lock = Script::new_builder()
            .code_hash(H256::default().pack())
            .hash_type(ScriptHashType::Data.into())
            .args(Bytes::default().pack())
            .build();
        let search_key = SearchKey {
            script: lock.into(),
            script_type: ScriptType::Lock,
            filter: None,
            group_by_transaction: None,
        };

        let mut sighash_type_hash = None;
        let mut multisig_type_hash = None;
        let mut dao_type_hash = None;
        let mut sighash_dep = None;
        let mut multisig_dep = None;
        let mut dao_dep = None;
        let page = client.get_cells(search_key, Order::Asc, 10.into(), None)?;
        for Cell {
            output,
            output_data,
            out_point,
            tx_index,
            ..
        } in page.objects
        {
            let index = out_point.index.value() as usize;
            let tx_index = tx_index.value() as usize;
            let output = CellOutput::from(output);
            let out_point = OutPoint::from(out_point);

            if tx_index == SIGHASH_OUTPUT_LOC.0 && index == SIGHASH_OUTPUT_LOC.1 {
                sighash_type_hash = output
                    .type_()
                    .to_opt()
                    .map(|script| script.calc_script_hash());
                let data_hash = CellOutput::calc_data_hash(output_data.as_bytes());
                if data_hash != CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL.pack() {
                    log::error!(
                        "System sighash script code hash error! found: {}, expected: {}",
                        data_hash,
                        CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
                    );
                }
            } else if tx_index == MULTISIG_OUTPUT_LOC.0 && index == MULTISIG_OUTPUT_LOC.1 {
                multisig_type_hash = output
                    .type_()
                    .to_opt()
                    .map(|script| script.calc_script_hash());
                let data_hash = CellOutput::calc_data_hash(output_data.as_bytes());
                if data_hash != CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL.pack() {
                    log::error!(
                        "System multisig script code hash error! found: {}, expected: {}",
                        data_hash,
                        CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL,
                    );
                }
            } else if tx_index == DAO_OUTPUT_LOC.0 && index == DAO_OUTPUT_LOC.1 {
                dao_type_hash = output
                    .type_()
                    .to_opt()
                    .map(|script| script.calc_script_hash());
                let data_hash = CellOutput::calc_data_hash(output_data.as_bytes());
                if data_hash != CODE_HASH_DAO.pack() {
                    log::error!(
                        "System dao script code hash error! found: {}, expected: {}",
                        data_hash,
                        CODE_HASH_DAO,
                    );
                }
                dao_dep = Some(CellDep::new_builder().out_point(out_point).build());
            } else if tx_index == SIGHASH_GROUP_OUTPUT_LOC.0 && index == SIGHASH_GROUP_OUTPUT_LOC.1
            {
                sighash_dep = Some(
                    CellDep::new_builder()
                        .out_point(out_point)
                        .dep_type(DepType::DepGroup.into())
                        .build(),
                );
            } else if tx_index == MULTISIG_GROUP_OUTPUT_LOC.0
                && index == MULTISIG_GROUP_OUTPUT_LOC.1
            {
                multisig_dep = Some(
                    CellDep::new_builder()
                        .out_point(out_point)
                        .dep_type(DepType::DepGroup.into())
                        .build(),
                );
            }
        }

        let sighash_type_hash = sighash_type_hash
            .ok_or_else(|| "No type hash(sighash) found in txs[0][1]".to_owned())
            .map_err(GetGenesisInfoError::TypeHashNotFound)?;
        let multisig_type_hash = multisig_type_hash
            .ok_or_else(|| "No type hash(multisig) found in txs[0][4]".to_owned())
            .map_err(GetGenesisInfoError::TypeHashNotFound)?;
        let dao_type_hash = dao_type_hash
            .ok_or_else(|| "No type hash(dao) found in txs[0][2]".to_owned())
            .map_err(GetGenesisInfoError::TypeHashNotFound)?;
        let sighash_dep = sighash_dep
            .ok_or_else(|| "No sighash dep group cell".to_owned())
            .map_err(GetGenesisInfoError::DepGroupNotFound)?;
        let multisig_dep = multisig_dep
            .ok_or_else(|| "No multisig dep group cell".to_owned())
            .map_err(GetGenesisInfoError::DepGroupNotFound)?;
        let dao_dep = dao_dep.expect("dao dep");

        let mut items = HashMap::default();
        items.insert(
            ScriptId::new_type(sighash_type_hash.unpack()),
            (sighash_dep, "Secp256k1 blake160 sighash all".to_string()),
        );
        items.insert(
            ScriptId::new_type(multisig_type_hash.unpack()),
            (multisig_dep, "Secp256k1 blake160 multisig all".to_string()),
        );
        items.insert(
            ScriptId::new_type(dao_type_hash.unpack()),
            (dao_dep, "Nervos DAO".to_string()),
        );
        let offchain = OffchainCellDepResolver { items };
        Ok(LightClientCellDepResolver { offchain })
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
    pub fn multisig_dep(&self) -> Option<&(CellDep, String)> {
        self.get(&ScriptId::new_type(MULTISIG_TYPE_HASH))
    }
    pub fn dao_dep(&self) -> Option<&(CellDep, String)> {
        self.get(&ScriptId::new_type(DAO_TYPE_HASH))
    }
}

impl CellDepResolver for LightClientCellDepResolver {
    fn resolve(&self, script: &Script) -> Option<CellDep> {
        self.offchain.resolve(script)
    }
}

pub struct LightClientHeaderDepResolver {
    client: Mutex<LightClientRpcClient>,
    // tx_hash => HeaderView
    headers: DashMap<Byte32, Option<HeaderView>>,
}

impl LightClientHeaderDepResolver {
    pub fn new(url: &str) -> LightClientHeaderDepResolver {
        let client = Mutex::new(LightClientRpcClient::new(url));
        LightClientHeaderDepResolver {
            client,
            headers: DashMap::new(),
        }
    }

    /// Check if headers all fetched
    pub fn is_ready(&self) -> bool {
        self.headers.iter().all(|pair| pair.value().is_some())
    }
}

impl HeaderDepResolver for LightClientHeaderDepResolver {
    fn resolve_by_tx(&self, tx_hash: &Byte32) -> Result<Option<HeaderView>, anyhow::Error> {
        if let Some(Some(header)) = self.headers.get(tx_hash).as_ref().map(|pair| pair.value()) {
            return Ok(Some(header.clone()));
        }
        match self.client.lock().fetch_transaction(tx_hash.unpack())? {
            FetchStatus::Fetched { data } => {
                let header: HeaderView = data.header.into();
                self.headers.insert(tx_hash.clone(), Some(header.clone()));
                Ok(Some(header))
            }
            status => {
                self.headers.insert(tx_hash.clone(), None);
                Err(anyhow!("fetching header by transaction: {:?}", status))
            }
        }
    }

    fn resolve_by_number(&self, _number: u64) -> Result<Option<HeaderView>, anyhow::Error> {
        Err(anyhow!(
            "unable to resolver header by number when use light client as backend"
        ))
    }
}

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
