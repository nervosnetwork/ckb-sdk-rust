pub mod dao;
pub mod udt;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;
use thiserror::Error;

use ckb_chain_spec::consensus::Consensus;
use ckb_dao::DaoCalculator;
use ckb_dao_utils::DaoError;
use ckb_jsonrpc_types as json_types;
use ckb_script::ScriptGroup;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{resolve_transaction_with_options, ResolveOptions},
        error::OutPointError,
        Capacity, CapacityError, FeeRate, HeaderView, TransactionView,
    },
    packed::{Byte32, CellInput, CellOutput, OutPoint, Script, Transaction, WitnessArgs},
    prelude::*,
};

use crate::constants::DAO_TYPE_HASH;
use crate::rpc::HttpRpcClient;
use crate::traits::{
    CellCollector, CellCollectorError, CellDepResolver, CellQueryOptions,
    TransactionDependencyProvider, TxDepProviderError,
};
use crate::types::ScriptId;
use crate::unlock::{ScriptUnlocker, UnlockError};
use crate::util::{clone_script_group, to_consensus_struct, transaction_maximum_withdraw};

/// Transaction builder errors
#[derive(Error, Debug)]
pub enum TransactionCrafterError {
    #[error("invalid parameter: `{0}`")]
    InvalidParameter(Box<dyn std::error::Error>),
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TxDepProviderError),
    #[error("cell collector error: `{0}`")]
    CellCollector(#[from] CellCollectorError),
    #[error("balance capacity error: `{0}`")]
    BalanceCapacity(#[from] BalanceTxCapacityError),
    #[error("resolve cell dep failed: `{0}`")]
    ResolveCellDepFailed(ScriptId),
    #[error("unlock error: `{0}`")]
    Unlock(#[from] UnlockError),
    #[error("other error: `{0}`")]
    Other(Box<dyn std::error::Error>),
}

/// Transaction Builder interface
pub trait TransactionCrafter {
    /// Build base transaction
    fn build_base(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
    ) -> Result<TransactionView, TransactionCrafterError>;

    /// Build balanced transaction that ready to sign:
    ///  * Build base transaction
    ///  * balance the capacity
    fn build_balanced(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        balancer: &CapacityBalancer,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TransactionCrafterError> {
        let base_tx = self.build_base(cell_collector, cell_dep_resolver)?;
        Ok(balance_tx_capacity(
            &base_tx,
            balancer,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
        )?)
    }

    /// Build unlocked transaction that ready to send or for further unlock:
    ///   * build base transaction
    ///   * balance the capacity
    ///   * unlock(sign) the transaction
    ///
    /// Return value:
    ///   * The built transaction
    ///   * The script groups that not unlocked
    fn build_unlocked(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        balancer: &CapacityBalancer,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TransactionCrafterError> {
        let balanced_tx =
            self.build_balanced(cell_collector, cell_dep_resolver, balancer, tx_dep_provider)?;
        Ok(unlock_tx(balanced_tx, tx_dep_provider, unlockers)?)
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum TransferAction {
    /// This action will crate a new cell, typecial lock script: cheque, sighash, multisig
    Create,
    /// This action will query the exists cell and update the amount, typecial lock script: acp
    Update,
}

#[derive(Error, Debug)]
pub enum TransactionFeeError {
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TxDepProviderError),
    #[error("out point error: `{0}`")]
    OutPoint(#[from] OutPointError),
    #[error("dao error: `{0}`")]
    Dao(#[from] DaoError),
    #[error("unexpected dao withdraw cell in inputs")]
    UnexpectedDaoWithdrawInput,
    #[error("capacity error: `{0}`")]
    CapacityError(#[from] CapacityError),
    #[error("capacity sub overflow, delta: `{0}`")]
    CapacityOverflow(u64),
}

/// Calculate the actual transaction fee of the transaction, include dao
/// withdraw capacity.
pub fn tx_fee(
    tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
) -> Result<u64, TransactionFeeError> {
    let rtx = resolve_transaction_with_options(
        tx,
        &mut HashSet::new(),
        &tx_dep_provider,
        &tx_dep_provider,
        ResolveOptions::default(),
    )?;
    let consensus = tx_dep_provider.get_consensus()?;
    let maximum_withdraw = transaction_maximum_withdraw(
        &DaoCalculator::new(&consensus, &tx_dep_provider),
        &rtx,
        &consensus,
        tx_dep_provider,
    )?
    .as_u64();
    let output_total = rtx.transaction.outputs_capacity()?.as_u64();
    maximum_withdraw
        .checked_sub(output_total)
        .ok_or_else(|| TransactionFeeError::CapacityOverflow(output_total - maximum_withdraw))
}

/// Calculate the actual transaction fee of the transaction.
///
/// If there is no dao cell in inputs, use this function will require less
/// dependencies. If there is dao cell in inputs it will return
/// `TransactionFeeError::UnexpectedDaoInput`.
pub fn tx_fee_without_dao_withdraw(
    tx: &TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
) -> Result<u64, TransactionFeeError> {
    let mut input_total: u64 = 0;
    for input in tx.inputs() {
        let since: u64 = input.since().unpack();
        let cell = tx_dep_provider.get_cell(&input.previous_output())?;
        // dao withdraw operation
        if since != 0 {
            if let Some(type_script) = cell.type_().to_opt() {
                if type_script.code_hash().as_slice() == DAO_TYPE_HASH.as_bytes() {
                    return Err(TransactionFeeError::UnexpectedDaoWithdrawInput);
                }
            }
        }
        let capacity: u64 = cell.capacity().unpack();
        input_total += capacity;
    }
    let output_total: u64 = tx.outputs_capacity().expect("capacity overflow").as_u64();
    input_total
        .checked_sub(output_total)
        .ok_or_else(|| TransactionFeeError::CapacityOverflow(output_total - input_total))
}

#[derive(Debug, Clone)]
pub struct CapacityProvider {
    pub lock_script: Script,
    /// The zero_lock size of WitnessArgs.lock field:
    ///   * sighash is: `65`
    ///   * multisig is: `MultisigConfig.to_witness_data().len() + 65 * MultisigConfig.threshold`
    pub init_witness_lock_field_size: usize,
}

impl CapacityProvider {
    pub fn new(lock_script: Script, init_witness_lock_field_size: usize) -> CapacityProvider {
        CapacityProvider {
            lock_script,
            init_witness_lock_field_size,
        }
    }
}

#[derive(Error, Debug)]
pub enum BalanceTxCapacityError {
    #[error("calculate transaction fee error: `{0}`")]
    TxFee(#[from] TransactionFeeError),
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TxDepProviderError),
    #[error("capacity not enough")]
    CapacityNotEnough,
    #[error("Force small change as fee failed, fee: `{0}`")]
    ForceSmallChangeAsFeeFailed(u64),
    #[error("cell collector error: `{0}`")]
    CellCollector(#[from] CellCollectorError),
    #[error("resolve cell dep failed: `{0}`")]
    ResolveCellDepFailed(ScriptId),
}

/// Transaction capacity balancer config
#[derive(Debug, Clone)]
pub struct CapacityBalancer {
    pub fee_rate: FeeRate,
    pub capacity_provider: CapacityProvider,
    pub force_small_change_as_fee: Option<u64>,
    pub has_dao_withdraw: bool,
}

/// Fill more inputs to balance the transaction capacity
///
///   * capacity_provider: Search cell by this lock script and filter out cells
///     with data or with type script or not mature.
///
///   * force_small_change_as_fee: When there is no more inputs for create a
///   change cell to balance the transaction capacity, force the addition
///   capacity as fee, the value is actual maximum transaction fee.
pub fn balance_tx_capacity(
    tx: &TransactionView,
    balancer: &CapacityBalancer,
    cell_collector: &mut dyn CellCollector,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    cell_dep_resolver: &dyn CellDepResolver,
) -> Result<TransactionView, BalanceTxCapacityError> {
    let capacity_provider = &balancer.capacity_provider;
    let base_change_output = CellOutput::new_builder()
        .lock(capacity_provider.lock_script.clone())
        .build();
    let base_change_occupied_capacity = base_change_output
        .occupied_capacity(Capacity::zero())
        .expect("init change occupied capacity")
        .as_u64();
    // the query is to collect just one cell
    let base_query = CellQueryOptions::new(capacity_provider.lock_script.clone());
    // check if capacity provider lock script already in inputs
    let mut has_provider = false;
    for input in tx.inputs() {
        let cell = tx_dep_provider.get_cell(&input.previous_output())?;
        if cell.lock() == capacity_provider.lock_script {
            has_provider = true;
        }
    }

    let mut cell_deps = Vec::new();
    let mut inputs = Vec::new();
    let mut change_output: Option<CellOutput> = None;
    let mut witnesses = Vec::new();
    loop {
        // Fill placehodler witnesses before adjust transaction fee.
        if !has_provider {
            while tx.witnesses().item_count() + witnesses.len() < tx.inputs().item_count() {
                witnesses.push(Default::default());
            }
            if tx.witnesses().item_count() + witnesses.len()
                < tx.inputs().item_count() + inputs.len()
            {
                let zero_lock = vec![0u8; capacity_provider.init_witness_lock_field_size];
                let witness_args = WitnessArgs::new_builder()
                    .lock(Some(Bytes::from(zero_lock)).pack())
                    .build();
                witnesses.push(witness_args.as_bytes().pack());
            }
        }
        let new_tx = {
            let mut builder = tx
                .data()
                .as_advanced_builder()
                .cell_deps(cell_deps.clone())
                .inputs(inputs.clone())
                .witnesses(witnesses.clone());
            if let Some(output) = change_output.clone() {
                builder = builder.output(output).output_data(Default::default());
            }
            builder.build()
        };
        let tx_size = new_tx.data().as_reader().serialized_size_in_block();
        let min_fee = balancer.fee_rate.fee(tx_size).as_u64();
        let mut need_more_capacity = 1;
        let fee_result: Result<u64, TransactionFeeError> = if balancer.has_dao_withdraw {
            tx_fee(new_tx.clone(), tx_dep_provider)
        } else {
            tx_fee_without_dao_withdraw(&new_tx, tx_dep_provider)
        };
        match fee_result {
            Ok(fee) if fee == min_fee => {
                return Ok(new_tx);
            }
            Ok(fee) if fee > min_fee => {
                let delta = fee - min_fee;
                if let Some(output) = change_output.take() {
                    // If change cell already exits, just change the capacity field
                    let old_capacity: u64 = output.capacity().unpack();
                    let new_capacity = old_capacity
                        .checked_add(delta)
                        .expect("change cell capacity add overflow");
                    // next loop round must return new_tx;
                    change_output = Some(output.as_builder().capacity(new_capacity.pack()).build());
                    need_more_capacity = 0;
                } else {
                    // If change cell not exists, add a change cell.
                    let extra_min_fee = balancer
                        .fee_rate
                        .fee(base_change_output.as_slice().len())
                        .as_u64();
                    // The extra capacity (delta - extra_min_fee) is enough to hold the change cell.
                    if delta >= base_change_occupied_capacity + extra_min_fee {
                        // next loop round must return new_tx;
                        change_output = Some(
                            base_change_output
                                .clone()
                                .as_builder()
                                .capacity((delta - extra_min_fee).pack())
                                .build(),
                        );
                        need_more_capacity = 0;
                    } else {
                        // peek if there is more live cell owned by this capacity provider
                        let (more_cells, _more_capacity) =
                            cell_collector.collect_live_cells(&base_query, false)?;
                        if more_cells.is_empty() {
                            if let Some(capacity) = balancer.force_small_change_as_fee {
                                if fee > capacity {
                                    return Err(
                                        BalanceTxCapacityError::ForceSmallChangeAsFeeFailed(fee),
                                    );
                                } else {
                                    return Ok(new_tx);
                                }
                            } else {
                                return Err(BalanceTxCapacityError::CapacityNotEnough);
                            }
                        } else {
                            // need more input to balance the capacity
                            change_output = Some(
                                base_change_output
                                    .clone()
                                    .as_builder()
                                    .capacity(base_change_occupied_capacity.pack())
                                    .build(),
                            );
                        }
                    }
                }
            }
            // fee is positive and `fee < min_fee`
            Ok(_fee) => {}
            Err(TransactionFeeError::CapacityOverflow(delta)) => {
                need_more_capacity = delta + min_fee;
            }
            Err(err) => {
                return Err(err.into());
            }
        }
        if need_more_capacity > 0 {
            let query = base_query.clone().min_capacity(need_more_capacity);
            let (more_cells, _more_capacity) = cell_collector.collect_live_cells(&query, true)?;
            if more_cells.is_empty() {
                return Err(BalanceTxCapacityError::CapacityNotEnough);
            }
            if cell_deps.is_empty() {
                let provider_script_id = ScriptId::from(&capacity_provider.lock_script);
                let provider_cell_dep = cell_dep_resolver.resolve(&provider_script_id).ok_or(
                    BalanceTxCapacityError::ResolveCellDepFailed(provider_script_id),
                )?;
                cell_deps.push(provider_cell_dep);
            }
            inputs.extend(
                more_cells
                    .into_iter()
                    .map(|cell| CellInput::new(cell.out_point, 0)),
            );
        }
    }
}

pub struct ScriptGroups {
    pub lock_groups: HashMap<Byte32, ScriptGroup>,
    pub type_groups: HashMap<Byte32, ScriptGroup>,
}

pub fn gen_script_groups(
    tx: &TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
) -> Result<ScriptGroups, TxDepProviderError> {
    #[allow(clippy::mutable_key_type)]
    let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
    #[allow(clippy::mutable_key_type)]
    let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
    for (i, input) in tx.inputs().into_iter().enumerate() {
        let output = tx_dep_provider.get_cell(&input.previous_output())?;
        let lock_group_entry = lock_groups
            .entry(output.calc_lock_hash())
            .or_insert_with(|| ScriptGroup::from_lock_script(&output.lock()));
        lock_group_entry.input_indices.push(i);
        if let Some(t) = &output.type_().to_opt() {
            let type_group_entry = type_groups
                .entry(t.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(t));
            type_group_entry.input_indices.push(i);
        }
    }
    Ok(ScriptGroups {
        lock_groups,
        type_groups,
    })
}

/// Build unlocked transaction that ready to send or for further unlock.
///
/// Return value:
///   * The built transaction
///   * The script groups that not unlocked
pub fn unlock_tx(
    balanced_tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
) -> Result<(TransactionView, Vec<ScriptGroup>), UnlockError> {
    let ScriptGroups { lock_groups, .. } = gen_script_groups(&balanced_tx, tx_dep_provider)?;
    let mut tx = balanced_tx;
    let mut not_unlocked = Vec::new();
    for script_group in lock_groups.values() {
        let script_id = ScriptId::from(&script_group.script);
        let script_args = script_group.script.args().raw_data();
        if let Some(unlocker) = unlockers
            .get(&script_id)
            .filter(|unlocker| unlocker.match_args(script_args.as_ref()))
        {
            tx = unlocker.unlock(&tx, script_group, tx_dep_provider)?;
        } else {
            not_unlocked.push(clone_script_group(script_group));
        }
    }
    Ok((tx, not_unlocked))
}

/// A cell_dep resolver use genesis info resolve system scripts and can register more cell_dep info.
pub struct DefaultCellDepResolver {}
/// A cell collector use ckb-indexer as backend
pub struct DefaultCellCollector {}

struct DefaultTxDepProviderInner {
    rpc_client: HttpRpcClient,
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
        let rpc_client = HttpRpcClient::new(url);
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
    ) -> Result<(CellOutput, Bytes), TxDepProviderError> {
        let mut inner = self.inner.lock();
        if let Some(pair) = inner.cell_cache.get(out_point) {
            return Ok(pair.clone());
        }
        // TODO: handle proposed/pending transactions
        let cell_with_status = inner
            .rpc_client
            .get_live_cell(out_point.clone().into(), true)
            .map_err(|err| TxDepProviderError::Other(err.into()))?;
        if cell_with_status.status != "live" {
            return Err(TxDepProviderError::Other(
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
    fn get_consensus(&self) -> Result<Consensus, TxDepProviderError> {
        let mut inner = self.inner.lock();
        if let Some(consensus) = inner.consensus.as_ref() {
            return Ok(consensus.clone());
        }
        let consensus = inner
            .rpc_client
            .get_consensus()
            .map(to_consensus_struct)
            .map_err(|err| TxDepProviderError::Other(err.into()))?;
        inner.consensus = Some(consensus.clone());
        Ok(consensus)
    }
    fn get_transaction(&self, tx_hash: &Byte32) -> Result<TransactionView, TxDepProviderError> {
        let mut inner = self.inner.lock();
        if let Some(tx) = inner.tx_cache.get(tx_hash) {
            return Ok(tx.clone());
        }
        // TODO: handle proposed/pending transactions
        let tx_with_status = inner
            .rpc_client
            .get_transaction(tx_hash.unpack())
            .map_err(|err| TxDepProviderError::Other(err.into()))?
            .ok_or_else(|| TxDepProviderError::NotFound("transaction".to_string()))?;
        if tx_with_status.tx_status.status != json_types::Status::Committed {
            return Err(TxDepProviderError::Other(
                format!("invalid transaction status: {:?}", tx_with_status.tx_status).into(),
            ));
        }
        let tx = Transaction::from(tx_with_status.transaction.unwrap().inner).into_view();
        inner.tx_cache.put(tx_hash.clone(), tx.clone());
        Ok(tx)
    }
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TxDepProviderError> {
        self.get_cell_with_data(out_point).map(|(output, _)| output)
    }
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TxDepProviderError> {
        self.get_cell_with_data(out_point)
            .map(|(_, output_data)| output_data)
    }
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TxDepProviderError> {
        let mut inner = self.inner.lock();
        if let Some(header) = inner.header_cache.get(block_hash) {
            return Ok(header.clone());
        }
        let header = inner
            .rpc_client
            .get_header(block_hash.unpack())
            .map_err(|err| TxDepProviderError::Other(err.into()))?
            .map(HeaderView::from)
            .ok_or_else(|| TxDepProviderError::NotFound("header".to_string()))?;
        inner.header_cache.put(block_hash.clone(), header.clone());
        Ok(header)
    }
}
