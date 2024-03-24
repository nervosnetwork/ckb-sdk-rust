pub mod acp;
pub mod cheque;
pub mod dao;
pub mod omni_lock;
pub mod transfer;
pub mod udt;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::anyhow;
use ckb_chain_spec::consensus::Consensus;
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::core::cell::{CellProvider, HeaderChecker};
use ckb_types::core::HeaderView;
use ckb_types::{
    core::{
        cell::resolve_transaction, error::OutPointError, Capacity, CapacityError, FeeRate,
        TransactionView,
    },
    packed::{Byte32, CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
};
use thiserror::Error;

use crate::types::ScriptGroup;
use crate::types::{HumanCapacity, ScriptId};
use crate::unlock::{ScriptUnlocker, UnlockError};
use crate::util::calculate_dao_maximum_withdraw4;
use crate::{constants::DAO_TYPE_HASH, NetworkType};
use crate::{
    traits::{
        CellCollector, CellCollectorError, CellDepResolver, CellQueryOptions, HeaderDepResolver,
        TransactionDependencyError, TransactionDependencyProvider, ValueRangeOption,
    },
    RpcError,
};

/// Transaction builder errors
#[derive(Error, Debug)]
pub enum TxBuilderError {
    #[error("invalid parameter: `{0}`")]
    InvalidParameter(anyhow::Error),

    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),
    #[error("ChangeIndex alread set: `{0}`")]
    ChangeIndex(usize),

    #[error("cell collector error: `{0}`")]
    CellCollector(#[from] CellCollectorError),

    #[error("balance capacity error: `{0}`")]
    BalanceCapacity(#[from] BalanceTxCapacityError),

    #[error("resolve cell dep failed: `{0}`")]
    ResolveCellDepFailed(Script),

    #[error("resolve header dep by transaction hash failed: `{0}`")]
    ResolveHeaderDepByTxHashFailed(Byte32),

    #[error("resolve header dep by block number failed: `{0}`")]
    ResolveHeaderDepByNumberFailed(u64),

    #[error("unlock error: `{0}`")]
    Unlock(#[from] UnlockError),

    #[error("build_balance_unlocked exceed max loop times, current is: `{0}`")]
    ExceedCycleMaxLoopTimes(u32),
    #[error("witness idx `{0}` is out of bound `{1}")]
    WitnessOutOfBound(usize, usize),
    #[error("unsupported networktype `{0}")]
    UnsupportedNetworkType(NetworkType),
    #[error("can not find specifed output to put small change")]
    NoOutputForSmallChange,

    #[error("other error: `{0}`")]
    Other(anyhow::Error),
}

/// Transaction Builder interface
pub trait TxBuilder {
    /// Build base transaction
    fn build_base(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError>;

    /// Build balanced transaction that ready to sign:
    ///  * Build base transaction
    ///  * Fill placeholder witness for lock script
    ///  * balance the capacity
    fn build_balanced(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        balancer: &CapacityBalancer,
        unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
    ) -> Result<TransactionView, TxBuilderError> {
        let base_tx = self.build_base(
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
        )?;
        let (tx_filled_witnesses, _) =
            fill_placeholder_witnesses(base_tx, tx_dep_provider, unlockers)?;
        Ok(balance_tx_capacity(
            &tx_filled_witnesses,
            balancer,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
            header_dep_resolver,
        )?)
    }

    /// Build unlocked transaction that ready to send or for further unlock:
    ///   * build base transaction
    ///   * balance the capacity
    ///   * unlock(sign) the transaction
    ///
    /// Return value:
    ///   * The built transaction
    ///   * The script groups that not unlocked by given `unlockers`
    fn build_unlocked(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        balancer: &CapacityBalancer,
        unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let balanced_tx = self.build_balanced(
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
            balancer,
            unlockers,
        )?;
        Ok(unlock_tx(balanced_tx, tx_dep_provider, unlockers)?)
    }

    /// Build unlocked transaction that ready to send or for further unlock, it's similar to `build_unlocked`,
    /// except it will try to check the consumed cycles limitation:
    /// If all input unlocked, and transaction fee can not meet the required transaction fee rate because of a big estimated cycles,
    /// it will tweak the change cell capacity or collect more cells to balance the transaction.
    ///
    /// Return value:
    ///   * The built transaction
    ///   * The script groups that not unlocked by given `unlockers`
    fn build_balance_unlocked(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &'static dyn TransactionDependencyProvider,
        balancer: &CapacityBalancer,
        unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let base_tx = self.build_base(
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
        )?;
        let (tx_filled_witnesses, _) =
            fill_placeholder_witnesses(base_tx, tx_dep_provider, unlockers)?;
        let (balanced_tx, mut change_idx) = rebalance_tx_capacity(
            &tx_filled_witnesses,
            balancer,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
            header_dep_resolver,
            0,
            None,
        )?;
        let (mut tx, unlocked_group) = unlock_tx(balanced_tx, tx_dep_provider, unlockers)?;
        if unlocked_group.is_empty() {
            let mut ready = false;
            const MAX_LOOP_TIMES: u32 = 16;
            let mut n = 0;
            while !ready && n < MAX_LOOP_TIMES {
                n += 1;

                let (new_tx, new_change_idx, ok) = balancer.check_cycle_fee(
                    tx,
                    cell_collector,
                    tx_dep_provider,
                    cell_dep_resolver,
                    header_dep_resolver,
                    change_idx,
                )?;
                tx = new_tx;
                ready = ok;
                change_idx = new_change_idx;
                if !ready {
                    let (new_tx, _) = unlock_tx(tx, tx_dep_provider, unlockers)?;
                    tx = new_tx
                }
            }
            if !ready && n >= MAX_LOOP_TIMES {
                return Err(TxBuilderError::ExceedCycleMaxLoopTimes(n));
            }
        }
        Ok((tx, unlocked_group))
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
    TxDep(#[from] TransactionDependencyError),

    #[error("header dependency provider error: `{0}`")]
    HeaderDep(#[from] anyhow::Error),

    #[error("out point error: `{0}`")]
    OutPoint(#[from] OutPointError),

    #[error("unexpected dao withdraw cell in inputs")]
    UnexpectedDaoWithdrawInput,

    #[error("capacity error: `{0}`")]
    CapacityError(#[from] CapacityError),

    #[error("capacity sub overflow, delta: `{0}`")]
    CapacityOverflow(u64),
}

/// Calculate the actual transaction fee of the transaction, include dao
/// withdraw capacity.
#[allow(clippy::unnecessary_lazy_evaluations)]
pub fn tx_fee(
    tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    header_dep_resolver: &dyn HeaderDepResolver,
) -> Result<u64, TransactionFeeError> {
    let mut input_total: u64 = 0;
    for input in tx.inputs() {
        let mut is_withdraw = false;
        let since: u64 = input.since().unpack();
        let cell = tx_dep_provider.get_cell(&input.previous_output())?;
        if since != 0 {
            if let Some(type_script) = cell.type_().to_opt() {
                if type_script.code_hash().as_slice() == DAO_TYPE_HASH.as_bytes() {
                    is_withdraw = true;
                }
            }
        }
        let capacity: u64 = if is_withdraw {
            let tx_hash = input.previous_output().tx_hash();
            let prepare_header = header_dep_resolver
                .resolve_by_tx(&tx_hash)
                .map_err(TransactionFeeError::HeaderDep)?
                .ok_or_else(|| {
                    TransactionFeeError::HeaderDep(anyhow!(
                        "resolve prepare header by transaction hash failed: {}",
                        tx_hash
                    ))
                })?;
            let data = tx_dep_provider.get_cell_data(&input.previous_output())?;
            assert_eq!(data.len(), 8);
            let deposit_number = {
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(data.as_ref());
                u64::from_le_bytes(number_bytes)
            };
            let deposit_header = header_dep_resolver
                .resolve_by_number(deposit_number)
                .map_err(TransactionFeeError::HeaderDep)?
                .ok_or_else(|| {
                    TransactionFeeError::HeaderDep(anyhow!(
                        "resolve deposit header by block number failed: {}",
                        deposit_number
                    ))
                })?;
            let occupied_capacity = cell
                .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                .unwrap();
            calculate_dao_maximum_withdraw4(
                &deposit_header,
                &prepare_header,
                &cell,
                occupied_capacity.as_u64(),
            )
        } else {
            cell.capacity().unpack()
        };
        input_total += capacity;
    }
    let output_total = tx.outputs_capacity()?.as_u64();
    #[allow(clippy::unnecessary_lazy_evaluations)]
    input_total
        .checked_sub(output_total)
        .ok_or_else(|| TransactionFeeError::CapacityOverflow(output_total - input_total))
}

#[derive(Debug, Clone)]
pub enum SinceSource {
    /// The vaule in the tuple is offset of the args, and the `since` is stored in `lock.args[offset..offset+8]`
    LockArgs(usize),
    /// raw since value
    Value(u64),
}

impl Default for SinceSource {
    fn default() -> SinceSource {
        SinceSource::Value(0)
    }
}

/// Provide capacity locked by a list of lock scripts.
///
/// The cells collected by `lock_script` will filter out those have type script
/// or data length is not `0` or is not mature.
#[derive(Debug, Clone)]
pub struct CapacityProvider {
    /// The lock scripts provider capacity. The second field of the tuple is the
    /// placeholder witness of the lock script.
    pub lock_scripts: Vec<(Script, WitnessArgs, SinceSource)>,
}

impl CapacityProvider {
    /// create a new capacity provider.
    pub fn new(lock_scripts: Vec<(Script, WitnessArgs, SinceSource)>) -> CapacityProvider {
        CapacityProvider { lock_scripts }
    }

    /// create a new capacity provider with the default since source.
    pub fn new_simple(lock_scripts: Vec<(Script, WitnessArgs)>) -> CapacityProvider {
        let lock_scripts = lock_scripts
            .into_iter()
            .map(|(script, witness)| (script, witness, SinceSource::default()))
            .collect();
        CapacityProvider { lock_scripts }
    }
}

#[derive(Error, Debug)]
pub enum BalanceTxCapacityError {
    #[error("calculate transaction fee error: `{0}`")]
    TxFee(#[from] TransactionFeeError),

    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),

    #[error("capacity not enough: `{0}`")]
    CapacityNotEnough(String),

    #[error("Force small change as fee failed, fee: `{0}`")]
    ForceSmallChangeAsFeeFailed(u64),

    #[error("empty capacity provider")]
    EmptyCapacityProvider,

    #[error("cell collector error: `{0}`")]
    CellCollector(#[from] CellCollectorError),

    #[error("resolve cell dep failed: `{0}`")]
    ResolveCellDepFailed(Script),

    #[error("invalid witness args: `{0}`")]
    InvalidWitnessArgs(anyhow::Error),

    #[error("Fail to parse since value from args, offset: `{0}`, args length: `{1}`")]
    InvalidSinceValue(usize, usize),

    #[error("change index not found at given index: `{0}`")]
    ChangeIndexNotFound(usize),

    #[error("Fail to estimate_cycles: `{0}`")]
    FailEstimateCycles(#[from] RpcError),

    #[error("verify script error: {0}")]
    VerifyScript(String),

    #[error("should not try to rebalance, orignal fee {0}, required fee: {1},")]
    AlreadyBalance(u64, u64),
}

/// Transaction capacity balancer config.
///
/// CapacityBalancer will try to balance the transaction capacity by adding inputs from CapacityProvider.
#[derive(Debug, Clone)]
pub struct CapacityBalancer {
    pub fee_rate: FeeRate,

    /// Search cell by this lock script and filter out cells with data or with
    /// type script or not mature.
    pub capacity_provider: CapacityProvider,

    /// Change cell's lock script if `None` use capacity_provider's first lock script
    pub change_lock_script: Option<Script>,

    /// When there is no more inputs for create a change cell to balance the
    /// transaction capacity, force the addition capacity as fee, the value is
    /// actual maximum transaction fee.
    pub force_small_change_as_fee: Option<u64>,
}

impl CapacityBalancer {
    /// Create a new balancer.
    ///
    /// # Arguments
    ///
    /// * `capacity_provider` - Use live cells with this lock script as capacity provider.
    /// * `placeholder_witness` - The witness used as a placeholder when adding new inputs.
    ///     This placeholder ensures that the transaction size does not increase after signing,
    ///     thus maintaining the validity of fee calculation.
    /// * `fee_rate` - The fee rate used to calculate the transaction fee.
    pub fn new_simple(
        capacity_provider: Script,
        placeholder_witness: WitnessArgs,
        fee_rate: u64,
    ) -> CapacityBalancer {
        CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            capacity_provider: CapacityProvider::new_simple(vec![(
                capacity_provider,
                placeholder_witness,
            )]),
            change_lock_script: None,
            force_small_change_as_fee: None,
        }
    }

    /// Create new simple capacity balancer with since source.
    pub fn new_simple_with_since(
        capacity_provider: Script,
        placeholder_witness: WitnessArgs,
        since_source: SinceSource,
        fee_rate: u64,
    ) -> CapacityBalancer {
        CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            capacity_provider: CapacityProvider::new(vec![(
                capacity_provider,
                placeholder_witness,
                since_source,
            )]),
            change_lock_script: None,
            force_small_change_as_fee: None,
        }
    }

    pub fn new_with_provider(fee_rate: u64, capacity_provider: CapacityProvider) -> Self {
        CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            capacity_provider,
            change_lock_script: None,
            force_small_change_as_fee: None,
        }
    }

    /// Set or clear the force_small_change_as_fee
    pub fn set_max_fee(&mut self, max_fee: Option<u64>) {
        self.force_small_change_as_fee = max_fee;
    }

    pub fn balance_tx_capacity(
        &mut self,
        tx: &TransactionView,
        cell_collector: &mut dyn CellCollector,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
    ) -> Result<TransactionView, BalanceTxCapacityError> {
        balance_tx_capacity(
            tx,
            self,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
            header_dep_resolver,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rebalance_tx_capacity(
        &self,
        tx: &TransactionView,
        cell_collector: &mut dyn CellCollector,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        accepted_min_fee: u64,
        change_index: Option<usize>,
    ) -> Result<(TransactionView, Option<usize>), BalanceTxCapacityError> {
        if let Some(idx) = change_index {
            let output = tx
                .outputs()
                .get(idx)
                .ok_or(BalanceTxCapacityError::ChangeIndexNotFound(idx))?;
            let base_change_occupied_capacity = output
                .occupied_capacity(Capacity::zero())
                .expect("init change occupied capacity")
                .as_u64();
            let output_header_extra = 4 + 4 + 4;
            // NOTE: extra_min_fee +1 is for `FeeRate::fee` round
            let extra_min_fee = self
                .fee_rate
                .fee(output.as_slice().len() as u64 + output_header_extra)
                .as_u64()
                + 1;
            let original_fee = tx_fee(tx.clone(), tx_dep_provider, header_dep_resolver)?;
            if original_fee >= accepted_min_fee {
                return Err(BalanceTxCapacityError::AlreadyBalance(
                    original_fee,
                    accepted_min_fee,
                ));
            }
            let extra_fee = accepted_min_fee - original_fee;
            // The extra capacity (delta - extra_min_fee) is enough to hold the change cell.
            let original_capacity: u64 = output.capacity().unpack();
            if original_capacity >= base_change_occupied_capacity + extra_min_fee + extra_fee {
                let output = output
                    .as_builder()
                    .capacity((original_capacity - extra_fee).pack())
                    .build();
                let mut outputs: Vec<_> = tx.outputs().into_iter().collect();
                outputs[idx] = output;
                let tx = tx.as_advanced_builder().set_outputs(outputs).build();
                return Ok((tx, change_index));
            };
        }

        rebalance_tx_capacity(
            tx,
            self,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
            header_dep_resolver,
            accepted_min_fee,
            change_index,
        )
    }

    pub fn check_cycle_fee(
        &self,
        tx: TransactionView,
        cell_collector: &mut dyn CellCollector,
        tx_dep_provider: &'static dyn TransactionDependencyProvider,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        change_index: Option<usize>,
    ) -> Result<(TransactionView, Option<usize>, bool), BalanceTxCapacityError> {
        let cycle_resolver = CycleResolver::new(tx_dep_provider);
        let cycle = cycle_resolver.estimate_cycles(&tx)?;
        let cycle_size = (cycle as f64 * bytes_per_cycle()) as usize;
        let serialized_size = tx.data().as_reader().serialized_size_in_block();
        if serialized_size >= cycle_size {
            return Ok((tx, None, true));
        }
        let fee = tx_fee(tx.clone(), tx_dep_provider, header_dep_resolver).unwrap();
        let cycle_fee = self.fee_rate.fee(cycle_size as u64).as_u64();

        if fee >= cycle_fee {
            return Ok((tx, None, true));
        }

        let (tx, idx) = self.rebalance_tx_capacity(
            &tx,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
            header_dep_resolver,
            cycle_fee,
            change_index,
        )?;
        Ok((tx, idx, false))
    }
}

const DEFAULT_BYTES_PER_CYCLE: f64 = 0.000_170_571_4;
pub const fn bytes_per_cycle() -> f64 {
    DEFAULT_BYTES_PER_CYCLE
}

pub struct CycleResolver<DL> {
    tx_dep_provider: DL,
    tip_header: HeaderView,
    consensus: Arc<Consensus>,
}

impl<
        DL: CellDataProvider
            + HeaderProvider
            + ExtensionProvider
            + CellProvider
            + HeaderChecker
            + Send
            + Sync
            + Clone
            + 'static,
    > CycleResolver<DL>
{
    pub fn new(tx_dep_provider: DL) -> Self {
        CycleResolver {
            tx_dep_provider,
            tip_header: HeaderView::new_advanced_builder().build(), // TODO
            consensus: Default::default(),                          // TODO
        }
    }

    fn estimate_cycles(&self, tx: &TransactionView) -> Result<u64, BalanceTxCapacityError> {
        let rtx = resolve_transaction(
            tx.clone(),
            &mut HashSet::new(),
            &self.tx_dep_provider,
            &self.tx_dep_provider,
        )
        .map_err(|err| {
            BalanceTxCapacityError::VerifyScript(format!("Resolve transaction error: {:?}", err))
        })?;

        let mut verifier = TransactionScriptsVerifier::new(
            Arc::new(rtx),
            self.tx_dep_provider.clone(),
            Arc::clone(&self.consensus),
            Arc::new(TxVerifyEnv::new_submit(&self.tip_header)),
        );
        verifier.set_debug_printer(|script_hash, message| {
            println!("script: {:x}, debug: {}", script_hash, message);
        });
        verifier.verify(u64::max_value()).map_err(|err| {
            BalanceTxCapacityError::VerifyScript(format!("Verify script error : {:?}", err))
        })
    }
}

/// Fill more inputs to balance the transaction capacity
pub fn balance_tx_capacity(
    tx: &TransactionView,
    balancer: &CapacityBalancer,
    cell_collector: &mut dyn CellCollector,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    cell_dep_resolver: &dyn CellDepResolver,
    header_dep_resolver: &dyn HeaderDepResolver,
) -> Result<TransactionView, BalanceTxCapacityError> {
    let (tx, _change_idx) = rebalance_tx_capacity(
        tx,
        balancer,
        cell_collector,
        tx_dep_provider,
        cell_dep_resolver,
        header_dep_resolver,
        0,
        None,
    )?;
    Ok(tx)
}

#[allow(clippy::too_many_arguments)]
fn rebalance_tx_capacity(
    tx: &TransactionView,
    balancer: &CapacityBalancer,
    cell_collector: &mut dyn CellCollector,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    cell_dep_resolver: &dyn CellDepResolver,
    header_dep_resolver: &dyn HeaderDepResolver,
    accepted_min_fee: u64,
    change_index: Option<usize>,
) -> Result<(TransactionView, Option<usize>), BalanceTxCapacityError> {
    let capacity_provider = &balancer.capacity_provider;
    if capacity_provider.lock_scripts.is_empty() {
        return Err(BalanceTxCapacityError::EmptyCapacityProvider);
    }
    let change_lock_script = balancer
        .change_lock_script
        .clone()
        .unwrap_or_else(|| capacity_provider.lock_scripts[0].0.clone());
    let (tx, base_change_output, base_change_occupied_capacity) = if let Some(idx) = change_index {
        let outputs = tx.outputs();
        let output = tx
            .outputs()
            .get(idx)
            .ok_or(BalanceTxCapacityError::ChangeIndexNotFound(idx))?;

        // remove change output
        let outputs: Vec<_> = outputs
            .into_iter()
            .enumerate()
            .filter_map(|(i, output)| if idx == i { None } else { Some(output) })
            .collect();
        let base_change_occupied_capacity = output
            .occupied_capacity(Capacity::zero())
            .expect("init change occupied capacity")
            .as_u64();
        let tx = tx.data().as_advanced_builder().set_outputs(outputs).build();
        (tx, output, base_change_occupied_capacity)
    } else {
        let base_change_output = CellOutput::new_builder().lock(change_lock_script).build();
        let base_change_occupied_capacity = base_change_output
            .occupied_capacity(Capacity::zero())
            .expect("init change occupied capacity")
            .as_u64();
        (
            tx.clone(),
            base_change_output,
            base_change_occupied_capacity,
        )
    };

    let mut lock_scripts = Vec::new();
    // remove duplicated lock script
    for (script, placeholder, since_source) in &capacity_provider.lock_scripts {
        if lock_scripts.iter().all(|(target, _, _)| target != script) {
            lock_scripts.push((script.clone(), placeholder.clone(), since_source.clone()));
        }
    }
    let mut lock_script_idx = 0;
    let mut cell_deps = Vec::new();
    #[allow(clippy::mutable_key_type)]
    let mut resolved_scripts = HashSet::new();
    let mut inputs = Vec::new();
    let mut change_output: Option<CellOutput> = if change_index.is_some() {
        Some(base_change_output.clone())
    } else {
        None
    };
    let mut changed_witnesses: HashMap<usize, WitnessArgs> = HashMap::default();
    let mut witnesses = Vec::new();
    loop {
        let (lock_script, placeholder_witness, since_source) = &lock_scripts[lock_script_idx];
        let base_query = {
            let mut query = CellQueryOptions::new_lock(lock_script.clone());
            query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
            query.data_len_range = Some(ValueRangeOption::new_exact(0));
            query
        };
        // check if capacity provider lock script already in inputs
        let mut has_provider = false;
        for input in tx.inputs().into_iter().chain(inputs.clone().into_iter()) {
            let cell = tx_dep_provider.get_cell(&input.previous_output())?;
            if cell.lock() == *lock_script {
                has_provider = true;
            }
        }
        while tx.witnesses().item_count() + witnesses.len()
            < tx.inputs().item_count() + inputs.len()
        {
            witnesses.push(Default::default());
        }
        let mut ret_change_index = None;
        let new_tx = {
            let mut all_witnesses = tx.witnesses().into_iter().collect::<Vec<_>>();
            for (idx, witness_args) in &changed_witnesses {
                all_witnesses[*idx] = witness_args.as_bytes().pack();
            }
            all_witnesses.extend(witnesses.clone());
            let output_len = tx.outputs().len();
            let mut builder = tx
                .data()
                .as_advanced_builder()
                .cell_deps(cell_deps.clone())
                .inputs(inputs.clone())
                .set_witnesses(all_witnesses);
            if let Some(output) = change_output.clone() {
                ret_change_index = Some(output_len);
                builder = builder.output(output).output_data(Default::default());
            }
            builder.build()
        };
        let tx_size = new_tx.data().as_reader().serialized_size_in_block();
        let min_fee = accepted_min_fee.max(balancer.fee_rate.fee(tx_size as u64).as_u64());
        let mut need_more_capacity = 1;
        let fee_result: Result<u64, TransactionFeeError> =
            tx_fee(new_tx.clone(), tx_dep_provider, header_dep_resolver);
        match fee_result {
            Ok(fee) if fee == min_fee => {
                return Ok((new_tx, ret_change_index));
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

                    // The output extra header size is for:
                    //   * first 4 bytes is for output data header (the length)
                    //   * second 4 bytes if for output data offset
                    //   * third 4 bytes is for output offset
                    let output_header_extra = 4 + 4 + 4;
                    // NOTE: extra_min_fee +1 is for `FeeRate::fee` round
                    let extra_min_fee = balancer
                        .fee_rate
                        .fee(base_change_output.as_slice().len() as u64 + output_header_extra)
                        .as_u64()
                        + 1;
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
                                    return Ok((new_tx, ret_change_index));
                                }
                            } else if lock_script_idx + 1 == lock_scripts.len() {
                                return Err(BalanceTxCapacityError::CapacityNotEnough(format!(
                                    "can not create change cell, left capacity={}",
                                    HumanCapacity(delta)
                                )));
                            } else {
                                lock_script_idx += 1;
                                continue;
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
            Ok(fee) => {
                need_more_capacity = min_fee - fee;
            }
            Err(TransactionFeeError::CapacityOverflow(delta)) => {
                need_more_capacity = delta + min_fee;
            }
            Err(err) => {
                return Err(err.into());
            }
        }
        if need_more_capacity > 0 {
            let query = {
                let mut query = base_query.clone();
                query.min_total_capacity = need_more_capacity;
                query
            };
            let (more_cells, _more_capacity) = cell_collector.collect_live_cells(&query, true)?;
            if more_cells.is_empty() {
                if lock_script_idx + 1 == lock_scripts.len() {
                    return Err(BalanceTxCapacityError::CapacityNotEnough(format!(
                        "need more capacity, value={}",
                        HumanCapacity(need_more_capacity)
                    )));
                } else {
                    lock_script_idx += 1;
                    continue;
                }
            }
            if !resolved_scripts.contains(lock_script) {
                let provider_cell_dep =
                    cell_dep_resolver.resolve(lock_script).ok_or_else(|| {
                        BalanceTxCapacityError::ResolveCellDepFailed(lock_script.clone())
                    })?;
                if tx
                    .cell_deps()
                    .into_iter()
                    .all(|cell_dep| cell_dep != provider_cell_dep)
                {
                    cell_deps.push(provider_cell_dep);
                    resolved_scripts.insert(lock_script);
                }
            }
            if !has_provider {
                if tx.witnesses().item_count() > tx.inputs().item_count() + inputs.len() {
                    let idx = tx.inputs().item_count() + inputs.len();
                    let witness_data = tx.witnesses().get(idx).expect("get witness").raw_data();
                    // in case witness filled before balance tx
                    let mut witness = if witness_data.is_empty() {
                        WitnessArgs::default()
                    } else {
                        WitnessArgs::from_slice(witness_data.as_ref())
                            .map_err(|err| BalanceTxCapacityError::InvalidWitnessArgs(err.into()))?
                    };
                    if let Some(data) = placeholder_witness.input_type().to_opt() {
                        witness = witness
                            .as_builder()
                            .input_type(Some(data.raw_data()).pack())
                            .build();
                    }
                    if let Some(data) = placeholder_witness.output_type().to_opt() {
                        witness = witness
                            .as_builder()
                            .output_type(Some(data.raw_data()).pack())
                            .build();
                    }
                    if let Some(data) = placeholder_witness.lock().to_opt() {
                        witness = witness
                            .as_builder()
                            .lock(Some(data.raw_data()).pack())
                            .build();
                    }
                    changed_witnesses.insert(idx, witness);
                } else {
                    witnesses.push(placeholder_witness.as_bytes().pack());
                }
            }
            let since = match since_source {
                SinceSource::LockArgs(offset) => {
                    let lock_arg = lock_script.args().raw_data();
                    if lock_arg.len() < offset + 8 {
                        return Err(BalanceTxCapacityError::InvalidSinceValue(
                            *offset,
                            lock_arg.len(),
                        ));
                    }
                    let mut since_bytes = [0u8; 8];
                    since_bytes.copy_from_slice(&lock_arg[*offset..*offset + 8]);
                    u64::from_le_bytes(since_bytes)
                }
                SinceSource::Value(since_value) => *since_value,
            };
            inputs.extend(
                more_cells
                    .into_iter()
                    .map(|cell| CellInput::new(cell.out_point, since)),
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
) -> Result<ScriptGroups, TransactionDependencyError> {
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
    for (i, output) in tx.outputs().into_iter().enumerate() {
        if let Some(t) = &output.type_().to_opt() {
            let type_group_entry = type_groups
                .entry(t.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(t));
            type_group_entry.output_indices.push(i);
        }
    }
    Ok(ScriptGroups {
        lock_groups,
        type_groups,
    })
}

/// Fill placeholder lock script witnesses
///
/// Return value:
///   * The updated transaction
///   * The script groups that not matched by given `unlockers`
pub fn fill_placeholder_witnesses(
    balanced_tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
) -> Result<(TransactionView, Vec<ScriptGroup>), UnlockError> {
    let ScriptGroups { lock_groups, .. } = gen_script_groups(&balanced_tx, tx_dep_provider)?;
    let mut tx = balanced_tx;
    let mut not_matched = Vec::new();
    for script_group in lock_groups.values() {
        let script_id = ScriptId::from(&script_group.script);
        let script_args = script_group.script.args().raw_data();
        if let Some(unlocker) = unlockers.get(&script_id) {
            if !unlocker.is_unlocked(&tx, script_group, tx_dep_provider)? {
                if unlocker.match_args(script_args.as_ref()) {
                    tx = unlocker.fill_placeholder_witness(&tx, script_group, tx_dep_provider)?;
                } else {
                    not_matched.push(script_group.clone());
                }
            }
        } else {
            not_matched.push(script_group.clone());
        }
    }
    Ok((tx, not_matched))
}

/// Build unlocked transaction that ready to send or for further unlock.
///
/// Return value:
///   * The built transaction
///   * The script groups that not unlocked by given `unlockers`
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
        if let Some(unlocker) = unlockers.get(&script_id) {
            if unlocker.is_unlocked(&tx, script_group, tx_dep_provider)? {
                tx = unlocker.clear_placeholder_witness(&tx, script_group)?;
            } else if unlocker.match_args(script_args.as_ref()) {
                tx = unlocker.unlock(&tx, script_group, tx_dep_provider)?;
            } else {
                not_unlocked.push(script_group.clone());
            }
        } else {
            not_unlocked.push(script_group.clone());
        }
    }
    Ok((tx, not_unlocked))
}

#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_signer_error() {
        use super::TxBuilderError;
        let error = TxBuilderError::ResolveHeaderDepByNumberFailed(0);
        let error = anyhow!(error);
        assert_eq!(
            "resolve header dep by block number failed: `0`",
            error.to_string()
        );
    }

    #[test]
    fn test_transaction_fee_error() {
        let error = super::TransactionFeeError::CapacityOverflow(0);
        let error = anyhow!(error);
        assert_eq!("capacity sub overflow, delta: `0`", error.to_string());
    }

    #[test]
    fn test_balance_tx_capacity_error() {
        let eror = super::BalanceTxCapacityError::EmptyCapacityProvider;
        let error = anyhow!(eror);
        assert_eq!("empty capacity provider", error.to_string())
    }
}
