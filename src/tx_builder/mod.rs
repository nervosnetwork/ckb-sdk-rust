mod dao;
mod udt;

use ckb_dao::DaoCalculator;
use ckb_dao_utils::DaoError;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{resolve_transaction_with_options, ResolveOptions},
        error::OutPointError,
        Capacity, FeeRate, TransactionView,
    },
    packed::{CellInput, CellOutput, OutPoint, Script, Transaction, WitnessArgs},
    prelude::*,
};
use std::collections::HashSet;
use thiserror::Error;

use crate::constants::DAO_TYPE_HASH;
use crate::traits::{TransactionDependencyProvider, TxDepProviderError};

/// Transaction builder errors
#[derive(Error, Debug)]
pub enum TransactionBuilderError {
    #[error("invalid parameter: `{0}`")]
    InvalidParameter(Box<dyn std::error::Error>),
    #[error("other error: `{0}`")]
    Other(Box<dyn std::error::Error>),
}

/// Transaction Builder interface
pub trait TransactionBuilder {
    fn build(&self) -> Result<TransactionView, TransactionBuilderError>;
}

/// Cell collector errors
#[derive(Error, Debug)]
pub enum CellCollectorError {
    #[error("internal error: `{0}`")]
    Internal(Box<dyn std::error::Error>),
    #[error("other error: `{0}`")]
    Other(Box<dyn std::error::Error>),
}

// FIXME: live cell struct
pub struct LiveCell {
    pub output: CellOutput,
    pub output_data: Bytes,
    pub out_point: OutPoint,
    pub block_number: u64,
    pub tx_index: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum DataBytesOption {
    Eq(usize),
    Gt(usize),
    Lt(usize),
    Ge(usize),
    Le(usize),
}
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum MaturityOption {
    Mature,
    Immature,
    Both,
}
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CellQueryOptions {
    // primary search key is lock script,
    lock_script: Script,
    type_script: Option<Script>,
    data_bytes: DataBytesOption,
    maturity: MaturityOption,
    total_capacity: u64,
}
impl CellQueryOptions {
    pub fn new(lock_script: Script) -> CellQueryOptions {
        CellQueryOptions {
            lock_script,
            type_script: None,
            data_bytes: DataBytesOption::Eq(0),
            maturity: MaturityOption::Mature,
            // 0 means no need capacity
            total_capacity: 1,
        }
    }
    pub fn type_script(&mut self, script: Option<Script>) -> &mut Self {
        self.type_script = script;
        self
    }
    pub fn data_bytes(&mut self, option: DataBytesOption) -> &mut Self {
        self.data_bytes = option;
        self
    }
    pub fn maturity(&mut self, option: MaturityOption) -> &mut Self {
        self.maturity = option;
        self
    }
    pub fn total_capacity(&mut self, value: u64) -> &mut Self {
        self.total_capacity = value;
        self
    }
}
pub trait CellCollector {
    fn collect_live_cells(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError>;

    fn lock_cell(&mut self, out_point: OutPoint) -> Result<(), CellCollectorError>;
    fn apply_tx(&mut self, tx: Transaction) -> Result<(), CellCollectorError>;
}

#[derive(Error, Debug)]
pub enum TransactionFeeError {
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TxDepProviderError),
    #[error("out point error: `{0}`")]
    OutPoint(#[from] OutPointError),
    #[error("dao error: `{0}`")]
    Dao(#[from] DaoError),
    #[error("unexpected dao cell in inputs")]
    UnexpectedDaoInput,
    #[error("capacity overflow, reason: `{0}`")]
    CapacityOverflow(String),
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
    Ok(DaoCalculator::new(&consensus, &tx_dep_provider)
        .transaction_fee(&rtx)?
        .as_u64())
}

/// Calculate the actual transaction fee of the transaction.
///
/// If there is no dao cell in inputs, use this function will require less
/// dependencies. If there is dao cell in inputs it will return
/// `TransactionFeeError::UnexpectedDaoInput`.
pub fn tx_fee_without_dao(
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
                    return Err(TransactionFeeError::UnexpectedDaoInput);
                }
            }
        }
        let capacity: u64 = cell.capacity().unpack();
        input_total += capacity;
    }
    let output_total: u64 = tx.outputs_capacity().expect("capacity overflow").as_u64();
    input_total.checked_sub(output_total).ok_or_else(|| {
        TransactionFeeError::CapacityOverflow(format!(
            "input total capacity({} shannons) less than otuput total capacity({} shannons)",
            input_total, output_total
        ))
    })
}

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
    fee_rate: FeeRate,
    capacity_provider: &CapacityProvider,
    force_small_change_as_fee: Option<u64>,
    cell_collector: &mut dyn CellCollector,
    tx_dep_provider: &dyn TransactionDependencyProvider,
) -> Result<TransactionView, BalanceTxCapacityError> {
    let init_change_output = CellOutput::new_builder()
        .lock(capacity_provider.lock_script.clone())
        .build();
    let init_change_occupied_capacity = init_change_output
        .occupied_capacity(Capacity::zero())
        .expect("init change occupied capacity")
        .as_u64();
    // the query is to collect just one cell
    let query = CellQueryOptions::new(capacity_provider.lock_script.clone());
    // check if capacity provider lock script already in inputs
    let mut has_provider = false;
    for input in tx.inputs() {
        let cell = tx_dep_provider.get_cell(&input.previous_output())?;
        if cell.lock() == capacity_provider.lock_script {
            has_provider = true;
        }
    }

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
                .inputs(inputs.clone())
                .witnesses(witnesses.clone());
            if let Some(output) = change_output.clone() {
                builder = builder.output(output).output_data(Default::default());
            }
            builder.build()
        };
        let tx_size = new_tx.data().as_reader().serialized_size_in_block();
        let min_fee = fee_rate.fee(tx_size).as_u64();
        let mut need_one_more_input = true;
        match tx_fee(new_tx.clone(), tx_dep_provider) {
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
                    need_one_more_input = false;
                } else {
                    // If change cell not exists, add a change cell.
                    let extra_min_fee = fee_rate.fee(init_change_output.as_slice().len()).as_u64();
                    // The extra capacity (delta - extra_min_fee) is enough to hold the change cell.
                    if delta >= init_change_occupied_capacity + extra_min_fee {
                        // next loop round must return new_tx;
                        change_output = Some(
                            init_change_output
                                .clone()
                                .as_builder()
                                .capacity((delta - extra_min_fee).pack())
                                .build(),
                        );
                        need_one_more_input = false;
                    } else {
                        // peek if there is more live cell owned by this capacity provider
                        let (more_cells, _more_capacity) =
                            cell_collector.collect_live_cells(&query, false)?;
                        if more_cells.is_empty() {
                            if let Some(capacity) = force_small_change_as_fee {
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
                                init_change_output
                                    .clone()
                                    .as_builder()
                                    .capacity(init_change_occupied_capacity.pack())
                                    .build(),
                            );
                        }
                    }
                }
            }
            Ok(fee) => {}
            Err(TransactionFeeError::Dao(DaoError::Overflow)) => {}
            Err(err) => {
                return Err(err.into());
            }
        }
        if need_one_more_input {
            let (more_cells, _more_capacity) = cell_collector.collect_live_cells(&query, true)?;
            if more_cells.is_empty() {
                return Err(BalanceTxCapacityError::CapacityNotEnough);
            }
            inputs.extend(
                more_cells
                    .into_iter()
                    .map(|cell| CellInput::new(cell.out_point, 0)),
            );
        }
    }
}
