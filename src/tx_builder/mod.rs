mod dao;
mod udt;

use ckb_dao::DaoCalculator;
use ckb_dao_utils::DaoError;
use ckb_types::{
    core::{
        cell::{resolve_transaction_with_options, ResolveOptions},
        error::OutPointError,
        FeeRate, TransactionView,
    },
    packed::Script,
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

// pub trait CellCollector {
//     fn get_live_cell_by_lock(
//         &mut self,
//         lock_script: &Script,
//     ) -> Result<Vec<Cell>, CellCollectorError>;
//     fn get_live_cell_by_type(
//         &mut self,
//         type_script: &Script,
//     ) -> Result<Vec<Cell>, CellCollectorError>;
// }

#[derive(Error, Debug)]
pub enum TransactionFeeError {
    #[error("capacity not enough for change cell")]
    CapacityNotEnoughForChangeCell,
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TxDepProviderError),
    #[error("out point error: `{0}`")]
    OutPoint(#[from] OutPointError),
    #[error("dao error: `{0}`")]
    Dao(#[from] DaoError),
    #[error("unexpected dao cell in inputs")]
    UnexpectedDaoInput,
    #[error("capacity sub overflow")]
    CapacitySubOverflow,
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
    let mut input_total_capacity: u64 = 0;
    for previous_output in tx.input_pts_iter() {
        let cell = tx_dep_provider.get_cell(&previous_output)?;
        let capacity: u64 = cell.capacity().unpack();
        input_total_capacity += capacity;
        if let Some(type_script) = cell.type_().to_opt() {
            if type_script.code_hash().as_slice() == DAO_TYPE_HASH.as_bytes() {
                return Err(TransactionFeeError::UnexpectedDaoInput);
            }
        }
    }
    let output_total_capacity: u64 = tx.outputs_capacity().expect("capacity overflow").as_u64();
    input_total_capacity
        .checked_sub(output_total_capacity)
        .ok_or(TransactionFeeError::CapacitySubOverflow)
}

// pub fn adjust_tx_fee(
//     cell_collector: &mut dyn CellCollector,
//     tx: &TransactionView,
//     fee_rate: FeeRate,
//     force_small_change_as_fee: bool,
// ) -> Result<TransactionView, TransactionFeeError> {
//     let mut change_capacity = actual_capacity - need_more_capacity;
//     let mut estimate_fee = estimate_tx_fee(tx, fee_rate);
//     let mut has_change_cell = false;
//     // Adjust change cell capacity
//     if change_capacity < min_change_capacity(capacity_provider) {
//         let one_more_input = cell_collector
//             .get_live_cell_by_lock(capacity_provider)
//             .take(1)
//             .collect();
//         if one_more_input.is_empty() {
//             if !force_small_change_as_fee {
//                 return Err(CapacityNotEnoughForChangeCell);
//             }
//         } else {
//             inputs += one_more_input;
//             change_capacity += one_more_input.capacity;
//             has_change_cell = true;
//         }
//     } else {
//         has_change_cell = true;
//     }
//     if has_change_cell {
//         let change_output = build_change_output(change_capacity, capacity_provider);
//         outputs.push(change_output);
//         outputs_data.push(Default::default());
//     }
//     tx
// }
