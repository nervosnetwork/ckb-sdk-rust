use std::collections::HashMap;

use super::{handler::HandlerContexts, input::TransactionInput};
use crate::{
    core::TransactionBuilder,
    traits::CellCollectorError,
    transaction::TransactionBuilderConfiguration,
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    ScriptGroup, TransactionWithScriptGroups,
};
use ckb_types::{
    core::{Capacity, TransactionView},
    packed::{self, Byte32, CellOutput, Script},
    prelude::{Builder, Entity, Pack, Unpack},
};
pub mod fee_calculator;
pub mod simple;
pub mod sudt;

pub use fee_calculator::FeeCalculator;
pub use simple::SimpleTransactionBuilder;

/// CKB transaction builder trait.
pub trait CkbTransactionBuilder {
    fn build(
        self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError>;
}

/// Change output builder trait.
pub trait ChangeBuilder {
    /// Initialize the change output and data, and add it to the transaction builder.
    fn init(&self, tx: &mut TransactionBuilder);

    /// Check if the inputs has enough capacity to build the transaction and pay the fee.
    fn check_balance(&mut self, input: TransactionInput, tx: &mut TransactionBuilder) -> bool;

    /// Finalize the transaction with the change capacity and data.
    fn finalize(&self, tx: TransactionBuilder) -> TransactionView;
}

/// A simple implementation for the change output builder trait.
pub struct DefaultChangeBuilder<'a> {
    configuration: &'a TransactionBuilderConfiguration,
    change_lock: Script,
    inputs: Vec<TransactionInput>,
}

impl<'a> DefaultChangeBuilder<'a> {
    /// Creates a new instance of `DefaultChangeBuilder`.
    pub fn new(
        configuration: &'a TransactionBuilderConfiguration,
        change_lock: Script,
        inputs: Vec<TransactionInput>,
    ) -> Self {
        Self {
            configuration,
            change_lock,
            inputs,
        }
    }

    /// Returns the change output and its data.
    pub fn get_change(&self) -> (CellOutput, packed::Bytes) {
        let change_output = CellOutput::new_builder()
            .lock(self.change_lock.clone())
            .build();
        let change_output_data = packed::Bytes::default();
        (change_output, change_output_data)
    }
}

impl<'a> ChangeBuilder for DefaultChangeBuilder<'a> {
    fn init(&self, tx: &mut TransactionBuilder) {
        let (change_output, change_output_data) = self.get_change();
        tx.output(change_output);
        tx.output_data(change_output_data);
    }

    fn check_balance(&mut self, input: TransactionInput, tx: &mut TransactionBuilder) -> bool {
        self.inputs.push(input);

        let outputs_capacity: u64 = tx
            .get_outputs()
            .iter()
            .map(|o| Unpack::<u64>::unpack(&o.capacity()))
            .sum();
        let (change_output, change_output_data) = self.get_change();
        let occupied_capacity = change_output
            .occupied_capacity(Capacity::bytes(change_output_data.len()).unwrap())
            .unwrap()
            .as_u64();

        let fee_calculator = self.configuration.fee_calculator();
        let required_capacity = outputs_capacity
            + occupied_capacity
            + fee_calculator.fee(self.configuration.estimate_tx_size);

        let inputs_capacity: u64 = self
            .inputs
            .iter()
            .map(|i| Unpack::<u64>::unpack(&i.previous_output().capacity()))
            .sum();
        inputs_capacity >= required_capacity
    }

    fn finalize(&self, mut tx: TransactionBuilder) -> TransactionView {
        // update change output capacity to real value
        let fee_calculator = self.configuration.fee_calculator();
        let fee = fee_calculator.fee_with_tx_builder(&tx);
        let inputs_capacity: u64 = self
            .inputs
            .iter()
            .map(|i| Unpack::<u64>::unpack(&i.previous_output().capacity()))
            .sum();
        let outputs_capacity: u64 = tx
            .get_outputs()
            .iter()
            .map(|o| Unpack::<u64>::unpack(&o.capacity()))
            .sum();
        let change_capacity = inputs_capacity - outputs_capacity - fee;
        let change_output = tx
            .outputs
            .last()
            .unwrap()
            .clone()
            .as_builder()
            .capacity(change_capacity.pack())
            .build();
        tx.set_output(tx.outputs.len() - 1, change_output);
        tx.build()
    }
}

/// a helper fn to build a transaction with common logic
fn inner_build<
    CB: ChangeBuilder,
    I: Iterator<Item = Result<TransactionInput, CellCollectorError>>,
>(
    mut tx: TransactionBuilder,
    mut change_builder: CB,
    input_iter: I,
    configuration: &TransactionBuilderConfiguration,
    contexts: &HandlerContexts,
) -> Result<TransactionWithScriptGroups, TxBuilderError> {
    let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
    let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();

    // setup outputs' type script group
    for (output_idx, output) in tx.get_outputs().clone().iter().enumerate() {
        if let Some(type_script) = &output.type_().to_opt() {
            type_groups
                .entry(type_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(type_script))
                .output_indices
                .push(output_idx);
        }
    }

    // setup change output and data
    change_builder.init(&mut tx);

    // collect inputs
    for (input_index, input) in input_iter.enumerate() {
        let input = input?;
        tx.input(input.cell_input());
        tx.witness(packed::Bytes::default());

        let previous_output = input.previous_output();
        let lock_script = previous_output.lock();
        lock_groups
            .entry(lock_script.calc_script_hash())
            .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
            .input_indices
            .push(input_index);

        if let Some(type_script) = previous_output.type_().to_opt() {
            type_groups
                .entry(type_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(&type_script))
                .input_indices
                .push(input_index);
        }

        // check if we have enough inputs
        if change_builder.check_balance(input, &mut tx) {
            // handle script groups
            let mut script_groups: Vec<ScriptGroup> = lock_groups
                .into_values()
                .chain(type_groups.into_values())
                .collect();

            for script_group in script_groups.iter_mut() {
                for handler in configuration.get_script_handlers() {
                    for context in &contexts.contexts {
                        if handler.build_transaction(&mut tx, script_group, context.as_ref())? {
                            break;
                        }
                    }
                }
            }

            let tx_view = change_builder.finalize(tx);

            return Ok(TransactionWithScriptGroups::new(tx_view, script_groups));
        }
    }

    Err(BalanceTxCapacityError::CapacityNotEnough("can not find enough inputs".to_string()).into())
}
