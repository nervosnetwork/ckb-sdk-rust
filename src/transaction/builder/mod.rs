use std::collections::HashMap;

use super::{
    handler::HandlerContexts,
    input::{InputIterator, TransactionInput},
};
use crate::{
    core::TransactionBuilder,
    traits::CellCollectorError,
    transaction::TransactionBuilderConfiguration,
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    ScriptGroup, TransactionWithScriptGroups,
};
use ckb_types::{
    core::Capacity,
    packed::{self, Byte32, CellOutput, Script},
    prelude::{Builder, Entity, Pack, Unpack},
};
pub mod fee_calculator;
pub use fee_calculator::FeeCalculator;

/// CKB transaction builder trait.
pub trait CkbTransactionBuilder {
    fn build(
        self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError>;
}

/// A simple transaction builder implementation, it will build a transaction with enough capacity to pay for the outputs and the fee.
pub struct SimpleTransactionBuilder {
    /// The change lock script, the default change lock script is the last lock script of the input iterator
    change_lock: Script,
    /// The transaction builder configuration
    configuration: TransactionBuilderConfiguration,
    /// Specified transaction inputs, used for building transaction with specific inputs, for example, building a DAO withdraw transaction
    transaction_inputs: Vec<TransactionInput>,
    /// The reward for the DAO withdraw transaction, the default value is 0
    reward: u64,
    /// The input iterator, used for building transaction with cell collector
    input_iter: InputIterator,
    /// The inner transaction builder
    tx: TransactionBuilder,
}

impl SimpleTransactionBuilder {
    pub fn new(configuration: TransactionBuilderConfiguration, input_iter: InputIterator) -> Self {
        Self {
            change_lock: input_iter
                .lock_scripts()
                .last()
                .expect("input iter should not be empty")
                .clone(),
            configuration,
            transaction_inputs: vec![],
            reward: 0,
            input_iter,
            tx: TransactionBuilder::default(),
        }
    }

    /// Update the change lock script.
    pub fn set_change_lock(&mut self, lock_script: Script) {
        self.change_lock = lock_script;
    }

    /// Add an output cell and output data to the transaction.
    pub fn add_output_and_data(&mut self, output: CellOutput, data: packed::Bytes) {
        self.tx.output(output);
        self.tx.output_data(data);
    }

    /// Add an output cell with the given lock script and capacity, the type script and the output data are empty.
    pub fn add_output<S: Into<Script>>(&mut self, output_lock_script: S, capacity: Capacity) {
        let output = CellOutput::new_builder()
            .capacity(capacity.pack())
            .lock(output_lock_script.into())
            .build();
        self.add_output_and_data(output, packed::Bytes::default());
    }
}

impl CkbTransactionBuilder for SimpleTransactionBuilder {
    fn build(
        self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError> {
        let Self {
            change_lock,
            configuration,
            transaction_inputs,
            mut input_iter,
            mut tx,
            reward,
        } = self;

        let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
        let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();

        // setup outputs' type script group
        let mut outputs_capacity = 0u64;
        for (output_idx, output) in tx.get_outputs().clone().iter().enumerate() {
            let output_capacity: u64 = output.capacity().unpack();
            outputs_capacity += output_capacity;
            if let Some(type_script) = &output.type_().to_opt() {
                type_groups
                    .entry(type_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(type_script))
                    .output_indices
                    .push(output_idx);
            }
        }

        // setup change output as placeholder with zero capacity
        let change_output = CellOutput::new_builder().lock(change_lock).build();
        let occupied_capacity = change_output
            .occupied_capacity(Capacity::zero())
            .unwrap()
            .as_u64();
        tx.output(change_output);
        tx.output_data(Default::default());

        // collect inputs
        let fee_calculator = configuration.fee_calculator();
        let required_capacity = outputs_capacity
            + occupied_capacity
            + fee_calculator.fee(configuration.estimate_tx_size)
            - reward;
        let mut has_enough_capacity = false;
        let mut inputs_capacity = 0u64;
        for (input_index, input) in InputView::new(&transaction_inputs, &mut input_iter).enumerate()
        {
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
            let input_capacity: u64 = previous_output.capacity().unpack();
            inputs_capacity += input_capacity;
            if inputs_capacity >= required_capacity {
                has_enough_capacity = true;
                break;
            }
        }

        if !has_enough_capacity {
            return Err(BalanceTxCapacityError::CapacityNotEnough(format!(
                "can not find enough inputs, inputs_capacity: {}, required_capacity: {}",
                inputs_capacity, required_capacity
            ))
            .into());
        }

        // handle script groups
        let script_groups = lock_groups
            .into_values()
            .chain(type_groups.into_values())
            .collect();

        for script_group in &script_groups {
            for handler in configuration.get_script_handlers() {
                for context in &contexts.contexts {
                    if handler.build_transaction(&mut tx, script_group, context.as_ref())? {
                        break;
                    }
                }
            }
        }

        // update change output capacity to real value
        let fee = fee_calculator.fee_with_tx_builder(&tx);
        let change_capacity = inputs_capacity + reward - outputs_capacity - fee;
        let change_output = tx
            .outputs
            .last()
            .unwrap()
            .clone()
            .as_builder()
            .capacity(change_capacity.pack())
            .build();
        tx.set_output(tx.outputs.len() - 1, change_output);

        Ok(TransactionWithScriptGroups::new(tx.build(), script_groups))
    }
}

struct InputView<'a> {
    index: usize,
    transaction_inputs: &'a Vec<TransactionInput>,
    input_iter: &'a mut InputIterator,
}

impl<'a> InputView<'a> {
    fn new(
        transaction_inputs: &'a Vec<TransactionInput>,
        input_iter: &'a mut InputIterator,
    ) -> InputView<'a> {
        InputView {
            index: 0,
            transaction_inputs,
            input_iter,
        }
    }
}

impl<'a> Iterator for InputView<'a> {
    type Item = Result<TransactionInput, CellCollectorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.transaction_inputs.len() {
            let input = self.transaction_inputs.get(self.index).unwrap();
            self.index += 1;
            return Some(Ok(input.clone()));
        }
        self.input_iter.next()
    }
}
