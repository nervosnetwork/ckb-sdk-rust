use std::collections::HashMap;

use super::{
    handler::HandlerContexts,
    input::{InputIterator, TransactionInput},
};
use crate::{
    traits::CellCollectorError,
    transaction::TransactionBuilderConfiguration,
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    Address, ScriptGroup, TransactionWithScriptGroups,
};
use ckb_types::{
    core::{Capacity, HeaderView},
    packed::{self, Byte32, CellOutput},
    prelude::{Builder, Entity, Pack, Unpack},
};
pub mod fee_calculator;
pub mod tx_data;
pub use fee_calculator::FeeCalculator;

pub trait CkbTransactionBuilder {
    fn build(
        &mut self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError>;
}

pub struct SimpleTransactionBuilder {
    change_output_index: Option<usize>,
    change_addr: Option<Address>,
    configuration: TransactionBuilderConfiguration,
    transaction_inputs: Vec<TransactionInput>,
    input_iter: InputIterator,
    tx: tx_data::TxData,
    reward: u64,
}

pub struct InitChangeOutputViewer<'a> {
    change_output_index: &'a mut Option<usize>,
    change_addr: &'a Option<Address>,
    tx: &'a mut tx_data::TxData,
}

impl<'a> InitChangeOutputViewer<'a> {
    fn init_change_output(&mut self) -> Result<(), TxBuilderError> {
        let change_output = CellOutput::new_builder()
            .capacity(Capacity::bytes(0).unwrap().pack())
            .lock(self.change_addr.as_ref().unwrap().into())
            .build();
        self.set_change_output(change_output, packed::Bytes::default())?;
        Ok(())
    }

    pub fn set_change_output(
        &mut self,
        output: CellOutput,
        data: packed::Bytes,
    ) -> Result<(), TxBuilderError> {
        if let Some(idx) = self.change_output_index.as_ref() {
            return Err(TxBuilderError::ChangeIndex(*idx));
        }
        *self.change_output_index = Some(self.tx.outputs_len());
        self.tx.add_output(output);
        self.tx.add_output_data(data);
        Ok(())
    }
}

impl SimpleTransactionBuilder {
    pub fn new(configuration: TransactionBuilderConfiguration, input_iter: InputIterator) -> Self {
        Self {
            change_output_index: None,
            change_addr: None,
            configuration,
            transaction_inputs: vec![],
            input_iter,
            tx: tx_data::TxData::default(),
            reward: 0,
        }
    }
    pub fn set_outputs(&mut self, outputs: Vec<CellOutput>, outputs_data: Vec<packed::Bytes>) {
        self.tx.set_outputs(outputs);
        self.tx.set_outputs_data(outputs_data);
    }

    pub fn add_output(&mut self, output: CellOutput, data: packed::Bytes) {
        self.tx.add_output(output);
        self.tx.add_output_data(data);
    }

    pub fn set_change_output(
        &mut self,
        output: CellOutput,
        data: packed::Bytes,
    ) -> Result<(), TxBuilderError> {
        if let Some(idx) = self.change_output_index.as_ref() {
            return Err(TxBuilderError::ChangeIndex(*idx));
        }
        self.change_output_index = Some(self.tx.outputs_len());
        self.add_output(output, data);
        Ok(())
    }

    pub fn add_input(&mut self, input: TransactionInput) {
        self.transaction_inputs.push(input);
    }

    pub fn add_header_dep(&mut self, header_dep: &HeaderView) {
        self.tx.add_header_dep(header_dep.hash());
    }

    fn get_change_occupied_capacity(
        change_output_index: &Option<usize>,
        tx: &tx_data::TxData,
    ) -> u64 {
        let change_index = *change_output_index.as_ref().unwrap();
        let change_output = tx.outputs.get(change_index).unwrap();
        let change_output_data = tx.outputs_data.get(change_index).unwrap();
        change_output
            .occupied_capacity(Capacity::bytes(change_output_data.len()).unwrap())
            .unwrap()
            .as_u64()
    }

    fn set_change_output_capacity(&mut self, change_capacity: u64) {
        let change_index = *self.change_output_index.as_ref().unwrap();
        let change_output = self.tx.outputs.get_mut(change_index).unwrap();
        let change_output = change_output
            .clone()
            .as_builder()
            .capacity(change_capacity.pack())
            .build();
        self.tx.outputs[change_index] = change_output;
    }
    fn handle_script(
        tx_data: &mut tx_data::TxData,
        configuration: &TransactionBuilderConfiguration,
        script_group: &ScriptGroup,
        contexts: &HandlerContexts,
    ) -> Result<(), TxBuilderError> {
        for handler in configuration.get_script_handlers() {
            for context in &contexts.contexts {
                if let Ok(true) = handler.build_transaction(tx_data, script_group, context.as_ref())
                {
                    break;
                }
            }
        }
        Ok(())
    }
}

macro_rules! celloutput_capacity {
    ($output:expr) => {{
        let tmp_capacity: u64 = $output.capacity().unpack();
        tmp_capacity
    }};
}

impl CkbTransactionBuilder for SimpleTransactionBuilder {
    fn build(
        &mut self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError> {
        let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
        let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
        let mut outputs_capacity = 0u64;

        for (i, output) in self.tx.outputs.clone().iter().enumerate() {
            outputs_capacity += celloutput_capacity!(output);
            if let Some(t) = &output.type_().to_opt() {
                let script_group = type_groups
                    .entry(t.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(&t));
                script_group.output_indices.push(i);
                Self::handle_script(&mut self.tx, &self.configuration, script_group, contexts)?;
            }
        }

        let mut state = BalanceState::Init;
        let mut inputs_capacity = 0u64;
        let calculator = self.configuration.fee_calculator();
        for (input_index, input) in
            InputView::new(&self.transaction_inputs, &mut self.input_iter).enumerate()
        {
            let input = input?;
            self.tx.add_input(input.cell_input());
            let previous_output = input.previous_output();
            self.tx.add_witness(packed::Bytes::default());
            let lock_script = previous_output.lock();
            let script_group = lock_groups
                .entry(lock_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script));
            script_group.input_indices.push(input_index);
            // add cellDeps and set witness placeholder
            Self::handle_script(&mut self.tx, &self.configuration, script_group, contexts)?;

            if let Some(t) = &previous_output.type_().to_opt() {
                let script_group = type_groups
                    .entry(t.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(t));

                script_group.input_indices.push(input_index);
                Self::handle_script(&mut self.tx, &self.configuration, script_group, contexts)?;
            }
            inputs_capacity += celloutput_capacity!(previous_output);
            // check if there is enough capacity for output capacity and change
            let fee = calculator.fee_with_tx_data(&self.tx);
            let change_capacity =
                (inputs_capacity + self.reward).checked_sub(outputs_capacity + fee);
            if let Some(change_capacity) = change_capacity {
                // it's already balanced, no need to add change output cell
                if change_capacity == 0 {
                    state = BalanceState::Success;
                    break;
                }
                if self.change_output_index.is_none() {
                    // TODO after change output is set, we should check if it's enough for change
                    InitChangeOutputViewer {
                        tx: &mut self.tx,
                        change_output_index: &mut self.change_output_index,
                        change_addr: &self.change_addr,
                    }
                    .init_change_output()?;
                }
                let change_require_capacity =
                    Self::get_change_occupied_capacity(&self.change_output_index, &self.tx);
                if change_capacity >= change_require_capacity {
                    self.set_change_output_capacity(change_capacity);
                    state = BalanceState::Success;
                    break;
                } else {
                    state = BalanceState::CapacityNotEnoughForChange(
                        change_require_capacity,
                        change_capacity,
                    );
                }
            } else {
                state = BalanceState::CapacityNotEnough(
                    (outputs_capacity + fee) - (inputs_capacity + self.reward),
                );
            }
        }

        if !state.is_success() {
            return Err(TxBuilderError::BalanceCapacity(state.into()));
        }
        let script_groups = lock_groups
            .into_values()
            .chain(type_groups.into_values())
            .collect();
        Ok(TransactionWithScriptGroups::new(
            self.tx.build_tx_view(),
            script_groups,
        ))
    }
}

enum BalanceState {
    Init,
    Success,
    // (left_capacity)
    CapacityNotEnough(u64),
    // (required_capacity, change_capacity)
    CapacityNotEnoughForChange(u64, u64),
}
impl BalanceState {
    #[inline]
    fn is_success(&self) -> bool {
        matches!(self, BalanceState::Success)
    }
}
impl Into<BalanceTxCapacityError> for BalanceState {
    fn into(self) -> BalanceTxCapacityError {
        BalanceTxCapacityError::CapacityNotEnough(self.to_string())
    }
}
impl ToString for BalanceState {
    fn to_string(&self) -> String {
        match self {
            BalanceState::Init => "Init".to_string(),
            BalanceState::Success => "Success".to_string(),
            BalanceState::CapacityNotEnough(left_capacity) => {
                format!("CapacityNotEnough, left_capacity: {}", left_capacity)
            }
            BalanceState::CapacityNotEnoughForChange(required_capacity, change_capacity) => {
                format!(
                    "CapacityNotEnoughForChange, required_capacity: {}, change_capacity: {}",
                    required_capacity, change_capacity
                )
            }
        }
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
