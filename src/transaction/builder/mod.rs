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
    Address, ScriptGroup, TransactionWithScriptGroups,
};
use ckb_types::{
    core::{Capacity, HeaderView},
    packed::{self, Byte32, CellOutput, Script},
    prelude::{Builder, Entity, Pack, Unpack},
};
pub mod fee_calculator;
pub use fee_calculator::FeeCalculator;

pub trait CkbTransactionBuilder {
    fn build(
        &mut self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError>;
}

pub struct SimpleTransactionBuilder {
    change_output_index: Option<usize>,
    change_lock: Option<Script>,
    configuration: TransactionBuilderConfiguration,
    transaction_inputs: Vec<TransactionInput>,
    input_iter: InputIterator,
    tx: TransactionBuilder,
    reward: u64,
}

impl SimpleTransactionBuilder {
    pub fn new(configuration: TransactionBuilderConfiguration, input_iter: InputIterator) -> Self {
        Self {
            change_output_index: None,
            change_lock: None,
            configuration,
            transaction_inputs: vec![],
            input_iter,
            tx: TransactionBuilder::default(),
            reward: 0,
        }
    }
    pub fn set_change_addr(&mut self, change_addr: &Address) {
        self.change_lock = Some(change_addr.into());
    }

    pub fn set_change_lock(&mut self, lock_script: Script) {
        self.change_lock = Some(lock_script);
    }

    pub fn set_outputs(&mut self, outputs: Vec<CellOutput>, outputs_data: Vec<packed::Bytes>) {
        self.tx.set_outputs(outputs);
        self.tx.set_outputs_data(outputs_data);
    }

    pub fn add_output(&mut self, output: CellOutput, data: packed::Bytes) {
        self.tx.output(output);
        self.tx.output_data(data);
    }

    pub fn add_output_from_addr(&mut self, addr: &Address, capacity: Capacity) {
        self.add_output_from_script(addr.into(), capacity);
    }

    pub fn add_output_from_script(&mut self, lock_script: Script, capacity: Capacity) {
        let output = CellOutput::new_builder()
            .capacity(capacity.pack())
            .lock(lock_script)
            .build();
        self.add_output(output, packed::Bytes::default());
    }

    pub fn add_input(&mut self, input: TransactionInput) {
        self.transaction_inputs.push(input);
    }

    pub fn add_header_dep(&mut self, header_dep: &HeaderView) {
        self.tx.dedup_header_dep(header_dep.hash());
    }

    fn set_change_output_capacity(&mut self, change_capacity: u64) {
        let mut outputs = self.tx.get_outputs().clone();
        outputs[self.change_output_index.unwrap()] = outputs
            [*self.change_output_index.as_ref().unwrap()]
        .clone()
        .as_builder()
        .capacity(change_capacity.pack())
        .build();
        self.tx.set_outputs(outputs);
    }

    fn handle_script(
        tx_data: &mut TransactionBuilder,
        configuration: &TransactionBuilderConfiguration,
        script_group: &ScriptGroup,
        contexts: &HandlerContexts,
    ) -> Result<(), TxBuilderError> {
        for handler in configuration.get_script_handlers() {
            for context in &contexts.contexts {
                if handler.build_transaction(tx_data, script_group, context.as_ref())? {
                    break;
                }
            }
        }
        Ok(())
    }

    fn add_output_capacity(
        tx_data: &mut TransactionBuilder,
        script: &Script,
        delta_capacity: u64,
    ) -> Result<(), TxBuilderError> {
        let target_script = script.calc_script_hash();
        let (idx, output) = tx_data
            .get_outputs()
            .iter()
            .enumerate()
            .find(|(_, output)| target_script == output.lock().calc_script_hash())
            .ok_or(TxBuilderError::NoOutputForSmallChange)?;
        let capacity: u64 = output.capacity().unpack();
        let output = output
            .clone()
            .as_builder()
            .capacity((capacity + delta_capacity).pack())
            .build();
        tx_data.set_output(idx, output);
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

        for (output_idx, output) in self.tx.get_outputs().clone().iter().enumerate() {
            outputs_capacity += celloutput_capacity!(output);
            if let Some(t) = &output.type_().to_opt() {
                let script_group = type_groups
                    .entry(t.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(t));
                script_group.output_indices.push(output_idx);
                Self::handle_script(&mut self.tx, &self.configuration, script_group, contexts)?;
            }
        }

        let mut state = BalanceState::Init;
        let mut inputs_capacity = 0u64;
        let mut mini_change_capacity = 0u64;
        let calculator = self.configuration.fee_calculator();
        for (input_index, input) in
            InputView::new(&self.transaction_inputs, &mut self.input_iter).enumerate()
        {
            let input = input?;
            self.tx.input(input.cell_input());
            let previous_output = input.previous_output();
            self.tx.witness(packed::Bytes::default());
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
            if let Some(mut change_capacity) = change_capacity {
                if self.change_output_index.is_none() {
                    // it's already balanced, no need to add change output cell
                    if change_capacity == 0 {
                        state = BalanceState::Success;
                        break;
                    }
                    match self.configuration.small_change_action {
                        super::SmallChangeAction::FindMoreInput => {}
                        super::SmallChangeAction::ToOutput {
                            ref target,
                            threshold,
                        } => {
                            if change_capacity < threshold {
                                Self::add_output_capacity(&mut self.tx, target, change_capacity)?;
                                state = BalanceState::Success;
                                break;
                            }
                        }
                        super::SmallChangeAction::AsFee { threshold } => {
                            if change_capacity < threshold {
                                state = BalanceState::Success;
                                break;
                            }
                        }
                    }
                    {
                        // init change
                        let change_output = CellOutput::new_builder()
                            .capacity(Capacity::bytes(0).unwrap().pack())
                            .lock(self.change_lock.as_ref().unwrap().clone())
                            .build();
                        let change_output_data = packed::Bytes::default();
                        mini_change_capacity = change_output
                            .occupied_capacity(Capacity::bytes(change_output_data.len()).unwrap())
                            .unwrap()
                            .as_u64();
                        self.change_output_index = Some(self.tx.get_outputs().len());
                        self.tx.output(change_output);
                        self.tx.output_data(change_output_data);
                    }
                    let new_fee = calculator.fee_with_tx_data(&self.tx);
                    if let Some(new_change) =
                        (inputs_capacity + self.reward).checked_sub(outputs_capacity + new_fee)
                    {
                        change_capacity = new_change;
                    } else {
                        state = BalanceState::CapacityNotEnoughForChange(
                            mini_change_capacity + new_fee - fee,
                            change_capacity,
                        );
                        continue;
                    }
                }
                if change_capacity >= mini_change_capacity {
                    self.set_change_output_capacity(change_capacity);
                    state = BalanceState::Success;
                    break;
                } else {
                    state = BalanceState::CapacityNotEnoughForChange(
                        mini_change_capacity,
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
            self.tx.clone().build(),
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

impl From<BalanceState> for BalanceTxCapacityError {
    fn from(val: BalanceState) -> Self {
        BalanceTxCapacityError::CapacityNotEnough(val.to_string())
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
