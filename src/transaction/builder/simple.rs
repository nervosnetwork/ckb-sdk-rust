use crate::{
    core::TransactionBuilder,
    transaction::{
        handler::HandlerContexts, input::InputIterator, TransactionBuilderConfiguration,
    },
    tx_builder::TxBuilderError,
    TransactionWithScriptGroups,
};
use ckb_types::{
    core::Capacity,
    packed::{self, CellOutput, Script},
    prelude::{Builder, Entity, Pack},
};

use super::{inner_build, CkbTransactionBuilder, DefaultChangeBuilder};

/// A simple transaction builder implementation, it will build a transaction with enough capacity to pay for the outputs and the fee.
pub struct SimpleTransactionBuilder {
    /// The change lock script, the default change lock script is the last lock script of the input iterator
    change_lock: Script,
    /// The transaction builder configuration
    configuration: TransactionBuilderConfiguration,
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
            input_iter,
            tx,
        } = self;

        let change_builder = DefaultChangeBuilder {
            configuration: &configuration,
            change_lock,
            inputs: Vec::new(),
        };

        inner_build(tx, change_builder, input_iter, &configuration, contexts)
    }
}
