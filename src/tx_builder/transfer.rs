use std::collections::HashSet;

use ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::CellOutput,
    prelude::*,
};

use super::{TxBuilder, TxBuilderError};
use crate::traits::{
    CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider,
};
use crate::types::ScriptId;

/// A builder to build a transaction simply transfer capcity to an address. It
/// will resolve the type script's cell_dep if given.
pub struct CapacityTransferBuilder {
    pub outputs: Vec<(CellOutput, Bytes)>,
}

impl CapacityTransferBuilder {
    pub fn new(outputs: Vec<(CellOutput, Bytes)>) -> CapacityTransferBuilder {
        CapacityTransferBuilder { outputs }
    }
}

impl TxBuilder for CapacityTransferBuilder {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for (output, output_data) in &self.outputs {
            outputs.push(output.clone());
            outputs_data.push(output_data.pack());
            if let Some(type_script) = output.type_().to_opt() {
                let script_id = ScriptId::from(&type_script);
                if !script_id.is_type_id() {
                    let cell_dep = cell_dep_resolver
                        .resolve(&type_script)
                        .ok_or(TxBuilderError::ResolveCellDepFailed(type_script))?;
                    cell_deps.insert(cell_dep);
                }
            }
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}


/// It's like CapacityTransferBuilder, except with a predefined transaction, it can be used when an open transaction is avaiable.
pub struct CapacityTransferBuilderWithTransaction {
    pub outputs: Vec<(CellOutput, Bytes)>,
    pub transaction: TransactionView,
}

impl CapacityTransferBuilderWithTransaction {
    pub fn new(outputs: Vec<(CellOutput, Bytes)>, transaction: TransactionView) -> CapacityTransferBuilderWithTransaction {
        CapacityTransferBuilderWithTransaction { outputs, transaction }
    }
}

impl TxBuilder for CapacityTransferBuilderWithTransaction {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for (output, output_data) in &self.outputs {
            outputs.push(output.clone());
            outputs_data.push(output_data.pack());
            if let Some(type_script) = output.type_().to_opt() {
                let script_id = ScriptId::from(&type_script);
                if !script_id.is_type_id() {
                    let cell_dep = cell_dep_resolver
                        .resolve(&type_script)
                        .ok_or(TxBuilderError::ResolveCellDepFailed(type_script))?;
                    cell_deps.insert(cell_dep);
                }
            }
        }
        Ok(self.transaction.as_advanced_builder()
            .cell_deps(cell_deps)
            .outputs(outputs)
            .outputs_data(outputs_data)
            .build())
    }
}

