use std::{collections::HashSet, ops::DerefMut};

use super::{
    builder::{BaseTransactionBuilder, CkbTransactionBuilder},
    TxBuilder, TxBuilderError,
};
use crate::{
    traits::{CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider},
    ScriptGroup,
};
use crate::{types::ScriptId, NetworkInfo};
use ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::CellOutput,
    prelude::*,
};
use std::ops::Deref;

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

pub struct DefaultCapacityTransferBuilder {
    pub base_builder: BaseTransactionBuilder,
}

impl DefaultCapacityTransferBuilder {
    pub fn new(network_info: NetworkInfo, sender: &str) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender)?,
        })
    }
}

impl Deref for DefaultCapacityTransferBuilder {
    type Target = BaseTransactionBuilder;

    fn deref(&self) -> &Self::Target {
        &self.base_builder
    }
}

impl DerefMut for DefaultCapacityTransferBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base_builder
    }
}

impl CkbTransactionBuilder for DefaultCapacityTransferBuilder {
    fn build_base(&mut self) -> Result<TransactionView, TxBuilderError> {
        let builder = CapacityTransferBuilder::new(self.base_builder.outputs.clone());
        builder.build_base(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
        )
    }

    fn build_balanced(&mut self) -> Result<TransactionView, TxBuilderError> {
        let builder = CapacityTransferBuilder::new(self.base_builder.outputs.clone());
        builder.build_balanced(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }

    fn build_unlocked(&mut self) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let builder = CapacityTransferBuilder::new(self.base_builder.outputs.clone());
        builder.build_unlocked(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }

    fn build_balance_unlocked(
        &mut self,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let builder = CapacityTransferBuilder::new(self.base_builder.outputs.clone());
        builder.build_balance_unlocked(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }
}
