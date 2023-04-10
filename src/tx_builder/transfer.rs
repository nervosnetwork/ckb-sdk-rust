use std::collections::HashSet;

use ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{CellOutput, WitnessArgs},
    prelude::*,
};

use super::{builder::BaseTransactionBuilder, TxBuilder, TxBuilderError};
use crate::types::ScriptId;
use crate::{
    impl_default_builder,
    traits::{CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider},
    Address, NetworkInfo,
};

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
    pub fn new_mainnet(sender: Address) -> Result<Self, TxBuilderError> {
        Self::new_with_address(&NetworkInfo::mainnet(), sender)
    }

    pub fn new_with_address(
        network_info: &NetworkInfo,
        sender: Address,
    ) -> Result<Self, TxBuilderError> {
        let mut ret = Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender)?,
        };
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();
        ret.set_sender_placeholder_witness(placeholder_witness);
        Ok(ret)
    }
}

impl From<&DefaultCapacityTransferBuilder> for CapacityTransferBuilder {
    fn from(val: &DefaultCapacityTransferBuilder) -> Self {
        CapacityTransferBuilder::new(val.base_builder.outputs.clone())
    }
}

impl_default_builder!(DefaultCapacityTransferBuilder, CapacityTransferBuilder);
