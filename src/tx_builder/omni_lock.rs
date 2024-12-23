use std::collections::HashSet;

use ckb_types::{
    bytes::Bytes,
    core::{DepType, TransactionBuilder, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint},
    prelude::*,
};

use super::{TxBuilder, TxBuilderError};
use crate::types::ScriptId;
use crate::{
    traits::{CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider},
    unlock::OmniLockConfig,
};

/// A builder to build an omnilock transfer transaction.
pub struct OmniLockTransferBuilder {
    pub outputs: Vec<(CellOutput, Bytes)>,
    pub cfg: OmniLockConfig,
    pub rce_cells: Option<Vec<OutPoint>>,
}

impl OmniLockTransferBuilder {
    pub fn new(
        outputs: Vec<(CellOutput, Bytes)>,
        cfg: OmniLockConfig,
        rce_cells: Option<Vec<OutPoint>>,
    ) -> OmniLockTransferBuilder {
        OmniLockTransferBuilder {
            outputs,
            cfg,
            rce_cells,
        }
    }
}

#[async_trait::async_trait]
impl TxBuilder for OmniLockTransferBuilder {
    async fn build_base_async(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        #[allow(clippy::mutable_key_type)]
        let mut inputs = HashSet::new();
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
        if let Some(admin_cfg) = self.cfg.get_admin_config() {
            if let Some(rce_cells) = self.rce_cells.as_ref() {
                if admin_cfg.rce_in_input() {
                    for cell in rce_cells {
                        let input = CellInput::new_builder()
                            .previous_output(cell.clone())
                            .build();
                        inputs.insert(input);
                        let cell_output = tx_dep_provider.get_cell_async(cell).await?;
                        // extract lock dep
                        let lock = cell_output.lock();
                        if let Some(cell_dep) = cell_dep_resolver.resolve(&lock) {
                            cell_deps.insert(cell_dep);
                        }
                        // extract type dependency
                        if let Some(type_) = cell_output.type_().to_opt() {
                            if let Some(cell_dep) = cell_dep_resolver.resolve(&type_) {
                                cell_deps.insert(cell_dep);
                            }
                        }
                    }
                } else {
                    for cell in rce_cells {
                        let cell_dep = CellDep::new_builder()
                            .out_point(cell.clone())
                            .dep_type(DepType::Code.into())
                            .build();
                        cell_deps.insert(cell_dep);
                    }
                }
            }
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_outputs(outputs)
            .set_inputs(inputs.into_iter().collect())
            .set_outputs_data(outputs_data)
            .build())
    }
}
