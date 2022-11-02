use std::collections::{HashSet, HashMap};

use ckb_types::{
    bytes::Bytes,
    core::{DepType, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H256,
};

use super::{TxBuilder, TxBuilderError, CapacityBalancer, fill_placeholder_witnesses, balance_tx_capacity};
use crate::{
    traits::{CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider},
    unlock::{omni_lock::ConfigError, OmniLockConfig, OmniUnlockMode, ScriptUnlocker},
};
use crate::{types::ScriptId, HumanCapacity};

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

    /// Create an OmniLockTransferBuilder with open out in the output list.
    /// After the transaction built, the open out should be removed.
    pub fn new_open(
        open_capacity: HumanCapacity,
        mut outputs: Vec<(CellOutput, Bytes)>,
        cfg: OmniLockConfig,
        rce_cells: Option<Vec<OutPoint>>,
    ) -> OmniLockTransferBuilder {
        let tmp_out = OmniLockTransferBuilder::build_tmp_open_out(open_capacity);
        outputs.push((tmp_out, Bytes::default()));
        OmniLockTransferBuilder {
            outputs,
            cfg,
            rce_cells,
        }
    }

    fn build_opentx_placeholder_hash() -> H256 {
        let mut ret = H256::default();
        let opentx = "opentx";
        let offset = ret.0.len() - opentx.len();
        ret.0[offset..].copy_from_slice(opentx.as_bytes());
        ret
    }

    fn build_opentx_tmp_script() -> Script {
        let tmp_locker = Self::build_opentx_placeholder_hash();
        Script::new_builder()
            .code_hash(tmp_locker.pack())
            .hash_type(ScriptHashType::Type.into())
            .args([0xffu8; 65].pack())
            .build()
    }

    pub fn build_tmp_open_out(open_capacity: HumanCapacity) -> CellOutput {
        let tmp_locker = Self::build_opentx_tmp_script();
        CellOutput::new_builder()
            .lock(tmp_locker)
            .capacity(open_capacity.0.pack())
            .build()
    }

    /// remove the open output
    pub fn remove_open_out(tx: TransactionView) -> TransactionView {
        let tmp_locker = Self::build_opentx_tmp_script();
        let tmp_idxes: HashSet<usize> = tx
            .outputs()
            .into_iter()
            .enumerate()
            .filter(|(_, out)| out.lock() == tmp_locker)
            .map(|(idx, _)| idx)
            .collect();
        let outputs: Vec<CellOutput> = tx
            .outputs()
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| !tmp_idxes.contains(idx))
            .map(|(_, out)| out)
            .collect();
        let outputs_data: Vec<ckb_types::packed::Bytes> = tx
            .outputs_data()
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| !tmp_idxes.contains(idx))
            .map(|(_, out)| out)
            .collect();
        tx.as_advanced_builder()
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build()
    }

    /// after the open transaction input list updated(exclude base input/output), the witness should be updated
    pub fn update_opentx_witness(
        tx: TransactionView,
        omnilock_config: &OmniLockConfig,
        unlock_mode: OmniUnlockMode,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        sender: &Script,
    ) -> Result<TransactionView, ConfigError> {
        // after set opentx config, need to update the witness field
        let placeholder_witness = omnilock_config.placeholder_witness(unlock_mode)?;
        let tmp_idxes: Vec<_> = tx
            .input_pts_iter()
            .enumerate()
            .filter(|(_, output)| tx_dep_provider.get_cell(output).unwrap().lock() == *sender)
            .map(|(idx, _)| idx)
            .collect();
        let witnesses: Vec<_> = tx
            .witnesses()
            .into_iter()
            .enumerate()
            .map(|(i, w)| {
                if tmp_idxes.contains(&i) {
                    placeholder_witness.as_bytes().pack()
                } else {
                    w
                }
            })
            .collect();
        let tx = tx.as_advanced_builder().set_witnesses(witnesses).build();
        Ok(tx)
    }
}

impl TxBuilder for OmniLockTransferBuilder {
    fn build_base(
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
                        let cell_output = tx_dep_provider.get_cell(cell)?;
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

    /// Build balanced transaction that ready to sign:
    ///  * Build base transaction
    ///  * Fill placeholder witness for lock script
    ///  * balance the capacity
    fn build_balanced(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
        balancer: &CapacityBalancer,
        unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
    ) -> Result<TransactionView, TxBuilderError> {
        let base_tx = self.build_base(
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
        )?;
        let (tx_filled_witnesses, _) =
            fill_placeholder_witnesses(base_tx, tx_dep_provider, unlockers)?;
        let mut tx = balance_tx_capacity(
            &tx_filled_witnesses,
            balancer,
            cell_collector,
            tx_dep_provider,
            cell_dep_resolver,
            header_dep_resolver,
        )?;
        if self.cfg.is_opentx_mode() {
            tx = OmniLockTransferBuilder::remove_open_out(tx);
        }
        Ok(tx)
    }
}
