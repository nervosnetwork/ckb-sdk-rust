use std::collections::HashSet;

use anyhow::anyhow;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, OutPoint, Script},
    prelude::*,
};

use super::{TxBuilder, TxBuilderError};
use crate::constants::{CHEQUE_CELL_SINCE, SIGHASH_TYPE_HASH};
use crate::traits::{
    CellCollector, CellDepResolver, CellQueryOptions, HeaderDepResolver,
    TransactionDependencyProvider, ValueRangeOption,
};
use crate::types::ScriptId;

pub struct ChequeClaimBuilder {
    /// The cheque cells to claim, all cells must have same lock script and same
    /// type script and cell data length is equals to 16.
    pub inputs: Vec<CellInput>,

    /// Add all SUDT amount to this cell, the type script must be the same with
    /// `inputs`. The receiver output will keep the lock script, capacity.
    pub receiver_input: CellInput,

    /// Sender's lock script, the script hash must match the cheque cell's lock script args.
    pub sender_lock_script: Script,
}

impl ChequeClaimBuilder {
    pub fn new(
        inputs: Vec<CellInput>,
        receiver_input: CellInput,
        sender_lock_script: Script,
    ) -> ChequeClaimBuilder {
        ChequeClaimBuilder {
            inputs,
            receiver_input,
            sender_lock_script,
        }
    }
}

#[async_trait::async_trait]
impl TxBuilder for ChequeClaimBuilder {
    async fn build_base_async(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.inputs.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "empty cheque inputs"
            )));
        }

        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut inputs = self.inputs.clone();
        inputs.push(self.receiver_input.clone());

        let receiver_input_cell = tx_dep_provider
            .get_cell_async(&self.receiver_input.previous_output())
            .await?;
        let receiver_input_data = tx_dep_provider
            .get_cell_data_async(&self.receiver_input.previous_output())
            .await?;
        let receiver_type_script = receiver_input_cell.type_().to_opt().ok_or_else(|| {
            TxBuilderError::InvalidParameter(anyhow!("receiver input missing type script"))
        })?;
        let receiver_input_lock_cell_dep =
            cell_dep_resolver
                .resolve(&receiver_input_cell.lock())
                .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(receiver_input_cell.lock()))?;
        cell_deps.insert(receiver_input_lock_cell_dep);

        if receiver_input_data.len() != 16 {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "invalid receiver input cell data length, expected: 16, got: {}",
                receiver_input_data.len()
            )));
        }
        let receiver_input_amount = {
            let mut amount_bytes = [0u8; 16];
            amount_bytes.copy_from_slice(receiver_input_data.as_ref());
            u128::from_le_bytes(amount_bytes)
        };

        let receiver_type_cell_dep = cell_dep_resolver
            .resolve(&receiver_type_script)
            .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(receiver_type_script.clone()))?;
        cell_deps.insert(receiver_type_cell_dep);

        let mut cheque_total_amount = 0;
        let mut cheque_total_capacity = 0;
        let mut last_lock_script = None;
        for input in &self.inputs {
            let out_point = input.previous_output();
            let input_cell = tx_dep_provider.get_cell_async(&out_point).await?;
            let input_data = tx_dep_provider.get_cell_data_async(&out_point).await?;
            let type_script = receiver_input_cell.type_().to_opt().ok_or_else(|| {
                TxBuilderError::InvalidParameter(anyhow!(
                    "cheque input missing type script: {}",
                    input
                ))
            })?;

            if input_data.len() != 16 {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "invalid cheque input cell data length, expected: 16, got: {}",
                    input_data.len()
                )));
            }
            if type_script != receiver_type_script {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "cheque input's type script not same with receiver input's type script: {}",
                    input
                )));
            }
            let input_amount = {
                let mut amount_bytes = [0u8; 16];
                amount_bytes.copy_from_slice(input_data.as_ref());
                u128::from_le_bytes(amount_bytes)
            };
            let input_capacity: u64 = input_cell.capacity().unpack();

            let lock_script = input_cell.lock();
            if last_lock_script.is_none() {
                last_lock_script = Some(lock_script.clone());
            } else if last_lock_script.as_ref() != Some(&lock_script) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "all cheque input lock script must be the same"
                )));
            }
            let lock_cell_dep = cell_dep_resolver
                .resolve(&lock_script)
                .ok_or(TxBuilderError::ResolveCellDepFailed(lock_script))?;

            cell_deps.insert(lock_cell_dep);
            cheque_total_amount += input_amount;
            cheque_total_capacity += input_capacity;
        }

        let cheque_lock_script = last_lock_script.unwrap();
        let cheque_lock_args = cheque_lock_script.args().raw_data();
        if cheque_lock_args.len() != 40 {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "invalid cheque lock args length, expected: 40, got: {}",
                cheque_lock_args.len()
            )));
        }
        let sender_lock_hash = self.sender_lock_script.calc_script_hash();
        if sender_lock_hash.as_slice()[0..20] != cheque_lock_args.as_ref()[20..40] {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "sender lock script is not match with cheque lock script args"
            )));
        }

        let receiver_output = receiver_input_cell;
        let receiver_output_data = {
            let receiver_output_amount = receiver_input_amount + cheque_total_amount;
            Bytes::from(receiver_output_amount.to_le_bytes().to_vec())
        };
        let sender_output = CellOutput::new_builder()
            .lock(self.sender_lock_script.clone())
            .capacity(cheque_total_capacity.pack())
            .build();
        let sender_output_data = Bytes::new();

        let outputs = vec![receiver_output, sender_output];
        let outputs_data = vec![receiver_output_data.pack(), sender_output_data.pack()];

        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}

pub struct ChequeWithdrawBuilder {
    /// The cheque cells to withdraw, all cells must have same lock script and same
    /// type script and cell data length is equals to 16.
    pub out_points: Vec<OutPoint>,

    /// Sender's lock script, must be a sighash address, and the script hash
    /// must match the cheque cell's lock script args.
    pub sender_lock_script: Script,

    /// If `acp_script_id` provided, will withdraw to anyone-can-pay address
    pub acp_script_id: Option<ScriptId>,
}

impl ChequeWithdrawBuilder {
    pub fn new(
        out_points: Vec<OutPoint>,
        sender_lock_script: Script,
        acp_script_id: Option<ScriptId>,
    ) -> ChequeWithdrawBuilder {
        ChequeWithdrawBuilder {
            out_points,
            sender_lock_script,
            acp_script_id,
        }
    }
}

#[async_trait::async_trait]
impl TxBuilder for ChequeWithdrawBuilder {
    async fn build_base_async(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.out_points.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "empty withdraw inputs"
            )));
        }

        let mut inputs = Vec::new();
        let mut last_lock_script = None;
        let mut last_type_script = None;
        let mut cheque_total_amount: u128 = 0;
        let mut cheque_total_capacity: u64 = 0;
        for out_point in &self.out_points {
            let input_cell = tx_dep_provider.get_cell_async(out_point).await?;
            let input_data = tx_dep_provider.get_cell_data_async(out_point).await?;
            let lock_script = input_cell.lock();
            let type_script = input_cell.type_().to_opt().ok_or_else(|| {
                TxBuilderError::InvalidParameter(anyhow!(
                    "cheque input missing type script: {}",
                    out_point
                ))
            })?;

            if last_lock_script.is_none() {
                last_lock_script = Some(lock_script.clone());
            } else if last_lock_script.as_ref() != Some(&lock_script) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "all cheque input lock script must be the same"
                )));
            }
            if last_type_script.is_none() {
                last_type_script = Some(type_script.clone());
            } else if last_type_script.as_ref() != Some(&type_script) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "all cheque input type script must be the same"
                )));
            }

            let input_amount = {
                let mut amount_bytes = [0u8; 16];
                amount_bytes.copy_from_slice(input_data.as_ref());
                u128::from_le_bytes(amount_bytes)
            };
            let input_capacity: u64 = input_cell.capacity().unpack();
            let input = CellInput::new(out_point.clone(), CHEQUE_CELL_SINCE);

            cheque_total_capacity += input_capacity;
            cheque_total_amount += input_amount;
            inputs.push(input);
        }

        let cheque_lock_script = last_lock_script.unwrap();
        let type_script = last_type_script.unwrap();

        let cheque_cell_dep = cell_dep_resolver
            .resolve(&cheque_lock_script)
            .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(cheque_lock_script.clone()))?;
        let type_cell_dep = cell_dep_resolver
            .resolve(&type_script)
            .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(type_script.clone()))?;

        let cheque_lock_args = cheque_lock_script.args().raw_data();
        if cheque_lock_args.len() != 40 {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "invalid cheque lock args length, expected: 40, got: {}",
                cheque_lock_args.len()
            )));
        }
        if self.sender_lock_script.code_hash() != SIGHASH_TYPE_HASH.pack()
            || self.sender_lock_script.hash_type() != ScriptHashType::Type.into()
            || self.sender_lock_script.args().raw_data().len() != 20
        {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "invalid sender lock script, expected: sighash address, got: {:?}",
                self.sender_lock_script
            )));
        }
        let sender_lock_hash = self.sender_lock_script.calc_script_hash();
        if sender_lock_hash.as_slice()[0..20] != cheque_lock_args.as_ref()[20..40] {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "sender lock script is match with cheque lock script args"
            )));
        }

        let mut cell_deps = vec![cheque_cell_dep, type_cell_dep];
        let (sender_lock, total_capacity, total_amount) =
            if let Some(script_id) = self.acp_script_id.as_ref() {
                let acp_lock = Script::new_builder()
                    .code_hash(script_id.code_hash.pack())
                    .hash_type(script_id.hash_type.into())
                    .args(self.sender_lock_script.args())
                    .build();
                let mut query = CellQueryOptions::new_lock(acp_lock.clone());
                query.secondary_script = Some(type_script.clone());
                query.data_len_range = Some(ValueRangeOption::new_min(16));
                let (acp_cells, _) = cell_collector
                    .collect_live_cells_async(&query, true)
                    .await?;
                if acp_cells.is_empty() {
                    return Err(TxBuilderError::Other(anyhow!(
                        "can not find acp cell by lock script: {:?}",
                        acp_lock
                    )));
                }
                let acp_cell = &acp_cells[0];
                let mut amount_bytes = [0u8; 16];
                amount_bytes.copy_from_slice(acp_cell.output_data.as_ref());
                let acp_amount = u128::from_le_bytes(amount_bytes);
                let acp_capacity = acp_cell
                    .output
                    .occupied_capacity(Capacity::bytes(acp_cell.output_data.len()).unwrap())
                    .expect("occupied_capacity")
                    .as_u64();
                let acp_cell_dep = cell_dep_resolver
                    .resolve(&acp_lock)
                    .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(acp_lock.clone()))?;
                cell_deps.push(acp_cell_dep);
                inputs.push(CellInput::new(acp_cell.out_point.clone(), 0));
                (
                    acp_lock,
                    cheque_total_capacity + acp_capacity,
                    cheque_total_amount + acp_amount,
                )
            } else {
                (
                    self.sender_lock_script.clone(),
                    cheque_total_capacity,
                    cheque_total_amount,
                )
            };

        let sender_output = CellOutput::new_builder()
            .lock(sender_lock)
            .type_(Some(type_script).pack())
            .capacity(total_capacity.pack())
            .build();
        let sender_output_data = Bytes::from(total_amount.to_le_bytes().to_vec());

        let outputs = vec![sender_output];
        let outputs_data = vec![sender_output_data.pack()];

        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}
