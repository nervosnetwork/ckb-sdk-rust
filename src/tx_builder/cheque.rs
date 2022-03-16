use std::collections::HashSet;

use ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, Script},
    prelude::*,
};

use super::{TxBuilder, TxBuilderError};
use crate::traits::{
    CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider,
};
use crate::types::ScriptId;

pub struct ChequeClaimUdtBuilder {
    /// The cheque cells to claim, must all have same lock script and type
    /// script and output data length is not less than 16.
    pub inputs: Vec<CellInput>,

    /// Add all UDT amount to this cell, the type script must be the same with
    /// `inputs`. The receiver output will keep the lock script, capacity and
    /// the rest of cell data.
    pub receiver_input: CellInput,

    /// Sender's lock script, the script hash must match the cheque cell's lock script args.
    pub sender_lock_script: Script,
}

impl TxBuilder for ChequeClaimUdtBuilder {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.inputs.is_empty() {
            return Err(TxBuilderError::InvalidParameter(
                "empty cheque inputs".to_string().into(),
            ));
        }

        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut inputs = self.inputs.clone();
        inputs.push(self.receiver_input.clone());

        let receiver_input_cell =
            tx_dep_provider.get_cell(&self.receiver_input.previous_output())?;
        let receiver_input_data =
            tx_dep_provider.get_cell_data(&self.receiver_input.previous_output())?;
        let receiver_type_script = receiver_input_cell.type_().to_opt().ok_or_else(|| {
            TxBuilderError::InvalidParameter(
                "receiver input missing type script".to_string().into(),
            )
        })?;

        if receiver_input_data.len() < 16 {
            return Err(TxBuilderError::InvalidParameter(
                format!(
                    "invalid receiver input cell data length, expected: 16, got: {}",
                    receiver_input_data.len()
                )
                .into(),
            ));
        }
        let receiver_input_amount = {
            let mut amount_bytes = [0u8; 16];
            amount_bytes.copy_from_slice(&receiver_input_data.as_ref()[0..16]);
            u128::from_le_bytes(amount_bytes)
        };

        let receiver_type_script_id = ScriptId::from(&receiver_type_script);
        let receiver_type_cell_dep = cell_dep_resolver.resolve(&receiver_type_script_id).ok_or(
            TxBuilderError::ResolveCellDepFailed(receiver_type_script_id),
        )?;
        let receiver_lock_script_id = ScriptId::from(&receiver_input_cell.lock());
        let receiver_lock_cell_dep = cell_dep_resolver.resolve(&receiver_lock_script_id).ok_or(
            TxBuilderError::ResolveCellDepFailed(receiver_lock_script_id),
        )?;
        cell_deps.insert(receiver_type_cell_dep);
        cell_deps.insert(receiver_lock_cell_dep);

        let mut cheque_total_amount = 0;
        let mut cheque_total_capacity = 0;
        let mut last_lock_script = None;
        for input in &self.inputs {
            let out_point = input.previous_output();
            let input_cell = tx_dep_provider.get_cell(&out_point)?;
            let input_data = tx_dep_provider.get_cell_data(&out_point)?;
            let type_script = receiver_input_cell.type_().to_opt().ok_or_else(|| {
                TxBuilderError::InvalidParameter(
                    format!("cheque input missing type script: {}", input).into(),
                )
            })?;

            if input_data.len() < 16 {
                return Err(TxBuilderError::InvalidParameter(
                    format!(
                        "invalid cheque input cell data length, expected: 16, got: {}",
                        input_data.len()
                    )
                    .into(),
                ));
            }
            if type_script != receiver_type_script {
                return Err(TxBuilderError::InvalidParameter(
                    format!(
                        "invalid cheque input cell type script not same with receiver input: {}",
                        input
                    )
                    .into(),
                ));
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
                return Err(TxBuilderError::InvalidParameter(
                    "all cheque input lock script must be the same"
                        .to_string()
                        .into(),
                ));
            }
            let lock_script_id = ScriptId::from(&lock_script);
            let lock_cell_dep = cell_dep_resolver
                .resolve(&lock_script_id)
                .ok_or(TxBuilderError::ResolveCellDepFailed(lock_script_id))?;

            cell_deps.insert(lock_cell_dep);
            cheque_total_amount += input_amount;
            cheque_total_capacity += input_capacity;
        }

        let cheque_lock_script = last_lock_script.unwrap();
        let cheque_lock_args = cheque_lock_script.args().raw_data();
        if cheque_lock_args.len() != 40 {
            return Err(TxBuilderError::InvalidParameter(
                format!(
                    "invalid cheque lock args length, expected: 40, got: {}",
                    cheque_lock_args.len()
                )
                .into(),
            ));
        }
        let sender_lock_hash = self.sender_lock_script.calc_script_hash();
        if sender_lock_hash.as_slice()[0..20] != cheque_lock_args.as_ref()[20..40] {
            return Err(TxBuilderError::InvalidParameter(
                "sender lock script is match with cheque lock script args"
                    .to_string()
                    .into(),
            ));
        }

        let receiver_output = receiver_input_cell;
        let receiver_output_data = {
            let receiver_output_amount = receiver_input_amount + cheque_total_amount;
            let mut data = receiver_input_data.as_ref().to_vec();
            data[0..16].copy_from_slice(&receiver_output_amount.to_le_bytes()[..]);
            Bytes::from(data)
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

pub struct ChequeWithdrawBuilder {}
