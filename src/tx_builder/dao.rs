use std::collections::HashSet;

use anyhow::anyhow;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};

use super::{TxBuilder, TxBuilderError};
use crate::constants::DAO_TYPE_HASH;
use crate::traits::{
    CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider,
};
use crate::types::{Since, SinceType};
use crate::util::{calculate_dao_maximum_withdraw4, minimal_unlock_point};

/// Deposit target
#[derive(Debug, Clone)]
pub struct DaoDepositReceiver {
    pub lock_script: Script,
    pub capacity: u64,
}
/// Build a Nervos DAO deposit transaction
#[derive(Debug, Clone)]
pub struct DaoDepositBuilder {
    /// The deposit targets
    pub receivers: Vec<DaoDepositReceiver>,
}

impl DaoDepositReceiver {
    pub fn new(lock_script: Script, capacity: u64) -> DaoDepositReceiver {
        DaoDepositReceiver {
            lock_script,
            capacity,
        }
    }
}

impl DaoDepositBuilder {
    pub fn new(receivers: Vec<DaoDepositReceiver>) -> DaoDepositBuilder {
        DaoDepositBuilder { receivers }
    }
}

#[async_trait::async_trait]
impl TxBuilder for DaoDepositBuilder {
    async fn build_base_async(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.receivers.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "empty dao receivers"
            )));
        }
        let dao_type_script = Script::new_builder()
            .code_hash(DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let dao_cell_dep = cell_dep_resolver
            .resolve(&dao_type_script)
            .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(dao_type_script.clone()))?;

        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for receiver in &self.receivers {
            let output = CellOutput::new_builder()
                .capacity(receiver.capacity.pack())
                .lock(receiver.lock_script.clone())
                .type_(Some(dao_type_script.clone()).pack())
                .build();
            outputs.push(output);
            outputs_data.push(Bytes::from(vec![0u8; 8]).pack());
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(vec![dao_cell_dep])
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}

#[derive(Debug, Clone)]
pub struct DaoPrepareItem {
    /// The cell to prepare withdraw (deposited cell)
    pub input: CellInput,

    /// If `lock_script` is `None` copy the lock script from input with same
    /// index, otherwise replace the lock script with the given script.
    pub lock_script: Option<Script>,
}
impl From<CellInput> for DaoPrepareItem {
    fn from(input: CellInput) -> DaoPrepareItem {
        DaoPrepareItem {
            input,
            lock_script: None,
        }
    }
}

/// Build a Nervos DAO withdraw Phase 1 transaction
#[derive(Debug, Clone)]
pub struct DaoPrepareBuilder {
    /// Prepare withdraw from those inputs (deposited cells)
    pub items: Vec<DaoPrepareItem>,
}
impl DaoPrepareBuilder {
    pub fn new(items: Vec<DaoPrepareItem>) -> DaoPrepareBuilder {
        DaoPrepareBuilder { items }
    }
}
impl From<Vec<CellInput>> for DaoPrepareBuilder {
    fn from(inputs: Vec<CellInput>) -> DaoPrepareBuilder {
        let items: Vec<_> = inputs.into_iter().map(DaoPrepareItem::from).collect();
        DaoPrepareBuilder { items }
    }
}

#[async_trait::async_trait]
impl TxBuilder for DaoPrepareBuilder {
    async fn build_base_async(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.items.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "No cell to prepare"
            )));
        }

        let dao_type_script = Script::new_builder()
            .code_hash(DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let dao_cell_dep = cell_dep_resolver
            .resolve(&dao_type_script)
            .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(dao_type_script.clone()))?;
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        cell_deps.insert(dao_cell_dep);

        let mut header_deps = Vec::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for DaoPrepareItem { input, lock_script } in &self.items {
            let out_point = input.previous_output();
            let tx_hash = out_point.tx_hash();
            let deposit_header = header_dep_resolver
                .resolve_by_tx_async(&tx_hash)
                .await
                .map_err(TxBuilderError::Other)?
                .ok_or_else(|| TxBuilderError::ResolveHeaderDepByTxHashFailed(tx_hash.clone()))?;
            let input_cell = tx_dep_provider.get_cell_async(&out_point).await?;
            if input_cell.type_().to_opt().as_ref() != Some(&dao_type_script) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "the input cell has invalid type script"
                )));
            }
            let input_lock_cell_dep = cell_dep_resolver
                .resolve(&input_cell.lock())
                .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(input_cell.lock()))?;
            let output = {
                let mut builder = input_cell.as_builder();
                if let Some(script) = lock_script {
                    builder = builder.lock(script.clone());
                }
                builder.build()
            };
            let output_data = Bytes::from(deposit_header.number().to_le_bytes().to_vec());

            cell_deps.insert(input_lock_cell_dep);
            header_deps.push(deposit_header.hash());
            inputs.push(input.clone());
            outputs.push(output);
            outputs_data.push(output_data.pack());
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_header_deps(header_deps)
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}

/// The dao withdraw receiver
///
#[derive(Debug, Clone)]
pub enum DaoWithdrawReceiver {
    /// Send all dao withdraw capacity to this lock script
    LockScript {
        script: Script,
        /// * `fee_rate`: If fee_rate is given, the fee is from withdraw capacity so
        ///   that no additional input and change cell is needed.
        fee_rate: Option<FeeRate>,
    },
    Custom {
        outputs: Vec<CellOutput>,
        outputs_data: Vec<Bytes>,
    },
}
#[derive(Debug, Clone)]
pub struct DaoWithdrawItem {
    /// The cell to withdraw (prepared cell)
    pub out_point: OutPoint,
    // TODO: let `XxxUnlocker` to produce the init witness
    /// The init witness with lock field filled with placeholder data (65 bytes
    /// 0u8 for sighash lock). If this field is `None` means the init witness is
    /// already included in current lock script group or will fill later in
    /// unlock action.
    pub init_witness: Option<WitnessArgs>,
}
/// Build a Nervos DAO withdraw Phase 2 transaction
#[derive(Debug, Clone)]
pub struct DaoWithdrawBuilder {
    /// Withdraw from those out_points (prepared cells)
    pub items: Vec<DaoWithdrawItem>,
    pub receiver: DaoWithdrawReceiver,
}

impl DaoWithdrawItem {
    pub fn new(out_point: OutPoint, init_witness: Option<WitnessArgs>) -> DaoWithdrawItem {
        DaoWithdrawItem {
            out_point,
            init_witness,
        }
    }
}
impl DaoWithdrawBuilder {
    pub fn new(items: Vec<DaoWithdrawItem>, receiver: DaoWithdrawReceiver) -> DaoWithdrawBuilder {
        DaoWithdrawBuilder { items, receiver }
    }
}

#[async_trait::async_trait]
impl TxBuilder for DaoWithdrawBuilder {
    async fn build_base_async(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.items.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "No cell to withdraw"
            )));
        }

        let dao_type_script = Script::new_builder()
            .code_hash(DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let dao_cell_dep = cell_dep_resolver
            .resolve(&dao_type_script)
            .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(dao_type_script.clone()))?;
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        cell_deps.insert(dao_cell_dep);

        let mut header_deps = Vec::new();
        let mut prepare_block_hashes = Vec::new();
        let mut inputs = Vec::new();
        let mut witnesses = Vec::new();
        let mut input_total = 0;
        for DaoWithdrawItem {
            out_point,
            init_witness,
        } in &self.items
        {
            let tx_hash = out_point.tx_hash();
            let prepare_header = header_dep_resolver
                .resolve_by_tx_async(&tx_hash)
                .await
                .map_err(TxBuilderError::Other)?
                .ok_or_else(|| TxBuilderError::ResolveHeaderDepByTxHashFailed(tx_hash.clone()))?;
            prepare_block_hashes.push(prepare_header.hash());
            let input_cell = tx_dep_provider.get_cell_async(out_point).await?;
            if input_cell.type_().to_opt().as_ref() != Some(&dao_type_script) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "the input cell has invalid type script"
                )));
            }
            let input_lock_cell_dep = cell_dep_resolver
                .resolve(&input_cell.lock())
                .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(input_cell.lock()))?;
            let data = tx_dep_provider.get_cell_data_async(out_point).await?;
            if data.len() != 8 {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "the input cell has invalid data length, expected: 8, got: {}",
                    data.len()
                )));
            }
            let deposit_number = {
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(data.as_ref());
                u64::from_le_bytes(number_bytes)
            };
            let deposit_header = match header_dep_resolver
                .resolve_by_number_async(deposit_number)
                .await
            {
                Err(_) => {
                    // for light client
                    let prepare_tx = tx_dep_provider.get_transaction_async(&tx_hash).await?;
                    for input in prepare_tx.inputs() {
                        let _ = header_dep_resolver
                            .resolve_by_tx_async(&input.previous_output().tx_hash())
                            .await
                            .map_err(TxBuilderError::Other)?;
                    }
                    header_dep_resolver
                        .resolve_by_number_async(deposit_number)
                        .await
                        .map_err(TxBuilderError::Other)?
                }
                Ok(i) => i,
            }
            .ok_or(TxBuilderError::ResolveHeaderDepByNumberFailed(
                deposit_number,
            ))?;
            let input = {
                let unlock_point = minimal_unlock_point(&deposit_header, &prepare_header);
                let since = Since::new(
                    SinceType::EpochNumberWithFraction,
                    unlock_point.full_value(),
                    false,
                );
                CellInput::new(out_point.clone(), since.value())
            };
            let deposit_block_hash = deposit_header.hash();
            let header_idx = header_deps
                .iter()
                .position(|hash| *hash == deposit_block_hash)
                .unwrap_or(header_deps.len());
            let witness = {
                let idx_data = Bytes::from((header_idx as u64).to_le_bytes().to_vec());
                init_witness
                    .clone()
                    .map(|witness| witness.as_builder())
                    .unwrap_or_else(WitnessArgs::new_builder)
                    .input_type(Some(idx_data).pack())
                    .build()
                    .as_bytes()
            };
            let occupied_capacity = input_cell
                .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                .unwrap();
            let input_capacity = calculate_dao_maximum_withdraw4(
                &deposit_header,
                &prepare_header,
                &input_cell,
                occupied_capacity.as_u64(),
            );
            input_total += input_capacity;

            cell_deps.insert(input_lock_cell_dep);
            if header_idx == header_deps.len() {
                header_deps.push(deposit_block_hash);
            }
            inputs.push(input);
            witnesses.push(witness.pack());
        }
        header_deps.extend(prepare_block_hashes.into_iter().collect::<HashSet<_>>());

        let (outputs, outputs_data) = match &self.receiver {
            DaoWithdrawReceiver::LockScript { script, fee_rate } => {
                let tmp_output = CellOutput::new_builder().lock(script.clone()).build();
                let occupied_capacity = tmp_output
                    .occupied_capacity(Capacity::zero())
                    .unwrap()
                    .as_u64();
                let capacity = if let Some(fee_rate) = fee_rate {
                    let tmp_tx = TransactionBuilder::default()
                        .set_cell_deps(cell_deps.clone().into_iter().collect())
                        .set_header_deps(header_deps.clone())
                        .set_inputs(inputs.clone())
                        .set_outputs(vec![tmp_output.clone()])
                        .set_outputs_data(vec![Bytes::new().pack()])
                        .set_witnesses(witnesses.clone())
                        .build();
                    let tx_size = tmp_tx.data().as_reader().serialized_size_in_block();
                    let tx_fee = fee_rate.fee(tx_size as u64).as_u64();
                    input_total - tx_fee
                } else {
                    input_total
                };
                let final_capacity = std::cmp::max(occupied_capacity, capacity);
                let output = tmp_output
                    .as_builder()
                    .capacity(final_capacity.pack())
                    .build();
                (vec![output], vec![Bytes::new().pack()])
            }
            DaoWithdrawReceiver::Custom {
                outputs,
                outputs_data,
            } => {
                if outputs.len() != outputs_data.len() {
                    return Err(TxBuilderError::InvalidParameter(anyhow!(
                        "receiver outputs length ({}) not match with outputs data length ({})",
                        outputs.len(),
                        outputs_data.len(),
                    )));
                }
                (
                    outputs.clone(),
                    outputs_data.iter().map(|data| data.pack()).collect(),
                )
            }
        };

        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_header_deps(header_deps)
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .set_witnesses(witnesses)
            .build())
    }
}
