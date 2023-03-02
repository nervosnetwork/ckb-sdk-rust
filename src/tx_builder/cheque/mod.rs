use std::collections::HashSet;

use anyhow::anyhow;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, FeeRate, ScriptHashType, TransactionBuilder, TransactionView},
    h256,
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};

use super::{TxBuilder, TxBuilderError};
use crate::{
    constants::{CHEQUE_CELL_SINCE, SIGHASH_TYPE_HASH},
    NetworkType,
};
use crate::{parser::Parser, types::ScriptId};
use crate::{
    traits::{
        CellCollector, CellDepResolver, CellQueryOptions, HeaderDepResolver,
        TransactionDependencyProvider, ValueRangeOption,
    },
    Address, AddressPayload,
};
/// this enum defines how the claim should store the output
#[derive(Debug, Clone)]
pub enum ClaimReceiverOutput {
    /// update a already existing cell
    Update(CellInput),
    /// create a new cell with cell output and output data, since it's a new create data, it's first 16 bytes muts be 0 for sudt.
    Create {
        cell_output: CellOutput,
        output_data: Bytes,
    },
    /// not set yet,
    None,
}

impl ClaimReceiverOutput {
    pub fn is_update(&self) -> bool {
        matches!(*self, Self::Update(_))
    }
    pub fn is_create(&self) -> bool {
        matches!(
            self,
            Self::Create {
                cell_output: _,
                output_data: _
            }
        )
    }
}

impl Default for ClaimReceiverOutput {
    fn default() -> Self {
        ClaimReceiverOutput::None
    }
}

pub struct ChequeClaimBuilder {
    /// The cheque cells to claim, all cells must have same lock script and same
    /// type script and cell data length is equals to 16.
    pub inputs: Vec<CellInput>,

    /// Add all SUDT amount to this cell, the type script must be the same with
    /// `inputs`. The receiver output will keep the lock script, capacity.
    pub receiver_input: ClaimReceiverOutput,

    /// Sender's lock script, the script hash must match the cheque cell's lock script args.
    pub sender_lock_script: Script,

    /// If fee_rate is given, the fee is from receiver's capacity so
    /// that no additional input and change cell is needed.
    pub fee_rate: Option<FeeRate>,
}

impl ChequeClaimBuilder {
    pub fn new(
        inputs: Vec<CellInput>,
        receiver_input: CellInput,
        sender_lock_script: Script,
    ) -> ChequeClaimBuilder {
        ChequeClaimBuilder {
            inputs,
            receiver_input: ClaimReceiverOutput::Update(receiver_input),
            sender_lock_script,
            fee_rate: None,
        }
    }
    pub fn new_with_receiver_output(
        inputs: Vec<CellInput>,
        receiver_output: ClaimReceiverOutput,
        sender_lock_script: Script,
    ) -> ChequeClaimBuilder {
        ChequeClaimBuilder {
            inputs,
            receiver_input: receiver_output,
            sender_lock_script,
            fee_rate: None,
        }
    }
    pub fn set_fee_rate(&mut self, fee_rate: Option<FeeRate>) {
        self.fee_rate = fee_rate;
    }
}

impl TxBuilder for ChequeClaimBuilder {
    fn build_base(
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
        let (receiver_input_cell, receiver_input_data) = match &self.receiver_input {
            ClaimReceiverOutput::Update(receiver_input) => {
                inputs.push(receiver_input.clone());
                (
                    tx_dep_provider.get_cell(&receiver_input.previous_output())?,
                    tx_dep_provider.get_cell_data(&receiver_input.previous_output())?,
                )
            }
            ClaimReceiverOutput::Create {
                cell_output,
                output_data,
            } => (cell_output.clone(), output_data.clone()),
            ClaimReceiverOutput::None => {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "receiver's target cell not set yet"
                )))
            }
        };

        let receiver_type_script = receiver_input_cell.type_().to_opt().ok_or_else(|| {
            TxBuilderError::InvalidParameter(anyhow!("receiver input missing type script"))
        })?;
        let receiver_input_lock_cell_dep =
            cell_dep_resolver
                .resolve(&receiver_input_cell.lock())
                .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(receiver_input_cell.lock()))?;
        cell_deps.insert(receiver_input_lock_cell_dep);

        if receiver_input_data.len() < 16 {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "invalid receiver input cell data length, expected at least 16, got: {}",
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
            let input_cell = tx_dep_provider.get_cell(&out_point)?;
            let input_data = tx_dep_provider.get_cell_data(&out_point)?;
            let type_script = input_cell.type_().to_opt().ok_or_else(|| {
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

        let mut receiver_output = receiver_input_cell;
        let receiver_output_data = {
            let receiver_output_amount = receiver_input_amount + cheque_total_amount;
            let mut new_data = receiver_input_data.as_ref().to_vec();
            new_data[0..16].copy_from_slice(&receiver_output_amount.to_le_bytes()[..]);
            Bytes::from(new_data)
        };

        let sender_output = CellOutput::new_builder()
            .lock(self.sender_lock_script.clone())
            .capacity(cheque_total_capacity.pack())
            .build();
        let sender_output_data = Bytes::new();

        let mut outputs = vec![receiver_output.clone(), sender_output];
        let outputs_data = vec![receiver_output_data.pack(), sender_output_data.pack()];
        let mut witness = vec![ckb_types::packed::Bytes::default(); self.inputs.len() + 1];
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build()
            .as_bytes()
            .pack();
        witness[self.inputs.len()] = placeholder_witness.clone();
        let receiver_lock_hash = receiver_output.lock().calc_script_hash();
        if receiver_lock_hash.as_slice()[0..20] != cheque_lock_args.as_ref()[0..20] {
            witness[0] = placeholder_witness.clone();
        }

        if let Some(fee_rate) = self.fee_rate {
            if self.receiver_input.is_update() {
                let occupied_capacity = receiver_output
                    .occupied_capacity(Capacity::bytes(receiver_output_data.len()).unwrap())
                    .unwrap()
                    .as_u64();

                let tmp_tx = TransactionBuilder::default()
                    .set_cell_deps(cell_deps.clone().into_iter().collect())
                    .set_inputs(inputs.clone())
                    .set_outputs(outputs.clone())
                    .set_outputs_data(outputs_data.clone())
                    .set_witnesses(witness.clone())
                    .build();

                let tx_size = tmp_tx.data().as_reader().serialized_size_in_block();
                let tx_fee = fee_rate.fee(tx_size as u64).as_u64();
                let original_capacity: u64 = receiver_output.capacity().unpack();
                let capacity = if original_capacity > tx_fee {
                    original_capacity - tx_fee
                } else {
                    original_capacity
                };
                let final_capacity = std::cmp::max(occupied_capacity, capacity);
                if final_capacity != original_capacity {
                    receiver_output = receiver_output
                        .as_builder()
                        .capacity(final_capacity.pack())
                        .build();
                    outputs[0] = receiver_output;
                }
            }
        }

        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .set_witnesses(witness)
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
    /// * `fee_rate`: If fee_rate is given, the fee is from withdraw capacity so
    /// that no additional input and change cell is needed.
    pub fee_rate: Option<FeeRate>,
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
            fee_rate: None,
        }
    }
    pub fn set_fee_rate(&mut self, fee_rate: Option<FeeRate>) {
        self.fee_rate = fee_rate;
    }
}

impl TxBuilder for ChequeWithdrawBuilder {
    fn build_base(
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
            let input_cell = tx_dep_provider.get_cell(out_point)?;
            let input_data = tx_dep_provider.get_cell_data(out_point)?;
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
                let (acp_cells, _) = cell_collector.collect_live_cells(&query, true)?;
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

        let mut sender_output = CellOutput::new_builder()
            .lock(sender_lock)
            .type_(Some(type_script).pack())
            .capacity(total_capacity.pack())
            .build();
        let sender_output_data = Bytes::from(total_amount.to_le_bytes().to_vec());
        let outputs_data = vec![sender_output_data.pack()];

        if let Some(fee_rate) = self.fee_rate {
            let occupied_capacity = sender_output
                .occupied_capacity(Capacity::zero())
                .unwrap()
                .as_u64();
            let placeholder_witness = WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                .build();
            let tmp_tx = TransactionBuilder::default()
                .set_cell_deps(cell_deps.clone().into_iter().collect())
                .set_inputs(inputs.clone())
                .set_outputs(vec![sender_output.clone()])
                .set_outputs_data(outputs_data.clone())
                .set_witnesses(vec![placeholder_witness.as_bytes().pack()])
                .build();

            let tx_size = tmp_tx.data().as_reader().serialized_size_in_block();
            let tx_fee = fee_rate.fee(tx_size as u64).as_u64();
            let capacity = if total_capacity > tx_fee {
                total_capacity - tx_fee
            } else {
                total_capacity
            };
            let final_capacity = std::cmp::max(occupied_capacity, capacity);
            sender_output = sender_output
                .as_builder()
                .capacity(final_capacity.pack())
                .build();
        }

        let outputs = vec![sender_output];

        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}

/// A cheque implementation metioned in the RFC:
/// https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0039-cheque/0039-cheque.md
pub const CHEQUE_CODE_HASH_MAINNET: H256 =
    h256!("0xe4d4ecc6e5f9a059bf2f7a82cca292083aebc0c421566a52484fe2ec51a9fb0c");
pub const CHEQUE_TX_HASH_MAINNET: H256 =
    h256!("0x04632cc459459cf5c9d384b43dee3e36f542a464bdd4127be7d6618ac6f8d268");
pub const CHEQUE_TX_INDEX_MAINNET: u32 = 0x0;

pub const CHEQUE_CODE_HASH_TESTNET: H256 =
    h256!("0x60d5f39efce409c587cb9ea359cefdead650ca128f0bd9cb3855348f98c70d5b");
pub const CHEQUE_TX_HASH_TESTNET: H256 =
    h256!("0x7f96858be0a9d584b4a9ea190e0420835156a6010a5fde15ffcdc9d9c721ccab");
pub const CHEQUE_TX_INDEX_TESTNET: u32 = 0x0;

pub fn build_cheque_address(
    network_type: NetworkType,
    sender: Address,
    receiver: Address,
) -> Address {
    let cheque_script_id = get_default_script_id(network_type);
    let sender_script_hash = Script::from(&sender).calc_script_hash();
    let receiver_script_hash = Script::from(&receiver).calc_script_hash();
    let mut script_args = vec![0u8; 40];
    script_args[0..20].copy_from_slice(&receiver_script_hash.as_slice()[0..20]);
    script_args[20..40].copy_from_slice(&sender_script_hash.as_slice()[0..20]);
    let cheque_script = Script::new_builder()
        .code_hash(cheque_script_id.code_hash.pack())
        .hash_type(cheque_script_id.hash_type.into())
        .args(Bytes::from(script_args).pack())
        .build();
    let cheque_payload = AddressPayload::from(cheque_script);
    Address::new(network_type, cheque_payload, true)
}

pub fn build_cheque_address_str(
    network_type: NetworkType,
    sender: &str,
    receiver: &str,
) -> Result<String, String> {
    let sender = Address::parse(sender)?;
    let receiver = Address::parse(receiver)?;
    let address = build_cheque_address(network_type, sender, receiver);
    Ok(address.to_string())
}

/// Add default cheque cell dependencies, the dependent cells are metioned in the RFC.
pub fn add_default_cheque_dep(dep_resolver: &mut dyn CellDepResolver, network_type: NetworkType) {
    let (code_hash, tx_hash, idx) = if network_type == NetworkType::Mainnet {
        (
            CHEQUE_CODE_HASH_MAINNET,
            CHEQUE_TX_HASH_MAINNET,
            CHEQUE_TX_INDEX_MAINNET,
        )
    } else if network_type == NetworkType::Testnet {
        (
            CHEQUE_CODE_HASH_TESTNET,
            CHEQUE_TX_HASH_TESTNET,
            CHEQUE_TX_INDEX_TESTNET,
        )
    } else {
        return;
    };

    let out_point = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes()).unwrap(), idx);
    let cell_dep = CellDep::new_builder()
        .out_point(out_point)
        .dep_type(DepType::DepGroup.into())
        .build();
    let script_id = ScriptId::new_type(code_hash);
    dep_resolver.insert(script_id, cell_dep);
}

pub fn get_default_script_id(network_type: NetworkType) -> ScriptId {
    let code_hash = if network_type == NetworkType::Mainnet {
        CHEQUE_CODE_HASH_MAINNET
    } else if network_type == NetworkType::Testnet {
        CHEQUE_CODE_HASH_TESTNET
    } else {
        panic!("can only handle mainnet and testnet");
    };
    ScriptId::new_type(code_hash)
}

mod builder;

pub use builder::{DefaultChequeClaimBuilder, DefaultChequeWithdrawBuilder};
