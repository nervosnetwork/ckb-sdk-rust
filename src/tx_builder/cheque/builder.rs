use crate::{
    parser::Parser,
    traits::{CellQueryOptions, ValueRangeOption},
    tx_builder::{
        builder::{impl_default_builder, BaseTransactionBuilder, CkbTransactionBuilder},
        TxBuilder, TxBuilderError,
    },
    unlock::{ChequeAction, ChequeUnlocker, ScriptUnlocker, SecpSighashUnlocker},
    Address, NetworkInfo, ScriptGroup, ScriptId,
};
use anyhow::anyhow;
use bytes::Bytes;

use ckb_types::{
    core::{Capacity, CapacityError, FeeRate, TransactionView},
    packed::{Byte32, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H256,
};

use std::ops::{Deref, DerefMut};

use super::{
    get_default_script_id, ChequeClaimBuilder, ChequeWithdrawBuilder, ClaimReceiverOutput,
};

pub struct DefaultChequeClaimBuilder {
    pub base_builder: BaseTransactionBuilder,
    /// The cheque cells to claim, all cells must have same lock script and same
    /// type script and cell data length is equals to 16.
    pub inputs: Vec<CellInput>,

    /// Add all SUDT amount to this cell, the type script must be the same with
    /// `inputs`. The receiver output will keep the lock script, capacity.
    pub receiver_target: ClaimReceiverOutput,

    /// Sender's lock script, the script hash must match the cheque cell's lock script args.
    pub sender_lock_script: Script,
}

impl DefaultChequeClaimBuilder {
    pub fn new(
        network_info: NetworkInfo,
        capacity_provider_addr: &str,
    ) -> Result<Self, TxBuilderError> {
        let capacity_vendor_address =
            Address::parse(capacity_provider_addr).map_err(TxBuilderError::AddressFormat)?;
        Self::new_with_address(network_info, capacity_vendor_address)
    }

    pub fn new_mainnet(sender_addr: &str) -> Result<Self, TxBuilderError> {
        Self::new(NetworkInfo::mainnet(), sender_addr)
    }

    pub fn new_with_address(
        network_info: NetworkInfo,
        capacity_provider_addr: Address,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new_with_address(
                network_info,
                capacity_provider_addr,
            )?,
            inputs: Vec::new(),
            receiver_target: ClaimReceiverOutput::default(),
            sender_lock_script: Script::default(),
        })
    }

    pub fn add_input(&mut self, input: CellInput) {
        self.inputs.push(input);
    }
    pub fn add_inputs(&mut self, inputs: &mut Vec<CellInput>) {
        self.inputs.append(inputs);
    }
    pub fn add_cheque_output_cell_str(
        &mut self,
        tx_hash: &str,
        idx: u32,
    ) -> Result<(), TxBuilderError> {
        let tx_hash =
            H256::parse(tx_hash).map_err(|e| TxBuilderError::InvalidParameter(anyhow!("{}", e)))?;
        self.add_cheque_output_cell(tx_hash, idx);
        Ok(())
    }
    pub fn add_cheque_output_cell(&mut self, tx_hash: H256, idx: u32) {
        let outpoint = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes()).unwrap(), idx);
        self.add_cheque_output(outpoint);
    }

    pub fn add_cheque_output(&mut self, outpoint: OutPoint) {
        let cheque_output = CellInput::new_builder()
            .previous_output(outpoint)
            .since(0u64.pack())
            .build();
        self.inputs.push(cheque_output);
    }
    pub fn add_cheque_outputs(&mut self, outpoints: Vec<OutPoint>) {
        for v in outpoints {
            self.add_cheque_output(v);
        }
    }

    pub fn set_sender_lock_script(&mut self, script: Script) {
        self.sender_lock_script = script;
    }

    pub fn set_receiver_target(&mut self, target: ClaimReceiverOutput) {
        self.receiver_target = target;
    }
    /// build a Create receiver target, type script from first input, lock script from receiver address, sudt amount is 0
    pub fn build_sudt_receiver_target(
        &mut self,
        receiver_addr: &Address,
    ) -> Result<(), TxBuilderError> {
        if self.inputs.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "claim input not set yet"
            )));
        }
        let lock_script = Script::from(receiver_addr.payload());
        let out_point = self.inputs[0].previous_output();
        let input_cell = self.base_builder.tx_dep_provider.get_cell(&out_point)?;
        let type_script = input_cell.type_();
        let mp_fun = |e: CapacityError| TxBuilderError::Other(anyhow!(e.to_string()));
        let cell_output = CellOutput::new_builder()
            .lock(lock_script)
            .type_(type_script)
            .build_exact_capacity(Capacity::bytes(16).map_err(mp_fun)?)
            .map_err(mp_fun)?;

        let output_data = Bytes::from(vec![0u8; 16]);
        self.receiver_target = ClaimReceiverOutput::Create {
            cell_output,
            output_data,
        };

        Ok(())
    }

    pub fn build_sudt_receiver_target_by_addr_str(
        &mut self,
        receiver_addr: &str,
    ) -> Result<(), TxBuilderError> {
        let receiver_addr = Address::parse(receiver_addr)
            .map_err(|e| TxBuilderError::InvalidParameter(anyhow!("can't parse address {}", e)))?;
        self.build_sudt_receiver_target(&receiver_addr)
    }

    // find a cell for receiver for update
    pub fn query_sudt_receiver_target(
        &mut self,
        receiver_addr: &Address,
    ) -> Result<(), TxBuilderError> {
        if self.inputs.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "claim input not set yet."
            )));
        }
        let lock_script = Script::from(receiver_addr.payload());
        let out_point = self.inputs[0].previous_output();
        let input_cell = self.base_builder.tx_dep_provider.get_cell(&out_point)?;
        let type_script = input_cell.type_();

        let base_query = {
            let mut query = CellQueryOptions::new_lock(lock_script);
            query.secondary_script = type_script.to_opt();
            query.data_len_range = Some(ValueRangeOption::new_min(16));
            query
        };

        let (more_cells, _more_capacity) = self
            .base_builder
            .cell_collector
            .collect_live_cells(&base_query, false)?;
        if more_cells.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "can't collect more cells according to first input's type script and receiver address"
            )));
        }
        let receiver_cell = more_cells[0].out_point.clone();
        let receiver_input = CellInput::new_builder()
            .previous_output(receiver_cell)
            .since(0u64.pack())
            .build();
        self.receiver_target = ClaimReceiverOutput::Update(receiver_input);

        Ok(())
    }

    // find a cell for receiver for update
    pub fn query_sudt_receiver_target_by_addr_str(
        &mut self,
        receiver_addr: &str,
    ) -> Result<(), TxBuilderError> {
        let receiver_addr = Address::parse(receiver_addr)
            .map_err(|e| TxBuilderError::InvalidParameter(anyhow!("can't parse address {}", e)))?;
        self.query_sudt_receiver_target(&receiver_addr)
    }

    pub fn add_sighash_unlocker_from_str<T: AsRef<str>>(
        &mut self,
        keys: &[T],
    ) -> Result<(), TxBuilderError> {
        let mut sign_keys = Vec::with_capacity(keys.len());
        for key in keys.iter() {
            let sender_key: H256 = H256::parse(key.as_ref()).map_err(TxBuilderError::KeyFormat)?;
            sign_keys.push(sender_key);
        }
        self.add_sighash_unlocker(&sign_keys)
    }

    /// add a sighash unlocker with private keys
    pub fn add_sighash_unlocker(&mut self, sign_keys: &[H256]) -> Result<(), TxBuilderError> {
        let sighash_unlocker = SecpSighashUnlocker::new_with_secret_h256(sign_keys)
            .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
        let sighash_script_id = SecpSighashUnlocker::script_id();
        self.unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );

        let cheque_unlocker = ChequeUnlocker::new_with_secret_h256(sign_keys, ChequeAction::Claim)
            .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
        let cheque_script_id = get_default_script_id(self.base_builder.network_info.network_type);
        self.base_builder.unlockers.insert(
            cheque_script_id,
            Box::new(cheque_unlocker) as Box<dyn ScriptUnlocker>,
        );
        Ok(())
    }
}

impl From<&DefaultChequeClaimBuilder> for ChequeClaimBuilder {
    fn from(val: &DefaultChequeClaimBuilder) -> Self {
        ChequeClaimBuilder::new_with_receiver_output(
            val.inputs.clone(),
            val.receiver_target.clone(),
            val.sender_lock_script.clone(),
        )
    }
}

impl_default_builder!(DefaultChequeClaimBuilder, ChequeClaimBuilder);

pub struct DefaultChequeWithdrawBuilder {
    pub base_builder: BaseTransactionBuilder,
    /// The cheque cells to withdraw, all cells must have same lock script and same
    /// type script and cell data length is equals to 16.
    pub cheque_out_points: Vec<OutPoint>,

    /// Sender's lock script, must be a sighash address, and the script hash
    /// must match the cheque cell's lock script args.
    pub sender_lock_script: Script,

    /// If `acp_script_id` provided, will withdraw to anyone-can-pay address
    pub acp_script_id: Option<ScriptId>,
    /// * `fee_rate`: If fee_rate is given, the fee is from withdraw capacity so
    /// that no additional input and change cell is needed.
    fee_rate: Option<FeeRate>,
}

impl DefaultChequeWithdrawBuilder {
    pub fn new(
        network_info: NetworkInfo,
        capacity_provider_addr: &str,
    ) -> Result<Self, TxBuilderError> {
        let capacity_vendor_address =
            Address::parse(capacity_provider_addr).map_err(TxBuilderError::AddressFormat)?;
        Self::new_with_address(network_info, capacity_vendor_address)
    }

    pub fn new_mainnet(sender_addr: &str) -> Result<Self, TxBuilderError> {
        Self::new(NetworkInfo::mainnet(), sender_addr)
    }

    pub fn new_with_address(
        network_info: NetworkInfo,
        capacity_provider_addr: Address,
    ) -> Result<Self, TxBuilderError> {
        let sender_lock_script = Script::from(capacity_provider_addr.payload());
        let base_builder =
            BaseTransactionBuilder::new_with_address(network_info, capacity_provider_addr)?;
        let fee_rate = Some(base_builder.balancer.fee_rate);
        Ok(Self {
            base_builder,
            cheque_out_points: Vec::new(),
            acp_script_id: None,
            sender_lock_script,
            fee_rate,
        })
    }

    pub fn add_cheque_outpoint_str(
        &mut self,
        tx_hash: &str,
        idx: u32,
    ) -> Result<(), TxBuilderError> {
        let tx_hash =
            H256::parse(tx_hash).map_err(|e| TxBuilderError::InvalidParameter(anyhow!("{}", e)))?;
        self.add_cheque_outpoint_cell(tx_hash, idx);
        Ok(())
    }
    pub fn add_cheque_outpoint_cell(&mut self, tx_hash: H256, idx: u32) {
        let outpoint = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes()).unwrap(), idx);
        self.add_cheque_outpoint(outpoint);
    }

    pub fn add_cheque_outpoint(&mut self, cheque_output: OutPoint) {
        self.cheque_out_points.push(cheque_output);
    }
    pub fn add_cheque_outpoints(&mut self, outpoints: Vec<OutPoint>) {
        for v in outpoints {
            self.add_cheque_outpoint(v);
        }
    }

    pub fn set_sender_lock_script(&mut self, script: Script) {
        self.sender_lock_script = script;
    }
    pub fn set_sender_lock_script_by_addr(&mut self, addr: &Address) {
        let script = Script::from(addr.payload());
        self.sender_lock_script = script;
    }
    pub fn set_sender_lock_script_by_addr_str(&mut self, addr: &str) -> Result<(), TxBuilderError> {
        let address =
            Address::parse(addr).map_err(|e| TxBuilderError::InvalidParameter(anyhow!("{}", e)))?;
        self.set_sender_lock_script_by_addr(&address);
        Ok(())
    }
    pub fn set_acp_script_id(&mut self, script_id: Option<ScriptId>) {
        self.acp_script_id = script_id;
    }

    pub fn add_sighash_unlocker_from_str<T: AsRef<str>>(
        &mut self,
        keys: &[T],
    ) -> Result<(), TxBuilderError> {
        let mut sign_keys = Vec::with_capacity(keys.len());
        for key in keys.iter() {
            let sender_key: H256 = H256::parse(key.as_ref()).map_err(TxBuilderError::KeyFormat)?;
            sign_keys.push(sender_key);
        }
        self.add_sighash_unlocker(&sign_keys)
    }

    /// add a sighash unlocker with private keys
    pub fn add_sighash_unlocker(&mut self, sign_keys: &[H256]) -> Result<(), TxBuilderError> {
        let sighash_unlocker = SecpSighashUnlocker::new_with_secret_h256(sign_keys)
            .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
        let sighash_script_id = SecpSighashUnlocker::script_id();
        self.unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );

        let cheque_unlocker =
            ChequeUnlocker::new_with_secret_h256(sign_keys, ChequeAction::Withdraw)
                .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
        let cheque_script_id = get_default_script_id(self.base_builder.network_info.network_type);
        self.base_builder.unlockers.insert(
            cheque_script_id,
            Box::new(cheque_unlocker) as Box<dyn ScriptUnlocker>,
        );
        Ok(())
    }
}

impl From<&DefaultChequeWithdrawBuilder> for ChequeWithdrawBuilder {
    fn from(val: &DefaultChequeWithdrawBuilder) -> Self {
        let mut v = ChequeWithdrawBuilder::new(
            val.cheque_out_points.clone(),
            val.sender_lock_script.clone(),
            val.acp_script_id.clone(),
        );
        v.set_fee_rate(val.fee_rate);
        v
    }
}

impl_default_builder!(DefaultChequeWithdrawBuilder, ChequeWithdrawBuilder);
