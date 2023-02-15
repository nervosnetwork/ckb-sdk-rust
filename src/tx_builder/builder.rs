use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::util::parse_hex_str;
use crate::ScriptGroup;
use crate::{
    rpc::CkbRpcClient,
    traits::{
        CellCollector, CellDepResolver, DefaultCellCollector, DefaultCellDepResolver,
        DefaultHeaderDepResolver, DefaultTransactionDependencyProvider, HeaderDepResolver,
        TransactionDependencyProvider,
    },
    tx_builder::CapacityBalancer,
    unlock::ScriptUnlocker,
    Address, HumanCapacity, NetworkInfo, ScriptId,
};
use ckb_jsonrpc_types as json_types;
use ckb_types::core::TransactionView;
use ckb_types::packed::{Byte32, OutPoint};
use ckb_types::H256;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, FeeRate},
    packed::{CellDep, CellOutput, Script, WitnessArgs},
    prelude::*,
};

use super::TxBuilderError;

/// base transaction builder
pub struct BaseTransactionBuilder {
    pub ckb_client: CkbRpcClient,
    pub sender: Address,
    pub outputs: Vec<(CellOutput, Bytes)>,
    pub cell_deps: HashSet<CellDep>,

    pub cell_collector: Box<dyn CellCollector>,
    pub cell_dep_resolver: Box<dyn CellDepResolver>,
    pub header_dep_resolver: Box<dyn HeaderDepResolver>,
    pub tx_dep_provider: Box<dyn TransactionDependencyProvider>,
    pub balancer: CapacityBalancer,
    pub unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
}

pub trait CkbTransactionBuilder {
    fn build_base(&mut self) -> Result<TransactionView, TxBuilderError>;
    /// build a balanced transaction
    fn build_balanced(&mut self) -> Result<TransactionView, TxBuilderError>;
    /// build a balanced transaction and unlocked
    fn build_unlocked(&mut self) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError>;
    /// build a balanced transaction and check cycle limit and the transaction is unlocked.
    fn build_balance_unlocked(
        &mut self,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError>;
}

impl BaseTransactionBuilder {
    /// build a new BaseTransactionBuilder.
    /// The placeholder_witness is default with 65 bytes lock, can be replaced later with set_placeholder_witness.
    /// # Arguments:
    ///   * `network_info` network type and url
    ///   * `sender` the sender address string
    pub fn new(
        network_info: NetworkInfo,
        sender_addr: &str,
    ) -> Result<BaseTransactionBuilder, TxBuilderError> {
        let sender_address =
            Address::from_str(sender_addr).map_err(TxBuilderError::AddressFormat)?;

        Self::new_with_address(network_info, sender_address)
    }

    pub fn new_with_address(
        network_info: NetworkInfo,
        sender_address: Address,
    ) -> Result<BaseTransactionBuilder, TxBuilderError> {
        let mut ckb_client = CkbRpcClient::new(network_info.url.as_str());
        let cell_dep_resolver = {
            let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
            DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block)).unwrap()
        };
        let cell_collector = DefaultCellCollector::new(&network_info.url);
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(&network_info.url, 10);

        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();

        let sender = sender_address.payload().into();
        let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);
        Ok(Self {
            ckb_client,
            sender: sender_address,
            outputs: vec![],
            cell_deps: HashSet::new(),
            cell_collector: Box::new(cell_collector),
            cell_dep_resolver: Box::new(cell_dep_resolver),
            header_dep_resolver: Box::new(DefaultHeaderDepResolver::new(&network_info.url)),
            tx_dep_provider: Box::new(tx_dep_provider),
            balancer,
            unlockers: HashMap::new(),
        })
    }

    /// build a output from address and capacity.
    pub fn build_output(receiver: &Address, capacity: HumanCapacity) -> CellOutput {
        CellOutput::new_builder()
            .lock(Script::from(receiver))
            .capacity(capacity.pack())
            .build()
    }
    /// Add output from receiver address and capacity
    /// # Arguments:
    ///   * `receiver_addr` receiver address string
    ///   * `capacity` capacity in shannon
    pub fn add_output_raw(
        &mut self,
        receiver_addr: &str,
        capacity: u64,
    ) -> Result<(), TxBuilderError> {
        let receiver_address =
            Address::from_str(receiver_addr).map_err(TxBuilderError::AddressFormat)?;
        let hum_capacity = HumanCapacity(capacity);
        let output = Self::build_output(&receiver_address, hum_capacity);
        self.outputs.push((output, Bytes::default()));
        Ok(())
    }

    pub fn add_output(&mut self, receiver: &Address, capacity: HumanCapacity) {
        let output = Self::build_output(receiver, capacity);
        self.outputs.push((output, Bytes::default()));
    }
    /// Add output with data from receiver address and capacity
    /// # Arguments:
    ///   * `receiver_addr` receiver address string
    ///   * `capacity` capacity in shannon
    pub fn add_output_data(&mut self, receiver: &Address, capacity: HumanCapacity, data: Bytes) {
        let output = Self::build_output(receiver, capacity);
        self.outputs.push((output, data));
    }

    pub fn set_fee_rate(&mut self, fee_rate: FeeRate) {
        self.balancer.fee_rate = fee_rate;
    }

    /// Set change lock script instead of use the same script of sender
    pub fn set_change_lock_script(&mut self, change_lock_script: Script) {
        self.balancer.change_lock_script = Some(change_lock_script);
    }

    /// Set change lock script instead of use the same script of sender
    pub fn set_change_addr(&mut self, change_addr: &str) -> Result<(), TxBuilderError> {
        let change_address =
            Address::from_str(change_addr).map_err(TxBuilderError::AddressFormat)?;
        self.balancer.change_lock_script = Some(Script::from(&change_address));
        Ok(())
    }
    /// Set the place holder witness if the default witness not fit the requirements.
    /// If can find a value with script, new place holder witness will be set, or the value will be appended.
    /// # Arguments:
    /// * `script` key to search the old place holder witness
    /// * `placeholder_witness` the new value
    pub fn set_placeholder_witness(&mut self, script: Script, placeholder_witness: WitnessArgs) {
        self.balancer
            .capacity_provider
            .set_witness(script, placeholder_witness);
    }

    pub fn set_sender_placeholder_witness(&mut self, placeholder_witness: WitnessArgs) {
        let script = Script::from(&self.sender);
        self.set_placeholder_witness(script, placeholder_witness);
    }

    /// clear the change lock script, so it will use the sender's according script.
    pub fn clear_change_lock_script(&mut self) {
        self.balancer.change_lock_script = None;
    }

    /// insert a cell cep to cell_dep_resolver
    pub fn insert_resolv_cell_dep(&mut self, code_hash: H256, tx_hash: H256, index: u32) {
        let out_point = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes()).unwrap(), index);
        let cell_dep = CellDep::new_builder().out_point(out_point).build();
        let script_id = ScriptId::new_type(code_hash);

        self.cell_dep_resolver.insert(script_id, cell_dep);
    }

    /// insert a cell cep to cell_dep_resolver
    pub fn insert_resolv_cell_dep_str(
        &mut self,
        code_hash: &str,
        tx_hash: &str,
        index: u32,
    ) -> Result<(), TxBuilderError> {
        let code_hash: H256 = parse_hex_str(code_hash).map_err(TxBuilderError::KeyFormat)?;
        let tx_hash: H256 = parse_hex_str(tx_hash).map_err(TxBuilderError::KeyFormat)?;

        let out_point = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes()).unwrap(), index);
        let cell_dep = CellDep::new_builder().out_point(out_point).build();
        let script_id = ScriptId::new_type(code_hash);

        self.cell_dep_resolver.insert(script_id, cell_dep);
        Ok(())
    }

    /// add a built unlocker
    pub fn add_unlocker(&mut self, unlocker: Box<dyn ScriptUnlocker>) {
        let address_payload = Script::from(&self.sender);
        let script_id = ScriptId::from(&address_payload);

        self.unlockers.insert(script_id, unlocker);
    }

    /// send a signed transaction
    pub fn send_transaction(
        &mut self,
        transaction: TransactionView,
    ) -> Result<H256, TxBuilderError> {
        // Send transaction
        let json_tx = json_types::TransactionView::from(transaction);
        // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = self
            .ckb_client
            .send_transaction(json_tx.inner, outputs_validator)?;
        Ok(tx_hash)
    }
}

macro_rules! impl_default_builder {
    ($name:ident, $base_name: ident) => {
        impl Deref for $name {
            type Target = BaseTransactionBuilder;

            fn deref(&self) -> &Self::Target {
                &self.base_builder
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.base_builder
            }
        }

        impl CkbTransactionBuilder for $name {
            fn build_base(&mut self) -> Result<TransactionView, TxBuilderError> {
                let builder = $base_name::from(&*self);
                builder.build_base(
                    self.base_builder.cell_collector.as_mut(),
                    self.base_builder.cell_dep_resolver.as_ref(),
                    self.base_builder.header_dep_resolver.as_ref(),
                    self.base_builder.tx_dep_provider.as_ref(),
                )
            }

            fn build_balanced(&mut self) -> Result<TransactionView, TxBuilderError> {
                let builder = $base_name::from(&*self);
                builder.build_balanced(
                    self.base_builder.cell_collector.as_mut(),
                    self.base_builder.cell_dep_resolver.as_ref(),
                    self.base_builder.header_dep_resolver.as_ref(),
                    self.base_builder.tx_dep_provider.as_ref(),
                    &self.base_builder.balancer,
                    &self.base_builder.unlockers,
                )
            }

            fn build_unlocked(
                &mut self,
            ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
                let builder = $base_name::from(&*self);
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
                let builder = $base_name::from(&*self);
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
    };
}
pub(crate) use impl_default_builder;
