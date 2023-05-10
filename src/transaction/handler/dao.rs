use anyhow::anyhow;
use ckb_types::{
    core::{DepType, ScriptHashType},
    h256,
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::{Builder, Entity, Pack},
};
use lazy_static::lazy_static;

use crate::{
    constants,
    traits::{
        DefaultHeaderDepResolver, DefaultTransactionDependencyProvider, HeaderDepResolver, LiveCell,
    },
    transaction::input::TransactionInput,
    tx_builder::{
        dao::{DaoDepositReceiver, DaoPrepareItem},
        TxBuilderError,
    },
    NetworkInfo, NetworkType, ScriptGroup,
};

use super::{HandlerContext, ScriptHandler};

lazy_static! {
    static ref DAO_TYPE_SCRIPT: Script = Script::new_builder()
        .code_hash(constants::DAO_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .build();
}

pub struct DaoScriptHandler {
    cell_deps: Vec<CellDep>,
}

#[derive(Clone, Debug, Default)]
pub struct DepositContext {
    // lock script, capacity list
    pub receivers: Vec<DaoDepositReceiver>,
}

impl DepositContext {
    pub fn new(lock_script: Script, capacity: u64) -> Self {
        let mut ret = Self::default();
        ret.add_output(lock_script, capacity);
        ret
    }

    pub fn add_output(&mut self, lock_script: Script, capacity: u64) {
        self.receivers
            .push(DaoDepositReceiver::new(lock_script, capacity));
    }
}

impl HandlerContext for DepositContext {}

#[derive(Default)]
pub struct WithdrawPhrase1Context {
    pub items: Vec<DaoPrepareItem>,
    pub rpc_url: String,
}

impl WithdrawPhrase1Context {
    /// add input.
    /// If `receiver_lock` is `None` copy the lock script from input with same
    /// index, otherwise replace the lock script with the given script.
    pub fn add_input(&mut self, input: CellInput, receiver_lock: Option<Script>) {
        self.items.push(DaoPrepareItem {
            input,
            lock_script: receiver_lock,
        });
    }

    pub fn add_input_outpoint(&mut self, input_outpoint: OutPoint, receiver_lock: Option<Script>) {
        self.items.push(DaoPrepareItem {
            input: CellInput::new_builder()
                .previous_output(input_outpoint)
                .build(),
            lock_script: receiver_lock,
        });
    }

    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            ..Default::default()
        }
    }
}

impl HandlerContext for WithdrawPhrase1Context {}

impl DaoScriptHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        script.code_hash() == constants::DAO_TYPE_HASH.pack()
    }
    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let mut ret = Self { cell_deps: vec![] };
        ret.init(network)?;
        Ok(ret)
    }

    pub fn build_phrase1_base(
        transaction_inputs: &mut Vec<TransactionInput>,
        tx_data: &mut crate::core::TransactionBuilder,
        context: &WithdrawPhrase1Context,
    ) -> Result<(), TxBuilderError> {
        if context.items.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "No cell to prepare"
            )));
        }

        let header_dep_resolver = DefaultHeaderDepResolver::new(&context.rpc_url);
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(&context.rpc_url, 10);

        for DaoPrepareItem { input, lock_script } in &context.items {
            let out_point = input.previous_output();
            let tx_hash = out_point.tx_hash();
            let deposit_header = header_dep_resolver
                .resolve_by_tx(&tx_hash)
                .map_err(TxBuilderError::Other)?
                .ok_or_else(|| TxBuilderError::ResolveHeaderDepByTxHashFailed(tx_hash.clone()))?;
            let (input_cell, data) = tx_dep_provider.get_cell_with_data(&out_point)?;
            if input_cell.type_().to_opt().as_ref() != Some(&DAO_TYPE_SCRIPT) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "the input cell has invalid type script"
                )));
            }

            let output = {
                let mut builder = input_cell.clone().as_builder();
                if let Some(script) = lock_script {
                    builder = builder.lock(script.clone());
                }
                builder.build()
            };
            let output_data = bytes::Bytes::from(deposit_header.number().to_le_bytes().to_vec());

            let live_cell = LiveCell {
                output: input_cell,
                output_data: data,
                out_point,
                block_number: deposit_header.number(),
                tx_index: u32::MAX, // TODO set correct tx_index
            };
            let transaction_input = TransactionInput::new(live_cell, 0);
            transaction_inputs.push(transaction_input);

            tx_data.dedup_header_dep(deposit_header.hash());

            tx_data.output(output);
            tx_data.output_data(output_data.pack());
        }
        Ok(())
    }

    pub fn build_deposit(
        _transaction_inputs: &mut [TransactionInput],
        tx_data: &mut crate::core::TransactionBuilder,
        context: &DepositContext,
    ) -> Result<(), TxBuilderError> {
        if context.receivers.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "empty dao receivers"
            )));
        }
        let dao_type_script = Script::new_builder()
            .code_hash(constants::DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();

        for receiver in &context.receivers {
            let output = CellOutput::new_builder()
                .capacity(receiver.capacity.pack())
                .lock(receiver.lock_script.clone())
                .type_(Some(dao_type_script.clone()).pack())
                .build();
            tx_data.output(output);
            tx_data.output_data(bytes::Bytes::from(vec![0u8; 8]).pack());
        }

        Ok(())
    }
}

impl ScriptHandler for DaoScriptHandler {
    fn prepare_transaction(
        &self,
        transaction_inputs: &mut Vec<TransactionInput>,
        tx_data: &mut crate::core::TransactionBuilder,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if let Some(args) = context.as_any().downcast_ref::<DepositContext>() {
            Self::build_deposit(transaction_inputs, tx_data, args)?;
            Ok(true)
        } else if let Some(args) = context.as_any().downcast_ref::<WithdrawPhrase1Context>() {
            Self::build_phrase1_base(transaction_inputs, tx_data, args)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn build_transaction(
        &self,
        tx_data: &mut crate::core::TransactionBuilder,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if !self.is_match(&script_group.script) {
            return Ok(false);
        }
        if let Some(_args) = context.as_any().downcast_ref::<DepositContext>() {
            tx_data.dedup_cell_deps(self.cell_deps.clone());
            if !script_group.input_indices.is_empty() {
                let index = script_group.input_indices.first().unwrap();
                let witness = WitnessArgs::new_builder()
                    .lock(Some(bytes::Bytes::from(vec![0u8; 65])).pack())
                    .build();
                tx_data.set_witness(*index, witness.as_bytes().pack());
            }
            Ok(true)
        } else if let Some(_args) = context.as_any().downcast_ref::<WithdrawPhrase1Context>() {
            tx_data.dedup_cell_deps(self.cell_deps.clone());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let out_point = if network.network_type == NetworkType::Mainnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0xe2fb199810d49a4d8beec56718ba2593b665db9d52299a0f9e6e75416d73ff5c")
                        .pack(),
                )
                .index(2u32.pack())
                .build()
        } else if network.network_type == NetworkType::Testnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f")
                        .pack(),
                )
                .index(2u32.pack())
                .build()
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::Code.into())
            .build();
        self.cell_deps.push(cell_dep);
        Ok(())
    }
}
