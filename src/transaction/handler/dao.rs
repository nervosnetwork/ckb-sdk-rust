use std::collections::HashMap;

use anyhow::anyhow;
use ckb_types::{
    core::{Capacity, DepType, ScriptHashType},
    h256,
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::{Builder, Entity, Pack, Unpack},
};
use lazy_static::lazy_static;

use crate::{
    constants,
    traits::{
        DefaultHeaderDepResolver, DefaultTransactionDependencyProvider, HeaderDepResolver,
        LiveCell, TransactionDependencyProvider,
    },
    transaction::{builder::PrepareTransactionViewer, input::TransactionInput},
    tx_builder::{
        dao::{DaoDepositReceiver, DaoPrepareItem},
        TxBuilderError,
    },
    util::{calculate_dao_maximum_withdraw4, minimal_unlock_point},
    NetworkInfo, NetworkType, ScriptGroup, Since, SinceType,
};

use super::{HandlerContext, ScriptHandler};

pub const DAO_DATA_LEN: usize = 8;
lazy_static! {
    static ref DAO_TYPE_SCRIPT: Script = Script::new_builder()
        .code_hash(constants::DAO_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .build();
    static ref DEPOSIT_CELL_DATA: ckb_types::packed::Bytes =
        bytes::Bytes::from(vec![0u8; DAO_DATA_LEN]).pack();
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

pub struct WithdrawPhrase2Context {
    /// Withdraw from those out_points (prepared cells)
    items: Vec<OutPoint>,
    rpc_url: String,
    // input_index => deposit_header_index
    deposit_header_indexes: HashMap<usize, usize>,
}

impl WithdrawPhrase2Context {
    pub fn new(items: Vec<OutPoint>, rpc_url: String) -> Self {
        Self {
            items,
            rpc_url,
            deposit_header_indexes: HashMap::new(),
        }
    }
}

impl HandlerContext for WithdrawPhrase2Context {}

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
        viewer: &mut PrepareTransactionViewer,
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
            viewer.transaction_inputs.push(transaction_input);

            viewer.tx.dedup_header_dep(deposit_header.hash());

            viewer.tx.output(output);
            viewer.tx.output_data(output_data.pack());
        }
        Ok(())
    }

    pub fn build_phrase2_base(
        viewer: &mut PrepareTransactionViewer,
        context: &mut WithdrawPhrase2Context,
    ) -> Result<(), TxBuilderError> {
        if context.items.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "No cell to withdraw"
            )));
        }

        let header_dep_resolver = DefaultHeaderDepResolver::new(&context.rpc_url);
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(&context.rpc_url, 10);

        let mut prepare_block_hashes = Vec::new();
        for out_point in &context.items {
            let tx_hash = out_point.tx_hash();
            let prepare_header = header_dep_resolver
                .resolve_by_tx(&tx_hash)
                .map_err(TxBuilderError::Other)?
                .ok_or_else(|| TxBuilderError::ResolveHeaderDepByTxHashFailed(tx_hash.clone()))?;
            prepare_block_hashes.push(prepare_header.hash());
            let input_cell = tx_dep_provider.get_cell(out_point)?;
            if input_cell.type_().to_opt().as_ref() != Some(&DAO_TYPE_SCRIPT) {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "the input cell has invalid type script"
                )));
            }

            let data = tx_dep_provider.get_cell_data(out_point)?;
            if data.len() != DAO_DATA_LEN {
                return Err(TxBuilderError::InvalidParameter(anyhow!(
                    "the input cell has invalid data length, expected: 8, got: {}",
                    data.len()
                )));
            }

            let deposit_header = {
                let deposit_number = {
                    let mut number_bytes = [0u8; DAO_DATA_LEN];
                    number_bytes.copy_from_slice(data.as_ref());
                    u64::from_le_bytes(number_bytes)
                };
                header_dep_resolver
                    .resolve_by_number(deposit_number)
                    .or_else(|_err| {
                        // for light client
                        let prepare_tx = tx_dep_provider.get_transaction(&tx_hash)?;
                        for input in prepare_tx.inputs() {
                            let _ = header_dep_resolver
                                .resolve_by_tx(&input.previous_output().tx_hash())?;
                        }
                        header_dep_resolver.resolve_by_number(deposit_number)
                    })
                    .map_err(TxBuilderError::Other)?
                    .ok_or(TxBuilderError::ResolveHeaderDepByNumberFailed(
                        deposit_number,
                    ))?
            };

            // calculate reward
            {
                let occupied_capacity = input_cell
                    .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                    .unwrap();
                let input_capacity = calculate_dao_maximum_withdraw4(
                    &deposit_header,
                    &prepare_header,
                    &input_cell,
                    occupied_capacity.as_u64(),
                );
                let tmp_capacity: u64 = input_cell.capacity().unpack();
                *viewer.reward += input_capacity - tmp_capacity;
            }
            // build live cell
            {
                let unlock_point = minimal_unlock_point(&deposit_header, &prepare_header);
                let since = Since::new(
                    SinceType::EpochNumberWithFraction,
                    unlock_point.full_value(),
                    false,
                );
                let live_cell = LiveCell {
                    output: input_cell,
                    output_data: data,
                    out_point: out_point.clone(),
                    block_number: deposit_header.number(),
                    tx_index: u32::MAX, // TODO set correct tx_index
                };
                let transaction_input = TransactionInput::new(live_cell, since.value());
                viewer.transaction_inputs.push(transaction_input);
            };
            let deposit_block_hash = deposit_header.hash();
            let dep_header_idx = viewer.tx.dedup_header_dep(deposit_block_hash);
            context
                .deposit_header_indexes
                .insert(viewer.transaction_inputs.len() - 1, dep_header_idx);
        }
        viewer.tx.dedup_header_deps(prepare_block_hashes);

        Ok(())
    }

    pub fn build_deposit(
        viewer: &mut PrepareTransactionViewer,
        context: &DepositContext,
    ) -> Result<(), TxBuilderError> {
        if context.receivers.is_empty() {
            return Err(TxBuilderError::InvalidParameter(anyhow!(
                "empty dao receivers"
            )));
        }
        for receiver in &context.receivers {
            let output = CellOutput::new_builder()
                .capacity(receiver.capacity.pack())
                .lock(receiver.lock_script.clone())
                .type_(Some(DAO_TYPE_SCRIPT.clone()).pack())
                .build();
            viewer.tx.output(output);
            viewer.tx.output_data(DEPOSIT_CELL_DATA.clone());
        }

        Ok(())
    }
}

impl ScriptHandler for DaoScriptHandler {
    fn prepare_transaction(
        &self,
        viewer: &mut PrepareTransactionViewer,
        context: &mut dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if let Some(args) = context.as_any().downcast_ref::<DepositContext>() {
            Self::build_deposit(viewer, args)?;
            Ok(true)
        } else if let Some(args) = context.as_any().downcast_ref::<WithdrawPhrase1Context>() {
            Self::build_phrase1_base(viewer, args)?;
            Ok(true)
        } else if let Some(args) = context.as_mut().downcast_mut::<WithdrawPhrase2Context>() {
            Self::build_phrase2_base(viewer, args)?;
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
        if context.as_any().is::<DepositContext>()
            || context.as_any().is::<WithdrawPhrase1Context>()
        {
            tx_data.dedup_cell_deps(self.cell_deps.clone());
            Ok(true)
        } else if let Some(args) = context.as_any().downcast_ref::<WithdrawPhrase2Context>() {
            tx_data.dedup_cell_deps(self.cell_deps.clone());
            if let Some(idx) = script_group.input_indices.last() {
                if let Some(dep_header_idx) = args.deposit_header_indexes.get(idx) {
                    let idx_data =
                        bytes::Bytes::from((*dep_header_idx as u64).to_le_bytes().to_vec());
                    tx_data.set_witness_input(*idx, Some(idx_data));
                }
            }
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
