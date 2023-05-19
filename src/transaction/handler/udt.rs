use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use ckb_types::{
    bytes,
    core::{Capacity, DepType},
    h256,
    packed::{CellDep, CellOutput, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
    H256,
};

use lazy_static::lazy_static;

use crate::{
    core::TransactionBuilder,
    traits::{CellCollector, CellQueryOptions, DefaultCellCollector, ValueRangeOption},
    transaction::{builder::PrepareTransactionViewer, input::TransactionInput},
    tx_builder::{udt::UdtType, TransferAction, TxBuilderError},
    NetworkInfo, NetworkType, ScriptGroup, ScriptGroupType, ScriptId,
};

use super::{HandlerContext, ScriptHandler};

lazy_static! {
    // Nervos implemented environment
    static ref MAINNET_SUDT_SCRIPT_ID: ScriptId = ScriptId::new_type(h256!("0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5"));
    static ref TESTNET_SUDT_SCRIPT_ID: ScriptId = ScriptId::new_type(h256!("0xc5e5dcf215925f7ef4dfaf5f4b4f105bc321c02776d6e7d52a1db3fcd9d011a4"));
}

pub struct UdtScriptHandler {
    cell_deps: Vec<CellDep>,
    script_id: ScriptId,
}

/// The udt issue/transfer receiver
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct UdtTargetReceiver {
    pub action: TransferAction,

    /// The lock script set to this udt cell, if `action` is `Update` will query
    /// input cell by this lock script.
    pub lock_script: Script,

    /// The capacity set to this udt cell when `action` is TransferAction::Create
    pub capacity: Option<u64>,

    /// The amount to issue/transfer
    pub amount: u128,

    /// Only for <xudt data> and only used when action == TransferAction::Create
    pub extra_data: Option<bytes::Bytes>,
}

pub struct ReceiverBuildOutput {
    pub input: Option<TransactionInput>,
    pub output: CellOutput,
    pub output_data: bytes::Bytes,
}

impl UdtTargetReceiver {
    pub fn new(action: TransferAction, lock_script: Script, amount: u128) -> UdtTargetReceiver {
        UdtTargetReceiver {
            action,
            lock_script,
            capacity: None,
            amount,
            extra_data: None,
        }
    }

    pub fn build(
        &self,
        type_script: &Script,
        cell_collector: &mut dyn CellCollector,
    ) -> Result<ReceiverBuildOutput, TxBuilderError> {
        match self.action {
            TransferAction::Create => {
                let data_len = self
                    .extra_data
                    .as_ref()
                    .map(|data| data.len())
                    .unwrap_or_default()
                    + 16;
                let mut data = BytesMut::with_capacity(data_len);
                data.put(&self.amount.to_le_bytes()[..]);
                if let Some(extra_data) = self.extra_data.as_ref() {
                    data.put(extra_data.as_ref());
                }

                let base_output = CellOutput::new_builder()
                    .lock(self.lock_script.clone())
                    .type_(Some(type_script.clone()).pack())
                    .build();
                let base_occupied_capacity = base_output
                    .occupied_capacity(Capacity::bytes(data_len).unwrap())
                    .unwrap()
                    .as_u64();
                let final_capacity = if let Some(capacity) = self.capacity.as_ref() {
                    if *capacity >= base_occupied_capacity {
                        *capacity
                    } else {
                        return Err(TxBuilderError::Other(anyhow!(
                            "Not enough capacity to hold a receiver cell, min: {}, actual: {}",
                            base_occupied_capacity,
                            *capacity,
                        )));
                    }
                } else {
                    base_occupied_capacity
                };
                let output = base_output
                    .as_builder()
                    .capacity(final_capacity.pack())
                    .build();
                Ok(ReceiverBuildOutput {
                    input: None,
                    output,
                    output_data: data.freeze(),
                })
            }
            TransferAction::Update => {
                let receiver_query = {
                    let mut query = CellQueryOptions::new_lock(self.lock_script.clone());
                    query.secondary_script = Some(type_script.clone());
                    query.data_len_range = Some(ValueRangeOption::new_min(16));
                    query
                };
                let (receiver_cells, _) =
                    cell_collector.collect_live_cells(&receiver_query, true)?;
                if receiver_cells.is_empty() {
                    return Err(TxBuilderError::Other(anyhow!(
                        "update receiver cell failed, cell not found, lock={:?}",
                        self.lock_script
                    )));
                }

                let mut amount_bytes = [0u8; 16];
                let receiver_cell = receiver_cells.into_iter().next().unwrap();
                amount_bytes.copy_from_slice(&receiver_cell.output_data.as_ref()[0..16]);
                let old_amount = u128::from_le_bytes(amount_bytes);
                let new_amount = old_amount + self.amount;
                let mut new_data = receiver_cell.output_data.as_ref().to_vec();
                new_data[0..16].copy_from_slice(&new_amount.to_le_bytes()[..]);
                let output_data = bytes::Bytes::from(new_data);

                Ok(ReceiverBuildOutput {
                    output: receiver_cell.output.clone(),
                    input: Some(receiver_cell.into()),
                    output_data,
                })
            }
        }
    }
}

pub struct UdtIssueContext {
    /// The udt type (sudt/xudt)
    pub udt_type: UdtType,

    /// The sudt/xudt script id
    pub script_id: ScriptId,

    /// We will collect a cell from owner, there must exists a cell that:
    ///   * type script is None
    ///   * data field is empty
    ///   * is mature
    pub owner: Script,

    /// The receivers
    pub receivers: Vec<UdtTargetReceiver>,
    pub rpc_url: String,
}

impl UdtIssueContext {
    pub fn new_simple(owner: Script, receiver:Script, amount: u128, net_info: &NetworkInfo) -> Self {
        let receiver = UdtTargetReceiver {
            action: TransferAction::Create,
            lock_script: receiver,
            capacity: None,
            amount,
            extra_data: None,
        };
        let script_id = if net_info.network_type == NetworkType::Mainnet {
            (*MAINNET_SUDT_SCRIPT_ID).clone()
        } else {
            (*TESTNET_SUDT_SCRIPT_ID).clone()
        };
        Self {
            udt_type: UdtType::Sudt,
            script_id,
            owner,
            receivers: vec![receiver],
            rpc_url: net_info.url.clone(),
        }
    }
    pub fn new(
        script_id: ScriptId,
        owner: Script,
        receivers: Vec<UdtTargetReceiver>,
        rpc_url: String,
    ) -> Self {
        Self {
            udt_type: UdtType::Sudt,
            script_id,
            owner,
            receivers,
            rpc_url,
        }
    }
    pub fn new_xudt(
        bytes: bytes::Bytes,
        script_id: ScriptId,
        owner: Script,
        receivers: Vec<UdtTargetReceiver>,
        rpc_url: String,
    ) -> Self {
        Self {
            udt_type: UdtType::Xudt(bytes),
            script_id,
            owner,
            receivers,
            rpc_url,
        }
    }
}

impl HandlerContext for UdtIssueContext {}
pub struct UdtTransferContext {
    /// The udt type script
    pub type_script: Script,

    /// Sender's lock script (we will asume there is only one udt cell identify
    /// by `type_script` and `sender`)
    pub sender: Script,

    /// The transfer receivers
    pub receivers: Vec<UdtTargetReceiver>,
    pub rpc_url: String,
}

impl UdtTransferContext {}

impl HandlerContext for UdtTransferContext {}

impl UdtScriptHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        ScriptId::from(script) == self.script_id
    }
    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let mut ret = Self {
            cell_deps: vec![],
            script_id: ScriptId::new_type(H256::default()),
        };
        ret.init(network)?;
        Ok(ret)
    }

    pub fn set_script_id(&mut self, script_id: ScriptId) {
        self.script_id = script_id;
    }

    pub fn set_cell_deps(&mut self, cell_deps: Vec<CellDep>) {
        self.cell_deps = cell_deps;
    }

    fn build_issue_base(
        viewer: &mut PrepareTransactionViewer,
        context: &UdtIssueContext,
    ) -> Result<(), TxBuilderError> {
        let mut cell_collector = DefaultCellCollector::new(&context.rpc_url);

        // Build output type script
        let owner_lock_hash = context.owner.calc_script_hash();
        let type_script = context
            .udt_type
            .build_script(&context.script_id, &owner_lock_hash);

        // Build outputs, outputs_data, cell_deps
        for receiver in &context.receivers {
            let ReceiverBuildOutput {
                input,
                output,
                output_data,
            } = receiver.build(&type_script, &mut cell_collector)?;
            if let Some(input) = input {
                viewer.transaction_inputs.push(input);
            }
            viewer.tx.output(output);
            viewer.tx.output_data(output_data.pack());
        }
        Ok(())
    }

    fn build_transfer_base(
        viewer: &mut PrepareTransactionViewer,
        context: &UdtTransferContext,
    ) -> Result<(), TxBuilderError> {
        let sender_query = {
            let mut query = CellQueryOptions::new_lock(context.sender.clone());
            query.secondary_script = Some(context.type_script.clone());
            query.data_len_range = Some(ValueRangeOption::new_min(16));
            query
        };

        let mut cell_collector = DefaultCellCollector::new(&context.rpc_url);
        let (sender_cells, _) = cell_collector.collect_live_cells(&sender_query, true)?;
        if sender_cells.is_empty() {
            return Err(TxBuilderError::Other(anyhow!("sender cell not found")));
        }
        let sender_cell = sender_cells.into_iter().next().unwrap();

        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&sender_cell.output_data.as_ref()[0..16]);
        let input_total = u128::from_le_bytes(amount_bytes);
        let output_total: u128 = context
            .receivers
            .iter()
            .map(|receiver| receiver.amount)
            .sum();
        if input_total < output_total {
            return Err(TxBuilderError::Other(anyhow!(
                "sender udt amount not enough, expected at least: {}, actual: {}",
                output_total,
                input_total
            )));
        }

        let sender_output_data = {
            let new_amount = input_total - output_total;
            let mut new_data = sender_cell.output_data.as_ref().to_vec();
            new_data[0..16].copy_from_slice(&new_amount.to_le_bytes()[..]);
            bytes::Bytes::from(new_data)
        };

        viewer.tx.output(sender_cell.output.clone());
        viewer.tx.output_data(sender_output_data.pack());
        viewer.transaction_inputs.push(sender_cell.into());

        for receiver in &context.receivers {
            let ReceiverBuildOutput {
                input,
                output,
                output_data,
            } = receiver.build(&context.type_script, &mut cell_collector)?;
            if let Some(input) = input {
                viewer.transaction_inputs.push(input);
            }
            viewer.tx.output(output);
            viewer.tx.output_data(output_data.pack());
        }

        Ok(())
    }
}

impl ScriptHandler for UdtScriptHandler {
    fn prepare_transaction(
        &self,
        viewer: &mut PrepareTransactionViewer,
        context: &mut dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if let Some(args) = context.as_any().downcast_ref::<UdtIssueContext>() {
            if self.script_id != args.script_id {
                return Ok(false);
            }
            Self::build_issue_base(viewer, args)?;
            Ok(true)
        } else if let Some(args) = context.as_any().downcast_ref::<UdtTransferContext>() {
            if self.script_id != (&args.type_script).into() {
                return Ok(false);
            }
            Self::build_transfer_base(viewer, args)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if script_group.group_type != ScriptGroupType::Type || !self.is_match(&script_group.script)
        {
            return Ok(false);
        }
        if let Some(args) = context.as_any().downcast_ref::<UdtIssueContext>() {
            // user may implemented it's own type script
            if self.script_id != args.script_id {
                return Ok(false);
            }
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            Ok(true)
        } else if let Some(args) = context.as_any().downcast_ref::<UdtTransferContext>() {
            // user may implemented it's own type script
            if self.script_id != (&args.type_script).into() {
                return Ok(false);
            }
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let out_point = if network.network_type == NetworkType::Mainnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0xc7813f6a415144643970c2e88e0bb6ca6a8edc5dd7c1022746f628284a9936d5")
                        .pack(),
                )
                .index(0u32.pack())
                .build()
        } else if network.network_type == NetworkType::Testnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0xe12877ebd2c3c364dc46c5c992bcfaf4fee33fa13eebdf82c591fc9825aab769")
                        .pack(),
                )
                .index(0u32.pack())
                .build()
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::Code.into())
            .build();
        self.cell_deps.push(cell_dep);

        self.script_id = if network.network_type == NetworkType::Mainnet {
            (*MAINNET_SUDT_SCRIPT_ID).clone()
        } else {
            (*TESTNET_SUDT_SCRIPT_ID).clone()
        };
        Ok(())
    }
}
