use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellOutput, OutPoint, Script},
    prelude::*,
};

use super::{TxBuilder, TxBuilderError};
use crate::constants::DAO_TYPE_HASH;
use crate::traits::{CellCollector, CellDepResolver};
use crate::types::ScriptId;

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

impl TxBuilder for DaoDepositBuilder {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
    ) -> Result<TransactionView, TxBuilderError> {
        if self.receivers.is_empty() {
            return Err(TxBuilderError::InvalidParameter(
                "empty dao receivers".to_string().into(),
            ));
        }
        let dao_type_script = Script::new_builder()
            .code_hash(DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let dao_script_id = ScriptId::from(&dao_type_script);
        let dao_cell_dep = cell_dep_resolver
            .resolve(&dao_script_id)
            .ok_or(TxBuilderError::ResolveCellDepFailed(dao_script_id))?;

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
pub struct DaoWithdrawItem {
    /// The cell to withdraw
    pub out_point: OutPoint,
    /// If `lock_script` is `None` copy the lock script from input with same index.
    pub lock_script: Option<Script>,
}
impl From<OutPoint> for DaoWithdrawItem {
    fn from(out_point: OutPoint) -> DaoWithdrawItem {
        DaoWithdrawItem {
            out_point,
            lock_script: None,
        }
    }
}
/// Build a Nervos DAO withdraw Phase 1 transaction
#[derive(Debug, Clone)]
pub struct DaoPrepareBuilder {
    /// Prepare withdraw from those out_points
    pub items: Vec<DaoWithdrawItem>,
}
impl DaoPrepareBuilder {
    pub fn new(out_points: Vec<OutPoint>) -> DaoPrepareBuilder {
        let items: Vec<_> = out_points.into_iter().map(DaoWithdrawItem::from).collect();
        DaoPrepareBuilder { items }
    }
}

/// Build a Nervos DAO withdraw Phase 2 transaction
#[derive(Debug, Clone)]
pub struct DaoWithdrawBuilder {
    /// Withdraw from those out_points
    pub items: Vec<DaoWithdrawItem>,
}
impl DaoWithdrawBuilder {
    pub fn new(out_points: Vec<OutPoint>) -> DaoWithdrawBuilder {
        let items: Vec<_> = out_points.into_iter().map(DaoWithdrawItem::from).collect();
        DaoWithdrawBuilder { items }
    }
}
