use crate::{
    core::TransactionBuilder, transaction::{
        handler::HandlerContexts, TransactionBuilderConfiguration,
    }, tx_builder::{BalanceTxCapacityError, TxBuilderError}, ScriptGroup, TransactionWithScriptGroups
};
use ckb_types::{
    packed::Byte32,

};

use ckb_jsonrpc_types::CellOutput;
use std::collections::HashMap;


pub struct OfflineTransactionBuilder {
    /// The transaction builder configuration
    configuration: TransactionBuilderConfiguration,
    /// The inner transaction builder
    tx: TransactionBuilder,
}

impl OfflineTransactionBuilder {
    pub fn new(configuration: TransactionBuilderConfiguration, tx: TransactionBuilder) -> Self {
        Self { configuration, tx }
    }

    pub fn build(
        self,
        contexts: &HandlerContexts,
        cells: Vec<CellOutput>,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError> {
        let Self { configuration, tx } = self;

        inner_build_without_cb(tx, cells, &configuration, contexts)
    }
}


/// a helper fn to build a transaction with common logic
fn inner_build_without_cb(
    mut tx: TransactionBuilder,
    prev_cells: Vec<CellOutput>,
    configuration: &TransactionBuilderConfiguration,
    contexts: &HandlerContexts,
) -> Result<TransactionWithScriptGroups, TxBuilderError> {
    let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
    let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();

    // setup outputs' type script group
    for (output_idx, output) in tx.get_outputs().clone().iter().enumerate() {
        if let Some(type_script) = &output.type_().to_opt() {
            type_groups
                .entry(type_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(type_script))
                .output_indices
                .push(output_idx);
        }
    }

    
    // collect inputs
    for (input_index, previous_output) in prev_cells.iter().enumerate() {
        let lock_script = previous_output.lock;
        lock_groups
            .entry(lock_script.calc_script_hash())
            .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
            .input_indices
            .push(input_index);

        if let Some(type_script) = previous_output.type_.to_opt() {
            type_groups
                .entry(type_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(&type_script))
                .input_indices
                .push(input_index);
        }


        let mut script_groups: Vec<ScriptGroup> = lock_groups
                .into_values()
                .chain(type_groups.into_values())
                .collect();

            for script_group in script_groups.iter_mut() {
                for handler in configuration.get_script_handlers() {
                    for context in &contexts.contexts {
                        if handler.build_transaction(&mut tx, script_group, context.as_ref())? {
                            break;
                        }
                    }
                }
            }

            let tx_view = tx.build();

            return Ok(TransactionWithScriptGroups::new(tx_view, script_groups));
    
    }

    Err(BalanceTxCapacityError::CapacityNotEnough("can not find enough inputs".to_string()).into())
}
