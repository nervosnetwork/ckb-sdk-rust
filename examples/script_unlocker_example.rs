use ckb_sdk::{
    traits::TransactionDependencyProvider,
    unlock::{ScriptUnlocker, UnlockError},
    ScriptGroup, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionView},
    h256,
    packed::{self, WitnessArgs},
    prelude::*,
};
use std::collections::HashMap;

/// An unlocker for the example script [CapacityDiff].
///
/// [CapacityDiff]: https://github.com/doitian/ckb-sdk-examples-capacity-diff
struct CapacityDiffUnlocker {}

#[async_trait::async_trait]
impl ScriptUnlocker for CapacityDiffUnlocker {
    // This works for any args
    fn match_args(&self, _args: &[u8]) -> bool {
        true
    }

    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> std::result::Result<TransactionView, UnlockError> {
        let witness_index = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_index {
            witnesses.push(Default::default());
        }
        let witness_bytes = &witnesses[witness_index];
        let builder = if witness_bytes.is_empty() {
            WitnessArgs::new_builder()
        } else {
            WitnessArgs::from_slice(witness_bytes.raw_data().as_ref())
                .map_err(|_| UnlockError::InvalidWitnessArgs(witness_index))?
                .as_builder()
        };

        let mut total = 0i64;
        for i in &script_group.input_indices {
            let cell = tx_dep_provider
                .get_cell_async(
                    &tx.inputs()
                        .get(*i)
                        .ok_or_else(|| other_unlock_error("input index out of bound"))?
                        .previous_output(),
                )
                .await?;
            let capacity: u64 = cell.capacity().unpack();
            total -= capacity as i64;
        }
        for output in tx.outputs() {
            if output.lock().as_slice() == script_group.script.as_slice() {
                let capacity: u64 = output.capacity().unpack();
                total += capacity as i64;
            }
        }

        witnesses[witness_index] = builder
            .lock(Some(Bytes::from(total.to_le_bytes().to_vec())).pack())
            .build()
            .as_bytes()
            .pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }

    // This is called before balancer. It's responsible to fill witness for inputs added manually
    // by users.
    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> std::result::Result<TransactionView, UnlockError> {
        let witness_index = script_group.input_indices[0];
        let witness_args_opt = tx
            .witnesses()
            .get(witness_index)
            .map_or(Ok(None), |bytes| {
                if bytes.is_empty() {
                    Ok(None)
                } else {
                    WitnessArgs::from_slice(bytes.raw_data().as_ref()).map(Some)
                }
            })
            .map_err(|_| UnlockError::InvalidWitnessArgs(witness_index))?;
        let witness_lock_len = witness_args_opt
            .as_ref()
            .map_or(0, |args| args.lock().to_opt().map_or(0, |lock| lock.len()));
        if witness_lock_len < 8 {
            let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
            while witnesses.len() <= witness_index {
                witnesses.push(Default::default());
            }
            let witness_args = witness_args_opt
                .map_or_else(WitnessArgs::new_builder, WitnessArgs::as_builder)
                .lock(Some(Bytes::from(vec![0u8; 8])).pack())
                .build();
            witnesses[witness_index] = witness_args.as_bytes().pack();
            Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
        } else {
            Ok(tx.clone())
        }
    }
}

fn other_unlock_error(message: &str) -> UnlockError {
    UnlockError::Other(std::io::Error::new(std::io::ErrorKind::Other, message).into())
}

fn main() {
    let script_id = ScriptId {
        code_hash: h256!("0x3e6dd90e2d6d8d7a17c5ddce9c257f638545d991a6eba7e4c82879f395b6883c"),
        hash_type: ScriptHashType::Data1,
    };

    let capacity_diff_unlocker: Box<dyn ScriptUnlocker> = Box::new(CapacityDiffUnlocker {});
    let _unlockers = HashMap::from([(script_id.clone(), capacity_diff_unlocker)]);
}
