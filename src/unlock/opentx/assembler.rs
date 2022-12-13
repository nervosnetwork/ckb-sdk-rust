use anyhow::anyhow;
use std::{cmp::Ordering, collections::HashSet, convert::TryFrom};

use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{Byte32, WitnessArgs},
    prelude::*,
};

use crate::{traits::TransactionDependencyProvider, unlock::omni_lock::OmniLockFlags};
use crate::{
    tx_builder::{gen_script_groups, ScriptGroups},
    types::omni_lock::OmniLockWitnessLock,
};

use super::OpenTxError;

/// Check if different
fn check_script_groups(group_vec: &[ScriptGroups]) -> Result<(), OpenTxError> {
    let mut keys = HashSet::new();
    for group in group_vec.iter() {
        let len = keys.len();
        keys.extend(group.lock_groups.keys().clone());
        if len + group.lock_groups.len() > keys.len() {
            return Err(OpenTxError::SameLockInDifferentOpenTx);
        }
    }
    Ok(())
}

/// Assemble a transaction from multiple opentransaction, remove duplicate cell deps and header deps.
/// Alter base input/output index.
pub fn assemble_new_tx(
    mut transactions: Vec<TransactionView>,
    provider: &dyn TransactionDependencyProvider,
    opentx_code_hash: Byte32,
) -> Result<TransactionView, OpenTxError> {
    if transactions.len() == 1 {
        return Ok(transactions.remove(0));
    }
    let mut builder = TransactionView::new_advanced_builder();
    let mut cell_deps = HashSet::new();
    let mut header_deps = HashSet::new();
    let mut base_input_idx = 0usize;
    let mut base_output_idx = 0usize;
    let mut base_input_cap = 0usize;
    let mut base_output_cap = 0usize;
    let group_vec: Result<Vec<_>, _> = transactions
        .iter()
        .map(|tx| gen_script_groups(tx, provider))
        .collect();
    let group_vec = group_vec?;
    check_script_groups(&group_vec)?;
    for tx in transactions.iter() {
        cell_deps.extend(tx.cell_deps());
        header_deps.extend(tx.header_deps());
        builder = builder.inputs(tx.inputs());
        base_input_cap += tx.inputs().len();
        base_output_cap += tx.outputs().len();
        // Handle opentx witness
        for (input, witness) in tx.inputs().into_iter().zip(tx.witnesses().into_iter()) {
            let lock = provider.get_cell(&input.previous_output())?.lock();
            let code_hash = lock.code_hash();
            // empty witness should be in a script group
            if !witness.is_empty() && code_hash.cmp(&opentx_code_hash) == Ordering::Equal {
                let args = &lock.args().raw_data();
                let witness_data = witness.raw_data();
                if witness_data.len() > 8 // sizeof base_input + sizeof base_output
                    && args.len() >= 22
                    && OmniLockFlags::from_bits_truncate(args[21]).contains(OmniLockFlags::OPENTX)
                {
                    // Parse lock data
                    let current_witness: WitnessArgs =
                        WitnessArgs::from_slice(witness_data.as_ref())?;
                    let lock_field = current_witness
                        .lock()
                        .to_opt()
                        .map(|data| data.raw_data())
                        .ok_or(OpenTxError::WitnessLockMissing)?;
                    let omnilock_witnesslock =
                        OmniLockWitnessLock::from_slice(lock_field.as_ref())?;

                    let mut data = omnilock_witnesslock
                        .signature()
                        .to_opt()
                        .map(|data| data.raw_data().as_ref().to_vec())
                        .ok_or(OpenTxError::SignatureMissing)?;

                    let mut tmp = [0u8; 4];
                    tmp.copy_from_slice(&data[0..4]);
                    let this_base_input_idx = u32::from_le_bytes(tmp)
                        + u32::try_from(base_input_idx).map_err(|e| anyhow!(e))?;
                    if this_base_input_idx as usize > base_input_cap {
                        return Err(OpenTxError::BaseInputIndexOverFlow);
                    }
                    data[0..4].copy_from_slice(&this_base_input_idx.to_le_bytes());

                    tmp.copy_from_slice(&data[4..8]);
                    let this_base_output_idx = u32::from_le_bytes(tmp)
                        + u32::try_from(base_output_idx).map_err(|e| anyhow!(e))?;
                    if this_base_output_idx as usize > base_output_cap {
                        return Err(OpenTxError::BaseOutputIndexOverFlow);
                    }
                    data[4..8].copy_from_slice(&this_base_output_idx.to_le_bytes());

                    let omnilock_witnesslock = omnilock_witnesslock
                        .as_builder()
                        .signature(Some(Bytes::from(data)).pack())
                        .build();
                    let witness = current_witness
                        .as_builder()
                        .lock(Some(omnilock_witnesslock.as_bytes()).pack())
                        .build();
                    builder = builder.witness(witness.as_bytes().pack());
                    continue;
                }
            }
            builder = builder.witness(witness);
        }
        builder = builder.outputs(tx.outputs());
        builder = builder.outputs_data(tx.outputs_data());

        base_input_idx += tx.inputs().len();
        base_output_idx += tx.outputs().len();
    }
    builder = builder.cell_deps(cell_deps).header_deps(header_deps);

    Ok(builder.build())
}
