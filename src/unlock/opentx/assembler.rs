use anyhow::anyhow;
use std::convert::TryFrom;

use std::{cmp::Ordering, collections::HashSet};

use ckb_types::{
    core::TransactionView,
    packed::{Byte32, WitnessArgs},
    prelude::*,
};

use crate::{traits::TransactionDependencyProvider, unlock::omni_lock::OmniLockFlags};

use super::OpenTxError;

/// Assemble a transaction from multiple opentransaction, remove duplicate cell deps and header deps.
/// Alter base input/output index.
pub fn assemble_new_tx(
    mut txes: Vec<TransactionView>,
    provider: Box<dyn TransactionDependencyProvider>,
    script_hash: Byte32,
) -> Result<TransactionView, OpenTxError> {
    if txes.len() == 1 {
        return Ok(txes.remove(0));
    }
    let mut builder = TransactionView::new_advanced_builder();
    let mut cell_deps = HashSet::new();
    let mut header_deps = HashSet::new();
    let mut base_input_idx = 0usize;
    let mut base_output_idx = 0usize;
    for tx in txes.iter() {
        cell_deps.extend(tx.cell_deps());
        header_deps.extend(tx.header_deps());
        builder = builder.inputs(tx.inputs());
        // handle opentx witness
        for (input, witness) in tx.inputs().into_iter().zip(tx.witnesses().into_iter()) {
            let lock = provider.get_cell(&input.previous_output())?.lock();
            let lock_hash = lock.calc_script_hash();
            if lock_hash.cmp(&script_hash) == Ordering::Equal {
                let args = &lock.args().raw_data();
                if args.len() >= 22
                    && OmniLockFlags::from_bits_truncate(args[21]).contains(OmniLockFlags::OPENTX)
                {
                    let mut data = (&witness.raw_data()).to_vec();
                    let mut tmp = [0u8; 4];
                    tmp.copy_from_slice(&data[0..4]);
                    let this_base_input_idx = u32::from_le_bytes(tmp)
                        + u32::try_from(base_input_idx).map_err(|e| anyhow!(e))?;
                    data[0..4].copy_from_slice(&this_base_input_idx.to_le_bytes());

                    tmp.copy_from_slice(&data[4..8]);
                    let this_base_output_idx = u32::from_le_bytes(tmp)
                        + u32::try_from(base_output_idx).map_err(|e| anyhow!(e))?;
                    data[4..8].copy_from_slice(&this_base_output_idx.to_le_bytes());
                    let witness = WitnessArgs::from_slice(&data)
                        .map_err(|e| anyhow!(e))?
                        .as_bytes()
                        .pack();

                    builder = builder.witness(witness);
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
