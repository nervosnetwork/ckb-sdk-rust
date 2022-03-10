use std::collections::HashSet;
use std::{ptr, sync::atomic};

use byteorder::{ByteOrder, LittleEndian};

use ckb_chain_spec::consensus::Consensus;
use ckb_dao::DaoCalculator;
use ckb_dao_utils::DaoError;
use ckb_jsonrpc_types as json_types;
use ckb_script::ScriptGroup;
use ckb_traits::CellDataProvider;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, ResolvedTransaction},
        Capacity, ScriptHashType,
    },
    packed::{Byte32, Script, WitnessArgs},
    prelude::*,
};

use crate::traits::TransactionDependencyProvider;

pub fn zeroize_privkey(key: &mut secp256k1::SecretKey) {
    let key_ptr = key.as_mut_ptr();
    for i in 0..key.len() as isize {
        unsafe { ptr::write_volatile(key_ptr.offset(i), Default::default()) }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

pub fn zeroize_slice(data: &mut [u8]) {
    for elem in data {
        unsafe { ptr::write_volatile(elem, Default::default()) }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

// FIXME: This function is copied from ckb-dao, should make that function public so we can remove it here.
pub fn transaction_maximum_withdraw(
    dao_calculator: &DaoCalculator<&dyn TransactionDependencyProvider>,
    rtx: &ResolvedTransaction,
    consensus: &Consensus,
    tx_dep_provider: &dyn TransactionDependencyProvider,
) -> Result<Capacity, DaoError> {
    #[allow(clippy::mutable_key_type)]
    let header_deps: HashSet<Byte32> = rtx.transaction.header_deps_iter().collect();
    rtx.resolved_inputs.iter().enumerate().try_fold(
        Capacity::zero(),
        |capacities, (i, cell_meta)| {
            let capacity: Result<Capacity, DaoError> = {
                let output = &cell_meta.cell_output;
                let is_dao_type_script = |type_script: Script| {
                    Into::<u8>::into(type_script.hash_type())
                        == Into::<u8>::into(ScriptHashType::Type)
                        && type_script.code_hash()
                            == consensus.dao_type_hash().expect("No dao system cell")
                };
                let is_withdrawing_input =
                    |cell_meta: &CellMeta| match tx_dep_provider.load_cell_data(cell_meta) {
                        Some(data) => data.len() == 8 && LittleEndian::read_u64(&data) > 0,
                        None => false,
                    };
                if output
                    .type_()
                    .to_opt()
                    .map(is_dao_type_script)
                    .unwrap_or(false)
                    && is_withdrawing_input(cell_meta)
                {
                    let withdrawing_header_hash = cell_meta
                        .transaction_info
                        .as_ref()
                        .map(|info| &info.block_hash)
                        .filter(|hash| header_deps.contains(hash))
                        .ok_or(DaoError::InvalidOutPoint)?;
                    let deposit_header_hash = rtx
                        .transaction
                        .witnesses()
                        .get(i)
                        .ok_or(DaoError::InvalidOutPoint)
                        .and_then(|witness_data| {
                            // dao contract stores header deps index as u64 in the input_type field of WitnessArgs
                            let witness =
                                WitnessArgs::from_slice(&Unpack::<Bytes>::unpack(&witness_data))
                                    .map_err(|_| DaoError::InvalidDaoFormat)?;
                            let header_deps_index_data: Option<Bytes> = witness
                                .input_type()
                                .to_opt()
                                .map(|witness| witness.unpack());
                            if header_deps_index_data.is_none()
                                || header_deps_index_data.clone().map(|data| data.len()) != Some(8)
                            {
                                return Err(DaoError::InvalidDaoFormat);
                            }
                            Ok(LittleEndian::read_u64(&header_deps_index_data.unwrap()))
                        })
                        .and_then(|header_dep_index| {
                            rtx.transaction
                                .header_deps()
                                .get(header_dep_index as usize)
                                .and_then(|hash| header_deps.get(&hash))
                                .ok_or(DaoError::InvalidOutPoint)
                        })?;
                    dao_calculator.calculate_maximum_withdraw(
                        output,
                        Capacity::bytes(cell_meta.data_bytes as usize)?,
                        deposit_header_hash,
                        withdrawing_header_hash,
                    )
                } else {
                    Ok(output.capacity().unpack())
                }
            };
            capacity.and_then(|c| c.safe_add(capacities).map_err(Into::into))
        },
    )
}

// FIXME: should derive `Clone` for ScriptGroup
pub fn clone_script_group(script_group: &ScriptGroup) -> ScriptGroup {
    ScriptGroup {
        script: script_group.script.clone(),
        group_type: script_group.group_type,
        input_indices: script_group.input_indices.clone(),
        output_indices: script_group.output_indices.clone(),
    }
}

// FIXME: todo
pub fn to_consensus_struct(json: json_types::Consensus) -> Consensus {
    unimplemented!()
}
