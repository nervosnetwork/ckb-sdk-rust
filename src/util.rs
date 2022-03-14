use std::collections::HashSet;
use std::{ptr, sync::atomic};

use byteorder::{ByteOrder, LittleEndian};

use ckb_chain_spec::consensus::{Consensus, ProposalWindow};
use ckb_dao::DaoCalculator;
use ckb_dao_utils::DaoError;
use ckb_jsonrpc_types as json_types;
use ckb_pow::Pow;
use ckb_script::ScriptGroup;
use ckb_traits::CellDataProvider;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, ResolvedTransaction},
        hardfork::HardForkSwitchBuilder,
        Capacity, EpochNumberWithFraction, Ratio, ScriptHashType,
    },
    packed::{Block, Byte32, Script, WitnessArgs},
    prelude::*,
    U256,
};

use crate::rpc::CkbRpcClient;
use crate::traits::{LiveCell, TransactionDependencyProvider};

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

pub fn to_consensus_struct(json: json_types::Consensus) -> Consensus {
    let (proposer_reward_ratio_number, proposer_reward_ratio_denom): (u64, u64) = {
        let proposer_reward_ratio_json =
            serde_json::to_value(&json.proposer_reward_ratio).expect("to json value");
        let u256_hex_to_u64 = |src| serde_json::from_str::<U256>(src).expect("convert u256").0[0];
        (
            u256_hex_to_u64(proposer_reward_ratio_json["number"].as_str().unwrap()),
            u256_hex_to_u64(proposer_reward_ratio_json["denom"].as_str().unwrap()),
        )
    };
    let hardfork_switch = {
        let mut builder = HardForkSwitchBuilder::default();
        for feature in json.hardfork_features {
            match feature.rfc.as_str() {
                "0028" => builder.rfc_0028 = feature.epoch_number.map(|v| v.value()),
                "0029" => builder.rfc_0029 = feature.epoch_number.map(|v| v.value()),
                "0030" => builder.rfc_0030 = feature.epoch_number.map(|v| v.value()),
                "0031" => builder.rfc_0031 = feature.epoch_number.map(|v| v.value()),
                "0032" => builder.rfc_0032 = feature.epoch_number.map(|v| v.value()),
                "0036" => builder.rfc_0036 = feature.epoch_number.map(|v| v.value()),
                "0038" => builder.rfc_0038 = feature.epoch_number.map(|v| v.value()),
                _ => panic!("unexpected rfc number: {}", feature.rfc),
            }
        }
        builder.build().expect("build hardfork switch")
    };
    Consensus {
        id: json.id,
        // NOTE: dummy value
        genesis_block: Block::default().into_view(),
        genesis_hash: json.genesis_hash.pack(),
        dao_type_hash: json.dao_type_hash.map(|v| v.pack()),
        secp256k1_blake160_sighash_all_type_hash: json
            .secp256k1_blake160_sighash_all_type_hash
            .map(|v| v.pack()),
        secp256k1_blake160_multisig_all_type_hash: json
            .secp256k1_blake160_multisig_all_type_hash
            .map(|v| v.pack()),
        initial_primary_epoch_reward: Capacity::shannons(json.initial_primary_epoch_reward.value()),
        secondary_epoch_reward: Capacity::shannons(json.secondary_epoch_reward.value()),
        max_uncles_num: json.max_uncles_num.value() as usize,
        orphan_rate_target: json.orphan_rate_target,
        epoch_duration_target: json.epoch_duration_target.value(),
        tx_proposal_window: ProposalWindow(
            json.tx_proposal_window.closest.value(),
            json.tx_proposal_window.farthest.value(),
        ),
        proposer_reward_ratio: Ratio::new(
            proposer_reward_ratio_number,
            proposer_reward_ratio_denom,
        ),
        // NOTE: dummy value
        pow: Pow::Dummy,
        cellbase_maturity: EpochNumberWithFraction::from_full_value(json.cellbase_maturity.value()),
        median_time_block_count: json.median_time_block_count.value() as usize,
        max_block_cycles: json.max_block_cycles.value(),
        max_block_bytes: json.max_block_bytes.value(),
        block_version: json.block_version.value(),
        tx_version: json.tx_version.value(),
        type_id_code_hash: json.type_id_code_hash,
        max_block_proposals_limit: json.max_block_proposals_limit.value(),
        // NOTE: dummy value
        genesis_epoch_ext: Default::default(),
        // NOTE: dummy value
        satoshi_pubkey_hash: Default::default(),
        // NOTE: dummy value
        satoshi_cell_occupied_ratio: Ratio::new(0, 0),
        primary_epoch_reward_halving_interval: json.primary_epoch_reward_halving_interval.value(),
        permanent_difficulty_in_dummy: json.permanent_difficulty_in_dummy,
        hardfork_switch,
    }
}

pub fn calc_max_mature_number(
    tip_epoch: EpochNumberWithFraction,
    max_mature_epoch: Option<(u64, u64)>,
    cellbase_maturity: EpochNumberWithFraction,
) -> u64 {
    if tip_epoch.to_rational() < cellbase_maturity.to_rational() {
        0
    } else if let Some((start_number, length)) = max_mature_epoch {
        let epoch_delta = tip_epoch.to_rational() - cellbase_maturity.to_rational();
        let index_bytes: [u8; 32] = ((epoch_delta.clone() - epoch_delta.into_u256())
            * U256::from(length))
        .into_u256()
        .to_le_bytes();
        let mut index_bytes_u64 = [0u8; 8];
        index_bytes_u64.copy_from_slice(&index_bytes[0..8]);
        u64::from_le_bytes(index_bytes_u64) + start_number
    } else {
        0
    }
}

pub fn get_max_mature_number(rpc_client: &mut CkbRpcClient) -> Result<u64, String> {
    let cellbase_maturity = EpochNumberWithFraction::from_full_value(
        rpc_client
            .get_consensus()
            .map_err(|err| err.to_string())?
            .cellbase_maturity
            .value(),
    );
    let tip_epoch = rpc_client
        .get_tip_header()
        .map(|header| EpochNumberWithFraction::from_full_value(header.inner.epoch.value()))
        .map_err(|err| err.to_string())?;
    let tip_epoch_number = tip_epoch.number();
    if tip_epoch_number < cellbase_maturity.number() {
        // No cellbase live cell is mature
        Ok(0)
    } else {
        let max_mature_epoch = rpc_client
            .get_epoch_by_number((tip_epoch_number - cellbase_maturity.number()).into())
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "Can not get epoch less than current epoch number".to_string())?;
        let start_number = max_mature_epoch.start_number;
        let length = max_mature_epoch.length;
        Ok(calc_max_mature_number(
            tip_epoch,
            Some((start_number.value(), length.value())),
            cellbase_maturity,
        ))
    }
}

pub fn is_mature(info: &LiveCell, max_mature_number: u64) -> bool {
    // Not cellbase cell
    info.tx_index > 0
    // Live cells in genesis are all mature
        || info.block_number == 0
        || info.block_number <= max_mature_number
}
