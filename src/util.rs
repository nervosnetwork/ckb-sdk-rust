use std::{ptr, sync::atomic};

use ckb_chain_spec::consensus::{Consensus, ProposalWindow};
use ckb_dao_utils::extract_dao_data;
use ckb_jsonrpc_types as json_types;
use ckb_pow::Pow;
use ckb_script::ScriptGroup;
use ckb_types::{
    core::{
        hardfork::HardForkSwitchBuilder, Capacity, EpochNumber, EpochNumberWithFraction,
        HeaderView, Ratio,
    },
    packed::{Block, CellOutput},
    prelude::*,
    U256,
};

use crate::rpc::CkbRpcClient;
use crate::traits::LiveCell;

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
        let u256_hex_to_u64 = |v| serde_json::from_value::<U256>(v).expect("convert u256").0[0];
        (
            u256_hex_to_u64(proposer_reward_ratio_json["numer"].clone()),
            u256_hex_to_u64(proposer_reward_ratio_json["denom"].clone()),
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

pub fn minimal_unlock_point(
    deposit_header: &HeaderView,
    prepare_header: &HeaderView,
) -> EpochNumberWithFraction {
    const LOCK_PERIOD_EPOCHES: EpochNumber = 180;

    // https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/dao.c#L182-L223
    let deposit_point = deposit_header.epoch();
    let prepare_point = prepare_header.epoch();
    let prepare_fraction = prepare_point.index() * deposit_point.length();
    let deposit_fraction = deposit_point.index() * prepare_point.length();
    let passed_epoch_cnt = if prepare_fraction > deposit_fraction {
        prepare_point.number() - deposit_point.number() + 1
    } else {
        prepare_point.number() - deposit_point.number()
    };
    let rest_epoch_cnt =
        (passed_epoch_cnt + (LOCK_PERIOD_EPOCHES - 1)) / LOCK_PERIOD_EPOCHES * LOCK_PERIOD_EPOCHES;
    EpochNumberWithFraction::new(
        deposit_point.number() + rest_epoch_cnt,
        deposit_point.index(),
        deposit_point.length(),
    )
}

pub fn calculate_dao_maximum_withdraw4(
    deposit_header: &HeaderView,
    prepare_header: &HeaderView,
    output: &CellOutput,
    occupied_capacity: u64,
) -> u64 {
    let (deposit_ar, _, _, _) = extract_dao_data(deposit_header.dao());
    let (prepare_ar, _, _, _) = extract_dao_data(prepare_header.dao());
    let output_capacity: Capacity = output.capacity().unpack();
    let counted_capacity = output_capacity.as_u64() - occupied_capacity;
    let withdraw_counted_capacity =
        u128::from(counted_capacity) * u128::from(prepare_ar) / u128::from(deposit_ar);
    occupied_capacity + withdraw_counted_capacity as u64
}

pub fn serialize_signature(signature: &secp256k1::recovery::RecoverableSignature) -> [u8; 65] {
    let (recov_id, data) = signature.serialize_compact();
    let mut signature_bytes = [0u8; 65];
    signature_bytes[0..64].copy_from_slice(&data[0..64]);
    signature_bytes[64] = recov_id.to_i32() as u8;
    signature_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_dao_utils::pack_dao_data;
    use ckb_types::{
        bytes::Bytes,
        core::{capacity_bytes, EpochNumberWithFraction, HeaderBuilder},
    };

    #[test]
    fn test_minimal_unlock_point() {
        let cases = vec![
            ((5, 5, 1000), (184, 4, 1000), (5 + 180, 5, 1000)),
            ((5, 5, 1000), (184, 5, 1000), (5 + 180, 5, 1000)),
            ((5, 5, 1000), (184, 6, 1000), (5 + 180, 5, 1000)),
            ((5, 5, 1000), (185, 4, 1000), (5 + 180, 5, 1000)),
            ((5, 5, 1000), (185, 5, 1000), (5 + 180, 5, 1000)),
            ((5, 5, 1000), (185, 6, 1000), (5 + 180 * 2, 5, 1000)), // 6/1000 > 5/1000
            ((5, 5, 1000), (186, 4, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (186, 5, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (186, 6, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (364, 4, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (364, 5, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (364, 6, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (365, 4, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (365, 5, 1000), (5 + 180 * 2, 5, 1000)),
            ((5, 5, 1000), (365, 6, 1000), (5 + 180 * 3, 5, 1000)),
            ((5, 5, 1000), (366, 4, 1000), (5 + 180 * 3, 5, 1000)),
            ((5, 5, 1000), (366, 5, 1000), (5 + 180 * 3, 5, 1000)),
            ((5, 5, 1000), (366, 6, 1000), (5 + 180 * 3, 5, 1000)),
        ];
        for (deposit_point, prepare_point, expected) in cases {
            let deposit_point =
                EpochNumberWithFraction::new(deposit_point.0, deposit_point.1, deposit_point.2);
            let prepare_point =
                EpochNumberWithFraction::new(prepare_point.0, prepare_point.1, prepare_point.2);
            let expected = EpochNumberWithFraction::new(expected.0, expected.1, expected.2);
            let deposit_header = HeaderBuilder::default()
                .epoch(deposit_point.full_value().pack())
                .build();
            let prepare_header = HeaderBuilder::default()
                .epoch(prepare_point.full_value().pack())
                .build();
            let actual = minimal_unlock_point(&deposit_header, &prepare_header);
            assert_eq!(
                expected, actual,
                "minimal_unlock_point deposit_point: {}, prepare_point: {}, expected: {}, actual: {}",
                deposit_point, prepare_point, expected, actual,
            );
        }
    }

    #[test]
    fn check_withdraw_calculation() {
        let data = Bytes::from(vec![1; 10]);
        let output = CellOutput::new_builder()
            .capacity(capacity_bytes!(1000000).pack())
            .build();
        let deposit_header = HeaderBuilder::default()
            .number(100.pack())
            .dao(pack_dao_data(
                10_000_000_000_123_456,
                Default::default(),
                Default::default(),
                Default::default(),
            ))
            .build();
        let prepare_header = HeaderBuilder::default()
            .number(200.pack())
            .dao(pack_dao_data(
                10_000_000_001_123_456,
                Default::default(),
                Default::default(),
                Default::default(),
            ))
            .build();

        let result = calculate_dao_maximum_withdraw4(
            &deposit_header,
            &prepare_header,
            &output,
            Capacity::bytes(data.len()).unwrap().as_u64(),
        );
        assert_eq!(result, 100_000_000_009_999);
    }
}
