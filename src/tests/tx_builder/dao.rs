use std::collections::HashMap;

use ckb_dao_utils::pack_dao_data;

use ckb_types::{
    bytes::Bytes,
    core::{Capacity, EpochNumberWithFraction, HeaderBuilder},
    packed::{CellInput, CellOutput, ScriptOpt, WitnessArgs},
    prelude::*,
};

use crate::constants::{ONE_CKB, SIGHASH_TYPE_HASH};
use crate::tests::{
    build_dao_script, build_sighash_script, init_context, ACCOUNT1_ARG, ACCOUNT1_KEY, FEE_RATE,
};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    dao::{
        DaoDepositBuilder, DaoDepositReceiver, DaoPrepareBuilder, DaoWithdrawBuilder,
        DaoWithdrawItem, DaoWithdrawReceiver,
    },
    CapacityBalancer, TxBuilder,
};
use crate::unlock::{ScriptUnlocker, SecpSighashUnlocker};
use crate::util::{calculate_dao_maximum_withdraw4, minimal_unlock_point};
use crate::{ScriptId, Since, SinceType};

use crate::test_util::random_out_point;

#[test]
fn test_dao_deposit() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let deposit_receiver = DaoDepositReceiver::new(sender.clone(), 120 * ONE_CKB);
    let builder = DaoDepositBuilder::new(vec![deposit_receiver]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    let deposit_output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(build_dao_script()).pack())
        .build();
    assert_eq!(tx.output(0).unwrap(), deposit_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![Bytes::from(vec![0u8; 8]), Bytes::default()];
    let outputs_data = tx
        .outputs_data()
        .into_iter()
        .map(|d| d.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(outputs_data, expected_outputs_data);
    let witnesses_len = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data().len())
        .collect::<Vec<_>>();
    assert_eq!(witnesses_len, vec![placeholder_witness.as_slice().len(), 0]);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_dao_prepare() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let mut ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let deposit_point = (5, 5, 1000);
    let deposit_number = deposit_point.0 * deposit_point.2 + deposit_point.1;
    let deposit_point =
        EpochNumberWithFraction::new(deposit_point.0, deposit_point.1, deposit_point.2);

    let deposit_input = CellInput::new(random_out_point(), 0);
    let deposit_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(build_dao_script()).pack())
        .build();
    let deposit_header = HeaderBuilder::default()
        .epoch(deposit_point.full_value().pack())
        .number(deposit_number.pack())
        .build();
    let deposit_block_hash = deposit_header.hash();
    ctx.add_live_cell(
        deposit_input.clone(),
        deposit_output.clone(),
        Bytes::from(vec![0u8; 8]),
        Some(deposit_block_hash.clone()),
    );
    ctx.add_header(deposit_header);

    let builder = DaoPrepareBuilder::from(vec![deposit_input]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(
        tx.header_deps().into_iter().collect::<Vec<_>>(),
        vec![deposit_block_hash]
    );
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), deposit_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![
        Bytes::from(deposit_number.to_le_bytes().to_vec()),
        Bytes::default(),
    ];
    let outputs_data = tx
        .outputs_data()
        .into_iter()
        .map(|d| d.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(outputs_data, expected_outputs_data);
    let witnesses_len = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data().len())
        .collect::<Vec<_>>();
    assert_eq!(witnesses_len, vec![placeholder_witness.as_slice().len(), 0]);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_dao_withdraw() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let mut ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let (deposit_point, prepare_point) = ((5, 5, 1000), (184, 4, 1000));
    let deposit_number = deposit_point.0 * deposit_point.2 + deposit_point.1;
    let prepare_number = prepare_point.0 * prepare_point.2 + prepare_point.1;
    let deposit_point =
        EpochNumberWithFraction::new(deposit_point.0, deposit_point.1, deposit_point.2);
    let prepare_point =
        EpochNumberWithFraction::new(prepare_point.0, prepare_point.1, prepare_point.2);
    let deposit_header = HeaderBuilder::default()
        .epoch(deposit_point.full_value().pack())
        .number(deposit_number.pack())
        .dao(pack_dao_data(
            10_000_000_000_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let prepare_header = HeaderBuilder::default()
        .epoch(prepare_point.full_value().pack())
        .number(prepare_number.pack())
        .dao(pack_dao_data(
            10_000_000_001_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let deposit_block_hash = deposit_header.hash();
    let prepare_block_hash = prepare_header.hash();

    let unlock_point = minimal_unlock_point(&deposit_header, &prepare_header);
    let since = Since::new(
        SinceType::EpochNumberWithFraction,
        unlock_point.full_value(),
        false,
    );
    let prepare_out_point = random_out_point();
    let prepare_input = CellInput::new(prepare_out_point.clone(), since.value());
    let prepare_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(build_dao_script()).pack())
        .build();
    ctx.add_live_cell(
        prepare_input,
        prepare_output.clone(),
        Bytes::from(deposit_number.to_le_bytes().to_vec()),
        Some(prepare_block_hash.clone()),
    );
    ctx.add_header(deposit_header.clone());
    ctx.add_header(prepare_header.clone());

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let withdraw_item = DaoWithdrawItem::new(prepare_out_point, Some(placeholder_witness.clone()));
    let withdraw_receiver = DaoWithdrawReceiver::LockScript {
        script: sender.clone(),
        fee_rate: None,
    };
    let builder = DaoWithdrawBuilder::new(vec![withdraw_item], withdraw_receiver);
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(
        tx.header_deps().into_iter().collect::<Vec<_>>(),
        vec![deposit_block_hash, prepare_block_hash]
    );
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    let occupied_capacity = prepare_output
        .occupied_capacity(Capacity::bytes(8).unwrap())
        .unwrap()
        .as_u64();
    let expected_capacity = calculate_dao_maximum_withdraw4(
        &deposit_header,
        &prepare_header,
        &prepare_output,
        occupied_capacity,
    );
    let expected_output = prepare_output
        .as_builder()
        .capacity(expected_capacity.pack())
        .type_(ScriptOpt::default())
        .build();
    assert_eq!(tx.output(0).unwrap(), expected_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![Bytes::default(), Bytes::default()];
    let outputs_data = tx
        .outputs_data()
        .into_iter()
        .map(|d| d.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(outputs_data, expected_outputs_data);
    let witnesses_len = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data().len())
        .collect::<Vec<_>>();
    let witness = placeholder_witness
        .as_builder()
        .input_type(Some(Bytes::from(vec![0u8; 8])).pack())
        .build();
    assert_eq!(witnesses_len, vec![witness.as_slice().len(), 0]);
    ctx.verify(tx, FEE_RATE).unwrap();
}
