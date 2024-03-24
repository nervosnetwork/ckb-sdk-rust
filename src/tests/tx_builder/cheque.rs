use std::collections::HashMap;

use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};

use crate::constants::{CHEQUE_CELL_SINCE, ONE_CKB, SIGHASH_TYPE_HASH};
use crate::tests::{
    build_cheque_script, build_sighash_script, init_context, ACCOUNT1_ARG, ACCOUNT1_KEY,
    ACCOUNT2_ARG, ACCOUNT2_KEY, CHEQUE_BIN, FEE_RATE, SUDT_BIN,
};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    cheque::{ChequeClaimBuilder, ChequeWithdrawBuilder},
    CapacityBalancer, TxBuilder,
};
use crate::unlock::{ChequeAction, ChequeUnlocker, ScriptUnlocker, SecpSighashUnlocker};
use crate::ScriptId;

use crate::test_util::random_out_point;

#[test]
fn test_cheque_claim() {
    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    let cheque_data_hash = H256::from(blake2b_256(CHEQUE_BIN));
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let cheque_script = build_cheque_script(&sender, &receiver, cheque_data_hash.clone());
    let type_script = Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(vec![9u8; 32]).pack())
        .build();
    let mut ctx = init_context(
        vec![(CHEQUE_BIN, true), (SUDT_BIN, false)],
        vec![
            (receiver.clone(), Some(100 * ONE_CKB)),
            (receiver.clone(), Some(200 * ONE_CKB)),
        ],
    );

    let receiver_input = CellInput::new(random_out_point(), 0);
    let receiver_output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver.clone())
        .type_(Some(type_script.clone()).pack())
        .build();
    let receiver_data = Bytes::from(1000u128.to_le_bytes().to_vec());
    ctx.add_live_cell(
        receiver_input.clone(),
        receiver_output.clone(),
        receiver_data,
        None,
    );

    let cheque_input = CellInput::new(random_out_point(), 0);
    let cheque_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(cheque_script)
        .type_(Some(type_script).pack())
        .build();
    let cheque_data = Bytes::from(500u128.to_le_bytes().to_vec());
    ctx.add_live_cell(
        cheque_input.clone(),
        cheque_output.clone(),
        cheque_data,
        None,
    );

    let builder = ChequeClaimBuilder::new(vec![cheque_input], receiver_input, sender.clone());
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(receiver.clone(), placeholder_witness.clone(), FEE_RATE);

    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account2_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer.clone()) as Box<_>);
    let cheque_unlocker = ChequeUnlocker::from((Box::new(signer) as Box<_>, ChequeAction::Claim));
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH),
        Box::new(sighash_unlocker),
    );
    unlockers.insert(
        ScriptId::new_data1(cheque_data_hash),
        Box::new(cheque_unlocker),
    );

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 3);
    assert_eq!(tx.inputs().len(), 3);
    let input_cells = vec![
        cheque_output,
        receiver_output.clone(),
        CellOutput::new_builder()
            .capacity((100 * ONE_CKB).pack())
            .lock(receiver.clone())
            .build(),
    ];
    for (idx, out_point) in tx.input_pts_iter().enumerate() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0, input_cells[idx]);
    }
    assert_eq!(tx.outputs().len(), 3);
    assert_eq!(tx.output(0).unwrap(), receiver_output);
    let sender_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(sender)
        .build();
    assert_eq!(tx.output(1).unwrap(), sender_output);
    assert_eq!(tx.output(2).unwrap().lock(), receiver);
    let expected_outputs_data = vec![
        Bytes::from((1000u128 + 500u128).to_le_bytes().to_vec()),
        Bytes::default(),
        Bytes::default(),
    ];
    let outputs_data = tx
        .outputs_data()
        .into_iter()
        .map(|d| d.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(outputs_data, expected_outputs_data);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 3);
    assert_eq!(witnesses[0].len(), 0);
    assert_eq!(witnesses[1].len(), placeholder_witness.as_slice().len());
    assert_eq!(witnesses[2].len(), 0);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_cheque_withdraw() {
    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    let cheque_data_hash = H256::from(blake2b_256(CHEQUE_BIN));
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let cheque_script = build_cheque_script(&sender, &receiver, cheque_data_hash.clone());
    let type_script = Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(vec![9u8; 32]).pack())
        .build();
    let mut ctx = init_context(
        vec![(CHEQUE_BIN, true), (SUDT_BIN, false)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
        ],
    );

    let cheque_out_point = random_out_point();
    let cheque_input = CellInput::new(cheque_out_point.clone(), CHEQUE_CELL_SINCE);
    let cheque_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(cheque_script)
        .type_(Some(type_script).pack())
        .build();
    let cheque_data = Bytes::from(500u128.to_le_bytes().to_vec());
    ctx.add_live_cell(cheque_input, cheque_output.clone(), cheque_data, None);

    let builder = ChequeWithdrawBuilder::new(vec![cheque_out_point], sender.clone(), None);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer.clone()) as Box<_>);
    let cheque_unlocker =
        ChequeUnlocker::from((Box::new(signer) as Box<_>, ChequeAction::Withdraw));
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH),
        Box::new(sighash_unlocker),
    );
    unlockers.insert(
        ScriptId::new_data1(cheque_data_hash),
        Box::new(cheque_unlocker),
    );

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 3);
    assert_eq!(tx.inputs().len(), 2);
    let input_cells = vec![
        cheque_output.clone(),
        CellOutput::new_builder()
            .capacity((100 * ONE_CKB).pack())
            .lock(sender.clone())
            .build(),
    ];
    for (idx, out_point) in tx.input_pts_iter().enumerate() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0, input_cells[idx]);
    }
    assert_eq!(tx.outputs().len(), 2);
    let sender_output = cheque_output.as_builder().lock(sender.clone()).build();
    assert_eq!(tx.output(0).unwrap(), sender_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![
        Bytes::from(500u128.to_le_bytes().to_vec()),
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
    assert_eq!(witnesses_len, vec![0, placeholder_witness.as_slice().len()]);
    ctx.verify(tx, FEE_RATE).unwrap();
}
