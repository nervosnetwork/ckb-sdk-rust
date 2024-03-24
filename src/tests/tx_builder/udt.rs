use std::collections::HashMap;

use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType},
    packed::{CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::constants::{ONE_CKB, SIGHASH_TYPE_HASH};
use crate::tests::{
    build_sighash_script, init_context, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACP_BIN,
    FEE_RATE, SUDT_BIN,
};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    udt::{UdtIssueBuilder, UdtTargetReceiver, UdtTransferBuilder, UdtType},
    CapacityBalancer, TransferAction, TxBuilder,
};
use crate::unlock::{AcpUnlocker, ScriptUnlocker, SecpSighashUnlocker};
use crate::ScriptId;

use crate::test_util::random_out_point;

#[test]
fn test_udt_issue() {
    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    let owner = build_sighash_script(ACCOUNT1_ARG);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let ctx = init_context(
        vec![(SUDT_BIN, false)],
        vec![
            (owner.clone(), Some(100 * ONE_CKB)),
            (owner.clone(), Some(200 * ONE_CKB)),
            (owner.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let sudt_script_id = ScriptId::new_data1(sudt_data_hash.clone());
    let udt_receiver = UdtTargetReceiver::new(TransferAction::Create, receiver.clone(), 500);
    let builder = UdtIssueBuilder {
        udt_type: UdtType::Sudt,
        script_id: sudt_script_id,
        owner: owner.clone(),
        receivers: vec![udt_receiver],
    };
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(owner.clone(), placeholder_witness.clone(), FEE_RATE);

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
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), owner);
    }
    assert_eq!(tx.outputs().len(), 2);
    let type_script = Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(owner.calc_script_hash().as_bytes().pack())
        .build();
    let output = CellOutput::new_builder()
        .lock(receiver)
        .type_(Some(type_script).pack())
        .build();
    let occupied_capacity = output
        .occupied_capacity(Capacity::bytes(16).unwrap())
        .unwrap()
        .as_u64();
    let output = output
        .as_builder()
        .capacity(occupied_capacity.pack())
        .build();
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), owner);
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
    assert_eq!(witnesses_len, vec![placeholder_witness.as_slice().len(), 0]);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_udt_transfer() {
    let acp_data_hash = H256::from(blake2b_256(ACP_BIN));
    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let owner = build_sighash_script(H160::default());
    let type_script = Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(owner.calc_script_hash().as_bytes().pack())
        .build();
    let mut ctx = init_context(
        vec![(ACP_BIN, true), (SUDT_BIN, false)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
        ],
    );

    let sender_input = CellInput::new(random_out_point(), 0);
    let sender_output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(type_script.clone()).pack())
        .build();
    let sender_data = Bytes::from(500u128.to_le_bytes().to_vec());
    ctx.add_live_cell(sender_input, sender_output.clone(), sender_data, None);

    let receiver_acp_lock = Script::new_builder()
        .code_hash(acp_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(ACCOUNT2_ARG.0.to_vec()).pack())
        .build();
    let receiver_input = CellInput::new(random_out_point(), 0);
    let receiver_output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver_acp_lock.clone())
        .type_(Some(type_script.clone()).pack())
        .build();
    let receiver_data = Bytes::from(100u128.to_le_bytes().to_vec());
    ctx.add_live_cell(receiver_input, receiver_output.clone(), receiver_data, None);

    let udt_receiver = UdtTargetReceiver::new(TransferAction::Update, receiver_acp_lock, 300);
    let builder = UdtTransferBuilder {
        type_script,
        sender: sender.clone(),
        receivers: vec![udt_receiver],
    };
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let acp_unlocker = AcpUnlocker::from(Box::<SecpCkbRawKeySigner>::default() as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );
    unlockers.insert(ScriptId::new_data1(acp_data_hash), Box::new(acp_unlocker));

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 3);
    assert_eq!(tx.inputs().len(), 3);
    let outputs = tx.outputs().into_iter().collect::<Vec<_>>();
    assert_eq!(outputs.len(), 3);
    assert_eq!(outputs[0..2], vec![sender_output, receiver_output]);
    let expected_outputs_data = vec![
        Bytes::from(200u128.to_le_bytes().to_vec()),
        Bytes::from(400u128.to_le_bytes().to_vec()),
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
    assert_eq!(
        witnesses_len,
        vec![placeholder_witness.as_slice().len(), 0, 0]
    );
    ctx.verify(tx, FEE_RATE).unwrap();
}
