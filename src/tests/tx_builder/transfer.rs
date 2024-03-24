use std::collections::HashMap;

use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};

use crate::tests::{
    build_multisig_script, build_multisig_unlockers, build_sighash_script, init_context,
    ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACCOUNT2_KEY, ACP_BIN,
    FEE_RATE, ONE_CKB, SIGHASH_TYPE_HASH,
};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    transfer::CapacityTransferBuilder, unlock_tx, CapacityBalancer, TxBuilder,
};
use crate::unlock::{AcpUnlocker, MultisigConfig, ScriptUnlocker, SecpSighashUnlocker};
use crate::ScriptId;

#[test]
fn test_transfer_from_sighash() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
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
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let witnesses_len = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data().len())
        .collect::<Vec<_>>();
    assert_eq!(witnesses_len, vec![placeholder_witness.as_slice().len(), 0]);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_transfer_from_multisig() {
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();

    let sender = build_multisig_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = cfg.placeholder_witness();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let unlockers = build_multisig_unlockers(account0_key, cfg.clone());
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let mut locked_groups = None;
    for key in [account0_key, account2_key] {
        let unlockers = build_multisig_unlockers(key, cfg.clone());
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
        tx = new_tx;
        locked_groups = Some(new_locked_groups);
    }

    assert_eq!(locked_groups, Some(Vec::new()));
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].len(), placeholder_witness.as_slice().len());
    assert_eq!(witnesses[1].len(), 0);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_transfer_from_acp() {
    let data_hash = H256::from(blake2b_256(ACP_BIN));
    let sender = Script::new_builder()
        .code_hash(data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(ACCOUNT1_ARG.0.to_vec()).pack())
        .build();
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let ctx = init_context(
        vec![(ACP_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let script_unlocker = AcpUnlocker::from(Box::new(signer) as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(ScriptId::new_data1(data_hash), Box::new(script_unlocker));

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].len(), placeholder_witness.as_slice().len());
    assert_eq!(witnesses[1].len(), 0);
    ctx.verify(tx, FEE_RATE).unwrap();
}
