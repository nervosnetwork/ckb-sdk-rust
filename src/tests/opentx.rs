use ckb_jsonrpc_types as json_types;
use std::collections::HashMap;

use crate::{
    constants::{ONE_CKB, SIGHASH_TYPE_HASH},
    tests::{
        build_sighash_script, init_context,
        omni_lock::{build_omnilock_script, build_omnilock_unlockers, OMNILOCK_BIN},
        ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACCOUNT2_KEY,
        ACCOUNT3_ARG, ACCOUNT3_KEY, FEE_RATE,
    },
    traits::{CellCollector, CellQueryOptions, SecpCkbRawKeySigner},
    tx_builder::{
        omni_lock::OmniLockTransferBuilder, transfer::CapacityTransferBuilderWithTransaction,
    },
    unlock::{
        opentx::OpentxWitness, MultisigConfig, OmniLockConfig, OmniUnlockMode, ScriptUnlocker,
        SecpSighashUnlocker,
    },
    util::{blake160, keccak160},
    ScriptId,
};

use ckb_crypto::secp::{Pubkey, SECP256K1};
use ckb_types::{
    bytes::Bytes,
    packed::{CellOutput, WitnessArgs},
    prelude::*,
};
use rand::Rng;

use crate::tx_builder::{unlock_tx, CapacityBalancer, TxBuilder};
const ZERO_FEE_RATE: u64 = 0;

#[test]
fn test_omnilock_transfer_from_sighash() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let cfg = OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()));
    test_omnilock_simple_hash(cfg);
}

#[test]
fn test_omnilock_transfer_from_ethereum() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    test_omnilock_simple_hash(cfg);
}

/// account0(200) => account0(exchange 199) + open pay 1,
/// account2(100) => account2(101 - transaction fee)
fn test_omnilock_simple_hash(mut cfg: OmniLockConfig) {
    cfg.set_opentx_mode();
    let unlock_mode = OmniUnlockMode::Normal;
    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(200 * ONE_CKB)),
            (receiver.clone(), Some(100 * ONE_CKB)),
            (receiver.clone(), Some(200 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((199 * ONE_CKB).pack())
        .lock(sender.clone())
        .build();
    let builder = OmniLockTransferBuilder::new_open(
        ONE_CKB.into(),
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        None,
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, ZERO_FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    let mut rng = rand::thread_rng();
    let salt: u32 = rng.gen();
    let wit = OpentxWitness::new_sig_all_relative(&tx, Some(salt)).unwrap();
    cfg.set_opentx_input(wit);
    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &sender,
    )
    .unwrap();
    // config updated, so unlockers must rebuilt.
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;
    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    // use the opentx

    // Build ScriptUnlocker
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account2_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(receiver.clone(), placeholder_witness, 1000);
    // // Build the transaction
    let query = CellQueryOptions::new_lock(receiver.clone());
    let (inputs, total_capacity) = cell_collector.collect_live_cells(&query, false).unwrap();
    let input = &inputs[0];
    let input_output = &input.out_point;
    println!("{:#x} total_capacity: {}", input_output, total_capacity);
    // let output = CellOutput::new_builder()
    //     .lock(receiver.clone())
    //     .capacity((100 * ONE_CKB).pack())
    //     .build();
    let builder = CapacityTransferBuilderWithTransaction::new(
        vec![/*(output.clone(), Bytes::default())*/],
        tx,
    );
    let (tx, still_locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    assert_eq!(1, still_locked_groups.len());

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    let output1 = tx.output(1).unwrap();
    assert_eq!(output1.lock(), receiver);
    let receiver_capacity: u64 = output1.capacity().unpack();
    assert!(receiver_capacity - 100 * ONE_CKB < ONE_CKB);
    assert_eq!(tx.witnesses().len(), 2);
    ctx.verify(tx, FEE_RATE).unwrap();
}

/// multisig(200) => multisig(exchange 199) + open pay 1, locked by account0, account1, account2
/// account3(400) => account2(401 - transaction fee)
#[test]
fn test_omnilock_transfer_from_multisig() {
    let unlock_mode = OmniUnlockMode::Normal;
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut cfg = OmniLockConfig::new_multisig(multi_cfg);
    cfg.set_opentx_mode();

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT3_ARG);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
            (receiver.clone(), Some(400 * ONE_CKB)),
            (receiver.clone(), Some(500 * ONE_CKB)),
            (receiver.clone(), Some(600 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((199 * ONE_CKB).pack())
        .lock(sender.clone())
        .build();
    let builder = OmniLockTransferBuilder::new_open(
        ONE_CKB.into(),
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        None,
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, ZERO_FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    // add opentx hash data
    let mut rng = rand::thread_rng();
    let salt: u32 = rng.gen();
    let wit = OpentxWitness::new_sig_all_relative(&tx, Some(salt)).unwrap();
    cfg.set_opentx_input(wit);
    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &sender,
    )
    .unwrap();
    for key in [account0_key, account2_key] {
        let unlockers = build_omnilock_unlockers(key, cfg.clone(), unlock_mode);
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
        assert!(new_locked_groups.is_empty());
        tx = new_tx;
    }

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    // use the opentx

    // Build ScriptUnlocker
    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account3_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(receiver.clone(), placeholder_witness.clone(), 1000);
    // // Build the transaction
    let query = CellQueryOptions::new_lock(receiver.clone());
    let (inputs, total_capacity) = cell_collector.collect_live_cells(&query, false).unwrap();
    let input = &inputs[0];
    let input_output = &input.out_point;
    println!("{:#x} total_capacity: {}", input_output, total_capacity);
    // let output = CellOutput::new_builder()
    //     .lock(receiver.clone())
    //     .capacity((100 * ONE_CKB).pack())
    //     .build();
    let builder = CapacityTransferBuilderWithTransaction::new(
        vec![/*(output.clone(), Bytes::default())*/],
        tx,
    );
    let (tx, still_locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    assert_eq!(1, still_locked_groups.len());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    let output1 = tx.output(1).unwrap();
    assert_eq!(output1.lock(), receiver);
    let receiver_capacity: u64 = output1.capacity().unpack();
    assert!(receiver_capacity - 400 * ONE_CKB < ONE_CKB);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[1].len(), placeholder_witness.as_slice().len());
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_transfer_from_sighash_absolute_from_start() {
    test_omnilock_transfer_from_sighash_absolute(true);
}
#[test]
fn test_omnilock_transfer_from_sighash_absolute_self() {
    test_omnilock_transfer_from_sighash_absolute(false);
}
fn test_omnilock_transfer_from_sighash_absolute(from_start: bool) {
    let cfgs: Vec<OmniLockConfig> = [ACCOUNT0_KEY, ACCOUNT2_KEY]
        .iter()
        .map(|key| {
            let priv_key = secp256k1::SecretKey::from_slice(key.as_bytes())
                .map_err(|err| format!("invalid sender secret key: {}", err))
                .unwrap();
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &priv_key);
            OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()))
        })
        .collect();
    test_omnilock_simple_hash_absolute(cfgs[0].clone(), cfgs[1].clone(), from_start);
}

#[test]
fn test_omnilock_transfer_from_ethereum_absolute_from_start() {
    test_omnilock_transfer_from_ethereum_absolute(true);
}
#[test]
fn test_omnilock_transfer_from_ethereum_absolute_from_self() {
    test_omnilock_transfer_from_ethereum_absolute(false);
}
fn test_omnilock_transfer_from_ethereum_absolute(from_start: bool) {
    let cfgs: Vec<OmniLockConfig> = [ACCOUNT0_KEY, ACCOUNT2_KEY]
        .iter()
        .map(|key| {
            let priv_key = secp256k1::SecretKey::from_slice(key.as_bytes()).unwrap();
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &priv_key);
            OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()))
        })
        .collect();
    test_omnilock_simple_hash_absolute(cfgs[0].clone(), cfgs[1].clone(), from_start);
}

/// account0(200) => account0(exchange 199) + open pay 1,
/// account2(100) => account2(101 - transaction fee)
fn test_omnilock_simple_hash_absolute(
    mut sender_cfg: OmniLockConfig,
    mut receiver_cfg: OmniLockConfig,
    from_start: bool,
) {
    sender_cfg.set_opentx_mode();
    receiver_cfg.set_opentx_mode();
    let unlock_mode = OmniUnlockMode::Normal;
    let sender = build_omnilock_script(&sender_cfg);
    let receiver = build_omnilock_script(&receiver_cfg);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(200 * ONE_CKB)),
            (receiver.clone(), Some(100 * ONE_CKB)),
            (receiver.clone(), Some(200 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((199 * ONE_CKB).pack())
        .lock(sender.clone())
        .build();
    let builder = OmniLockTransferBuilder::new_open(
        (ONE_CKB).into(),
        vec![(output.clone(), Bytes::default())],
        sender_cfg.clone(),
        None,
    );
    let placeholder_witness = sender_cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, ZERO_FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, sender_cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    let mut rng = rand::thread_rng();
    let salt: u32 = rng.gen();
    let wit = OpentxWitness::new_sig_all_absolute(&tx, Some(salt)).unwrap();
    sender_cfg.set_opentx_input(wit);
    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &sender_cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &sender,
    )
    .unwrap();
    // config updated, so unlockers must rebuilt.
    let unlockers = build_omnilock_unlockers(account0_key, sender_cfg.clone(), unlock_mode);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    // use the opentx
    let opentx_input_len = tx.inputs().len();
    let opentx_output_len = tx.outputs().len();
    receiver_cfg.set_opentx_reserve_bytes_by_commands(20);
    // Build ScriptUnlocker
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account2_key, receiver_cfg.clone(), unlock_mode);

    // Build CapacityBalancer
    let placeholder_witness = receiver_cfg.placeholder_witness(unlock_mode).unwrap();
    // why + 100? After update openwitness input list, will need tens of bytes more, if not +100, after update, should calculate adjust the fee again.
    // If adjust the transaction fee later, the exchange may mot be enough to maintain the minimal capacity.
    let balancer = CapacityBalancer::new_simple(receiver.clone(), placeholder_witness, FEE_RATE);

    let builder = CapacityTransferBuilderWithTransaction::new(
        vec![/*(output.clone(), Bytes::default())*/],
        tx,
    );
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    assert_eq!(opentx_input_len + 1, tx.inputs().len());
    assert_eq!(opentx_output_len + 1, tx.outputs().len());

    let salt: u32 = rng.gen();
    let mut wit = if from_start {
        OpentxWitness::new_sig_all_absolute(&tx, Some(salt))
    } else {
        OpentxWitness::new_sig_to_end_absolute(&tx, Some(salt), opentx_input_len, opentx_output_len)
    }
    .unwrap(); //OpentxWitness::new_sig_all_absolute(&tx, Some(salt)).unwrap();
    wit.add_tx_hash_input();
    receiver_cfg.set_opentx_input(wit);

    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &receiver_cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &receiver,
    )
    .unwrap();

    // config updated, so unlockers must rebuilt.
    let unlockers = build_omnilock_unlockers(account2_key, receiver_cfg.clone(), unlock_mode);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();

    assert_eq!(1, new_locked_groups.len());
    tx = new_tx;

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    let output1 = tx.output(1).unwrap();
    assert_eq!(output1.lock(), receiver);
    let receiver_capacity: u64 = output1.capacity().unpack();
    assert!(receiver_capacity - 100 * ONE_CKB < ONE_CKB);
    assert_eq!(tx.witnesses().len(), 2);
    ctx.verify(tx, FEE_RATE).unwrap();
}
#[test]
fn test_omnilock_transfer_from_multisig_absolute_from_start() {
    test_omnilock_transfer_from_multisig_absolute(true);
}

#[test]
fn test_omnilock_transfer_from_multisig_absolute_from_self() {
    test_omnilock_transfer_from_multisig_absolute(false);
}

/// multisig(200) => multisig(exchange 199) + open pay 1, locked by account0, account1, account2
/// account3(400) => account2(401 - transaction fee)
fn test_omnilock_transfer_from_multisig_absolute(from_start: bool) {
    let unlock_mode = OmniUnlockMode::Normal;
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut sender_cfg = OmniLockConfig::new_multisig(multi_cfg);
    sender_cfg.set_opentx_mode();

    let sender = build_omnilock_script(&sender_cfg);
    let lock_args = vec![
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
        ACCOUNT3_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut receiver_cfg = OmniLockConfig::new_multisig(multi_cfg);
    receiver_cfg.set_opentx_mode();
    let receiver = build_omnilock_script(&receiver_cfg);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
            (receiver.clone(), Some(400 * ONE_CKB)),
            (receiver.clone(), Some(500 * ONE_CKB)),
            (receiver.clone(), Some(600 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((199 * ONE_CKB).pack())
        .lock(sender.clone())
        .build();
    let builder = OmniLockTransferBuilder::new_open(
        ONE_CKB.into(),
        vec![(output.clone(), Bytes::default())],
        sender_cfg.clone(),
        None,
    );
    let placeholder_witness = sender_cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, ZERO_FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, sender_cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    // add opentx hash data
    let mut rng = rand::thread_rng();
    let salt: u32 = rng.gen();
    let wit = OpentxWitness::new_sig_all_absolute(&tx, Some(salt)).unwrap();
    sender_cfg.set_opentx_input(wit);
    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &sender_cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &sender,
    )
    .unwrap();
    for key in [account0_key, account2_key] {
        let unlockers = build_omnilock_unlockers(key, sender_cfg.clone(), unlock_mode);
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
        assert!(new_locked_groups.is_empty());
        tx = new_tx;
    }

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    // use the opentx
    let opentx_input_len = tx.inputs().len();
    let opentx_output_len = tx.outputs().len();
    receiver_cfg.set_opentx_reserve_bytes_by_commands(20);
    // Build ScriptUnlocker
    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account1_key, receiver_cfg.clone(), unlock_mode);
    // Build CapacityBalancer
    let placeholder_witness = receiver_cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer = CapacityBalancer::new_simple(receiver.clone(), placeholder_witness, FEE_RATE);

    let builder = CapacityTransferBuilderWithTransaction::new(vec![], tx);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    assert_eq!(opentx_input_len + 1, tx.inputs().len());
    assert_eq!(opentx_output_len + 1, tx.outputs().len());

    let salt: u32 = rng.gen();
    let mut wit = if from_start {
        OpentxWitness::new_sig_all_absolute(&tx, Some(salt))
    } else {
        OpentxWitness::new_sig_to_end_absolute(&tx, Some(salt), opentx_input_len, opentx_output_len)
    }
    .unwrap(); //OpentxWitness::new_sig_all_absolute(&tx, Some(salt)).unwrap();
    wit.add_tx_hash_input();
    receiver_cfg.set_opentx_input(wit);

    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &receiver_cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &receiver,
    )
    .unwrap();

    for key in [account1_key, account3_key] {
        let unlockers = build_omnilock_unlockers(key, receiver_cfg.clone(), unlock_mode);
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
        assert_eq!(1, new_locked_groups.len());
        tx = new_tx;
    }
    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    let output1 = tx.output(1).unwrap();
    assert_eq!(output1.lock(), receiver);
    let receiver_capacity: u64 = output1.capacity().unpack();
    assert!(receiver_capacity - 400 * ONE_CKB < ONE_CKB);

    assert_eq!(tx.witnesses().len(), 2);
    ctx.verify(tx, FEE_RATE).unwrap();
}
