use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use std::collections::HashMap;

use crate::{
    constants::{ONE_CKB, SIGHASH_TYPE_HASH},
    test_util::random_out_point,
    tests::{
        build_sighash_script, init_context,
        omni_lock::{build_omnilock_script, build_omnilock_unlockers, OMNILOCK_BIN},
        ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACCOUNT2_KEY,
        ACCOUNT3_ARG, ACCOUNT3_KEY, FEE_RATE, SUDT_BIN,
    },
    traits::{CellCollector, CellQueryOptions, SecpCkbRawKeySigner},
    tx_builder::{
        omni_lock::OmniLockTransferBuilder, transfer::CapacityTransferBuilder,
        udt::UdtTransferBuilder,
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
    core::{Capacity, ScriptHashType},
    packed::{CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};
use rand::Rng;

use crate::tx_builder::{unlock_tx, CapacityBalancer, TxBuilder};
const ZERO_FEE_RATE: u64 = 0;

fn build_simple_config(key: H256) -> OmniLockConfig {
    let priv_key = secp256k1::SecretKey::from_slice(key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &priv_key);
    OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()))
}
#[test]
fn test_opentx_pay_from_sighash() {
    let cfg = build_simple_config(ACCOUNT0_KEY);
    test_opentx_pay_simple_hash(cfg);
}

#[test]
fn test_opentx_pay_from_ethereum() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    test_opentx_pay_simple_hash(cfg);
}

/// account0(200) => account0(exchange 199) + open pay 1,
/// account2(100) => account2(101 - transaction fee)
fn test_opentx_pay_simple_hash(mut cfg: OmniLockConfig) {
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
    let builder = CapacityTransferBuilder::new_with_transaction(
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
fn test_opentx_pay_from_multisig() {
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
    let builder = CapacityTransferBuilder::new_with_transaction(
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
fn test_opentx_pay_receive_sighash_absolute_from_start() {
    test_opentx_pay_receive_sighash_absolute(true);
}
#[test]
fn test_opentx_pay_receive_sighash_absolute_self() {
    test_opentx_pay_receive_sighash_absolute(false);
}
fn test_opentx_pay_receive_sighash_absolute(from_start: bool) {
    let sender_cfg = build_simple_config(ACCOUNT0_KEY);
    let receiver_cfg = build_simple_config(ACCOUNT2_KEY);
    test_opentx_pay_receive_simple_hash_absolute(sender_cfg, receiver_cfg, from_start);
}

#[test]
fn test_opentx_pay_receive_ethereum_absolute_from_start() {
    test_opentx_pay_receive_ethereum_absolute(true);
}
#[test]
fn test_opentx_pay_receive_ethereum_absolute_from_self() {
    test_opentx_pay_receive_ethereum_absolute(false);
}
fn test_opentx_pay_receive_ethereum_absolute(from_start: bool) {
    let cfgs: Vec<OmniLockConfig> = [ACCOUNT0_KEY, ACCOUNT2_KEY]
        .iter()
        .map(|key| {
            let priv_key = secp256k1::SecretKey::from_slice(key.as_bytes()).unwrap();
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &priv_key);
            OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()))
        })
        .collect();
    test_opentx_pay_receive_simple_hash_absolute(cfgs[0].clone(), cfgs[1].clone(), from_start);
}

/// account0(200) => account0(exchange 199) + open pay 1,
/// account2(100) => account2(101 - transaction fee)
fn test_opentx_pay_receive_simple_hash_absolute(
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

    let builder = CapacityTransferBuilder::new_with_transaction(
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
fn test_opentx_pay_receive_multisig_absolute_from_start() {
    test_opentx_pay_receive_multisig_absolute(true);
}

#[test]
fn test_opentx_pay_receive_multisig_absolute_from_self() {
    test_opentx_pay_receive_multisig_absolute(false);
}

/// multisig(200) => multisig(exchange 199) + open pay 1, locked by account0, account1, account2
/// account3(400) => account2(401 - transaction fee)
fn test_opentx_pay_receive_multisig_absolute(from_start: bool) {
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

    let builder = CapacityTransferBuilder::new_with_transaction(vec![], tx);
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

#[test]
fn test_opentx_udt_open_buy() {
    // ACCOUNT1(alice) will spend 50.01 CKB with fee to buy 1,000,000 SUDT
    // ACCOUNT2(bob) collect the 50 CKB with the transfer 1,000,000 SUDT
    let unlock_mode = OmniUnlockMode::Normal;
    let mut alice_cfg = build_simple_config(ACCOUNT1_KEY);
    alice_cfg.set_opentx_mode();
    let alice = build_omnilock_script(&alice_cfg);
    let bob = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(
        vec![(OMNILOCK_BIN, true), (SUDT_BIN, false)],
        vec![
            (alice.clone(), Some(300 * ONE_CKB)),
            (bob.clone(), Some(400 * ONE_CKB)),
        ],
    );
    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    let owner = build_sighash_script(H160::default());
    let type_script = Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(owner.calc_script_hash().as_bytes().pack())
        .build();
    let sudt_input = CellInput::new(random_out_point(), 0);
    let sudt_output = CellOutput::new_builder()
        .capacity(ONE_CKB.pack())
        .lock(bob.clone())
        .type_(Some(type_script.clone()).pack())
        .build();
    let sudt_capacity = sudt_output
        .occupied_capacity(Capacity::bytes(16).unwrap())
        .unwrap()
        .as_u64();
    println!("sudt_capacity: {}", sudt_capacity);
    let sudt_output = sudt_output
        .as_builder()
        .capacity(sudt_capacity.pack())
        .build();
    let sudt_data = Bytes::from(1_000_000u128.to_le_bytes().to_vec());
    ctx.add_live_cell(sudt_input, sudt_output, sudt_data.clone(), None);

    let fee = 100_0000u64;
    // build opentx alice's input
    let builder = OmniLockTransferBuilder::new_open(
        (50 * ONE_CKB + sudt_capacity + fee).into(),
        vec![],
        alice_cfg.clone(),
        None,
    );
    let placeholder_witness = alice_cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer = CapacityBalancer::new_simple(alice.clone(), placeholder_witness, ZERO_FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let alice_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(alice_key, alice_cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    // add sudt output
    let sudt_output = CellOutput::new_builder()
        .capacity((sudt_capacity).pack())
        .lock(alice.clone())
        .type_(Some(type_script.clone()).pack())
        .build();
    tx = tx
        .as_advanced_builder()
        .output(sudt_output.clone())
        .output_data(sudt_data.pack())
        .build();
    // update opentx input list
    let mut rng = rand::thread_rng();
    let salt: u32 = rng.gen();
    let wit = OpentxWitness::new_sig_all_relative(&tx, Some(salt)).unwrap();
    alice_cfg.set_opentx_input(wit);
    tx = OmniLockTransferBuilder::update_opentx_witness(
        tx,
        &alice_cfg,
        OmniUnlockMode::Normal,
        &ctx,
        &alice,
    )
    .unwrap();
    // config updated, so unlockers must rebuilt.
    let unlockers = build_omnilock_unlockers(alice_key, alice_cfg.clone(), unlock_mode);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;
    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    // use opentx
    let builder = UdtTransferBuilder::new_with_transaction(type_script, bob.clone(), vec![], tx);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(bob, placeholder_witness, FEE_RATE);

    let bob_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![bob_key]);
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
    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );
    assert_eq!(locked_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 3);
    assert_eq!(tx.inputs().len(), 3);
    let outputs = tx.outputs().into_iter().collect::<Vec<_>>();
    assert_eq!(outputs.len(), 4);
    assert_eq!(outputs[1], sudt_output);
    let expected_outputs_data = vec![
        Bytes::from(1_000_000u128.to_le_bytes().to_vec()),
        Bytes::from(0u128.to_le_bytes().to_vec()),
    ];
    let outputs_data = tx
        .outputs_data()
        .into_iter()
        .map(|d| d.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(outputs_data[1..3], expected_outputs_data);
    ctx.verify(tx, FEE_RATE).unwrap();
}
