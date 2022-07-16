use std::collections::HashMap;

use crate::{
    constants::{ONE_CKB, SIGHASH_TYPE_HASH},
    test_util::random_out_point,
    tests::{
        build_sighash_script, init_context,
        omni_lock_util::{add_rce_cells, generate_rc},
        ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACCOUNT2_KEY,
        ACCOUNT3_ARG, ACCOUNT3_KEY, FEE_RATE,
    },
    traits::SecpCkbRawKeySigner,
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses, transfer::CapacityTransferBuilder,
        CapacityProvider,
    },
    unlock::{
        omni_lock::{AdminConfig, Identity},
        IdentityFlag, MultisigConfig, OmniLockConfig, OmniLockScriptSigner, OmniLockUnlocker,
        ScriptUnlocker, SecpSighashUnlocker,
    },
    util::blake160,
    ScriptId,
};

use ckb_crypto::secp::{Pubkey, SECP256K1};
use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::{FeeRate, ScriptHashType},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::tx_builder::{unlock_tx, CapacityBalancer, TxBuilder};

const OMNILOCK_BIN: &[u8] = include_bytes!("../test-data/omni_lock");

fn build_omnilock_script(cfg: &OmniLockConfig) -> Script {
    let omnilock_data_hash = H256::from(blake2b_256(OMNILOCK_BIN));
    Script::new_builder()
        .code_hash(omnilock_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(cfg.build_args().pack())
        .build()
}

fn build_omnilock_unlockers(
    key: secp256k1::SecretKey,
    config: OmniLockConfig,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = if config.is_ethereum() {
        SecpCkbRawKeySigner::new_with_ethereum_secret_keys(vec![key])
    } else {
        SecpCkbRawKeySigner::new_with_secret_keys(vec![key])
    };
    let script = build_omnilock_script(&config);
    let omnilock_script_signer =
        OmniLockScriptSigner::new(Box::new(signer) as Box<_>, config.clone());
    let omnilock_unlocker = OmniLockUnlocker::new(omnilock_script_signer, config);
    let omnilock_script_id = ScriptId::from(&script);
    let mut unlockers = HashMap::default();
    unlockers.insert(
        omnilock_script_id,
        Box::new(omnilock_unlocker) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}

#[test]
fn test_omnilock_transfer_from_sighash() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let cfg = OmniLockConfig::new_pubkey_hash(&pubkey.into());
    test_omnilock_simple_hash(cfg);
}

#[test]
fn test_omnilock_transfer_from_ethereum() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let cfg = OmniLockConfig::new_ethereum(&Pubkey::from(pubkey));
    test_omnilock_simple_hash(cfg);
}
fn test_omnilock_simple_hash(cfg: OmniLockConfig) {
    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
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
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account2_key, cfg.clone());
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let unlockers = build_omnilock_unlockers(account2_key, cfg);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

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
fn test_omnilock_transfer_from_sighash_wl() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let cfg = OmniLockConfig::new_pubkey_hash_with_lockarg(pubkey_hash);
    test_omnilock_simple_hash_rc(cfg);
}

#[test]
fn test_omnilock_transfer_from_ethereum_wl() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let cfg = OmniLockConfig::new_ethereum(&Pubkey::from(pubkey));

    test_omnilock_simple_hash_rc(cfg);
}

fn test_omnilock_simple_hash_rc(mut cfg: OmniLockConfig) {
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let (proof_vec, rc_type_id, rce_cells) = generate_rc(&mut ctx, cfg.id().to_smt_key().into());
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        cfg.id().clone(),
        None,
    ));

    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![(sender.clone(), Some(300 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = cfg.placeholder_witness();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone());

    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();
    let base_tx = add_rce_cells(base_tx, &rce_cells);

    let (tx_filled_witnesses, _) = fill_placeholder_witnesses(base_tx, &ctx, &unlockers).unwrap();
    let mut tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &ctx,
        &ctx,
        &ctx,
    )
    .unwrap();

    let unlockers = build_omnilock_unlockers(account0_key, cfg);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    // println!(
    //     "> tx: {}",
    //     serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    // );
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 4);
    assert_eq!(tx.inputs().len(), 1);
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
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].len(), placeholder_witness.as_slice().len());

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_transfer_from_sighash2_wl() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let cfg = OmniLockConfig::new_pubkey_hash_with_lockarg(pubkey_hash);
    test_omnilock_simple_hash_rc2(cfg);
}

fn build_alternative_auth(secretkey: &[u8], flag: IdentityFlag) -> Identity {
    let sender_key = secp256k1::SecretKey::from_slice(secretkey).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    Identity::new(flag, pubkey_hash)
}

fn test_omnilock_simple_hash_rc2(mut cfg: OmniLockConfig) {
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let alternative_auth =
        build_alternative_auth(ACCOUNT1_KEY.as_bytes(), IdentityFlag::PubkeyHash);
    let (proof_vec, rc_type_id, rce_cells) =
        generate_rc(&mut ctx, alternative_auth.to_smt_key().into());
    let admin_config = AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        alternative_auth,
        None,
    );
    cfg.set_admin_config(admin_config);

    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![(sender.clone(), Some(300 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = cfg.placeholder_witness();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account1_key, cfg.clone());

    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();
    let base_tx = add_rce_cells(base_tx, &rce_cells);

    let (tx_filled_witnesses, _) = fill_placeholder_witnesses(base_tx, &ctx, &unlockers).unwrap();
    let mut tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &ctx,
        &ctx,
        &ctx,
    )
    .unwrap();

    let unlockers = build_omnilock_unlockers(account1_key, cfg);

    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 4);
    assert_eq!(tx.inputs().len(), 1);
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
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].len(), placeholder_witness.as_slice().len());

    ctx.verify(tx, FEE_RATE).unwrap();
}
#[test]
fn test_omnilock_transfer_from_multisig() {
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let cfg = OmniLockConfig::new_multisig(multi_cfg);

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
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
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone());
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let mut locked_groups = None;
    for key in [account0_key, account2_key] {
        let unlockers = build_omnilock_unlockers(key, cfg.clone());
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
        assert!(new_locked_groups.is_empty());
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
fn test_omnilock_transfer_from_multisig_wl() {
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut cfg = OmniLockConfig::new_multisig(multi_cfg.clone());

    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let (proof_vec, rc_type_id, rce_cells) = generate_rc(&mut ctx, cfg.id().to_smt_key().into());
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        cfg.id().clone(),
        Some(multi_cfg),
    ));
    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![
        (sender.clone(), Some(100 * ONE_CKB)),
        (sender.clone(), Some(200 * ONE_CKB)),
        (sender.clone(), Some(300 * ONE_CKB)),
    ] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

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
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone());
    // let mut tx = builder
    //     .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
    //     .unwrap();
    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();
    let base_tx = add_rce_cells(base_tx, &rce_cells);

    let (tx_filled_witnesses, _) = fill_placeholder_witnesses(base_tx, &ctx, &unlockers).unwrap();
    let mut tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &ctx,
        &ctx,
        &ctx,
    )
    .unwrap();

    let mut locked_groups = None;
    for key in [account0_key, account2_key] {
        let unlockers = build_omnilock_unlockers(key, cfg.clone());
        let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
        assert!(new_locked_groups.is_empty());
        tx = new_tx;
        locked_groups = Some(new_locked_groups);
    }

    assert_eq!(locked_groups, Some(Vec::new()));
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 4);
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
fn test_omnilock_transfer_from_ownerlock() {
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let sender1 = build_sighash_script(ACCOUNT1_ARG);
    let hash = H160::from_slice(&sender1.calc_script_hash().as_slice()[0..20]).unwrap();
    let cfg = OmniLockConfig::new_ownerlock(hash);
    let sender0 = build_omnilock_script(&cfg);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender0.clone(), Some(50 * ONE_CKB)),
            (sender1.clone(), Some(61 * ONE_CKB)),
        ],
    );

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver.clone())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness0 = cfg.placeholder_witness();
    let placeholder_witness1 = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let balancer = CapacityBalancer {
        fee_rate: FeeRate::from_u64(FEE_RATE),
        capacity_provider: CapacityProvider::new(vec![
            (sender0.clone(), placeholder_witness0.clone()),
            (sender1.clone(), placeholder_witness1.clone()),
        ]),
        change_lock_script: None,
        force_small_change_as_fee: Some(ONE_CKB),
    };

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);

    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    let mut senders = vec![sender0, sender1];
    for out_point in tx.input_pts_iter() {
        let sender = ctx.get_input(&out_point).unwrap().0.lock();
        // println!("code hash:{:?}", sender.code_hash());
        assert!(senders.contains(&sender));
        senders.retain(|x| x != &sender);
    }
    assert!(senders.is_empty());
    assert_eq!(tx.outputs().len(), 1);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(0).unwrap().lock(), receiver);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].len(), placeholder_witness0.as_slice().len());
    assert_eq!(witnesses[1].len(), placeholder_witness1.as_slice().len());
    ctx.verify(tx, FEE_RATE).unwrap();
}

// unlock by administrator configuration
#[test]
fn test_omnilock_transfer_from_ownerlock_wl_admin() {
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let sender1 = build_sighash_script(ACCOUNT1_ARG);
    let hash = H160::from_slice(&sender1.calc_script_hash().as_slice()[0..20]).unwrap();
    let mut cfg = OmniLockConfig::new_ownerlock(hash);

    let owner_sender = build_sighash_script(ACCOUNT3_ARG);
    let mut ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![(owner_sender.clone(), Some(61 * ONE_CKB))],
    );

    let owner_hash = H160::from_slice(&owner_sender.calc_script_hash().as_slice()[0..20]).unwrap();
    let owner_id = Identity::new(IdentityFlag::OwnerLock, owner_hash);
    let (proof_vec, rc_type_id, rce_cells) = generate_rc(&mut ctx, owner_id.to_smt_key().into());
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        owner_id,
        None,
    ));
    let sender0 = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![(sender0.clone(), Some(50 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver.clone())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness0 = cfg.placeholder_witness();
    let placeholder_witness1 = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let balancer = CapacityBalancer {
        fee_rate: FeeRate::from_u64(FEE_RATE),
        capacity_provider: CapacityProvider::new(vec![
            (sender0.clone(), placeholder_witness0.clone()),
            (owner_sender.clone(), placeholder_witness1.clone()),
        ]),
        change_lock_script: None,
        force_small_change_as_fee: Some(ONE_CKB),
    };

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg);

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes()).unwrap();
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account3_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);

    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );
    // let mut tx = builder
    //     .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
    //     .unwrap();
    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();
    let base_tx = add_rce_cells(base_tx, &rce_cells);

    let (tx_filled_witnesses, _) = fill_placeholder_witnesses(base_tx, &ctx, &unlockers).unwrap();
    let mut tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &ctx,
        &ctx,
        &ctx,
    )
    .unwrap();

    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 5);
    assert_eq!(tx.inputs().len(), 2);
    let mut senders = vec![sender0, owner_sender];
    for out_point in tx.input_pts_iter() {
        let sender = ctx.get_input(&out_point).unwrap().0.lock();
        // println!("code hash:{:?}", sender.code_hash());
        assert!(senders.contains(&sender));
        senders.retain(|x| x != &sender);
    }
    assert!(senders.is_empty());
    assert_eq!(tx.outputs().len(), 1);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(0).unwrap().lock(), receiver);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].len(), placeholder_witness0.as_slice().len());
    assert_eq!(witnesses[1].len(), placeholder_witness1.as_slice().len());
    ctx.verify(tx, FEE_RATE).unwrap();
}
