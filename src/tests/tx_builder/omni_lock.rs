use std::collections::HashMap;

use crate::{
    constants::{ONE_CKB, SIGHASH_TYPE_HASH},
    test_util::random_out_point,
    tests::{
        build_omnilock_script, build_sighash_script, init_context,
        tx_builder::omni_lock_util::generate_rc, ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG,
        ACCOUNT1_KEY, ACCOUNT2_ARG, ACCOUNT2_KEY, ACCOUNT3_ARG, ACCOUNT3_KEY, ALWAYS_SUCCESS_BIN,
        FEE_RATE, OMNILOCK_BIN, SUDT_BIN,
    },
    traits::{CellDepResolver, SecpCkbRawKeySigner},
    tx_builder::{
        acp::{AcpTransferBuilder, AcpTransferReceiver},
        balance_tx_capacity, fill_placeholder_witnesses,
        omni_lock::OmniLockTransferBuilder,
        udt::{UdtTargetReceiver, UdtTransferBuilder},
        unlock_tx, CapacityBalancer, CapacityProvider, TransferAction, TxBuilder,
    },
    types::xudt_rce_mol::SmtProofEntryVec,
    unlock::{
        omni_lock::{AdminConfig, Identity},
        IdentityFlag, InfoCellData, MultisigConfig, OmniLockAcpConfig, OmniLockConfig,
        OmniLockScriptSigner, OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker,
        SecpSighashUnlocker,
    },
    util::{blake160, keccak160},
    ScriptId, Since,
};

use ckb_crypto::secp::{Pubkey, SECP256K1};
use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::{FeeRate, ScriptHashType},
    packed::{Byte32, CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};
use rand::Rng;

fn build_omnilock_unlockers(
    key: secp256k1::SecretKey,
    config: OmniLockConfig,
    unlock_mode: OmniUnlockMode,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = if config.is_ethereum() {
        SecpCkbRawKeySigner::new_with_ethereum_secret_keys(vec![key])
    } else {
        SecpCkbRawKeySigner::new_with_secret_keys(vec![key])
    };
    let script = build_omnilock_script(&config);
    let omnilock_script_signer =
        OmniLockScriptSigner::new(Box::new(signer) as Box<_>, config.clone(), unlock_mode);
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

fn test_omnilock_simple_hash(cfg: OmniLockConfig) {
    let unlock_mode = OmniUnlockMode::Normal;
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
    let builder =
        OmniLockTransferBuilder::new(vec![(output.clone(), Bytes::default())], cfg.clone(), None);
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account2_key, cfg, unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    let json_tx: ckb_jsonrpc_types::TransactionView =
        ckb_jsonrpc_types::TransactionView::from(tx.clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

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
    let mut cfg = OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_pubkey_hash(blake160(&pubkey.serialize()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_simple_hash_rc(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_transfer_from_sighash_wl_input_admin() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_pubkey_hash(blake160(&pubkey.serialize()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_simple_hash_rc_input(cfg);
}

fn test_omnilock_simple_hash_rc_input(mut cfg: OmniLockConfig) {
    let unlock_mode = OmniUnlockMode::Admin;
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(
        vec![(OMNILOCK_BIN, true), (ALWAYS_SUCCESS_BIN, false)],
        vec![],
    );
    let mut admin_config = cfg.get_admin_config().unwrap().clone();

    let (proof_vec, rc_type_id, rce_cells) = generate_rc(
        &mut ctx,
        admin_config.get_auth().to_smt_key().into(),
        admin_config.rce_in_input(),
        ACCOUNT3_ARG,
    );
    admin_config.set_proofs(proof_vec);
    admin_config.set_rc_type_id(H256::from_slice(rc_type_id.as_ref()).unwrap());
    cfg.set_admin_config(admin_config);

    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![(sender.clone(), Some(100 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = OmniLockTransferBuilder::new(
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        Some(rce_cells.clone()),
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes()).unwrap();
    let mut unlockers = build_omnilock_unlockers(account3_key, cfg.clone(), unlock_mode);

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account3_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);

    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );

    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();

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

    assert_eq!(rce_cells.len(), 3); // rc_rule for input, rc_rule for output, rc_rule_vec
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 3); // one is omnilock, one is sighash, one is always success
    assert_eq!(tx.inputs().len(), 4);
    for out_point in tx.input_pts_iter().skip(rce_cells.len()) {
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
    assert_eq!(witnesses.len(), 4);
    assert_eq!(
        witnesses[rce_cells.len()].len(),
        placeholder_witness.as_slice().len()
    );

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_transfer_from_ethereum_wl_input_admin() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_simple_hash_rc_input(cfg);
}

#[test]
fn test_omnilock_transfer_from_ethereum_wl() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_simple_hash_rc(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_transfer_from_sighash_wl_admin() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_pubkey_hash(blake160(&pubkey.serialize()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));

    test_omnilock_simple_hash_rc(cfg, OmniUnlockMode::Admin);
}

#[test]
fn test_omnilock_transfer_from_ethereum_wl_admin() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_simple_hash_rc(cfg, OmniUnlockMode::Admin);
}

fn test_omnilock_simple_hash_rc(mut cfg: OmniLockConfig, unlock_mode: OmniUnlockMode) {
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let (rce_cells, rce_cells_len) = match unlock_mode {
        OmniUnlockMode::Admin => {
            let mut admin_config = cfg.get_admin_config().unwrap().clone();
            let rc_args = match unlock_mode {
                OmniUnlockMode::Admin => ACCOUNT3_ARG,
                OmniUnlockMode::Normal => ACCOUNT0_ARG,
            };
            let (proof_vec, rc_type_id, rce_cells) = generate_rc(
                &mut ctx,
                admin_config.get_auth().to_smt_key().into(),
                false,
                rc_args,
            );
            admin_config.set_proofs(proof_vec);
            admin_config.set_rc_type_id(H256::from_slice(rc_type_id.as_ref()).unwrap());
            cfg.set_admin_config(admin_config);
            let rce_cells_len = rce_cells.len();
            (Some(rce_cells), rce_cells_len)
        }
        OmniUnlockMode::Normal => (None, 0),
    };
    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![(sender.clone(), Some(300 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = OmniLockTransferBuilder::new(
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        rce_cells,
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let unlock_key = match unlock_mode {
        OmniUnlockMode::Admin => ACCOUNT3_KEY,
        OmniUnlockMode::Normal => ACCOUNT0_KEY,
    };
    let account0_key = secp256k1::SecretKey::from_slice(unlock_key.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);

    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();

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

    let unlockers = build_omnilock_unlockers(account0_key, cfg, unlock_mode);
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    // println!(
    //     "> tx: {}",
    //     serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    // );
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1 + rce_cells_len);
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
    let cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);
    test_omnilock_simple_hash_rc2(cfg);
}

fn build_alternative_auth(secretkey: &[u8], flag: IdentityFlag) -> Identity {
    let sender_key = secp256k1::SecretKey::from_slice(secretkey).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    Identity::new(flag, pubkey_hash)
}

fn test_omnilock_simple_hash_rc2(mut cfg: OmniLockConfig) {
    let unlock_mode = OmniUnlockMode::Admin;
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let alternative_auth =
        build_alternative_auth(ACCOUNT1_KEY.as_bytes(), IdentityFlag::PubkeyHash);
    let (proof_vec, rc_type_id, rce_cells) = generate_rc(
        &mut ctx,
        alternative_auth.to_smt_key().into(),
        false,
        ACCOUNT1_ARG,
    );
    let admin_config = AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        alternative_auth,
        None,
        false,
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
    let builder = OmniLockTransferBuilder::new(
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        Some(rce_cells),
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account1_key, cfg.clone(), unlock_mode);

    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();

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

    let unlockers = build_omnilock_unlockers(account1_key, cfg, unlock_mode);

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
    let unlock_mode = OmniUnlockMode::Normal;
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
    let builder =
        OmniLockTransferBuilder::new(vec![(output.clone(), Bytes::default())], cfg.clone(), None);
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let mut locked_groups = None;
    for key in [account0_key, account2_key] {
        let unlockers = build_omnilock_unlockers(key, cfg.clone(), unlock_mode);
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
fn test_omnilock_transfer_from_multisig_wl_normal() {
    test_omnilock_transfer_from_multisig_wl_commnon(OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_transfer_from_multisig_wl_admin() {
    test_omnilock_transfer_from_multisig_wl_commnon(OmniUnlockMode::Admin);
}

fn test_omnilock_transfer_from_multisig_wl_commnon(unlock_mode: OmniUnlockMode) {
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut cfg = OmniLockConfig::new_multisig(multi_cfg);

    let lock_args = vec![
        ACCOUNT3_ARG.clone(), // the different key
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let admin_id = Identity::new_multisig(multi_cfg.clone());
    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let (proof_vec, rc_type_id, rce_cells) =
        generate_rc(&mut ctx, admin_id.to_smt_key().into(), false, ACCOUNT0_ARG);
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        admin_id,
        Some(multi_cfg),
        false,
    ));
    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![
        (sender.clone(), Some(100 * ONE_CKB)),
        (sender.clone(), Some(200 * ONE_CKB)),
        (sender.clone(), Some(300 * ONE_CKB)),
    ] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = OmniLockTransferBuilder::new(
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        Some(rce_cells),
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let key0 = match unlock_mode {
        OmniUnlockMode::Admin => ACCOUNT3_KEY,
        OmniUnlockMode::Normal => ACCOUNT0_KEY,
    };
    let account0_key = secp256k1::SecretKey::from_slice(key0.as_bytes()).unwrap();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    // let mut tx = builder
    //     .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
    //     .unwrap();
    let base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();

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
        let unlockers = build_omnilock_unlockers(key, cfg.clone(), unlock_mode);
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
    let unlock_mode = OmniUnlockMode::Normal;
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
    let builder =
        OmniLockTransferBuilder::new(vec![(output.clone(), Bytes::default())], cfg.clone(), None);
    let placeholder_witness0 = cfg.placeholder_witness(unlock_mode).unwrap();
    let placeholder_witness1 = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let balancer = CapacityBalancer {
        fee_rate: FeeRate::from_u64(FEE_RATE),
        capacity_provider: CapacityProvider::new_simple(vec![
            (sender0.clone(), placeholder_witness0.clone()),
            (sender1.clone(), placeholder_witness1.clone()),
        ]),
        change_lock_script: None,
        force_small_change_as_fee: Some(ONE_CKB),
    };

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg, unlock_mode);

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
    let unlock_mode = OmniUnlockMode::Admin;
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
    let (proof_vec, rc_type_id, rce_cells) =
        generate_rc(&mut ctx, owner_id.to_smt_key().into(), false, ACCOUNT0_ARG);
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        owner_id,
        None,
        false,
    ));
    let sender0 = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in vec![(sender0.clone(), Some(50 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver.clone())
        .build();
    let builder = OmniLockTransferBuilder::new(
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        Some(rce_cells),
    );
    let placeholder_witness0 = cfg.placeholder_witness(unlock_mode).unwrap();
    let placeholder_witness1 = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let balancer = CapacityBalancer {
        fee_rate: FeeRate::from_u64(FEE_RATE),
        capacity_provider: CapacityProvider::new_simple(vec![
            (sender0.clone(), placeholder_witness0.clone()),
            (owner_sender.clone(), placeholder_witness1.clone()),
        ]),
        change_lock_script: None,
        force_small_change_as_fee: Some(ONE_CKB),
    };

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg, unlock_mode);

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

#[test]
fn test_omnilock_transfer_from_acp() {
    // account0 sender with acp
    // account2 receiver

    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);

    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);

    cfg.set_acp_config(OmniLockAcpConfig::new(0, 0));
    let unlock_mode = OmniUnlockMode::Normal;
    let sender = build_omnilock_script(&cfg);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
        ],
    );
    let output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();

    let builder =
        OmniLockTransferBuilder::new(vec![(output.clone(), Bytes::default())], cfg.clone(), None);

    let placeholder_witness = cfg.placeholder_witness(OmniUnlockMode::Normal).unwrap();

    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg, unlock_mode);
    let signer0 = SecpCkbRawKeySigner::new_with_secret_keys(vec![account0_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer0) as Box<_>);
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH),
        Box::new(sighash_unlocker),
    );
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
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
fn test_omnilock_transfer_to_acp() {
    // account0 sender
    // account2 receiver with acp

    let sender = build_sighash_script(ACCOUNT0_ARG);

    let receiver_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &receiver_key);

    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);
    cfg.set_acp_config(OmniLockAcpConfig::new(9, 5));
    let unlock_mode = OmniUnlockMode::Normal;
    let receiver = build_omnilock_script(&cfg);

    let ctx = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (receiver.clone(), Some(61 * ONE_CKB)),
        ],
    );

    let acp_receiver = AcpTransferReceiver::new(receiver.clone(), 10 * ONE_CKB);
    let builder = AcpTransferBuilder::new(vec![acp_receiver]);

    let placeholder_witness1 = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness1.clone(), FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg, unlock_mode);
    let signer0 = SecpCkbRawKeySigner::new_with_secret_keys(vec![account0_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer0) as Box<_>);
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH),
        Box::new(sighash_unlocker),
    );
    let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(new_locked_groups.is_empty());
    tx = new_tx;

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    let acp_output = CellOutput::new_builder()
        .capacity(((61 + 10) * ONE_CKB).pack())
        .lock(receiver)
        .build();
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), acp_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].len(), 0);
    assert_eq!(witnesses[1].len(), placeholder_witness1.as_slice().len());
    ctx.verify(tx, FEE_RATE).unwrap();
}

fn build_omnilock_acp_cfg(account_key: &H256) -> OmniLockConfig {
    let receiver_key = secp256k1::SecretKey::from_slice(account_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &receiver_key);
    let mut cfg = OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()));
    cfg.set_acp_config(OmniLockAcpConfig::new(9, 2));
    cfg
}

#[test]
fn test_omnilock_udt_transfer() {
    // +---------+--------+--------+--------+------+------+-----------+
    // | account |  role  |from_ckb|from_udt|to_ckb|to_udt|   type    |
    // +---------+--------+--------+--------+------+------+-----------+
    // |account1 |sender  |200     |500     |200   |200   |udt        |
    // +---------+--------+--------+--------+------+------+-----------+
    // |account2 |receiver|200     |100     |200   |400   |acp+udt    |
    // +---------+--------+--------+--------+------+------+-----------+
    // |account1 |receiver|100     |0       |99.98x|0     |fee        |
    // +---------+--------+--------+--------+------+------+-----------+

    let unlock_mode = OmniUnlockMode::Normal;

    let sender_cfg = build_omnilock_acp_cfg(&ACCOUNT1_KEY);
    let receiver_cfg = build_omnilock_acp_cfg(&ACCOUNT2_KEY);

    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let owner = build_sighash_script(H160::default());
    let type_script = Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(owner.calc_script_hash().as_bytes().pack())
        .build();
    let mut ctx = init_context(
        vec![(OMNILOCK_BIN, true), (SUDT_BIN, false)],
        vec![
            // transaction fee pool
            (sender.clone(), Some(100 * ONE_CKB)),
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

    let receiver_acp_lock = build_omnilock_script(&receiver_cfg);
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
    let mut unlockers = build_omnilock_unlockers(account1_key, sender_cfg, unlock_mode);
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

#[test]
fn test_omnilock_transfer_from_sighash_timelock() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);
    test_omnilock_simple_hash_timelock(cfg);
}

#[test]
fn test_omnilock_transfer_from_ethereum_timelock() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    test_omnilock_simple_hash_timelock(cfg);
}

fn test_omnilock_simple_hash_timelock(mut cfg: OmniLockConfig) {
    let unlock_mode = OmniUnlockMode::Normal;
    let epoch_number = 200;
    let since = Since::new_absolute_epoch(epoch_number);

    cfg.set_time_lock_config(since.value());

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let mut ctx = init_context(vec![(OMNILOCK_BIN, true)], vec![]);

    let prepare_out_point = random_out_point();
    let prepare_input = CellInput::new(prepare_out_point, since.value());
    let prepare_output = CellOutput::new_builder()
        .capacity((300 * ONE_CKB + 1000).pack())
        .lock(sender.clone())
        .build();
    ctx.add_live_cell(prepare_input, prepare_output, Bytes::default(), None);

    let output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder =
        OmniLockTransferBuilder::new(vec![(output.clone(), Bytes::default())], cfg.clone(), None);
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let since_source = cfg.get_since_source();
    let balancer = CapacityBalancer::new_simple_with_since(
        sender.clone(),
        placeholder_witness.clone(),
        since_source,
        FEE_RATE,
    );

    let mut cell_collector = ctx.to_live_cells_context();
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account2_key, cfg.clone(), unlock_mode);
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    // let unlockers = build_omnilock_unlockers(account2_key, cfg, unlock_mode);
    // let (new_tx, new_locked_groups) = unlock_tx(tx.clone(), &ctx, &unlockers).unwrap();
    assert!(locked_groups.is_empty());
    // tx = new_tx;

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 1);

    let mut since_bytes = [0u8; 8];
    since_bytes.copy_from_slice(tx.inputs().get(0).unwrap().since().as_slice());
    let input_since = u64::from_le_bytes(since_bytes);
    assert_eq!(input_since, since.value());

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

fn build_sudt_script(omnilock_hash: Byte32) -> Script {
    let sudt_data_hash = H256::from(blake2b_256(SUDT_BIN));
    Script::new_builder()
        .code_hash(sudt_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(omnilock_hash.as_bytes().pack())
        .build()
}

fn build_info_cell_type_script() -> (Script, H256) {
    let mut rng = rand::thread_rng();
    let data_hash = H256::from(blake2b_256(ALWAYS_SUCCESS_BIN));
    let mut args = vec![0u8; 32];
    rng.fill(&mut args[..]);
    let script = Script::new_builder()
        .code_hash(data_hash.pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(args).pack())
        .build();
    let script_hash = script.calc_script_hash();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(script_hash.as_slice());
    (script, H256::from_slice(&hash).unwrap())
}

#[test]
fn test_omnilock_sudt_supply() {
    let unlock_mode = OmniUnlockMode::Normal;
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);
    let (info_cell_type_script, type_script_hash) = build_info_cell_type_script();
    cfg.set_info_cell(type_script_hash);

    let sender = build_omnilock_script(&cfg);
    let sudt_script = build_sudt_script(sender.calc_script_hash());
    let mut ctx = init_context(
        vec![
            (OMNILOCK_BIN, true),
            (SUDT_BIN, false),
            (ALWAYS_SUCCESS_BIN, false),
        ],
        vec![
            // (sender.clone(), Some(200 * ONE_CKB)),// transaction fee pool
        ],
    );
    // build input cell
    let mut info_cell = InfoCellData::new_simple(
        2000,
        10000,
        H256::from_slice(sudt_script.calc_script_hash().as_slice()).unwrap(),
    );
    let input = CellInput::new(random_out_point(), 0);
    let output = CellOutput::new_builder()
        .capacity((1000 * ONE_CKB + 1000).pack())
        .lock(sender.clone())
        .type_(Some(info_cell_type_script.clone()).pack())
        .build();

    ctx.add_live_cell(input.clone(), output, info_cell.pack(), None);

    info_cell.current_supply = 3000u128;
    let output_supply_data = info_cell.pack();
    let output_supply = CellOutput::new_builder()
        .capacity(((1000 - 16) * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(info_cell_type_script).pack())
        .build();

    let mint_receiver = build_sighash_script(ACCOUNT1_ARG);
    let mint_output = CellOutput::new_builder()
        .capacity((16 * ONE_CKB).pack())
        .type_(Some(sudt_script).pack())
        .lock(mint_receiver.clone())
        .build();

    let builder = OmniLockTransferBuilder::new(
        vec![
            (output_supply.clone(), output_supply_data),
            (mint_output, 1000u128.pack().as_bytes()),
        ],
        cfg.clone(),
        None,
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let mut balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);
    balancer.force_small_change_as_fee = Some(ONE_CKB); // TODO: use correct transaction fee

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let mut unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account0_key]);
    let script_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);

    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(script_unlocker),
    );

    let mut base_tx = builder
        .build_base(&mut cell_collector, &ctx, &ctx, &ctx)
        .unwrap();
    base_tx = base_tx.as_advanced_builder().input(input).build();

    if let Some(cell_dep) = ctx.resolve(&sender) {
        base_tx = base_tx.as_advanced_builder().cell_dep(cell_dep).build();
    }

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
    assert_eq!(tx.cell_deps().len(), 3);
    assert_eq!(tx.inputs().len(), 1);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output_supply);
    assert_eq!(tx.output(1).unwrap().lock(), mint_receiver);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].len(), placeholder_witness.as_slice().len());

    ctx.verify(tx, FEE_RATE).unwrap();
}
