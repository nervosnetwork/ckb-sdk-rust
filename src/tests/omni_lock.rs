use std::collections::HashMap;

use crate::{
    constants::ONE_CKB,
    tests::{
        build_sighash_script, init_context, ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT2_ARG,
        ACCOUNT2_KEY, FEE_RATE,
    },
    traits::SecpCkbRawKeySigner,
    tx_builder::transfer::CapacityTransferBuilder,
    unlock::{
        MultisigConfig, OmniLockConfig, OmniLockScriptSigner, OmniLockUnlocker, ScriptUnlocker,
    },
    ScriptId,
};

use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{CellOutput, Script},
    prelude::*,
    H256,
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
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![key]);
    let script = build_omnilock_script(&config);
    let omnilock_script_signer = OmniLockScriptSigner::new(Box::new(signer) as Box<_>, config);
    let omnilock_unlocker = OmniLockUnlocker::new(omnilock_script_signer);
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
    let cfg = OmniLockConfig::new_pubkey_hash_with_lockarg(ACCOUNT2_ARG.clone());

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
    let account2_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes()).unwrap();
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
