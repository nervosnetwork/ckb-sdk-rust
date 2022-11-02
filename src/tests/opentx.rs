use ckb_jsonrpc_types as json_types;
use std::collections::HashMap;

use crate::{
    constants::{ONE_CKB, SIGHASH_TYPE_HASH},
    test_util::random_out_point,
    tests::{
        build_sighash_script, init_context,
        omni_lock::{build_omnilock_script, build_omnilock_unlockers, OMNILOCK_BIN},
        omni_lock_util::generate_rc,
        ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACCOUNT2_KEY,
        ACCOUNT3_ARG, ACCOUNT3_KEY, ALWAYS_SUCCESS_BIN, FEE_RATE, SUDT_BIN,
    },
    traits::{CellCollector, CellDepResolver, CellQueryOptions, SecpCkbRawKeySigner},
    tx_builder::{
        acp::{AcpTransferBuilder, AcpTransferReceiver},
        balance_tx_capacity, fill_placeholder_witnesses,
        omni_lock::OmniLockTransferBuilder,
        transfer::{CapacityTransferBuilder, CapacityTransferBuilderWithTransaction},
        udt::{UdtTargetReceiver, UdtTransferBuilder},
        CapacityProvider, TransferAction,
    },
    types::xudt_rce_mol::SmtProofEntryVec,
    unlock::{
        omni_lock::{AdminConfig, Identity},
        opentx::OpentxWitness,
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
        .lock(receiver.clone())
        .build();
    let builder = OmniLockTransferBuilder::new_open(
        (1 * ONE_CKB).into(),
        vec![(output.clone(), Bytes::default())],
        cfg.clone(),
        None,
    );
    let placeholder_witness = cfg.placeholder_witness(unlock_mode).unwrap();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), ZERO_FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let unlockers = build_omnilock_unlockers(account0_key, cfg.clone(), unlock_mode);
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();
    tx = OmniLockTransferBuilder::remove_open_out(tx);

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
    assert_eq!(tx.output(1).unwrap().lock(), receiver);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    ctx.verify(tx, FEE_RATE).unwrap();
}
