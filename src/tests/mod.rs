use std::collections::HashMap;

use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType},
    h160, h256,
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::constants::{MULTISIG_TYPE_HASH, ONE_CKB, SIGHASH_TYPE_HASH};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    transfer::CapacityTransferBuilder, unlock_tx, CapacityBalancer, TxBuilder,
};
use crate::unlock::{
    MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker,
    SecpSighashScriptSigner, SecpSighashUnlocker,
};
use crate::ScriptId;

use crate::test_util::{random_out_point, Context};

// ckt1qyq86vaa6e8tsruv5ngcd5tp7lcvcewxy7cquuksvj
const ACCOUNT0_KEY: H256 =
    h256!("0x8fdf1d6df54c6c9c0167a657c0f68a9bb3bf4304942ce487880e86ce6099191c");
const ACCOUNT0_ARG: H160 = h160!("0x7d33bdd64eb80f8ca4d186d161f7f0cc65c627b0");

// ckt1qyqfjslcvyaay029vvfxtn80rxnwmlma43xscrqn85
const ACCOUNT1_KEY: H256 =
    h256!("0xdbb62c0f0dd23088dba5ade3b4ed2279f733780de1985d344bf398c1c757ef49");
const ACCOUNT1_ARG: H160 = h160!("0x9943f8613bd23d45631265ccef19a6edff7dac4d");

// ckt1qyq9qaekmruccau7u3eff4wsv8v74gxmlptqj2lcte
// const ACCOUNT2_KEY: H256 =
//     h256!("0x5f9eceb1af9fe48b97e2df350450d7416887ccca62f537733f1377ee9efb8906");
const ACCOUNT2_ARG: H160 = h160!("0x507736d8f98c779ee47294d5d061d9eaa0dbf856");

const FEE_RATE: u64 = 1000;
const GENESIS_JSON: &str = include_str!("../test-data/genesis_block.json");

#[test]
fn test_sighash_unlocker() {
    let genesis_block: json_types::BlockView = serde_json::from_str(GENESIS_JSON).unwrap();
    let genesis_block: BlockView = genesis_block.into();
    let mut ctx = Context::from_genesis_block(&genesis_block);

    let sender = Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(ACCOUNT1_ARG.0.to_vec()).pack())
        .build();
    let receiver = Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(ACCOUNT2_ARG.0.to_vec()).pack())
        .build();

    for capacity_ckb in [100, 200, 300] {
        ctx.add_simple_live_cell(
            random_out_point(),
            sender.clone(),
            Some(capacity_ckb * ONE_CKB),
        );
    }
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
    let script_signer = SecpSighashScriptSigner::new(Box::new(signer));
    let script_unlocker = SecpSighashUnlocker::new(script_signer);
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

fn build_multisig_unlockers(
    key: secp256k1::SecretKey,
    config: MultisigConfig,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![key]);
    let multisig_signer = SecpMultisigScriptSigner::new(Box::new(signer), config);
    let multisig_unlocker = SecpMultisigUnlocker::new(multisig_signer);
    let multisig_script_id = ScriptId::new_type(MULTISIG_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        multisig_script_id,
        Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}

#[test]
fn test_multisig_unlocker() {
    let genesis_block: json_types::BlockView = serde_json::from_str(GENESIS_JSON).unwrap();
    let genesis_block: BlockView = genesis_block.into();
    let mut ctx = Context::from_genesis_block(&genesis_block);

    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();

    let sender = Script::new_builder()
        .code_hash(MULTISIG_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(cfg.hash160().0.to_vec()).pack())
        .build();
    let receiver = Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(ACCOUNT2_ARG.0.to_vec()).pack())
        .build();

    for capacity_ckb in [100, 200, 300] {
        ctx.add_simple_live_cell(
            random_out_point(),
            sender.clone(),
            Some(capacity_ckb * ONE_CKB),
        );
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
    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let unlockers = build_multisig_unlockers(account0_key.clone(), cfg.clone());
    let mut tx = builder
        .build_balanced(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    let mut locked_groups = None;
    for key in [account0_key, account1_key] {
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
