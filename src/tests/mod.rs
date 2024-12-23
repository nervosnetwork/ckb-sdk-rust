use std::collections::HashMap;

use ckb_dao_utils::pack_dao_data;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, EpochNumberWithFraction, HeaderBuilder, ScriptHashType},
    h160, h256,
    packed::{CellInput, CellOutput, Script, ScriptOpt, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::constants::{
    CHEQUE_CELL_SINCE, DAO_TYPE_HASH, MULTISIG_TYPE_HASH, ONE_CKB, SIGHASH_TYPE_HASH,
};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    acp::{AcpTransferBuilder, AcpTransferReceiver},
    cheque::{ChequeClaimBuilder, ChequeWithdrawBuilder},
    dao::{
        DaoDepositBuilder, DaoDepositReceiver, DaoPrepareBuilder, DaoWithdrawBuilder,
        DaoWithdrawItem, DaoWithdrawReceiver,
    },
    transfer::CapacityTransferBuilder,
    udt::{UdtIssueBuilder, UdtTargetReceiver, UdtTransferBuilder, UdtType},
    unlock_tx, CapacityBalancer, TransferAction, TxBuilder,
};
use crate::unlock::{
    AcpUnlocker, ChequeAction, ChequeUnlocker, MultisigConfig, ScriptUnlocker,
    SecpMultisigUnlocker, SecpSighashUnlocker,
};
use crate::util::{calculate_dao_maximum_withdraw4, minimal_unlock_point};
use crate::{ScriptId, Since, SinceType};

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
const ACCOUNT2_KEY: H256 =
    h256!("0x5f9eceb1af9fe48b97e2df350450d7416887ccca62f537733f1377ee9efb8906");
const ACCOUNT2_ARG: H160 = h160!("0x507736d8f98c779ee47294d5d061d9eaa0dbf856");

// ckt1qyqd405g5etkp3nzacls0hhpvfqf77eqk62q90dhzj
const ACCOUNT3_KEY: H256 =
    h256!("0xeee9d3c8b01ade50e1cc22c64cf358a4f20fc2b4f93f89af0a281e0de11ca06f");
const ACCOUNT3_ARG: H160 = h160!("0xdabe88a65760c662ee3f07dee162409f7b20b694");

const FEE_RATE: u64 = 1000;
const GENESIS_JSON: &str = include_str!("../test-data/genesis_block.json");
const SUDT_BIN: &[u8] = include_bytes!("../test-data/simple_udt");
const ACP_BIN: &[u8] = include_bytes!("../test-data/anyone_can_pay");
const CHEQUE_BIN: &[u8] = include_bytes!("../test-data/ckb-cheque-script");
const ALWAYS_SUCCESS_BIN: &[u8] = include_bytes!("../test-data/always_success");

fn build_sighash_script(args: H160) -> Script {
    Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(args.0.to_vec()).pack())
        .build()
}

fn build_multisig_script(cfg: &MultisigConfig) -> Script {
    Script::new_builder()
        .code_hash(MULTISIG_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(cfg.hash160().0.to_vec()).pack())
        .build()
}

fn build_dao_script() -> Script {
    Script::new_builder()
        .code_hash(DAO_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .build()
}

fn build_cheque_script(sender: &Script, receiver: &Script, cheque_data_hash: H256) -> Script {
    let sender_script_hash = sender.calc_script_hash();
    let receiver_script_hash = receiver.calc_script_hash();
    let mut script_args = vec![0u8; 40];
    script_args[0..20].copy_from_slice(&receiver_script_hash.as_slice()[0..20]);
    script_args[20..40].copy_from_slice(&sender_script_hash.as_slice()[0..20]);
    Script::new_builder()
        .code_hash(cheque_data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(script_args).pack())
        .build()
}

fn build_multisig_unlockers(
    key: secp256k1::SecretKey,
    config: MultisigConfig,
) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![key]);
    let multisig_unlocker = SecpMultisigUnlocker::from((Box::new(signer) as Box<_>, config));
    let multisig_script_id = ScriptId::new_type(MULTISIG_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        multisig_script_id,
        Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}

fn init_context(contracts: Vec<(&[u8], bool)>, live_cells: Vec<(Script, Option<u64>)>) -> Context {
    // ckb-cli --url https://testnet.ckb.dev rpc get_block_by_number --number 0 --output-format json --raw-data > genensis_block.json
    let genesis_block: json_types::BlockView = serde_json::from_str(GENESIS_JSON).unwrap();
    let genesis_block: BlockView = genesis_block.into();
    let mut ctx = Context::new(&genesis_block, contracts);
    for (lock, capacity_opt) in live_cells {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }
    ctx
}

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
fn test_transfer_capacity_overflow() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let ctx = init_context(Vec::new(), vec![(sender.clone(), Some(100 * ONE_CKB))]);

    let large_amount: u64 = u64::MAX;
    let output = CellOutput::new_builder()
        .capacity((large_amount).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    let mut cell_collector = ctx.to_live_cells_context();
    let res = builder.build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("capacity not enough"));
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

#[test]
fn test_transfer_to_acp() {
    let data_hash = H256::from(blake2b_256(ACP_BIN));
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = Script::new_builder()
        .code_hash(data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(ACCOUNT2_ARG.0.to_vec()).pack())
        .build();
    let ctx = init_context(
        vec![(ACP_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
            (receiver.clone(), Some(99 * ONE_CKB)),
        ],
    );

    let acp_receiver = AcpTransferReceiver::new(receiver.clone(), 150 * ONE_CKB);
    let builder = AcpTransferBuilder::new(vec![acp_receiver]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer1 = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let sighash_unlocker = AcpUnlocker::from(Box::new(signer1) as Box<_>);
    let acp_unlocker = AcpUnlocker::from(Box::<SecpCkbRawKeySigner>::default() as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH),
        Box::new(sighash_unlocker),
    );
    unlockers.insert(ScriptId::new_data1(data_hash), Box::new(acp_unlocker));

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 3);
    let input_cells = [
        CellOutput::new_builder()
            .capacity((99 * ONE_CKB).pack())
            .lock(receiver.clone())
            .build(),
        CellOutput::new_builder()
            .capacity((100 * ONE_CKB).pack())
            .lock(sender.clone())
            .build(),
        CellOutput::new_builder()
            .capacity((200 * ONE_CKB).pack())
            .lock(sender.clone())
            .build(),
    ];
    for (idx, out_point) in tx.input_pts_iter().enumerate() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0, input_cells[idx]);
    }
    assert_eq!(tx.outputs().len(), 2);
    let acp_output = CellOutput::new_builder()
        .capacity(((99 + 150) * ONE_CKB).pack())
        .lock(receiver)
        .build();
    assert_eq!(tx.output(0).unwrap(), acp_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
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
    let input_cells = [
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
    let input_cells = [
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

#[test]
fn test_dao_deposit() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let deposit_receiver = DaoDepositReceiver::new(sender.clone(), 120 * ONE_CKB);
    let builder = DaoDepositBuilder::new(vec![deposit_receiver]);
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
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    let deposit_output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(build_dao_script()).pack())
        .build();
    assert_eq!(tx.output(0).unwrap(), deposit_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![Bytes::from(vec![0u8; 8]), Bytes::default()];
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
fn test_dao_prepare() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let mut ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let deposit_point = (5, 5, 1000);
    let deposit_number = deposit_point.0 * deposit_point.2 + deposit_point.1;
    let deposit_point =
        EpochNumberWithFraction::new(deposit_point.0, deposit_point.1, deposit_point.2);

    let deposit_input = CellInput::new(random_out_point(), 0);
    let deposit_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(build_dao_script()).pack())
        .build();
    let deposit_header = HeaderBuilder::default()
        .epoch(deposit_point.full_value().pack())
        .number(deposit_number.pack())
        .build();
    let deposit_block_hash = deposit_header.hash();
    ctx.add_live_cell(
        deposit_input.clone(),
        deposit_output.clone(),
        Bytes::from(vec![0u8; 8]),
        Some(deposit_block_hash.clone()),
    );
    ctx.add_header(deposit_header);

    let builder = DaoPrepareBuilder::from(vec![deposit_input]);
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
    assert_eq!(
        tx.header_deps().into_iter().collect::<Vec<_>>(),
        vec![deposit_block_hash]
    );
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), deposit_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![
        Bytes::from(deposit_number.to_le_bytes().to_vec()),
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
fn test_dao_withdraw() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let mut ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let (deposit_point, prepare_point) = ((5, 5, 1000), (184, 4, 1000));
    let deposit_number = deposit_point.0 * deposit_point.2 + deposit_point.1;
    let prepare_number = prepare_point.0 * prepare_point.2 + prepare_point.1;
    let deposit_point =
        EpochNumberWithFraction::new(deposit_point.0, deposit_point.1, deposit_point.2);
    let prepare_point =
        EpochNumberWithFraction::new(prepare_point.0, prepare_point.1, prepare_point.2);
    let deposit_header = HeaderBuilder::default()
        .epoch(deposit_point.full_value().pack())
        .number(deposit_number.pack())
        .dao(pack_dao_data(
            10_000_000_000_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let prepare_header = HeaderBuilder::default()
        .epoch(prepare_point.full_value().pack())
        .number(prepare_number.pack())
        .dao(pack_dao_data(
            10_000_000_001_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let deposit_block_hash = deposit_header.hash();
    let prepare_block_hash = prepare_header.hash();

    let unlock_point = minimal_unlock_point(&deposit_header, &prepare_header);
    let since = Since::new(
        SinceType::EpochNumberWithFraction,
        unlock_point.full_value(),
        false,
    );
    let prepare_out_point = random_out_point();
    let prepare_input = CellInput::new(prepare_out_point.clone(), since.value());
    let prepare_output = CellOutput::new_builder()
        .capacity((220 * ONE_CKB).pack())
        .lock(sender.clone())
        .type_(Some(build_dao_script()).pack())
        .build();
    ctx.add_live_cell(
        prepare_input,
        prepare_output.clone(),
        Bytes::from(deposit_number.to_le_bytes().to_vec()),
        Some(prepare_block_hash.clone()),
    );
    ctx.add_header(deposit_header.clone());
    ctx.add_header(prepare_header.clone());

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let withdraw_item = DaoWithdrawItem::new(prepare_out_point, Some(placeholder_witness.clone()));
    let withdraw_receiver = DaoWithdrawReceiver::LockScript {
        script: sender.clone(),
        fee_rate: None,
    };
    let builder = DaoWithdrawBuilder::new(vec![withdraw_item], withdraw_receiver);
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
    assert_eq!(
        tx.header_deps().into_iter().collect::<Vec<_>>(),
        vec![deposit_block_hash, prepare_block_hash]
    );
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    let occupied_capacity = prepare_output
        .occupied_capacity(Capacity::bytes(8).unwrap())
        .unwrap()
        .as_u64();
    let expected_capacity = calculate_dao_maximum_withdraw4(
        &deposit_header,
        &prepare_header,
        &prepare_output,
        occupied_capacity,
    );
    let expected_output = prepare_output
        .as_builder()
        .capacity(expected_capacity.pack())
        .type_(ScriptOpt::default())
        .build();
    assert_eq!(tx.output(0).unwrap(), expected_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let expected_outputs_data = vec![Bytes::default(), Bytes::default()];
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
    let witness = placeholder_witness
        .as_builder()
        .input_type(Some(Bytes::from(vec![0u8; 8])).pack())
        .build();
    assert_eq!(witnesses_len, vec![witness.as_slice().len(), 0]);
    ctx.verify(tx, FEE_RATE).unwrap();
}

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

pub mod ckb_indexer_rpc;
pub mod ckb_rpc;
pub mod cycle;
pub mod omni_lock;
pub mod omni_lock_util;
pub mod transaction;
