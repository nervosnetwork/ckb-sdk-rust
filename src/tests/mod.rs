mod ckb_indexer_rpc;
mod ckb_rpc;
mod transaction;
mod tx_builder;

use std::collections::HashMap;

use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType},
    h160, h256,
    packed::Script,
    prelude::*,
    H160, H256,
};

use crate::constants::{DAO_TYPE_HASH, MULTISIG_TYPE_HASH, ONE_CKB, SIGHASH_TYPE_HASH};
use crate::traits::SecpCkbRawKeySigner;
use crate::unlock::{MultisigConfig, ScriptUnlocker, SecpMultisigUnlocker};
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
