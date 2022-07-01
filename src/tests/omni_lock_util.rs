use bytes::Bytes;
use ckb_types::core::DepType;
use ckb_types::core::ScriptHashType;
use ckb_types::molecule;
use rand::thread_rng;
use rand::Rng;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use ckb_hash::{Blake2b, Blake2bBuilder};
use lazy_static::lazy_static;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;

use crate::test_util::random_out_point;
use crate::test_util::Context;
use crate::types::xudt_rce_mol::RCCellVecBuilder;
use crate::types::xudt_rce_mol::RCDataBuilder;
use crate::types::xudt_rce_mol::SmtProofBuilder;
use crate::types::xudt_rce_mol::SmtProofEntryBuilder;
use crate::types::xudt_rce_mol::SmtProofEntryVec;
use crate::types::xudt_rce_mol::SmtProofEntryVecBuilder;
use crate::types::xudt_rce_mol::{RCDataUnion, RCRuleBuilder};
use crate::ScriptId;
use ckb_types::packed::*;
use ckb_types::prelude::*;

use super::ALWAYS_SUCCESS;

lazy_static! {
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    pub static ref SMT_NOT_EXISTING: H256 = H256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
}

// on(1): white list
// off(0): black list
pub const WHITE_BLACK_LIST_MASK: u8 = 0x2;

// on(1): emergency halt mode
// off(0): not int emergency halt mode
pub const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;
pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";
pub struct CKBBlake2bHasher(Blake2b);

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
}

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

pub fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

// return smt root and proof
pub fn build_smt_on_wl(hashes: &[[u8; 32]], on: bool) -> (H256, Vec<u8>) {
    let existing_pairs: Vec<(H256, H256)> = hashes
        .iter()
        .map(|hash| ((*hash).into(), *SMT_EXISTING))
        .collect();

    // this is the hash on white list, and "hashes" are on that.
    let key_on_wl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_wl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let mut pairs = vec![(key_on_wl1, *SMT_EXISTING), (key_on_wl2, *SMT_EXISTING)];
    if on {
        pairs.extend(existing_pairs.clone());
    }

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(existing_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof
        .compile(existing_pairs.clone())
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, existing_pairs)
        .expect("verify compiled proof");
    if on {
        assert!(test_on);
    } else {
        assert!(!test_on);
    }
    (*root, compiled_proof.into())
}

// return smt root and proof
fn build_smt_on_bl(hashes: &[[u8; 32]], on: bool) -> (H256, Vec<u8>) {
    let test_pairs: Vec<(H256, H256)> = hashes
        .iter()
        .map(|hash| ((*hash).into(), *SMT_NOT_EXISTING))
        .collect();
    // this is the hash on black list, but "hashes" are not on that.
    let key_on_bl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_bl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let pairs = vec![(key_on_bl1, *SMT_EXISTING), (key_on_bl2, *SMT_EXISTING)];
    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(test_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof.compile(test_pairs.clone()).expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(smt.root(), test_pairs)
        .expect("verify compiled proof");
    assert!(test_on);
    if on {
        let mut new_root = *root;
        let one = new_root.get_bit(0);
        if one {
            new_root.clear_bit(0);
        } else {
            new_root.set_bit(0);
        }
        (new_root, compiled_proof.into())
    } else {
        (*root, compiled_proof.into())
    }
}

#[derive(Copy, Clone, PartialEq)]
#[allow(dead_code)]
pub enum TestScheme {
    None,
    LongWitness,

    OnWhiteList,
    NotOnWhiteList,
    OnlyInputOnWhiteList,
    OnlyOutputOnWhiteList,
    BothOnWhiteList,
    OnBlackList,
    NotOnBlackList,
    BothOn,
    EmergencyHaltMode,

    OwnerLockMismatched,
    OwnerLockWithoutWitness,

    RsaWrongSignature,
}

pub fn generate_single_proof(scheme: TestScheme, smt_key: &[[u8; 32]]) -> (Vec<u8>, Bytes) {
    let hash = smt_key;
    let mut is_black_list = false;
    let mut is_emergency_halt = false;
    let (smt_root, proof) = match scheme {
        TestScheme::OnWhiteList => {
            is_black_list = false;
            build_smt_on_wl(hash, true)
        }
        TestScheme::NotOnWhiteList => {
            is_black_list = false;
            build_smt_on_wl(hash, false)
        }
        TestScheme::OnBlackList => {
            is_black_list = true;
            build_smt_on_bl(hash, true)
        }
        TestScheme::NotOnBlackList => {
            is_black_list = true;
            build_smt_on_bl(hash, false)
        }
        TestScheme::EmergencyHaltMode => {
            is_emergency_halt = true;
            (H256::default(), Vec::<u8>::default())
        }
        _ => (H256::default(), Vec::<u8>::default()),
    };

    let rc_data = build_rc_rule(&smt_root.into(), is_black_list, is_emergency_halt);
    (proof, rc_data)
}

fn build_rc_rule(smt_root: &[u8; 32], is_black: bool, is_emergency: bool) -> Bytes {
    let mut flags: u8 = 0;

    if !is_black {
        flags ^= WHITE_BLACK_LIST_MASK;
    }
    if is_emergency {
        flags ^= EMERGENCY_HALT_MODE_MASK;
    }
    let rcrule = RCRuleBuilder::default()
        .flags(flags.into())
        .smt_root(smt_root.pack())
        .build();
    let res = RCDataBuilder::default()
        .set(RCDataUnion::RCRule(rcrule))
        .build();
    res.as_bytes()
}

pub fn generate_proofs(
    scheme: TestScheme,
    smt_key: &[[u8; 32]],
) -> (Vec<Vec<u8>>, Vec<Bytes>, Vec<u8>) {
    let mut proofs = Vec::<Vec<u8>>::default();
    let mut rc_data = Vec::<Bytes>::default();
    let mut proof_masks = Vec::<u8>::default();

    match scheme {
        TestScheme::BothOn => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnBlackList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(3);
        }
        TestScheme::OnlyInputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::NotOnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::OnlyOutputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::NotOnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::BothOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        _ => {
            let (proof1, rc_data1) = generate_single_proof(scheme, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
        }
    }

    (proofs, rc_data, proof_masks)
}

fn build_proofs(proofs: Vec<Vec<u8>>, proof_masks: Vec<u8>) -> SmtProofEntryVec {
    assert_eq!(proofs.len(), proof_masks.len());

    let mut builder = SmtProofEntryVecBuilder::default();
    let iter = proofs.iter().zip(proof_masks.iter());
    for (p, m) in iter {
        let proof_builder = SmtProofBuilder::default()
            .set(p.iter().map(|v| molecule::prelude::Byte::new(*v)).collect());

        let temp = SmtProofEntryBuilder::default()
            .proof(proof_builder.build())
            .mask((*m).into());
        builder = builder.push(temp.build());
    }
    builder.build()
}

pub fn generate_rc(
    ctx: &mut Context,
    smt_key: [u8; 32],
    scheme: TestScheme,
) -> (SmtProofEntryVec, Bytes, Vec<OutPoint>) {
    let (proofs, rc_datas, proof_masks) = generate_proofs(scheme, &[smt_key]);
    let mut rce_cells = vec![];
    let rc_root = generate_rce_cell(ctx, rc_datas, &mut rce_cells);

    let proof_vec = build_proofs(proofs, proof_masks);
    (proof_vec, rc_root.as_bytes(), rce_cells)
}

pub fn build_always_success_script() -> Script {
    let data_hash = CellOutput::calc_data_hash(ALWAYS_SUCCESS);
    Script::new_builder()
        .code_hash(data_hash)
        .hash_type(ScriptHashType::Data.into())
        .build()
}
//
// deploy "bin" to cell, then build a script to point it.
//
// it can:
// * build lock script, set is_type to false
// * build type script, set is_type to true
// * build type script without upgrading, set is_type to false
// * build extension script, set is_type to true
// * build extension script without upgrading, set is_type to false
// * build RCE cell, is_type = true. Only the Script.code_hash is kept for further use.
//   when in this case, to make "args" passed in unique
// when in_input_cell is on, the cell is not in deps but in input.
fn build_script(
    ctx: &mut Context,
    is_type: bool,
    in_input_cell: bool,
    bin: &Bytes,
    args: Bytes,
    rce_cells: &mut Vec<OutPoint>,
) -> Script {
    // this hash to make type script in code unique
    // then make "type script hash" unique, which will be code_hash in "type script"
    let hash = ckb_hash::blake2b_256(bin);
    let always_success = build_always_success_script();

    let type_script_in_code = {
        if in_input_cell {
            let hash: Bytes = Bytes::copy_from_slice(&hash);
            always_success
                .clone()
                .as_builder()
                .args(hash.pack())
                .build()
        } else {
            // this args can be anything
            let args = vec![0u8; 32];
            Script::new_builder()
                .args(args.pack())
                .code_hash(hash.pack())
                .hash_type(ScriptHashType::Type.into())
                .build()
        }
    };

    // it not needed to set "type script" when is_type is false
    let capacity = bin.len() as u64;
    let output = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(always_success)
        .type_(Some(type_script_in_code.clone()).pack())
        .build();
    let out_point = random_out_point();
    let cell_dep = CellDep::new_builder()
        .out_point(out_point.clone())
        .dep_type(DepType::Code.into())
        .build();
    ctx.add_cell_dep(cell_dep.clone(), output, bin.clone(), None);
    rce_cells.push(out_point);

    let code_hash = if is_type {
        ckb_hash::blake2b_256(type_script_in_code.as_slice())
    } else {
        ckb_hash::blake2b_256(bin)
    };
    let hash_type = if is_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data
    };

    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();

    let script_id = ScriptId::from(&script);
    ctx.add_cell_dep_map(script_id, cell_dep);
    script
}

// first generate N RCE cells with each contained one RCRule
// then collect all these RCE cell hash and create the final RCE cell.
pub fn generate_rce_cell(
    ctx: &mut Context,
    rc_data: Vec<Bytes>,
    rce_cells: &mut Vec<OutPoint>,
) -> Byte32 {
    let mut rng = thread_rng();
    let mut cell_vec_builder = RCCellVecBuilder::default();

    for rc_rule in rc_data {
        let mut random_args: [u8; 32] = Default::default();
        rng.fill(&mut random_args[..]);
        let rce_script = build_script(
            ctx,
            true,
            false,
            &rc_rule,
            Bytes::copy_from_slice(random_args.as_ref()),
            rce_cells,
        );

        let hash = rce_script.code_hash();

        cell_vec_builder =
            cell_vec_builder.push(Byte32::from_slice(hash.as_slice()).expect("Byte32::from_slice"));
    }

    let cell_vec = cell_vec_builder.build();

    let rce_cell_content = RCDataBuilder::default()
        .set(RCDataUnion::RCCellVec(cell_vec))
        .build();

    let mut random_args: [u8; 32] = Default::default();
    rng.fill(&mut random_args[..]);
    let bin = rce_cell_content.as_slice();
    let rce_script = build_script(
        ctx,
        true,
        false,
        &Bytes::copy_from_slice(bin),
        Bytes::copy_from_slice(random_args.as_ref()),
        rce_cells,
    );
    rce_script.code_hash()
}

pub fn add_rce_cells(
    tx: ckb_types::core::TransactionView,
    rce_cells: &[OutPoint],
) -> ckb_types::core::TransactionView {
    if !rce_cells.is_empty() {
        let mut builder = tx.as_advanced_builder();
        for cell in rce_cells {
            builder = builder.cell_dep(
                CellDep::new_builder()
                    .out_point(cell.clone())
                    .dep_type(DepType::Code.into())
                    .build(),
            );
        }
        return builder.build();
    }
    tx
}
