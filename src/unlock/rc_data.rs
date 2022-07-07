use lazy_static::lazy_static;
use sparse_merkle_tree::default_store::DefaultStore;

use sparse_merkle_tree::{SparseMerkleTree, H256};

use crate::types::xudt_rce_mol::RCDataBuilder;
use crate::types::xudt_rce_mol::{
    RCDataUnion, RCRuleBuilder, SmtProofBuilder, SmtProofEntryBuilder, SmtProofEntryVec,
    SmtProofEntryVecBuilder,
};
use bytes::Bytes;
use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_types::molecule;
use ckb_types::prelude::*;
use sparse_merkle_tree::traits::Hasher;

lazy_static! {
    static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    static ref SMT_NOT_EXISTING: H256 = H256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
}

type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

// on(1): white list
// off(0): black list
const WHITE_BLACK_LIST_MASK: u8 = 0x2;

// on(1): emergency halt mode
// off(0): not int emergency halt mode
const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;
const BLAKE2B_KEY: &[u8] = &[];
const BLAKE2B_LEN: usize = 32;
const PERSONALIZATION: &[u8] = b"ckb-default-hash";
struct CKBBlake2bHasher(Blake2b);

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

fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

// return smt root and proof
pub fn build_smt_on_wl(hashes: &[[u8; 32]], on: bool) -> (H256, Vec<u8>) {
    let (_, root, compiled_proof) = if on {
        build_smt_wl(hashes, hashes, &[])
    } else {
        build_smt_wl(hashes, &[], hashes)
    };
    (root, compiled_proof)
}

fn map_exist(hash: &[u8; 32]) -> (H256, H256) {
    ((*hash).into(), *SMT_EXISTING)
}
fn map_noexist(hash: &[u8; 32]) -> (H256, H256) {
    ((*hash).into(), *SMT_NOT_EXISTING)
}
/// Build a white list smt tree with old hashes, hashes on the tree and hashes not on the tree.
/// # Panics
///
/// Panics if on hashes and off hashes have same element.
pub fn build_smt_wl(
    orig_hashes: &[[u8; 32]],
    on_hashes: &[[u8; 32]],
    off_hashes: &[[u8; 32]],
) -> (Vec<[u8; 32]>, H256, Vec<u8>) {
    assert!(
        !on_hashes.iter().any(|x| off_hashes.contains(x)),
        "hash can't be on and off at the same time, on:{:#?} off:{:#?}",
        on_hashes,
        off_hashes
    );
    let mut hashes = orig_hashes.to_vec();
    hashes.extend(on_hashes);
    hashes.sort_unstable();
    hashes.dedup();
    let hashes: Vec<[u8; 32]> = hashes
        .into_iter()
        .filter(|x| !off_hashes.contains(x))
        .collect();
    let pairs: Vec<(H256, H256)> = hashes.iter().map(map_exist).collect();
    let proof_pairs: Vec<(H256, H256)> = on_hashes
        .iter()
        .map(map_exist)
        .chain(off_hashes.iter().map(map_exist))
        .collect();

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(proof_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof.compile(proof_pairs.clone()).expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, proof_pairs)
        .expect("verify compiled proof");

    assert!(test_on == off_hashes.is_empty());
    (hashes, *root, compiled_proof.into())
}

// return smt root and proof
pub fn build_smt_on_bl(hashes: &[[u8; 32]], on: bool) -> (H256, Vec<u8>) {
    let (_, root, compiled_proof) = if on {
        build_smt_bl(hashes, hashes, &[])
    } else {
        build_smt_bl(hashes, &[], hashes)
    };
    (root, compiled_proof)
}

/// Build smt tree with old hashes, hashes on the tree and hashes not on the tree.
/// # Panics
///
/// Panics if on hashes and off hashes have same element.
pub fn build_smt_bl(
    orig_hashes: &[[u8; 32]],
    on_hashes: &[[u8; 32]],
    off_hashes: &[[u8; 32]],
) -> (Vec<[u8; 32]>, H256, Vec<u8>) {
    assert!(
        !on_hashes.iter().any(|x| off_hashes.contains(x)),
        "hash can't not on and off at the same time, on:{:#?} off:{:#?}",
        on_hashes,
        off_hashes
    );
    let mut hashes = orig_hashes.to_vec();
    hashes.extend(on_hashes);
    hashes.sort_unstable();
    hashes.dedup();
    let hashes: Vec<[u8; 32]> = hashes
        .into_iter()
        .filter(|x| !off_hashes.contains(x))
        .collect();
    let pairs: Vec<(H256, H256)> = hashes.iter().map(map_exist).collect();
    let proof_pairs: Vec<(H256, H256)> = on_hashes
        .iter()
        .map(map_noexist)
        .chain(off_hashes.iter().map(map_noexist))
        .collect();

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(proof_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof.");
    let compiled_proof = proof.compile(proof_pairs.clone()).expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, proof_pairs)
        .expect("verify compiled proof.");

    assert!(test_on == on_hashes.is_empty());
    (hashes, *root, compiled_proof.into())
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

pub fn build_proofs(proofs: Vec<Vec<u8>>, proof_masks: Vec<u8>) -> SmtProofEntryVec {
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

pub fn generate_single_proof(on: bool, smt_key: &[[u8; 32]]) -> (Vec<u8>, Bytes) {
    let hash = smt_key;
    let (smt_root, proof) = build_smt_on_wl(hash, on);

    let rc_rule = build_rc_rule(&smt_root.into(), false, false);
    (proof, rc_rule)
}

pub fn generate_proofs(smt_key: &[[u8; 32]]) -> (Vec<Vec<u8>>, Vec<Bytes>, Vec<u8>) {
    let mut proofs = Vec::<Vec<u8>>::default();
    let mut rc_rules = Vec::<Bytes>::default();
    let mut proof_masks = Vec::<u8>::default();

    let (proof1, rc_rule1) = generate_single_proof(true, smt_key);
    proofs.push(proof1);
    rc_rules.push(rc_rule1);
    proof_masks.push(1); // input

    let (proof2, rc_rule2) = generate_single_proof(false, smt_key);
    proofs.push(proof2);
    rc_rules.push(rc_rule2);
    proof_masks.push(2); // output

    (proofs, rc_rules, proof_masks)
}
