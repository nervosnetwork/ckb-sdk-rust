use lazy_static::lazy_static;

use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256 as SmtH256};

use crate::types::xudt_rce_mol::{
    RCDataBuilder, RCDataUnion, RCRuleBuilder, SmtProofBuilder, SmtProofEntryBuilder,
    SmtProofEntryVec, SmtProofEntryVecBuilder,
};
use bytes::Bytes;
use ckb_hash::{new_blake2b, Blake2b};
use ckb_types::{molecule, prelude::*};
use sparse_merkle_tree::traits::Hasher;
use thiserror::Error;

lazy_static! {
    pub static ref SMT_EXISTING: SmtH256 = SmtH256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    pub static ref SMT_NOT_EXISTING: SmtH256 = SmtH256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
}

type SMT = SparseMerkleTree<CKBBlake2bHasher, SmtH256, DefaultStore<SmtH256>>;
pub type Result<T> = ::core::result::Result<T, RcDataError>;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum RcDataError {
    #[error("fail to build the smt tree:`{0}`")]
    BuildTree(String),
    #[error("fail to compile proof, reason:`{0}`")]
    CompileProof(String),
}

// on(1): white list
// off(0): black list
const WHITE_BLACK_LIST_MASK: u8 = 0x2;

// on(1): emergency halt mode
// off(0): not int emergency halt mode
const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;
pub struct CKBBlake2bHasher(Blake2b);

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = new_blake2b();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &SmtH256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> SmtH256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
}

fn new_smt(pairs: Vec<(SmtH256, SmtH256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

fn map_exist(hash: &SmtH256) -> (SmtH256, SmtH256) {
    (*hash, *SMT_EXISTING)
}

fn map_noexist(hash: &SmtH256) -> (SmtH256, SmtH256) {
    (*hash, *SMT_NOT_EXISTING)
}

/// Build the white list smt tree with the given hashes
/// # Arguments
/// * `hashes` The given the hashes.
/// * `on` indicate if the give `hashes` on the list.
pub fn build_smt_on_wl(hashes: &[SmtH256], on: bool) -> Result<(SmtH256, Vec<u8>)> {
    let smt_keys = if on { hashes.to_vec() } else { vec![] };

    build_smt_wl(&smt_keys, hashes)
}

/// Build a white list smt tree with it's keys and gnerate proofs with the according keys.
/// # Arguments
/// * `smt_keys` - A list of hashes which to build the smt tree.
/// * `proof_keys` - The keys to generate the proofs.
/// # Return
/// The smt_tree root and the proofs of the proof_keys.
pub fn build_smt_wl(smt_keys: &[SmtH256], proof_keys: &[SmtH256]) -> Result<(SmtH256, Vec<u8>)> {
    let pairs: Vec<(SmtH256, SmtH256)> = smt_keys.iter().map(map_exist).collect();
    let proof_pairs: Vec<(SmtH256, SmtH256)> = proof_keys.iter().map(map_exist).collect();

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(proof_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .map_err(|err| RcDataError::BuildTree(err.to_string()))?;
    let compiled_proof = proof
        .compile(proof_pairs)
        .map_err(|e| RcDataError::CompileProof(e.to_string()))?;

    Ok((*root, compiled_proof.into()))
}

// return smt root and proof
pub fn build_smt_on_bl(hashes: &[SmtH256], on: bool) -> Result<(SmtH256, Vec<u8>)> {
    let smt_keys = if on { hashes.to_vec() } else { vec![] };
    build_smt_bl(&smt_keys, hashes)
}

/// Build a black list smt tree with it's keys and gnerate proofs with the according keys.
/// # Arguments
/// * `smt_keys` - A list of hashes which to build the smt tree.
/// * `proof_keys` - The keys to generate the proofs.
/// # Return
/// The smt_tree root and the proofs of the proof_keys.
pub fn build_smt_bl(smt_keys: &[SmtH256], proof_keys: &[SmtH256]) -> Result<(SmtH256, Vec<u8>)> {
    let pairs: Vec<(SmtH256, SmtH256)> = smt_keys.iter().map(map_exist).collect();
    let proof_pairs: Vec<(SmtH256, SmtH256)> = proof_keys.iter().map(map_noexist).collect();

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(proof_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .map_err(|err| RcDataError::BuildTree(err.to_string()))?;
    let compiled_proof = proof
        .compile(proof_pairs)
        .map_err(|e| RcDataError::CompileProof(e.to_string()))?;

    Ok((*root, compiled_proof.into()))
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

#[repr(u8)]
pub enum Mask {
    Neither = 0,
    Input = 1,
    Output = 2,
    Both = 3,
}
pub struct ProofWithMask {
    pub proof: Vec<u8>,
    pub mask: Mask,
}

impl ProofWithMask {
    pub fn new(proof: Vec<u8>, mask: Mask) -> Self {
        ProofWithMask { proof, mask }
    }
}

pub fn build_proofs(proofs: Vec<ProofWithMask>) -> SmtProofEntryVec {
    let mut builder = SmtProofEntryVecBuilder::default();
    for ProofWithMask { proof, mask } in proofs {
        let proof_builder = SmtProofBuilder::default().set(
            proof
                .iter()
                .map(|v| molecule::prelude::Byte::new(*v))
                .collect(),
        );

        let temp = SmtProofEntryBuilder::default()
            .proof(proof_builder.build())
            .mask((mask as u8).into());
        builder = builder.push(temp.build());
    }
    builder.build()
}

pub fn generate_single_proof(
    on: bool,
    smt_key: &[SmtH256],
    whitelist: bool,
) -> Result<(Vec<u8>, Bytes)> {
    let hash = smt_key;
    let (smt_root, proof) = if whitelist {
        build_smt_on_wl(hash, on)?
    } else {
        build_smt_on_bl(hash, on)?
    };

    let rc_rule = build_rc_rule(&smt_root.into(), !whitelist, false);
    Ok((proof, rc_rule))
}

pub type RcProofWithRule = (Vec<ProofWithMask>, Vec<Bytes>);
pub fn generate_proofs(smt_key: &[SmtH256], whitelist: bool) -> Result<RcProofWithRule> {
    let mut proofs = Vec::<ProofWithMask>::default();
    let mut rc_rules = Vec::<Bytes>::default();

    let (proof1, rc_rule1) = generate_single_proof(true, smt_key, whitelist)?;
    proofs.push(ProofWithMask::new(proof1, Mask::Input));
    rc_rules.push(rc_rule1);

    let (proof2, rc_rule2) = generate_single_proof(false, smt_key, whitelist)?;
    proofs.push(ProofWithMask::new(proof2, Mask::Output));
    rc_rules.push(rc_rule2);

    Ok((proofs, rc_rules))
}
