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

use std::sync::LazyLock;

pub static SMT_EXISTING: LazyLock<SmtH256> = LazyLock::new(|| {
    SmtH256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
});
pub static SMT_NOT_EXISTING: LazyLock<SmtH256> = LazyLock::new(|| {
    SmtH256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
});

#[allow(clippy::upper_case_acronyms)]
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

/// The list type of an omnilock admin rule list type.
pub enum ListType {
    /// Indicate it's a white list.
    White,
    /// Indicate it's a black list.
    Black,
}

/// a builder to build rc_rule
pub struct RcRuleDataBuilder {
    /// the smt tree
    smt: SMT,
    /// the list type
    list_type: ListType,
    /// indicate if the rule is emergency
    is_emergency: bool,
}

impl RcRuleDataBuilder {
    pub fn new(list_type: ListType, is_emergency: bool) -> Self {
        let smt = SMT::default();
        RcRuleDataBuilder {
            smt,
            list_type,
            is_emergency,
        }
    }
    /// create a default smt tree with initial smt values.
    pub fn new_smt(pairs: &[(SmtH256, SmtH256)], list_type: ListType, is_emergency: bool) -> Self {
        let mut builder = RcRuleDataBuilder::new(list_type, is_emergency);
        builder.update(pairs);
        builder
    }

    /// update key/value pair into the smt tree
    pub fn update(&mut self, pairs: &[(SmtH256, SmtH256)]) {
        for (key, value) in pairs {
            self.smt.update(*key, *value).unwrap();
        }
    }
    /// calculate the root hash of the smt tree.
    pub fn root(&self) -> SmtH256 {
        *self.smt.root()
    }

    /// Build smt with the given hashes
    /// # Arguments
    /// * `hashes` The given the hashes.
    pub fn update_hashes(&mut self, hashes: &[SmtH256]) {
        let pairs: Vec<(SmtH256, SmtH256)> =
            hashes.iter().map(|hash| (*hash, *SMT_EXISTING)).collect();
        self.update(&pairs);
    }

    /// Build a smt tree with it's keys and gnerate proofs with the according keys.
    /// # Arguments
    /// * `keys` - The keys to generate the proofs.
    /// # Return
    /// The smt_tree root and the proofs of the proof_keys.
    pub fn proof_keys(&mut self, keys: &[SmtH256]) -> Result<Vec<u8>> {
        let proof = self
            .smt
            .merkle_proof(keys.to_vec())
            .map_err(|err| RcDataError::BuildTree(err.to_string()))?;
        let compiled_proof = proof
            .compile(keys.to_vec())
            .map_err(|e| RcDataError::CompileProof(e.to_string()))?;
        Ok(compiled_proof.into())
    }

    /// Build the rc_rule after key/value pairs are set.
    pub fn build_rc_rule(&self) -> Bytes {
        let smt_root = self.smt.root();
        let mut flags: u8 = 0;

        if let ListType::White = self.list_type {
            flags ^= WHITE_BLACK_LIST_MASK;
        }
        if self.is_emergency {
            flags ^= EMERGENCY_HALT_MODE_MASK;
        }
        let rcrule = RCRuleBuilder::default()
            .flags(flags.into())
            .smt_root(Into::<[u8; 32]>::into(*smt_root).pack())
            .build();
        let res = RCDataBuilder::default()
            .set(RCDataUnion::RCRule(rcrule))
            .build();
        res.as_bytes()
    }

    /// Build a proof and a rc_rule
    /// # Arguments
    /// * `on` - If the given smt_keys are on the smt tree.
    /// * `smt_key` - A list of smt keys.
    ///
    /// # Return
    /// A proof and the according rc rule.
    pub fn build_single_proof(
        &mut self,
        smt_key: &[SmtH256],
        on: bool,
    ) -> Result<(Vec<u8>, Bytes)> {
        let hash = if on { smt_key } else { &[] };
        self.update_hashes(hash);
        let proof = self.proof_keys(smt_key)?;

        let rc_rule = self.build_rc_rule();
        Ok((proof, rc_rule))
    }
}

/// Indicate which the rule is applied to.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Mask {
    /// apply none to input or output.
    Neither = 0,
    /// apply to input
    Input = 1,
    /// apply to output.
    Output = 2,
    /// apply to both input and output.
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
#[derive(Default)]
pub struct RcRuleVecBuilder {
    proofs: Vec<ProofWithMask>,
    rc_rules: Vec<Bytes>,
}

impl RcRuleVecBuilder {
    pub fn new() -> RcRuleVecBuilder {
        RcRuleVecBuilder::default()
    }

    /// Add proof and according rule to the list.
    pub fn add_rule(&mut self, proof: ProofWithMask, rc_rule: Bytes) {
        self.proofs.push(proof);
        self.rc_rules.push(rc_rule);
    }

    /// build a rule and single proof and add them with self.add_rule.
    /// # Arguments
    /// * `smt_key` The keys.
    /// * `mask`  The mask indicate which rule to apply.
    /// * `list_type` The black/white list type.
    /// * `is_emergency` if it's emergency
    pub fn build_single_proof_and_rule(
        &mut self,
        smt_key: &[SmtH256],
        mask: Mask,
        list_type: ListType,
        is_emergency: bool,
        on: bool,
    ) -> Result<()> {
        let mut rc_rule_builder = RcRuleDataBuilder::new(list_type, is_emergency);
        let (proof, rc_rule) = rc_rule_builder.build_single_proof(smt_key, on)?;
        let proof_with_mask = ProofWithMask::new(proof, mask);
        self.add_rule(proof_with_mask, rc_rule);

        Ok(())
    }

    pub fn build_proofs(&self) -> SmtProofEntryVec {
        let mut builder = SmtProofEntryVecBuilder::default();
        for ProofWithMask { proof, mask } in &self.proofs {
            let proof_builder = SmtProofBuilder::default().set(
                proof
                    .iter()
                    .map(|v| molecule::prelude::Byte::new(*v))
                    .collect(),
            );

            let temp = SmtProofEntryBuilder::default()
                .proof(proof_builder.build())
                .mask((*mask as u8).into());
            builder = builder.push(temp.build());
        }
        builder.build()
    }

    pub fn proofs(&self) -> &Vec<ProofWithMask> {
        &self.proofs
    }

    pub fn rc_rules(&self) -> &Vec<Bytes> {
        &self.rc_rules
    }
}

#[cfg(test)]
mod tests {
    use ckb_types::prelude::*;
    use sparse_merkle_tree::{CompiledMerkleProof, H256 as SmtH256};

    use crate::types::xudt_rce_mol::{RCData, RCDataUnion};

    use super::*;
    #[test]
    fn test_build_smt_on_bl() {
        let smt_key = SmtH256::zero();
        let mut builder = RcRuleDataBuilder::new(ListType::Black, false);
        builder.update_hashes(&[smt_key]);
        let (root, proof) = (builder.root(), builder.proof_keys(&[smt_key]).unwrap());
        let compiled_proof = CompiledMerkleProof(proof);
        assert!(!compiled_proof
            .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_NOT_EXISTING)])
            .unwrap());

        let mut builder = RcRuleDataBuilder::new(ListType::Black, false);
        let (root, proof) = (builder.root(), builder.proof_keys(&[smt_key]).unwrap());
        let compiled_proof = CompiledMerkleProof(proof);
        assert!(compiled_proof
            .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_NOT_EXISTING)])
            .unwrap());
    }

    #[test]
    fn test_build_smt_on_wl() {
        let smt_key = SmtH256::zero();
        let mut builder = RcRuleDataBuilder::new(ListType::White, false);
        builder.update_hashes(&[smt_key]);
        let (root, proof) = (builder.root(), builder.proof_keys(&[smt_key]).unwrap());
        let compiled_proof = CompiledMerkleProof(proof);
        assert!(compiled_proof
            .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_EXISTING)])
            .unwrap());

        let mut builder = RcRuleDataBuilder::new(ListType::White, false);
        let (root, proof) = (builder.root(), builder.proof_keys(&[smt_key]).unwrap());
        let compiled_proof = CompiledMerkleProof(proof);
        assert!(!compiled_proof
            .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_EXISTING)])
            .unwrap());
    }

    #[test]
    fn test_generate_single_proof_on_wl() {
        let smt_key = SmtH256::zero();
        let mut builder = RcRuleDataBuilder::new(ListType::White, false);
        builder.update_hashes(&[smt_key]);
        let (proof, rc_rule) = builder.build_single_proof(&[smt_key], true).unwrap();
        let compiled_proof = CompiledMerkleProof(proof);
        let rc_data = RCData::from_slice(&rc_rule).unwrap();
        let rcdata_union = rc_data.to_enum();
        if let RCDataUnion::RCRule(rc_rule) = rcdata_union {
            let root = rc_rule.smt_root();
            let mut root_hash = [0u8; 32];
            root_hash.copy_from_slice(root.as_slice());
            let root = SmtH256::from(root_hash);
            assert!(compiled_proof
                .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_EXISTING)])
                .unwrap());

            let flags: u8 = rc_rule.flags().into();
            assert_eq!(flags, WHITE_BLACK_LIST_MASK);
        } else {
            panic!("expected rc_rule");
        }
    }
    #[test]
    fn test_generate_single_proof_off_wl() {
        let smt_key = SmtH256::zero();
        let mut builder = RcRuleDataBuilder::new(ListType::White, false);
        let (proof, rc_rule) = builder.build_single_proof(&[smt_key], false).unwrap();
        let compiled_proof = CompiledMerkleProof(proof);
        let rc_data = RCData::from_slice(&rc_rule).unwrap();
        let rcdata_union = rc_data.to_enum();
        if let RCDataUnion::RCRule(rc_rule) = rcdata_union {
            let root = rc_rule.smt_root();
            let mut root_hash = [0u8; 32];
            root_hash.copy_from_slice(root.as_slice());
            let root = SmtH256::from(root_hash);
            assert!(!compiled_proof
                .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_EXISTING)])
                .unwrap());

            let flags: u8 = rc_rule.flags().into();
            assert_eq!(flags, WHITE_BLACK_LIST_MASK);
        } else {
            panic!("expected rc_rule");
        }
    }
    #[test]
    fn test_generate_single_proof_on_bl() {
        let smt_key = SmtH256::zero();
        let mut builder = RcRuleDataBuilder::new(ListType::Black, false);
        let (proof, rc_rule) = builder.build_single_proof(&[smt_key], true).unwrap();
        let compiled_proof = CompiledMerkleProof(proof);
        let rc_data = RCData::from_slice(&rc_rule).unwrap();
        let rcdata_union = rc_data.to_enum();
        if let RCDataUnion::RCRule(rc_rule) = rcdata_union {
            let root = rc_rule.smt_root();
            let mut root_hash = [0u8; 32];
            root_hash.copy_from_slice(root.as_slice());
            let root = SmtH256::from(root_hash);
            assert!(compiled_proof
                .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_EXISTING)])
                .unwrap());

            let flags: u8 = rc_rule.flags().into();
            assert_eq!(flags, 0);
        } else {
            panic!("expected rc_rule");
        }
    }
    #[test]
    fn test_generate_single_proof_off_bl() {
        let smt_key = SmtH256::zero();
        let mut builder = RcRuleDataBuilder::new(ListType::Black, false);
        let (proof, rc_rule) = builder.build_single_proof(&[smt_key], false).unwrap();
        let compiled_proof = CompiledMerkleProof(proof);
        let rc_data = RCData::from_slice(&rc_rule).unwrap();
        let rcdata_union = rc_data.to_enum();
        if let RCDataUnion::RCRule(rc_rule) = rcdata_union {
            let root = rc_rule.smt_root();
            let mut root_hash = [0u8; 32];
            root_hash.copy_from_slice(root.as_slice());
            let root = SmtH256::from(root_hash);
            assert!(!compiled_proof
                .verify::<CKBBlake2bHasher>(&root, vec![(smt_key, *SMT_EXISTING)])
                .unwrap());

            let flags: u8 = rc_rule.flags().into();
            assert_eq!(flags, 0);
        } else {
            panic!("expected rc_rule");
        }
    }
}

#[cfg(test)]
mod anyhow_tests {
    // test cases make sure new added exception won't breadk `anyhow!(e_variable)` usage,
    use anyhow::anyhow;
    #[test]
    fn test_rc_data_error() {
        let error = super::RcDataError::BuildTree("BuildTree".to_string());
        let error = anyhow!(error);
        assert_eq!("fail to build the smt tree:`BuildTree`", error.to_string());
    }
}
