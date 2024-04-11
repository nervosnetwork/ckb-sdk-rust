use std::collections::HashMap;
use ckb_crypto::secp::Pubkey;
use thiserror::Error;

use ckb_hash::blake2b_256;

use ckb_types::{
    bytes::Bytes,
    core::{TransactionView},
    H160,
};


use crate::util::{serialize_signature, zeroize_privkey};
use crate::SECP256K1;
use crate::util::keccak160;


use super::{Signer, SignerError};

/// Parse Genesis Info errors
#[derive(Error, Debug)]
pub enum ParseGenesisInfoError {
    #[error("invalid block number, expected: 0, got: `{0}`")]
    InvalidBlockNumber(u64),
    #[error("data not found: `{0}`")]
    DataHashNotFound(String),
    #[error("type not found: `{0}`")]
    TypeHashNotFound(String),
}

/// A signer use secp256k1 raw key, the id is `blake160(pubkey)`.
#[derive(Default, Clone)]
pub struct SecpCkbRawKeySigner {
    keys: HashMap<H160, secp256k1::SecretKey>,
}

impl SecpCkbRawKeySigner {
    pub fn new(keys: HashMap<H160, secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        SecpCkbRawKeySigner { keys }
    }
    pub fn new_with_secret_keys(keys: Vec<secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        let mut signer = SecpCkbRawKeySigner::default();
        for key in keys {
            signer.add_secret_key(key);
        }
        signer
    }
    pub fn add_secret_key(&mut self, key: secp256k1::SecretKey) {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
        let hash160 = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        self.keys.insert(hash160, key);
    }

    /// Create SecpkRawKeySigner from secret keys for ethereum algorithm.
    pub fn new_with_ethereum_secret_keys(keys: Vec<secp256k1::SecretKey>) -> SecpCkbRawKeySigner {
        let mut signer = SecpCkbRawKeySigner::default();
        for key in keys {
            signer.add_ethereum_secret_key(key);
        }
        signer
    }
    /// Add a ethereum secret key
    pub fn add_ethereum_secret_key(&mut self, key: secp256k1::SecretKey) {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &key);
        let hash160 = keccak160(Pubkey::from(pubkey).as_ref());
        self.keys.insert(hash160, key);
    }
}

impl Signer for SecpCkbRawKeySigner {
    fn match_id(&self, id: &[u8]) -> bool {
        id.len() == 20 && self.keys.contains_key(&H160::from_slice(id).unwrap())
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        _tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        if !self.match_id(id) {
            return Err(SignerError::IdNotFound);
        }
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg = secp256k1::Message::from_slice(message).expect("Convert to message failed");
        let key = self.keys.get(&H160::from_slice(id).unwrap()).unwrap();
        if recoverable {
            let sig = SECP256K1.sign_ecdsa_recoverable(&msg, key);
            Ok(Bytes::from(serialize_signature(&sig).to_vec()))
        } else {
            let sig = SECP256K1.sign_ecdsa(&msg, key);
            Ok(Bytes::from(sig.serialize_compact().to_vec()))
        }
    }
}

impl Drop for SecpCkbRawKeySigner {
    fn drop(&mut self) {
        for (_, mut secret_key) in self.keys.drain() {
            zeroize_privkey(&mut secret_key);
        }
    }
}
#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_parse_genesis_info_error() {
        let error = super::ParseGenesisInfoError::DataHashNotFound("DataHashNotFound".to_string());
        let error = anyhow!(error);
        assert_eq!("data not found: `DataHashNotFound`", error.to_string());
    }
}
