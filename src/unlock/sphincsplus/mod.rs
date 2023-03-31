use std::{collections::HashMap, ffi::c_ulonglong};

use anyhow::anyhow;
use bytes::Bytes;
use ckb_types::{packed::WitnessArgs, prelude::*, H256};

use std::convert::TryFrom;

use ckb_hash::blake2b_256;
use thiserror::Error;

use crate::{
    traits::{Signer, SignerError},
    util::zeroize_slice,
};

#[link(name = "sphincsplus", kind = "static")]
extern "C" {
    // uint32_t sphincs_plus_get_pk_size();
    fn sphincs_plus_get_pk_size() -> u32;

    // uint32_t sphincs_plus_get_sk_size();
    fn sphincs_plus_get_sk_size() -> u32;

    // uint32_t sphincs_plus_get_sign_size();
    fn sphincs_plus_get_sign_size() -> u32;

    // int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk);
    fn sphincs_plus_generate_keypair(pk: *mut u8, sk: *mut u8) -> i32;

    // int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign);
    fn sphincs_plus_sign(message: *const u8, sk: *const u8, out_sign: *mut u8) -> i32;

    // int sphincs_plus_verify(uint8_t *sign, uint32_t sign_size, uint8_t *message,
    //                         uint32_t message_size, uint8_t *pubkey,
    //                         uint32_t pubkey_size);
    fn sphincs_plus_verify(
        sign: *const u8,
        sign_size: u32,
        message: *const u8,
        message_sizse: u32,
        pk: *const u8,
        pk_size: u32,
    ) -> i32;

    // int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
    //     const unsigned char *seed)
    fn crypto_sign_seed_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;

    // unsigned long long crypto_sign_seedbytes(void);
    fn crypto_sign_seedbytes() -> c_ulonglong;
}

pub struct SphincsPlus;

impl SphincsPlus {
    /// get public key length
    pub fn pk_len() -> usize {
        unsafe { sphincs_plus_get_pk_size() as usize }
    }
    /// get private key length
    pub fn sk_len() -> usize {
        unsafe { sphincs_plus_get_sk_size() as usize }
    }

    /// get signature length
    pub fn sign_len() -> usize {
        unsafe { sphincs_plus_get_sign_size() as usize }
    }
    /// get seed bytes length, include sk.seed, sk.prf, pk.seed
    pub fn seed_len() -> usize {
        unsafe { crypto_sign_seedbytes() as usize }
    }

    /// get lock length in witness
    pub fn lock_len() -> usize {
        Self::sign_len() + Self::pk_len()
    }

    /// build lock data for witness lock with all zero bytes
    pub fn zero_lock() -> Bytes {
        Bytes::from(vec![0u8; SphincsPlus::lock_len()])
    }

    /// build a placeholder witness for sphincs plus
    pub fn placeholder_witness() -> WitnessArgs {
        WitnessArgs::new_builder()
            .lock(Some(Self::zero_lock()).pack())
            .build()
    }
}

/// Transaction builder errors
#[derive(Error, Debug)]
pub enum SphincsPlusError {
    /// Generate key pair failed.
    #[error("generate sphincs plus failed with return value: `{0}`")]
    GenerateKeyPair(i32),

    /// Sign failed, possible error values are:
    /// - 1, signature length is not equal to SphincsPlus::sign_len()
    #[error("sign failed with return value: `{0}`")]
    Sign(i32),
    /// Signature verify failed, possible error values are:
    /// - 200, parameters' length are not all correct
    /// - 201, singned failed with public key
    /// - 202, sined message length is not correct
    /// - 203, provided signature is not equal to public key calculated signature
    #[error("verify failed: `{0}`")]
    Verify(i32),
    /// Publick key length is not correct.
    #[error("public key length is not correct")]
    PublicKeyLen,
    /// Private key length is not correct.
    #[error("private key length is not correct")]
    PrivateKeyLen,
    #[error("The private key is invalid")]
    InvalidPrivateKey,
    /// Other errors
    #[error("other error: `{0}`")]
    Other(anyhow::Error),
}

#[derive(Default, Clone)]
pub struct SphincsPlusPrivateKey(Vec<u8>);

impl SphincsPlusPrivateKey {
    /// create a new SphincsPlus, and generate a new key pair
    pub fn new() -> Result<Self, SphincsPlusError> {
        let mut s = Self(vec![0; SphincsPlus::sk_len()]);
        let mut pk = vec![0; SphincsPlus::pk_len()];

        let ret = unsafe { sphincs_plus_generate_keypair(pk.as_mut_ptr(), s.0.as_mut_ptr()) };
        if ret != 0 {
            Err(SphincsPlusError::GenerateKeyPair(ret))
        } else {
            Ok(s)
        }
    }

    /// verify if the private key is valid, by generate the private key from the seed.
    pub fn is_valid(&self) -> Result<(), SphincsPlusError> {
        if self.0.len() != SphincsPlus::sk_len() {
            return Err(SphincsPlusError::PrivateKeyLen);
        }
        let mut sk = vec![0; SphincsPlus::sk_len()];
        let mut pk = vec![0; SphincsPlus::pk_len()];

        let ret =
            unsafe { crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), self.0.as_ptr()) };
        if ret != 0 {
            return Err(SphincsPlusError::GenerateKeyPair(ret));
        }
        if sk != self.0 {
            return Err(SphincsPlusError::InvalidPrivateKey);
        }
        Ok(())
    }

    pub fn pub_key(&self) -> SphincsPlusPublicKey {
        let pk = self.0[SphincsPlus::sk_len() - SphincsPlus::pk_len()..].to_vec();
        SphincsPlusPublicKey(pk)
    }

    /// sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SphincsPlusError> {
        let mut s = vec![0; SphincsPlus::lock_len()];

        let ret = unsafe { sphincs_plus_sign(msg.as_ptr(), self.0.as_ptr(), s.as_mut_ptr()) };
        if ret != 0 {
            Err(SphincsPlusError::Sign(ret))
        } else {
            // copy public key
            s[SphincsPlus::sign_len()..]
                .copy_from_slice(&self.0[SphincsPlus::sk_len() - SphincsPlus::pk_len()..]);
            Ok(s)
        }
    }
}

impl TryFrom<Vec<u8>> for SphincsPlusPrivateKey {
    type Error = SphincsPlusError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != SphincsPlus::sk_len() {
            return Err(SphincsPlusError::PrivateKeyLen);
        }
        let private_key = Self(value);
        private_key.is_valid()?;
        Ok(private_key)
    }
}

pub struct SphincsPlusPublicKey(Vec<u8>);

impl SphincsPlusPublicKey {
    /// verify if a message is correctly signed
    pub fn verify(&self, msg: &[u8], sign: &[u8]) -> Result<(), SphincsPlusError> {
        let ret = unsafe {
            sphincs_plus_verify(
                sign.as_ptr(),
                sign.len() as u32,
                msg.as_ptr(),
                msg.len() as u32,
                self.0.as_ptr(),
                self.0.len() as u32,
            )
        };
        if ret != 0 {
            Err(SphincsPlusError::Verify(ret))
        } else {
            Ok(())
        }
    }

    /// Generate lock args.
    pub fn lock_args(&self) -> [u8; 32] {
        blake2b_256(&self.0)
    }
}

/// A signer use secp256k1 raw key, the id is `blake160(pubkey)`.
#[derive(Default, Clone)]
pub struct SphincsPlusRawKeysSigner {
    keys: HashMap<H256, SphincsPlusPrivateKey>,
}

impl SphincsPlusRawKeysSigner {
    pub fn new(keys: HashMap<H256, SphincsPlusPrivateKey>) -> SphincsPlusRawKeysSigner {
        SphincsPlusRawKeysSigner { keys }
    }
    pub fn new_with_private_keys(keys: Vec<SphincsPlusPrivateKey>) -> SphincsPlusRawKeysSigner {
        let mut signer = SphincsPlusRawKeysSigner::default();
        for key in keys {
            signer.add_secret_key(key);
        }
        signer
    }
    pub fn add_secret_key(&mut self, key: SphincsPlusPrivateKey) {
        let lock_args = key.pub_key().lock_args();
        let hash256 = H256::from_slice(&lock_args).expect("Generate hash(H256) from pubkey failed");
        self.keys.insert(hash256, key);
    }
}

impl Signer for SphincsPlusRawKeysSigner {
    fn match_id(&self, id: &[u8]) -> bool {
        id.len() == 32 && self.keys.contains_key(&H256::from_slice(id).unwrap())
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        _recoverable: bool,
        _tx: &ckb_types::core::TransactionView,
    ) -> Result<bytes::Bytes, SignerError> {
        if !self.match_id(id) {
            return Err(SignerError::IdNotFound);
        }
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let key = self.keys.get(&H256::from_slice(id).unwrap()).unwrap();
        let sig = key
            .sign(message)
            .map_err(|e| anyhow!("{}", e.to_string()))?;
        Ok(bytes::Bytes::from(sig))
    }
}

impl Drop for SphincsPlusRawKeysSigner {
    fn drop(&mut self) {
        for (_, mut secret_key) in self.keys.drain() {
            zeroize_slice(&mut secret_key.0);
        }
    }
}

pub(crate) mod signer;
pub(crate) mod unlocker;
