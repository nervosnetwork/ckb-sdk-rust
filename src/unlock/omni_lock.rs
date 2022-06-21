use std::fmt::Display;

use crate::{types::omni_lock::OmniLockWitnessLock, util::blake160};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    packed::WitnessArgs,
    prelude::*,
    H160,
};

use ckb_crypto::secp::Pubkey;
pub use ckb_types::prelude::Pack;
use serde::{Deserialize, Serialize};

use bitflags::bitflags;

use super::MultisigConfig;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
#[repr(u8)]
pub enum IdentityFlag {
    /// The auth content represents the blake160 hash of a secp256k1 public key.
    /// The lock script will perform secp256k1 signature verification, the same as the SECP256K1/blake160 lock.
    PubkeyHash = 0,
    /// It follows the same unlocking methods used by Ethereum.
    Ethereum = 1,
    /// It follows the same unlocking methods used by EOS.
    Eos = 2,
    /// It follows the same unlocking methods used by Tron.
    Tron = 3,
    /// It follows the same unlocking methods used by Bitcoin
    Bitcoin = 4,
    ///  It follows the same unlocking methods used by Dogecoin.
    Dogecoin = 5,
    /// It follows the same unlocking method used by CKB MultiSig.
    Multisig = 6,

    /// The auth content that represents the blake160 hash of a lock script.
    /// The lock script will check if the current transaction contains an input cell with a matching lock script.
    /// Otherwise, it would return with an error. It's similar to P2SH in BTC.
    OwnerLock = 0xFC,
    /// The auth content that represents the blake160 hash of a preimage.
    /// The preimage contains exec information that is used to delegate signature verification to another script via exec.
    Exec = 0xFD,
    /// The auth content that represents the blake160 hash of a preimage.
    /// The preimage contains dynamic linking information that is used to delegate signature verification to the dynamic linking script.
    /// The interface described in Swappable Signature Verification Protocol Spec is used here.
    Dl = 0xFE,
}

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct Identity {
    /// Indicate what's auth content of blake160 will be.
    flag: IdentityFlag,
    /// The auth content of the identity.
    blake160: H160,
}
impl Identity {
    /// convert the identify to smt_key.
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret[0] = self.flag as u8;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }

    /// get the flag
    pub fn flag(&self) -> IdentityFlag {
        self.flag
    }
    /// get the hash
    pub fn blake160(&self) -> &H160 {
        &self.blake160
    }
}

impl From<Identity> for [u8; 21] {
    fn from(id: Identity) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flag as u8;
        res[1..].copy_from_slice(id.blake160.as_bytes());
        res
    }
}

impl From<Identity> for Vec<u8> {
    fn from(id: Identity) -> Self {
        let mut bytes: Vec<u8> = vec![id.flag as u8];
        bytes.extend(id.blake160.as_bytes());
        bytes
    }
}

impl From<Identity> for ckb_types::bytes::Bytes {
    fn from(id: Identity) -> Self {
        let v: Vec<u8> = id.into();
        v.into()
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(")?;
        let alternate = f.alternate();
        if alternate {
            write!(f, "0x")?;
        }
        write!(f, "{:02x},", self.flag as u8)?;
        if alternate {
            write!(f, "0x")?;
        }
        for x in self.blake160.as_bytes() {
            write!(f, "{:02x}", x)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}
bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct OmniLockFlags: u8 {
        /// administrator mode, flag is 1, affected args:  RC cell type ID, affected field:omni_identity/signature in OmniLockWitnessLock
        const ADMIN = 1;
        // anyone-can-pay mode, flag is 1<<1, affected args: minimum ckb/udt in ACP
        const ACP = 1<<1;
        /// time-lock mode, flag is 1<<2, affected args: since for timelock
        const TIME_LOCK = 1<<2;
        /// supply mode, flag is 1<<3, affected args: type script hash for supply
        const SUPPLY = 1<<3;
    }
}

/// OmniLock configuration
/// The lock argument has the following data structure:
/// 1. 21 byte auth
/// 2. 1 byte Omnilock flags
/// 3. 32 byte RC cell type ID, optional
/// 4. 2 bytes minimum ckb/udt in ACP, optional
/// 5. 8 bytes since for time lock, optional
/// 6. 32 bytes type script hash for supply, optional
#[derive(Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct OmniLockConfig {
    /// The auth id of the OmniLock
    id: Identity,
    /// The multisig config.
    multisig_config: Option<MultisigConfig>,
    /// The omni lock flags, it indicates whether the other four fields exist.
    omni_lock_flags: OmniLockFlags,
}

impl OmniLockConfig {
    /// Create a pubkey hash algorithm omnilock with proper argument
    /// # Arguments
    /// * `lock_arg` proper 20 bytes auth content
    pub fn new_pubkey_hash_with_lockarg(lock_arg: H160) -> Self {
        Self::new(IdentityFlag::PubkeyHash, lock_arg)
    }

    /// Create a pubkey hash algorithm omnilock with pubkey
    pub fn new_pubkey_hash(pubkey: &Pubkey) -> Self {
        let pubkey_hash = blake160(&pubkey.serialize());
        Self::new(IdentityFlag::PubkeyHash, pubkey_hash)
    }

    pub fn new_multisig(multisig_config: MultisigConfig) -> Self {
        let blake160 = multisig_config.hash160();
        OmniLockConfig {
            id: Identity {
                flag: IdentityFlag::Multisig,
                blake160,
            },
            multisig_config: Some(multisig_config),
            omni_lock_flags: OmniLockFlags::empty(),
        }
    }

    /// Create a new OmniLockConfig
    pub fn new(flag: IdentityFlag, blake160: H160) -> Self {
        let blake160 = if flag == IdentityFlag::PubkeyHash {
            blake160
        } else {
            H160::from_slice(&[0; 20]).unwrap()
        };

        OmniLockConfig {
            id: Identity { flag, blake160 },
            multisig_config: None,
            omni_lock_flags: OmniLockFlags::empty(),
        }
    }

    pub fn id(&self) -> &Identity {
        &self.id
    }

    /// Return the reference content of the multisig config.
    /// If the multisig config is None, it will panic.
    pub fn multisig_config(&self) -> &MultisigConfig {
        self.multisig_config.as_ref().unwrap()
    }

    pub fn omni_lock_flags(&self) -> &OmniLockFlags {
        &self.omni_lock_flags
    }

    /// Build lock script arguments
    pub fn build_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);

        // auth
        bytes.put_u8(self.id.flag as u8);
        bytes.put(self.id.blake160.as_ref());
        bytes.put_u8(self.omni_lock_flags.bits);

        bytes.freeze()
    }

    /// Indicate whether is a sighash type.
    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flag == IdentityFlag::PubkeyHash
    }

    /// Check if it is a mutlisig flag.
    pub fn is_multisig(&self) -> bool {
        self.id.flag == IdentityFlag::Multisig
    }

    pub fn placeholder_witness_lock(&self) -> Bytes {
        match self.id.flag {
            IdentityFlag::PubkeyHash => OmniLockWitnessLock::new_builder()
                .signature(Some(Bytes::from(vec![0u8; 65])).pack())
                .build()
                .as_bytes(),
            IdentityFlag::Multisig => {
                let multisig_config = self.multisig_config.as_ref().unwrap();
                let config_data = multisig_config.to_witness_data();
                let multisig_len = config_data.len() + multisig_config.threshold() as usize * 65;
                let mut omni_sig = vec![0u8; multisig_len];
                omni_sig[..config_data.len()].copy_from_slice(&config_data);
                OmniLockWitnessLock::new_builder()
                    .signature(Some(Bytes::from(omni_sig)).pack())
                    .build()
                    .as_bytes()
            }
            _ => todo!("to support other placeholder_witness_lock implementions"),
        }
    }

    /// Build zero lock content for signature
    pub fn zero_lock(&self) -> Bytes {
        let len = match self.id.flag {
            IdentityFlag::PubkeyHash => OmniLockWitnessLock::new_builder()
                .signature(Some(Bytes::from(vec![0u8; 65])).pack())
                .build()
                .as_bytes()
                .len(),
            IdentityFlag::Multisig => {
                let multisig_config = self.multisig_config.as_ref().unwrap();
                let multisig_len = 4
                    + 20 * multisig_config.sighash_addresses().len()
                    + 65 * multisig_config.threshold() as usize;
                OmniLockWitnessLock::new_builder()
                    .signature(Some(Bytes::from(vec![0u8; multisig_len])).pack())
                    .build()
                    .as_bytes()
                    .len()
            }
            _ => todo!("to support other zero lock implementions"),
        };
        Bytes::from(vec![0u8; len])
    }

    /// Create a zero lock witness placeholder
    pub fn placeholder_witness(&self) -> WitnessArgs {
        if self.is_pubkey_hash() || self.is_multisig() {
            let lock = self.placeholder_witness_lock();
            WitnessArgs::new_builder().lock(Some(lock).pack()).build()
        } else {
            todo!("to support other placeholder_witness implementions");
        }
    }

    /// Build proper witness lock
    pub fn build_witness_lock(signature: Bytes) -> Bytes {
        OmniLockWitnessLock::new_builder()
            .signature(Some(signature).pack())
            .build()
            .as_bytes()
    }
}
