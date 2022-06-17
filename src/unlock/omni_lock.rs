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

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
#[repr(u8)]
pub enum IdentityFlags {
    PubkeyHash = 0,
}

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct Identity {
    /// Indicate what's auth content of blake160 will be.
    pub flags: IdentityFlags,
    /// The auth content of the identity.
    pub blake160: H160,
}
impl Identity {
    /// convert the identify to smt_key.
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret[0] = self.flags as u8;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }
}

impl From<Identity> for [u8; 21] {
    fn from(id: Identity) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flags as u8;
        res[1..].copy_from_slice(id.blake160.as_bytes());
        res
    }
}

impl From<Identity> for Vec<u8> {
    fn from(id: Identity) -> Self {
        let mut bytes: Vec<u8> = vec![id.flags as u8];
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
        write!(f, "{:02x},", self.flags as u8)?;
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
        // administrator mode 0b00000001, affected args:  RC cell type ID, affected field:omni_identity/signature in OmniLockWitnessLock
        const ADMIN = 0b00000001;
        // anyone-can-pay mode 0b00000010, affected args: minimum ckb/udt in ACP
        const ACP = 0b00000010;
        // time-lock mode 0b00000100, affected args: since for timelock
        const TIME_LOCK = 0b00000100;
        // supply mode	0b00001000, affected args: type script hash for supply
        const SUPPLY = 0b00001000;
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
#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct OmniLockConfig {
    /// The auth id of the OmniLock
    pub id: Identity,
    /// The omni lock flags, it indicates whether the other four fields exist.
    pub omni_lock_flags: OmniLockFlags,
}

impl OmniLockConfig {
    /// Create a pubkey hash algorithm omnilock with proper argument
    /// # Arguments
    /// * `lock_arg` proper 20 bytes auth content
    pub fn new_pubkey_hash_with_lockarg(lock_arg: Bytes) -> Self {
        assert!(lock_arg.len() == 20);
        Self::new(
            IdentityFlags::PubkeyHash,
            H160::from_slice(&lock_arg).unwrap(),
        )
    }

    /// Create a pubkey hash algorithm omnilock with pubkey
    pub fn new_pubkey_hash(pubkey: &Pubkey) -> Self {
        let pubkey_hash = blake160(&pubkey.serialize());
        Self::new(IdentityFlags::PubkeyHash, pubkey_hash)
    }

    /// Create a new OmniLockConfig
    pub fn new(flags: IdentityFlags, blake160: H160) -> Self {
        let blake160 = if flags == IdentityFlags::PubkeyHash {
            blake160
        } else {
            H160::from_slice(&[0; 20]).unwrap()
        };

        OmniLockConfig {
            id: Identity { flags, blake160 },
            omni_lock_flags: OmniLockFlags::empty(),
        }
    }

    /// Build lock script arguments
    pub fn build_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);

        // auth
        bytes.put_u8(self.id.flags as u8);
        bytes.put(self.id.blake160.as_ref());
        bytes.put_u8(self.omni_lock_flags.bits);

        bytes.freeze()
    }

    /// Indicate whether is a sighash type.
    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flags == IdentityFlags::PubkeyHash
    }

    /// Build zero lock content for signature
    pub fn zero_lock(&self) -> Bytes {
        if self.is_pubkey_hash() {
            let len = OmniLockWitnessLock::new_builder()
                .signature(Some(Bytes::from(vec![0u8; 65])).pack())
                .build()
                .as_bytes()
                .len();

            Bytes::from(vec![0u8; len])
        } else {
            todo!("to support other zero lock implementions");
        }
    }

    /// Create a zero lock witness placeholder
    pub fn placeholder_witness(&self) -> WitnessArgs {
        if self.is_pubkey_hash() {
            let zero_lock = self.zero_lock();
            WitnessArgs::new_builder()
                .lock(Some(zero_lock).pack())
                .build()
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
