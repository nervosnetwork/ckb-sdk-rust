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

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum IdentityFlags {
    PubkeyHash = 0,
}

impl From<IdentityFlags> for u8 {
    fn from(val: IdentityFlags) -> Self {
        val as u8
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub flags: IdentityFlags,
    pub blake160: H160,
}
impl Identity {
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret: [u8; 32] = Default::default();
        ret[0] = self.flags.into();
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }
}

impl From<Identity> for [u8; 21] {
    fn from(id: Identity) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flags.into();
        res[1..].copy_from_slice(id.blake160.as_bytes());
        res
    }
}

impl From<Identity> for Vec<u8> {
    fn from(id: Identity) -> Self {
        let mut bytes: Vec<u8> = vec![id.flags.into()];
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
        let v: Vec<u8> = self.clone().into();
        for i in v {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

/*
<1 byte Omnilock flags>
<32 byte RC cell type ID, optional>
<2 bytes minimum ckb/udt in ACP, optional>
<8 bytes since for time lock, optional>
<32 bytes type script hash for supply, optional>
*/

#[derive(Clone, Serialize, Deserialize)]
pub struct OmniLockConfig {
    pub id: Identity,
    pub omni_lock_flags: u8,
}

impl OmniLockConfig {
    pub fn new_pubkey_hash_with_lockarg(lock_arg: Bytes) -> Self {
        assert!(lock_arg.len() == 20);
        Self::new(IdentityFlags::PubkeyHash, blake160(&lock_arg))
    }

    pub fn new_pubkey_hash(pubkey: &Pubkey) -> Self {
        let pubkey_hash = blake160(&pubkey.serialize());
        Self::new(IdentityFlags::PubkeyHash, pubkey_hash)
    }

    pub fn new(flags: IdentityFlags, blake160: H160) -> Self {
        let blake160 = if flags == IdentityFlags::PubkeyHash {
            blake160
        } else {
            H160::from_slice(&[0; 20]).unwrap()
        };

        OmniLockConfig {
            id: Identity { flags, blake160 },
            omni_lock_flags: 0,
        }
    }

    pub fn build_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);

        // auth
        bytes.put_u8(self.id.flags.into());
        bytes.put(self.id.blake160.as_ref());
        bytes.put_u8(self.omni_lock_flags);

        bytes.freeze()
    }

    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flags == IdentityFlags::PubkeyHash
    }

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

    pub fn build_witness_lock(signature: Bytes) -> Bytes {
        OmniLockWitnessLock::new_builder()
            .signature(Some(signature).pack())
            .build()
            .as_bytes()
    }
}
