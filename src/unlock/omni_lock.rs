use core::hash;
use std::fmt::Display;

use crate::{
    types::{
        omni_lock::{Auth, Identity as IdentityType, IdentityOpt, OmniLockWitnessLock},
        xudt_rce_mol::SmtProofEntryVec,
    },
    util::{blake160, keccak160},
};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    packed::WitnessArgs,
    prelude::*,
    H160, H256,
};

use ckb_crypto::secp::Pubkey;
pub use ckb_types::prelude::Pack;
use serde::{de::Unexpected, Deserialize, Serialize};

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
    /// Indicate what's auth content of auth_content will be.
    flag: IdentityFlag,
    /// The auth content of the identity.
    auth_content: H160,
}
impl Identity {
    /// convert the identify to smt_key.
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret[0] = self.flag as u8;
        (&mut ret[1..21]).copy_from_slice(self.auth_content.as_ref());
        ret
    }

    /// get the flag
    pub fn flag(&self) -> IdentityFlag {
        self.flag
    }
    /// get the auth content of the identity
    pub fn auth_content(&self) -> &H160 {
        &self.auth_content
    }
}

impl From<Identity> for [u8; 21] {
    fn from(id: Identity) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flag as u8;
        res[1..].copy_from_slice(id.auth_content.as_bytes());
        res
    }
}

impl From<Identity> for Vec<u8> {
    fn from(id: Identity) -> Self {
        let mut bytes: Vec<u8> = vec![id.flag as u8];
        bytes.extend(id.auth_content.as_bytes());
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
        for x in self.auth_content.as_bytes() {
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

impl Serialize for SmtProofEntryVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("SmtProofEntryVec", &self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for SmtProofEntryVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Bytes::deserialize(deserializer)?;
        SmtProofEntryVec::from_slice(bytes.as_ref()).map_err(|e| {
            serde::de::Error::invalid_value(
                Unexpected::Bytes(bytes.as_ref()),
                &format!(
                    "can not convert the value to SmtProofEntryVec:　{}",
                    e.to_string()
                )
                .as_str(),
            )
        })
    }
}

impl hash::Hash for SmtProofEntryVec {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        self.as_slice().hash(state);
    }
}

// impl Eq

impl PartialEq for SmtProofEntryVec {
    fn eq(&self, other: &SmtProofEntryVec) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for SmtProofEntryVec {}

/// The administrator mode configuration.
#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct AdminConfig {
    /// The rc cell's type script hash, the type script should be a type id script.
    rc_type_id: H256,
    /// The smt proofs
    proofs: SmtProofEntryVec,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            rc_type_id: Default::default(),
            proofs: SmtProofEntryVec::default(),
        }
    }
}

impl AdminConfig {
    pub fn set_rc_type_id(&mut self, rc_type_id: H256) {
        self.rc_type_id = rc_type_id;
    }
    pub fn set_proofs(&mut self, proofs: SmtProofEntryVec) {
        self.proofs = proofs;
    }
    pub fn rc_type_id(&self) -> &H256 {
        &self.rc_type_id
    }
    pub fn proofs(&self) -> &SmtProofEntryVec {
        &self.proofs
    }

    pub fn new(root: H256, proofs: SmtProofEntryVec) -> AdminConfig {
        AdminConfig {
            rc_type_id: root,
            proofs,
        }
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
    id: Identity,
    /// The multisig config.
    multisig_config: Option<MultisigConfig>,
    /// The omni lock flags, it indicates whether the other four fields exist.
    omni_lock_flags: OmniLockFlags,
    ///　The administrator configuration.
    admin_config: Option<AdminConfig>,
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
                auth_content: blake160,
            },
            multisig_config: Some(multisig_config),
            omni_lock_flags: OmniLockFlags::empty(),
            admin_config: None,
        }
    }
    /// Create an ethereum algorithm omnilock with pubkey
    pub fn new_ethereum(pubkey: &Pubkey) -> Self {
        let pubkey_hash = keccak160(pubkey.as_ref());
        Self::new(IdentityFlag::Ethereum, pubkey_hash)
    }

    /// Create an ownerlock omnilock with according script hash.
    /// # Arguments
    /// * `script_hash` the proper blake160 hash of according ownerlock script.
    pub fn new_ownerlock(script_hash: H160) -> Self {
        Self::new(IdentityFlag::OwnerLock, script_hash)
    }

    /// Create a new OmniLockConfig
    pub fn new(flag: IdentityFlag, auth_content: H160) -> Self {
        let auth_content = match flag {
            IdentityFlag::PubkeyHash | IdentityFlag::Ethereum | IdentityFlag::OwnerLock => {
                auth_content
            }
            _ => H160::from_slice(&[0; 20]).unwrap(),
        };

        OmniLockConfig {
            id: Identity { flag, auth_content },
            multisig_config: None,
            omni_lock_flags: OmniLockFlags::empty(),
            admin_config: None,
        }
    }

    pub fn set_admin_config(&mut self, admin_config: AdminConfig) {
        self.omni_lock_flags.set(OmniLockFlags::ADMIN, true);
        self.admin_config = Some(admin_config);
    }

    pub fn id(&self) -> &Identity {
        &self.id
    }

    /// Return the reference content of the multisig config.
    /// If the multisig config is None, it will panic.
    pub fn multisig_config(&self) -> Option<&MultisigConfig> {
        self.multisig_config.as_ref()
    }

    pub fn omni_lock_flags(&self) -> &OmniLockFlags {
        &self.omni_lock_flags
    }

    pub fn use_rc(&self) -> bool {
        self.admin_config.is_some()
    }

    /// Build lock script arguments
    pub fn build_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);

        // auth
        bytes.put_u8(self.id.flag as u8);
        if self.admin_config.is_none() {
            bytes.put(self.id.auth_content.as_ref());
        } else {
            bytes.put(H160::default().as_ref());
        }
        bytes.put_u8(self.omni_lock_flags.bits);

        if let Some(config) = self.admin_config.as_ref() {
            bytes.put(config.rc_type_id.as_bytes());
        }

        bytes.freeze()
    }

    /// Calculate script args length
    pub fn get_args_len(&self) -> usize {
        let mut len = 22;
        if self.omni_lock_flags.contains(OmniLockFlags::ADMIN) {
            len += 32;
        }
        if self.omni_lock_flags.contains(OmniLockFlags::ACP) {
            len += 2;
        }
        if self.omni_lock_flags.contains(OmniLockFlags::TIME_LOCK) {
            len += 8;
        }
        if self.omni_lock_flags.contains(OmniLockFlags::SUPPLY) {
            len += 32;
        }
        len
    }

    /// Indicate whether is a sighash type.
    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flag == IdentityFlag::PubkeyHash
    }

    /// Indicate whether is a ethereum type.
    pub fn is_ethereum(&self) -> bool {
        self.id.flag == IdentityFlag::Ethereum
    }

    /// Check if it is a mutlisig flag.
    pub fn is_multisig(&self) -> bool {
        self.id.flag == IdentityFlag::Multisig
    }

    /// Check if it is a ownerlock flag.
    pub fn is_ownerlock(&self) -> bool {
        self.id.flag == IdentityFlag::OwnerLock
    }

    pub fn placeholder_witness_lock(&self) -> Bytes {
        let mut builder = match self.id.flag {
            IdentityFlag::PubkeyHash | IdentityFlag::Ethereum => OmniLockWitnessLock::new_builder()
                .signature(Some(Bytes::from(vec![0u8; 65])).pack()),
            IdentityFlag::Multisig => {
                let multisig_config = self.multisig_config.as_ref().unwrap();
                let config_data = multisig_config.to_witness_data();
                let multisig_len = config_data.len() + multisig_config.threshold() as usize * 65;
                let mut omni_sig = vec![0u8; multisig_len];
                omni_sig[..config_data.len()].copy_from_slice(&config_data);
                OmniLockWitnessLock::new_builder().signature(Some(Bytes::from(omni_sig)).pack())
            }
            IdentityFlag::OwnerLock => OmniLockWitnessLock::new_builder(),
            _ => todo!("to support other placeholder_witness_lock implementions"),
        };

        if let Some(config) = self.admin_config.as_ref() {
            let mut temp = [0u8; 21];
            temp[0] = self.id.flag as u8;
            temp[1..21].copy_from_slice(self.id.auth_content.as_bytes());
            let auth = Auth::from_slice(&temp).unwrap();
            let ident = IdentityType::new_builder()
                .identity(auth)
                .proofs(config.proofs.clone())
                .build();

            let ident_opt = IdentityOpt::new_builder().set(Some(ident)).build();
            builder = builder.omni_identity(ident_opt);
        }
        builder.build().as_bytes()
    }

    /// Build zero lock content for signature
    pub fn zero_lock(&self) -> Bytes {
        let len = self.placeholder_witness_lock().len();
        Bytes::from(vec![0u8; len])
    }

    /// Create a zero lock witness placeholder
    pub fn placeholder_witness(&self) -> WitnessArgs {
        match self.id.flag {
            IdentityFlag::PubkeyHash | IdentityFlag::Ethereum | IdentityFlag::Multisig => {
                let lock = self.placeholder_witness_lock();
                WitnessArgs::new_builder().lock(Some(lock).pack()).build()
            }
            IdentityFlag::OwnerLock => {
                if self.admin_config.as_ref().is_some() {
                    let lock = self.placeholder_witness_lock();
                    WitnessArgs::new_builder().lock(Some(lock).pack()).build()
                } else {
                    WitnessArgs::default()
                }
            }
            _ => todo!("to support other placeholder_witness implementions"),
        }
    }
}
#[cfg(test)]
mod tests {
    use ckb_types::packed::Byte;

    use crate::{
        types::xudt_rce_mol::{SmtProof, SmtProofEntry, SmtProofEntryVec},
        unlock::omni_lock::AdminConfig,
    };
    use ckb_types::{h256, prelude::*};
    #[test]
    fn test_adminconfig_serde() {
        let mut i = (0u8..=255u8).cycle();
        let type_id = h256!("0x1234567890abcdeffedcba0987654321");
        let mut proofs_builder = SmtProofEntryVec::new_builder();
        for _ in 0..2 {
            let proof = SmtProof::new_builder()
                .extend(i.by_ref().take(8).map(Byte::new))
                .build();
            let entry = SmtProofEntry::new_builder()
                .mask(Byte::new(0))
                .proof(proof)
                .build();
            proofs_builder = proofs_builder.push(entry);
        }
        let cfg = AdminConfig {
            rc_type_id: type_id,
            proofs: proofs_builder.build(),
        };
        let x = serde_json::to_string_pretty(&cfg).unwrap();
        let cfg2: AdminConfig = serde_json::from_str(&x).unwrap();
        assert_eq!(cfg, cfg2);
    }
}
