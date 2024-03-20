use core::hash;
use std::fmt::Display;

use crate::{
    tx_builder::SinceSource,
    types::{
        omni_lock::{Auth, Identity as IdentityType, IdentityOpt, OmniLockWitnessLock},
        xudt_rce_mol::SmtProofEntryVec,
    },
};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    packed::WitnessArgs,
    prelude::*,
    H160, H256,
};

pub use ckb_types::prelude::Pack;
use enum_repr_derive::{FromEnumToRepr, TryFromReprToEnum};
use serde::{de::Unexpected, Deserialize, Serialize};
use std::convert::TryFrom;

use bitflags::bitflags;

use super::{MultisigConfig, OmniUnlockMode};
use thiserror::Error;

#[derive(
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Debug,
    Hash,
    Eq,
    PartialEq,
    TryFromReprToEnum,
    FromEnumToRepr,
)]
#[repr(u8)]
#[derive(Default)]
pub enum IdentityFlag {
    /// The auth content represents the blake160 hash of a secp256k1 public key.
    /// The lock script will perform secp256k1 signature verification, the same as the SECP256K1/blake160 lock.
    #[default]
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

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Default)]
pub struct Identity {
    /// Indicate what's auth content of auth_content will be.
    flag: IdentityFlag,
    /// The auth content of the identity.
    auth_content: H160,
}

impl Identity {
    /// Create a new identity.
    pub fn new(flag: IdentityFlag, auth_content: H160) -> Self {
        Identity { flag, auth_content }
    }

    /// Create a pubkey hash algorithm Identity
    /// # Arguments
    /// * `pubkey_hash` blake160 hash of a public key.
    pub fn new_pubkey_hash(pubkey_hash: H160) -> Self {
        Self::new(IdentityFlag::PubkeyHash, pubkey_hash)
    }

    /// Create a mulltisig Identity
    pub fn new_multisig(multisig_config: MultisigConfig) -> Self {
        let blake160 = multisig_config.hash160();
        Identity::new(IdentityFlag::Multisig, blake160)
    }
    /// Create an ethereum Identity omnilock with pubkey
    /// # Arguments
    /// * `pubkey_hash` keccak160 hash of public key
    pub fn new_ethereum(pubkey_hash: H160) -> Self {
        Self::new(IdentityFlag::Ethereum, pubkey_hash)
    }

    /// Create an ownerlock omnilock with according script hash.
    /// # Arguments
    /// * `script_hash` the proper blake160 hash of according ownerlock script.
    pub fn new_ownerlock(script_hash: H160) -> Self {
        Self::new(IdentityFlag::OwnerLock, script_hash)
    }

    /// convert the identify to smt_key.
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret[0] = self.flag as u8;
        ret[1..21].copy_from_slice(self.auth_content.as_ref());
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

    /// Parse the Identity from an u8 slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, String> {
        if slice.len() < 21 {
            return Err("Not enough bytes to parse".to_string());
        }
        let flag = IdentityFlag::try_from(slice[0])
            .map_err(|e| format!("can't parse {} to validate IdentityFlag.", e))?;
        let auth_content = H160::from_slice(&slice[1..21]).map_err(|e| e.to_string())?;
        Ok(Identity { flag, auth_content })
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
                &format!("can not convert the value to SmtProofEntryVec:　{}", e).as_str(),
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

/// The info cell internal data of the supply mode.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct InfoCellData {
    /// Current the version is 0, 1 byute
    pub version: u8,
    /// Only the current supply field can be updated during the transactions.16 bytes, little endian number
    pub current_supply: u128,
    /// The max supply limit.16 bytes, little endian number
    pub max_supply: u128,
    /// Type script hash. 32 bytes, sUDT type script hash
    pub sudt_script_hash: H256,
    /// Other data of variable length
    pub other_data: Vec<u8>,
}

impl InfoCellData {
    /// Create an InfoCellData with must exist fields.
    /// # Arguments
    /// * `current_supply` The current supply value
    /// * `max_supply` The max supply value.
    /// * `sudt_script_hash` The type script hash
    pub fn new_simple(current_supply: u128, max_supply: u128, sudt_script_hash: H256) -> Self {
        InfoCellData::new(current_supply, max_supply, sudt_script_hash, vec![])
    }

    /// Create an InfoCellData with all fields except `version` since it is 0 currently
    pub fn new(
        current_supply: u128,
        max_supply: u128,
        sudt_script_hash: H256,
        other_data: Vec<u8>,
    ) -> Self {
        InfoCellData {
            version: 0u8,
            current_supply,
            max_supply,
            sudt_script_hash,
            other_data,
        }
    }

    /// Pack the data into bytes for the cell storage.
    pub fn pack(&self) -> Bytes {
        let len = 65 + self.other_data.len();
        let mut bytes = BytesMut::with_capacity(len);
        bytes.put_u8(self.version);
        bytes.put_u128_le(self.current_supply);
        bytes.put_u128_le(self.max_supply);
        bytes.extend(self.sudt_script_hash.as_bytes());
        bytes.extend(&self.other_data);
        bytes.freeze()
    }
}

/// The administrator mode configuration.
#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Default)]
pub struct AdminConfig {
    /// The rc cell's type script hash, the type script should be a type id script.
    rc_type_id: H256,
    /// The smt proofs
    proofs: SmtProofEntryVec,
    /// The alternative auth content to the args part.
    auth: Identity,
    /// multisig cnfiguration
    multisig_config: Option<MultisigConfig>,
    /// If set the rce cell in the input
    rce_in_input: bool,
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

    /// set the additional auth, it will be used to sign the transaction.
    pub fn set_auth(&mut self, auth: Identity) {
        self.auth = auth;
    }

    /// return a reference to the auth content
    pub fn get_auth(&self) -> &Identity {
        &self.auth
    }

    /// return the content of the multisig config
    pub fn get_multisig_config(&self) -> Option<&MultisigConfig> {
        self.multisig_config.as_ref()
    }

    /// Set the config rce_in_input to the specified value
    pub fn set_rce_in_input(&mut self, value: bool) {
        self.rce_in_input = value;
    }

    /// Get the configuration about if smt is in the input list.
    pub fn rce_in_input(&self) -> bool {
        self.rce_in_input
    }

    pub fn new(
        rc_type_id: H256,
        proofs: SmtProofEntryVec,
        auth: Identity,
        multisig_config: Option<MultisigConfig>,
        rce_in_input: bool,
    ) -> AdminConfig {
        AdminConfig {
            rc_type_id,
            proofs,
            auth,
            multisig_config,
            rce_in_input,
        }
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("there is no admin configuration in the OmniLockConfig")]
    NoAdminConfig,

    #[error("there is no multisig config in the OmniLockConfig")]
    NoMultiSigConfig,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Default)]
pub struct OmniLockAcpConfig {
    /// Tthe minimal transfer amount will be 10^ckb_minimum, if ckb_minimum is 0, means no minimum is enforced on the transfer operation.
    pub ckb_minimum: u8,
    /// Tthe minimal transfer amount will be 10^udt_minimum, if udt_minimum is 0, means no minimum is enforced on the transfer operation.
    pub udt_minimum: u8,
}

impl OmniLockAcpConfig {
    pub fn new(ckb_minimum: u8, udt_minimum: u8) -> Self {
        OmniLockAcpConfig {
            ckb_minimum,
            udt_minimum,
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
    /// The acp configuration
    acp_config: Option<OmniLockAcpConfig>,
    /// 8 bytes since for time lock
    time_lock_config: Option<u64>,
    // 32 bytes type script hash
    info_cell: Option<H256>,
}

impl OmniLockConfig {
    /// Create a pubkey hash algorithm omnilock with proper argument
    /// # Arguments
    /// * `lock_arg` blake160 hash of a public key.
    pub fn new_pubkey_hash(lock_arg: H160) -> Self {
        Self::new(IdentityFlag::PubkeyHash, lock_arg)
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
            acp_config: None,
            time_lock_config: None,
            info_cell: None,
        }
    }
    /// Create an ethereum algorithm omnilock with pubkey
    ///
    /// # Arguments
    ///
    /// * `pubkey_hash` - a ehtereum address of an account.
    ///
    /// ```
    /// // pubkey is a public ethereum address
    /// use ckb_sdk::unlock::OmniLockConfig;
    /// use ckb_sdk::util::keccak160;
    /// use ckb_crypto::secp::Pubkey;
    ///
    /// let pubkey = Pubkey::from([0u8; 64]);
    /// let pubkey_hash = keccak160(pubkey.as_ref());
    /// let config = OmniLockConfig::new_ethereum(pubkey_hash);
    /// ```
    pub fn new_ethereum(pubkey_hash: H160) -> Self {
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
            acp_config: None,
            time_lock_config: None,
            info_cell: None,
        }
    }

    /// Set the admin cofiguration, and set the OmniLockFlags::ADMIN flag.
    /// # Arguments
    /// * `admin_config` The new admin config.
    pub fn set_admin_config(&mut self, admin_config: AdminConfig) {
        self.omni_lock_flags.set(OmniLockFlags::ADMIN, true);
        self.admin_config = Some(admin_config);
    }

    /// Remove the admin configuration, set it to `None`, and clear the OmniLockFlags::ADMIN flag.
    pub fn clear_admin_config(&mut self) {
        self.omni_lock_flags.set(OmniLockFlags::ADMIN, false);
        self.admin_config = None;
    }

    /// Set the acp configuration, and set the OmniLockFlags::ACP flag.
    pub fn set_acp_config(&mut self, acp_config: OmniLockAcpConfig) {
        self.omni_lock_flags.set(OmniLockFlags::ACP, true);
        self.acp_config = Some(acp_config);
    }

    /// Remove the acp config, set it to None, and clear the OmniLockFlags::ACP flag.
    pub fn clear_acp_config(&mut self) {
        self.omni_lock_flags.set(OmniLockFlags::ACP, false);
        self.acp_config = None;
    }
    /// Set the time lock config with raw since value, and set the OmniLockFlags::TIME_LOCK flag.
    pub fn set_time_lock_config(&mut self, since: u64) {
        self.omni_lock_flags.set(OmniLockFlags::TIME_LOCK, true);
        self.time_lock_config = Some(since);
    }
    /// Remove the time lock config, set it to None, and clear the OmniLockFlags::TIME_LOCK flag.
    pub fn clear_time_lock_config(&mut self) {
        self.omni_lock_flags.set(OmniLockFlags::TIME_LOCK, false);
        self.time_lock_config = None;
    }

    /// Set the info cell to the configuration, and set the OmniLockFlags::SUPPLY to omni_lock_flags.
    pub fn set_info_cell(&mut self, type_script_hash: H256) {
        self.omni_lock_flags.set(OmniLockFlags::SUPPLY, true);
        self.info_cell = Some(type_script_hash);
    }

    /// Clear the info cell to None, and clear OmniLockFlags::SUPPLY from omni_lock_flags.
    pub fn clear_info_cell(&mut self) {
        self.omni_lock_flags.set(OmniLockFlags::SUPPLY, false);
        self.info_cell = None;
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
        bytes.put(self.id.auth_content.as_ref());
        bytes.put_u8(self.omni_lock_flags.bits);

        if let Some(config) = self.admin_config.as_ref() {
            bytes.put(config.rc_type_id.as_bytes());
        }
        if let Some(config) = self.acp_config.as_ref() {
            bytes.put_u8(config.ckb_minimum);
            bytes.put_u8(config.udt_minimum);
        }
        if let Some(since) = self.time_lock_config.as_ref() {
            bytes.extend(since.to_le_bytes().iter());
        }

        if let Some(info_cell) = self.info_cell.as_ref() {
            bytes.extend(info_cell.as_bytes());
        }
        bytes.freeze()
    }

    /// return the internal reference of admin_config
    pub fn get_admin_config(&self) -> Option<&AdminConfig> {
        self.admin_config.as_ref()
    }

    pub fn get_info_cell(&self) -> Option<&H256> {
        self.info_cell.as_ref()
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

    /// Get the since source from args.
    pub fn get_since_source(&self) -> SinceSource {
        if self.omni_lock_flags.contains(OmniLockFlags::TIME_LOCK) {
            let mut offset = 22;
            if self.omni_lock_flags.contains(OmniLockFlags::ADMIN) {
                offset += 32;
            }
            if self.omni_lock_flags.contains(OmniLockFlags::ACP) {
                offset += 2;
            }
            SinceSource::LockArgs(offset)
        } else {
            SinceSource::Value(0)
        }
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

    pub fn placeholder_witness_lock(
        &self,
        unlock_mode: OmniUnlockMode,
    ) -> Result<Bytes, ConfigError> {
        let mut builder = match self.id.flag {
            IdentityFlag::PubkeyHash | IdentityFlag::Ethereum => OmniLockWitnessLock::new_builder()
                .signature(Some(Bytes::from(vec![0u8; 65])).pack()),
            IdentityFlag::Multisig => {
                let multisig_config = match unlock_mode {
                    OmniUnlockMode::Admin => self
                        .admin_config
                        .as_ref()
                        .ok_or(ConfigError::NoAdminConfig)?
                        .multisig_config
                        .as_ref()
                        .ok_or(ConfigError::NoMultiSigConfig)?,
                    OmniUnlockMode::Normal => self
                        .multisig_config
                        .as_ref()
                        .ok_or(ConfigError::NoMultiSigConfig)?,
                };
                let config_data = multisig_config.to_witness_data();
                let multisig_len = config_data.len() + multisig_config.threshold() as usize * 65;
                let mut omni_sig = vec![0u8; multisig_len];
                omni_sig[..config_data.len()].copy_from_slice(&config_data);
                OmniLockWitnessLock::new_builder().signature(Some(Bytes::from(omni_sig)).pack())
            }
            IdentityFlag::OwnerLock => OmniLockWitnessLock::new_builder(),
            _ => todo!("to support other placeholder_witness_lock implementions"),
        };

        if unlock_mode == OmniUnlockMode::Admin {
            if let Some(config) = self.admin_config.as_ref() {
                let mut temp = [0u8; 21];
                temp[0] = config.auth.flag as u8;
                temp[1..21].copy_from_slice(config.auth.auth_content.as_bytes());
                let auth = Auth::from_slice(&temp).unwrap();
                let ident = IdentityType::new_builder()
                    .identity(auth)
                    .proofs(config.proofs.clone())
                    .build();

                let ident_opt = IdentityOpt::new_builder().set(Some(ident)).build();
                builder = builder.omni_identity(ident_opt);
            } else {
                return Err(ConfigError::NoAdminConfig);
            }
        }
        Ok(builder.build().as_bytes())
    }

    /// Build zero lock content for signature
    pub fn zero_lock(&self, unlock_mode: OmniUnlockMode) -> Result<Bytes, ConfigError> {
        let len = self.placeholder_witness_lock(unlock_mode)?.len();
        Ok(Bytes::from(vec![0u8; len]))
    }

    /// Create a zero lock witness placeholder
    pub fn placeholder_witness(
        &self,
        unlock_mode: OmniUnlockMode,
    ) -> Result<WitnessArgs, ConfigError> {
        match self.id.flag {
            IdentityFlag::PubkeyHash | IdentityFlag::Ethereum | IdentityFlag::Multisig => {
                let lock = self.placeholder_witness_lock(unlock_mode)?;
                Ok(WitnessArgs::new_builder().lock(Some(lock).pack()).build())
            }
            IdentityFlag::OwnerLock => {
                if self.admin_config.is_some() {
                    let lock = self.placeholder_witness_lock(unlock_mode)?;
                    Ok(WitnessArgs::new_builder().lock(Some(lock).pack()).build())
                } else {
                    Ok(WitnessArgs::default())
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
            ..Default::default()
        };
        let x = serde_json::to_string_pretty(&cfg).unwrap();
        let cfg2: AdminConfig = serde_json::from_str(&x).unwrap();
        assert_eq!(cfg, cfg2);
    }
}
#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_config_error() {
        let error = super::ConfigError::NoAdminConfig;
        let error = anyhow!(error);
        assert_eq!(
            "there is no admin configuration in the OmniLockConfig",
            error.to_string()
        );
    }
}
