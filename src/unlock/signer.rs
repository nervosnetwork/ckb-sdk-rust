use std::collections::HashSet;

use anyhow::anyhow;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_types::{
    bytes::{Bytes, BytesMut},
    core::{ScriptHashType, TransactionView},
    error::VerificationError,
    packed::{self, BytesOpt, Script, WitnessArgs},
    prelude::*,
    H160,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{constants::MULTISIG_TYPE_HASH, types::omni_lock::OmniLockWitnessLock};
use crate::{
    traits::{Signer, SignerError},
    util::convert_keccak256_hash,
};
use crate::{
    types::{AddressPayload, CodeHashIndex, ScriptGroup, Since},
    Address, NetworkType,
};

use super::{
    omni_lock::{ConfigError, Identity},
    IdentityFlag, OmniLockConfig,
};

#[derive(Error, Debug)]
pub enum ScriptSignError {
    #[error("signer error: `{0}`")]
    Signer(#[from] SignerError),

    #[error("witness count in current transaction not enough to cover current script group")]
    WitnessNotEnough,

    #[error("the witness is not empty and not WitnessArgs format: `{0}`")]
    InvalidWitnessArgs(#[from] VerificationError),

    #[error("the Omni lock witness lock field is invalid: `{0}`")]
    InvalidOmniLockWitnessLock(String),

    #[error("invalid multisig config: `{0}`")]
    InvalidMultisigConfig(String),

    #[error("there already too many signatures in current WitnessArgs.lock field (old_count + new_count > threshold)")]
    TooManySignatures,

    #[error("there is an configuration error: `{0}`")]
    InvalidConfig(#[from] ConfigError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Script signer logic:
///   * Generate message to sign
///   * Sign the message by wallet
///   * Put the signature into tx.witnesses
pub trait ScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool;

    /// Add signature information to witnesses
    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError>;
}

/// Signer for secp256k1 sighash all lock script
pub struct SecpSighashScriptSigner {
    // Can be: SecpCkbRawKeySigner, HardwareWalletSigner
    signer: Box<dyn Signer>,
}

impl SecpSighashScriptSigner {
    pub fn new(signer: Box<dyn Signer>) -> SecpSighashScriptSigner {
        SecpSighashScriptSigner { signer }
    }

    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    fn sign_tx_with_owner_id(
        &self,
        owner_id: &[u8],
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        let tx_new = tx
            .as_advanced_builder()
            .set_witnesses(witnesses.clone())
            .build();

        let zero_lock = Bytes::from(vec![0u8; 65]);
        let message = generate_message(&tx_new, script_group, zero_lock)?;

        let signature = self.signer.sign(owner_id, message.as_ref(), true)?;

        // Put signature into witness
        let witness_data = witnesses[witness_idx].raw_data();
        let mut current_witness: WitnessArgs = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };
        current_witness = current_witness
            .as_builder()
            .lock(Some(signature).pack())
            .build();
        witnesses[witness_idx] = current_witness.as_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }
}

impl ScriptSigner for SecpSighashScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        args.len() == 20 && self.signer.match_id(args)
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let args = script_group.script.args().raw_data();
        self.sign_tx_with_owner_id(args.as_ref(), tx, script_group)
    }
}

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize, Debug)]
pub struct MultisigConfig {
    sighash_addresses: Vec<H160>,
    require_first_n: u8,
    threshold: u8,
}
impl MultisigConfig {
    pub fn new_with(
        sighash_addresses: Vec<H160>,
        require_first_n: u8,
        threshold: u8,
    ) -> Result<MultisigConfig, ScriptSignError> {
        let mut addr_set: HashSet<&H160> = HashSet::default();
        for addr in &sighash_addresses {
            if !addr_set.insert(addr) {
                return Err(ScriptSignError::InvalidMultisigConfig(format!(
                    "Duplicated address: {:?}",
                    addr
                )));
            }
        }
        if threshold as usize > sighash_addresses.len() {
            return Err(ScriptSignError::InvalidMultisigConfig(format!(
                "Invalid threshold {} > {}",
                threshold,
                sighash_addresses.len()
            )));
        }
        if require_first_n > threshold {
            return Err(ScriptSignError::InvalidMultisigConfig(format!(
                "Invalid require-first-n {} > {}",
                require_first_n, threshold
            )));
        }
        Ok(MultisigConfig {
            sighash_addresses,
            require_first_n,
            threshold,
        })
    }

    pub fn contains_address(&self, target: &H160) -> bool {
        self.sighash_addresses
            .iter()
            .any(|payload| payload == target)
    }
    pub fn sighash_addresses(&self) -> &Vec<H160> {
        &self.sighash_addresses
    }
    pub fn require_first_n(&self) -> u8 {
        self.require_first_n
    }
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn hash160(&self) -> H160 {
        let witness_data = self.to_witness_data();
        let params_hash = blake2b_256(witness_data);
        H160::from_slice(&params_hash[0..20]).unwrap()
    }

    pub fn to_address_payload(&self, since_absolute_epoch: Option<u64>) -> AddressPayload {
        let hash160 = self.hash160();
        if let Some(absolute_epoch_number) = since_absolute_epoch {
            let since_value = Since::new_absolute_epoch(absolute_epoch_number).value();
            let mut args = BytesMut::from(hash160.as_bytes());
            args.extend_from_slice(&since_value.to_le_bytes()[..]);
            AddressPayload::new_full(
                ScriptHashType::Type,
                MULTISIG_TYPE_HASH.pack(),
                args.freeze(),
            )
        } else {
            AddressPayload::new_short(CodeHashIndex::Multisig, hash160)
        }
    }

    pub fn to_witness_data(&self) -> Vec<u8> {
        let reserved_byte = 0u8;
        let mut witness_data = vec![
            reserved_byte,
            self.require_first_n,
            self.threshold,
            self.sighash_addresses.len() as u8,
        ];
        for sighash_address in &self.sighash_addresses {
            witness_data.extend_from_slice(sighash_address.as_bytes());
        }
        witness_data
    }

    pub fn placeholder_witness(&self) -> WitnessArgs {
        let config_data = self.to_witness_data();
        let mut zero_lock = vec![0u8; config_data.len() + 65 * self.threshold() as usize];
        zero_lock[0..config_data.len()].copy_from_slice(config_data.as_ref());
        WitnessArgs::new_builder()
            .lock(Some(Bytes::from(zero_lock)).pack())
            .build()
    }

    pub fn to_address(&self, network: NetworkType, since_absolute_epoch: Option<u64>) -> Address {
        let payload = self.to_address_payload(since_absolute_epoch);
        Address::new(network, payload, true)
    }
}

impl From<&MultisigConfig> for Script {
    fn from(value: &MultisigConfig) -> Self {
        Script::new_builder()
            .code_hash(MULTISIG_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(value.hash160().as_bytes().to_vec()).pack())
            .build()
    }
}

/// Signer for secp256k1 multisig all lock script
pub struct SecpMultisigScriptSigner {
    // Can be: SecpCkbRawKeySigner, HardwareWalletSigner
    signer: Box<dyn Signer>,
    config: MultisigConfig,
    config_hash: [u8; 32],
}
impl SecpMultisigScriptSigner {
    pub fn new(signer: Box<dyn Signer>, config: MultisigConfig) -> SecpMultisigScriptSigner {
        let config_hash = blake2b_256(config.to_witness_data());
        SecpMultisigScriptSigner {
            signer,
            config,
            config_hash,
        }
    }
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }
    pub fn config(&self) -> &MultisigConfig {
        &self.config
    }
}

impl ScriptSigner for SecpMultisigScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        self.config_hash[0..20] == args[0..20]
            && self
                .config
                .sighash_addresses
                .iter()
                .any(|id| self.signer.match_id(id.as_bytes()))
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        let tx_new = tx
            .as_advanced_builder()
            .set_witnesses(witnesses.clone())
            .build();

        let config_data = self.config.to_witness_data();
        let mut zero_lock = vec![0u8; config_data.len() + 65 * (self.config.threshold as usize)];
        zero_lock[0..config_data.len()].copy_from_slice(&config_data);
        let message = generate_message(&tx_new, script_group, Bytes::from(zero_lock.clone()))?;

        let signatures = self
            .config
            .sighash_addresses
            .iter()
            .filter(|id| self.signer.match_id(id.as_bytes()))
            .map(|id| self.signer.sign(id.as_bytes(), message.as_ref(), true))
            .collect::<Result<Vec<_>, SignerError>>()?;
        // Put signature into witness
        let witness_idx = script_group.input_indices[0];
        let witness_data = witnesses[witness_idx].raw_data();
        let mut current_witness: WitnessArgs = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };
        let mut lock_field = current_witness
            .lock()
            .to_opt()
            .map(|data| data.raw_data().as_ref().to_vec())
            .unwrap_or(zero_lock);
        if lock_field.len() != config_data.len() + self.config.threshold() as usize * 65 {
            return Err(ScriptSignError::Other(anyhow!(
                "invalid witness lock field length: {}, expected: {}",
                lock_field.len(),
                config_data.len() + self.config.threshold() as usize * 65,
            )));
        }
        for signature in signatures {
            let mut idx = config_data.len();
            while idx < lock_field.len() {
                // Put signature into an empty place.
                if lock_field[idx..idx + 65] == signature {
                    break;
                } else if lock_field[idx..idx + 65] == [0u8; 65] {
                    lock_field[idx..idx + 65].copy_from_slice(signature.as_ref());
                    break;
                }
                idx += 65;
            }
            if idx >= lock_field.len() {
                return Err(ScriptSignError::TooManySignatures);
            }
        }

        current_witness = current_witness
            .as_builder()
            .lock(Some(Bytes::from(lock_field)).pack())
            .build();
        witnesses[witness_idx] = current_witness.as_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }
}

pub struct AcpScriptSigner {
    sighash_signer: SecpSighashScriptSigner,
}

impl AcpScriptSigner {
    pub fn new(signer: Box<dyn Signer>) -> AcpScriptSigner {
        let sighash_signer = SecpSighashScriptSigner::new(signer);
        AcpScriptSigner { sighash_signer }
    }
}

impl ScriptSigner for AcpScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        args.len() >= 20 && args.len() <= 22 && {
            let id = &args[0..20];
            self.sighash_signer.signer().match_id(id)
        }
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let args = script_group.script.args().raw_data();
        let id = &args[0..20];
        self.sighash_signer
            .sign_tx_with_owner_id(id, tx, script_group)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ChequeAction {
    Claim,
    Withdraw,
}
pub struct ChequeScriptSigner {
    sighash_signer: SecpSighashScriptSigner,
    action: ChequeAction,
}
impl ChequeScriptSigner {
    pub fn new(signer: Box<dyn Signer>, action: ChequeAction) -> ChequeScriptSigner {
        let sighash_signer = SecpSighashScriptSigner::new(signer);
        ChequeScriptSigner {
            sighash_signer,
            action,
        }
    }
    pub fn owner_id<'t>(&self, args: &'t [u8]) -> &'t [u8] {
        if args.len() != 40 {
            &args[0..0]
        } else if self.action == ChequeAction::Claim {
            &args[0..20]
        } else {
            &args[20..40]
        }
    }
    pub fn action(&self) -> ChequeAction {
        self.action
    }
}

impl ScriptSigner for ChequeScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        // NOTE: Require signer raw key map as: {script_hash[0..20] -> private key}
        args.len() == 40 && self.sighash_signer.signer().match_id(self.owner_id(args))
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let args = script_group.script.args().raw_data();
        let id = self.owner_id(args.as_ref());
        self.sighash_signer
            .sign_tx_with_owner_id(id, tx, script_group)
    }
}

/// Common logic of generate message for certain script group. Overwrite
/// this method to support special use case.
pub fn generate_message(
    tx: &TransactionView,
    script_group: &ScriptGroup,
    zero_lock: Bytes,
) -> Result<Bytes, ScriptSignError> {
    if tx.witnesses().item_count() <= script_group.input_indices[0] {
        return Err(ScriptSignError::WitnessNotEnough);
    }

    let witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    let witness_data = witnesses[script_group.input_indices[0]].raw_data();
    let mut init_witness = if witness_data.is_empty() {
        WitnessArgs::default()
    } else {
        WitnessArgs::from_slice(witness_data.as_ref())?
    };
    init_witness = init_witness
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    // Other witnesses in current script group
    let other_witnesses: Vec<([u8; 8], Bytes)> = script_group
        .input_indices
        .iter()
        .skip(1)
        .filter_map(|idx| witnesses.get(*idx))
        .map(|witness| {
            (
                (witness.item_count() as u64).to_le_bytes(),
                witness.raw_data(),
            )
        })
        .collect();
    // The witnesses not covered by any inputs
    let outter_witnesses: Vec<([u8; 8], Bytes)> = if tx.inputs().len() < witnesses.len() {
        witnesses[tx.inputs().len()..witnesses.len()]
            .iter()
            .map(|witness| {
                (
                    (witness.item_count() as u64).to_le_bytes(),
                    witness.raw_data(),
                )
            })
            .collect()
    } else {
        Default::default()
    };

    let mut blake2b = new_blake2b();
    blake2b.update(tx.hash().as_slice());
    blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
    blake2b.update(&init_witness.as_bytes());
    for (len_le, data) in other_witnesses {
        blake2b.update(&len_le);
        blake2b.update(&data);
    }
    for (len_le, data) in outter_witnesses {
        blake2b.update(&len_le);
        blake2b.update(&data);
    }
    let mut message = vec![0u8; 32];
    blake2b.finalize(&mut message);
    Ok(Bytes::from(message))
}

/// specify the unlock mode for a omnilock transaction.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash, Default)]
pub enum OmniUnlockMode {
    /// Use the normal mode to unlock the omnilock transaction.
    #[default]
    Normal = 1,
    /// Use the admin mode to unlock the omnilock transaction.
    Admin = 2,
}

pub struct OmniLockScriptSigner {
    signer: Box<dyn Signer>,
    config: OmniLockConfig,
    unlock_mode: OmniUnlockMode,
}

impl OmniLockScriptSigner {
    pub fn new(
        signer: Box<dyn Signer>,
        config: OmniLockConfig,
        unlock_mode: OmniUnlockMode,
    ) -> OmniLockScriptSigner {
        OmniLockScriptSigner {
            signer,
            config,
            unlock_mode,
        }
    }
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }
    pub fn config(&self) -> &OmniLockConfig {
        &self.config
    }
    /// return the unlock mode
    pub fn unlock_mode(&self) -> OmniUnlockMode {
        self.unlock_mode
    }

    fn sign_multisig_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        let tx_new = tx
            .as_advanced_builder()
            .set_witnesses(witnesses.clone())
            .build();

        let zero_lock = self.config.zero_lock(self.unlock_mode)?;
        let zero_lock_len = zero_lock.len();
        let message = generate_message(&tx_new, script_group, zero_lock)?;

        let multisig_config = match self.unlock_mode {
            OmniUnlockMode::Admin => self
                .config
                .get_admin_config()
                .ok_or(ConfigError::NoAdminConfig)?
                .get_multisig_config(),
            OmniUnlockMode::Normal => self.config.multisig_config(),
        }
        .ok_or(ConfigError::NoMultiSigConfig)?;
        let signatures = multisig_config
            .sighash_addresses
            .iter()
            .filter(|id| self.signer.match_id(id.as_bytes()))
            .map(|id| self.signer.sign(id.as_bytes(), message.as_ref(), true))
            .collect::<Result<Vec<_>, SignerError>>()?;
        // Put signature into witness
        let witness_idx = script_group.input_indices[0];
        let witness_data = witnesses[witness_idx].raw_data();
        let mut current_witness: WitnessArgs = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };
        let lock_field = current_witness.lock().to_opt().map(|data| data.raw_data());
        let omnilock_witnesslock = if let Some(lock_field) = lock_field {
            if lock_field.len() != zero_lock_len {
                return Err(ScriptSignError::Other(anyhow!(
                    "invalid witness lock field length: {}, expected: {}",
                    lock_field.len(),
                    zero_lock_len,
                )));
            }
            OmniLockWitnessLock::from_slice(lock_field.as_ref())?
        } else {
            OmniLockWitnessLock::default()
        };
        let config_data = multisig_config.to_witness_data();
        let mut omni_sig = omnilock_witnesslock
            .signature()
            .to_opt()
            .map(|data| data.raw_data().as_ref().to_vec())
            .unwrap_or_else(|| {
                let mut omni_sig =
                    vec![0u8; config_data.len() + multisig_config.threshold() as usize * 65];
                omni_sig[..config_data.len()].copy_from_slice(&config_data);
                omni_sig
            });
        for signature in signatures {
            let mut idx = config_data.len();
            while idx < omni_sig.len() {
                // Put signature into an empty place.
                if omni_sig[idx..idx + 65] == signature {
                    break;
                } else if omni_sig[idx..idx + 65] == [0u8; 65] {
                    omni_sig[idx..idx + 65].copy_from_slice(signature.as_ref());
                    break;
                }
                idx += 65;
            }
            if idx >= omni_sig.len() {
                return Err(ScriptSignError::TooManySignatures);
            }
        }
        let lock = omnilock_witnesslock
            .as_builder()
            .signature(Some(Bytes::from(omni_sig)).pack())
            .build()
            .as_bytes();

        current_witness = current_witness.as_builder().lock(Some(lock).pack()).build();
        witnesses[witness_idx] = current_witness.as_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }

    fn sign_ethereum_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        id: &Identity,
    ) -> Result<TransactionView, ScriptSignError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        let tx_new = tx
            .as_advanced_builder()
            .set_witnesses(witnesses.clone())
            .build();

        let zero_lock = self.config.zero_lock(self.unlock_mode())?;
        let message = generate_message(&tx_new, script_group, zero_lock)?;
        let message = convert_keccak256_hash(message.as_ref());

        let signature = self
            .signer
            .sign(id.auth_content().as_ref(), message.as_ref(), true)?;

        // Put signature into witness
        let witness_data = witnesses[witness_idx].raw_data();
        let mut current_witness: WitnessArgs = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };

        let lock = Self::build_witness_lock(current_witness.lock(), signature)?;
        current_witness = current_witness.as_builder().lock(Some(lock).pack()).build();
        witnesses[witness_idx] = current_witness.as_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }

    /// Build proper witness lock
    pub fn build_witness_lock(
        orig_lock: BytesOpt,
        signature: Bytes,
    ) -> Result<Bytes, ScriptSignError> {
        let lock_field = orig_lock.to_opt().map(|data| data.raw_data());
        let omnilock_witnesslock = if let Some(lock_field) = lock_field {
            OmniLockWitnessLock::from_slice(lock_field.as_ref())?
        } else {
            OmniLockWitnessLock::default()
        };

        Ok(omnilock_witnesslock
            .as_builder()
            .signature(Some(signature).pack())
            .build()
            .as_bytes())
    }
}

impl ScriptSigner for OmniLockScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        if args.len() != self.config.get_args_len() {
            return false;
        }

        if self.unlock_mode == OmniUnlockMode::Admin {
            if let Some(admin_config) = self.config.get_admin_config() {
                if args.len() < 54 {
                    return false;
                }
                // Check if the args match the rc_type_id in the admin_config
                if admin_config.rc_type_id().as_bytes() != &args[22..54] {
                    return false;
                }
                if let Some(multisig_cfg) = admin_config.get_multisig_config() {
                    return multisig_cfg
                        .sighash_addresses
                        .iter()
                        .any(|id| self.signer.match_id(id.as_bytes()));
                } else {
                    return self
                        .signer
                        .match_id(admin_config.get_auth().auth_content().as_bytes());
                }
            }
            return false;
        }
        if self.config.id().flag() as u8 != args[0] {
            return false;
        }
        match self.config.id().flag() {
            IdentityFlag::PubkeyHash | IdentityFlag::Ethereum => self
                .signer
                .match_id(self.config.id().auth_content().as_ref()),
            IdentityFlag::Multisig => {
                self.config.id().auth_content().as_ref() == &args[1..21]
                    && self
                        .config
                        .multisig_config()
                        .unwrap()
                        .sighash_addresses
                        .iter()
                        .any(|id| self.signer.match_id(id.as_bytes()))
            }

            IdentityFlag::OwnerLock => {
                // should not reach here, return true for compatible reason
                true
            }
            _ => todo!("other auth type not supported yet"),
        }
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let id = match self.unlock_mode {
            OmniUnlockMode::Admin => self
                .config
                .get_admin_config()
                .ok_or(ConfigError::NoAdminConfig)?
                .get_auth()
                .clone(),
            OmniUnlockMode::Normal => self.config.id().clone(),
        };
        match id.flag() {
            IdentityFlag::PubkeyHash => {
                let witness_idx = script_group.input_indices[0];
                let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
                while witnesses.len() <= witness_idx {
                    witnesses.push(Default::default());
                }
                let tx_new = tx
                    .as_advanced_builder()
                    .set_witnesses(witnesses.clone())
                    .build();

                let zero_lock = self.config.zero_lock(self.unlock_mode)?;
                let message = generate_message(&tx_new, script_group, zero_lock)?;

                let signature =
                    self.signer
                        .sign(id.auth_content().as_ref(), message.as_ref(), true)?;

                // Put signature into witness
                let witness_data = witnesses[witness_idx].raw_data();
                let mut current_witness: WitnessArgs = if witness_data.is_empty() {
                    WitnessArgs::default()
                } else {
                    WitnessArgs::from_slice(witness_data.as_ref())?
                };

                let lock = Self::build_witness_lock(current_witness.lock(), signature)?;

                current_witness = current_witness.as_builder().lock(Some(lock).pack()).build();
                witnesses[witness_idx] = current_witness.as_bytes().pack();
                Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
            }
            IdentityFlag::Ethereum => self.sign_ethereum_tx(tx, script_group, &id),
            IdentityFlag::Multisig => self.sign_multisig_tx(tx, script_group),
            IdentityFlag::OwnerLock => {
                // should not reach here, just return a clone for compatible reason.
                Ok(tx.clone())
            }
            _ => {
                todo!("not supported yet");
            }
        }
    }
}

#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_script_sign_error() {
        let error = anyhow!(super::ScriptSignError::WitnessNotEnough);
        assert_eq!(
            "witness count in current transaction not enough to cover current script group",
            error.to_string()
        );
    }
}
