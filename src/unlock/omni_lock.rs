use std::fmt::Display;

use crate::{
    constants::OMNILOCK_TYPE_HASH,
    traits::{Signer, TransactionDependencyProvider},
    types::{omni_lock::OmniLockWitnessLock, AddressPayload},
    ScriptGroup,
};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{ScriptHashType, TransactionView},
    packed::{self, WitnessArgs},
    prelude::*,
};

use ckb_crypto::secp::Pubkey;
pub use ckb_types::prelude::Pack;
use serde::{Deserialize, Serialize};

use super::{
    fill_witness_lock, generate_message, ScriptSignError, ScriptSigner, ScriptUnlocker, UnlockError,
};
pub const IDENTITY_FLAGS_PUBKEY_HASH: u8 = 0;

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub flags: u8,
    pub blake160: Bytes,
}
impl Identity {
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret: [u8; 32] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }
}

impl From<Identity> for [u8; 21] {
    fn from(id: Identity) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flags;
        res[1..].copy_from_slice(&id.blake160);
        res
    }
}

impl From<Identity> for Vec<u8> {
    fn from(id: Identity) -> Self {
        let mut bytes = vec![id.flags];
        bytes.extend(id.blake160.clone());
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
    pub fn new_pubkey_hash(pubkey: &Pubkey) -> Self {
        Self::new(IDENTITY_FLAGS_PUBKEY_HASH, pubkey)
    }

    pub fn new(flags: u8, pubkey: &Pubkey) -> Self {
        let pubkey_hash = blake160(&pubkey.serialize());
        let blake160 = if flags == IDENTITY_FLAGS_PUBKEY_HASH {
            pubkey_hash
        } else {
            Bytes::from(&[0; 20][..])
        };

        OmniLockConfig {
            id: Identity { flags, blake160 },
            omni_lock_flags: 0,
        }
    }

    pub fn build_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);

        // auth
        bytes.put_u8(self.id.flags);
        bytes.put(self.id.blake160.as_ref());
        bytes.put_u8(self.omni_lock_flags);

        bytes.freeze()
    }

    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_PUBKEY_HASH
    }

    pub fn to_address_payload(&self) -> AddressPayload {
        let args = self.build_args();
        AddressPayload::new_full(ScriptHashType::Type, OMNILOCK_TYPE_HASH.pack(), args)
    }

    pub fn zero_lock(&self) -> Bytes {
        if self.is_pubkey_hash() {
            let len = OmniLockWitnessLock::new_builder()
                .signature(Some(Bytes::from(vec![0u8; 65])).pack())
                .build()
                .as_bytes().len();

            Bytes::from(vec![0u8; len])
        } else {
            unreachable!("should not reach here");
        }
    }

    pub fn placeholder_witness(&self) -> WitnessArgs {
        if self.is_pubkey_hash() {
            let zero_lock = self.zero_lock();
            WitnessArgs::new_builder()
                .lock(Some(zero_lock).pack())
                .build()
        } else {
            unreachable!("should not reach here");
        }
    }

    pub fn build_witness_lock(signature: Bytes) -> Bytes {
        OmniLockWitnessLock::new_builder()
            .signature(Some(signature).pack())
            .build()
            .as_bytes()
    }
}

pub fn blake160(message: &[u8]) -> Bytes {
    let r = ckb_hash::blake2b_256(message);
    Bytes::copy_from_slice(&r[..20])
}

pub struct OmniLockScriptSigner {
    signer: Box<dyn Signer>,
    config: OmniLockConfig,
}

impl OmniLockScriptSigner {
    pub fn new(signer: Box<dyn Signer>, config: OmniLockConfig) -> OmniLockScriptSigner {
        OmniLockScriptSigner { signer, config }
    }
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }
    pub fn config(&self) -> &OmniLockConfig {
        &self.config
    }
}

impl ScriptSigner for OmniLockScriptSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        if !(args.len() == 22 && args[0] == self.config.id.flags) {
            return false;
        }
        if self.config.id.flags == IDENTITY_FLAGS_PUBKEY_HASH {
            self.signer.match_id(self.config.id.blake160.as_ref())
        } else {
            false
        }
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        if self.config.is_pubkey_hash() {
            let witness_idx = script_group.input_indices[0];
            let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
            while witnesses.len() <= witness_idx {
                witnesses.push(Default::default());
            }
            let tx_new = tx
                .as_advanced_builder()
                .set_witnesses(witnesses.clone())
                .build();

            let zero_lock = self.config.zero_lock();
            let message = generate_message(&tx_new, script_group, zero_lock)?;

            let signature =
                self.signer
                    .sign(self.config.id.blake160.as_ref(), message.as_ref(), true, tx)?;

            let signature = OmniLockConfig::build_witness_lock(signature);
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
        } else {
            unreachable!("not supported, should not reach here!");
        }
    }
}

pub struct OmniLockUnlocker {
    signer: OmniLockScriptSigner,
}
impl OmniLockUnlocker {
    pub fn new(signer: OmniLockScriptSigner) -> OmniLockUnlocker {
        OmniLockUnlocker { signer }
    }
}
impl From<(Box<dyn Signer>, OmniLockConfig)> for OmniLockUnlocker {
    fn from((signer, config): (Box<dyn Signer>, OmniLockConfig)) -> OmniLockUnlocker {
        OmniLockUnlocker::new(OmniLockScriptSigner::new(signer, config))
    }
}
impl ScriptUnlocker for OmniLockUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        args.len() == 22 && self.signer.match_args(args)
    }

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group)?)
    }

    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        let config = self.signer.config();
        let zero_lock = config.zero_lock();
        fill_witness_lock(tx, script_group, zero_lock)
    }
}
