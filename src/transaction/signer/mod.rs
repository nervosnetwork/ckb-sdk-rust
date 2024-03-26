use ckb_types::{core, H256};
use std::collections::HashMap;

use crate::{
    constants,
    unlock::{MultisigConfig, OmniLockConfig, UnlockError},
    NetworkInfo, NetworkType, ScriptGroup, ScriptId, TransactionWithScriptGroups,
};

use self::sighash::Secp256k1Blake160SighashAllSigner;

use super::handler::Type2Any;

pub mod multisig;
pub mod omnilock;
pub mod sighash;

pub trait CKBScriptSigner {
    fn match_context(&self, context: &dyn SignContext) -> bool;
    fn sign_transaction(
        &self,
        tx_view: &core::TransactionView,
        script_group: &ScriptGroup,
        context: &dyn SignContext,
    ) -> Result<core::TransactionView, UnlockError>;
}

pub trait SignContext: Type2Any {}

pub struct SignContexts {
    pub contexts: Vec<Box<dyn SignContext>>,
}

impl SignContexts {
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    pub fn new_sighash(keys: Vec<secp256k1::SecretKey>) -> Self {
        let sighash_context = sighash::Secp256k1Blake160SighashAllSignerContext::new(keys);
        Self {
            contexts: vec![Box::new(sighash_context)],
        }
    }

    pub fn new_sighash_h256(keys: Vec<H256>) -> Result<Self, secp256k1::Error> {
        let keys = keys
            .into_iter()
            .map(|key| secp256k1::SecretKey::from_slice(key.as_bytes()))
            .collect::<Result<Vec<_>, secp256k1::Error>>()?;
        let sighash_context = sighash::Secp256k1Blake160SighashAllSignerContext::new(keys);
        Ok(Self {
            contexts: vec![Box::new(sighash_context)],
        })
    }

    pub fn new_multisig(key: secp256k1::SecretKey, multisig_config: MultisigConfig) -> Self {
        let multisig_context =
            multisig::Secp256k1Blake160MultisigAllSignerContext::new(vec![key], multisig_config);
        Self {
            contexts: vec![Box::new(multisig_context)],
        }
    }

    pub fn new_multisig_h256(
        key: &H256,
        multisig_config: MultisigConfig,
    ) -> Result<Self, secp256k1::Error> {
        let key = secp256k1::SecretKey::from_slice(key.as_bytes())?;
        Ok(Self::new_multisig(key, multisig_config))
    }

    pub fn new_omnilock(keys: Vec<secp256k1::SecretKey>, omnilock_config: OmniLockConfig) -> Self {
        let omnilock_context = omnilock::OmnilockSignerContext::new(keys, omnilock_config);
        Self {
            contexts: vec![Box::new(omnilock_context)],
        }
    }

    #[inline]
    pub fn add_context(&mut self, context: Box<dyn SignContext>) {
        self.contexts.push(context);
    }
}

pub struct TransactionSigner {
    unlockers: HashMap<ScriptId, Box<dyn CKBScriptSigner>>,
}

impl TransactionSigner {
    pub fn new(network: &NetworkInfo) -> Self {
        let mut unlockers = HashMap::default();

        let sighash_script_id = ScriptId::new_type(constants::SIGHASH_TYPE_HASH.clone());
        unlockers.insert(
            sighash_script_id,
            Box::new(Secp256k1Blake160SighashAllSigner {}) as Box<_>,
        );

        unlockers.insert(
            ScriptId::new_type(constants::MULTISIG_TYPE_HASH.clone()),
            Box::new(multisig::Secp256k1Blake160MultisigAllSigner {}) as Box<_>,
        );

        match network.network_type {
            NetworkType::Mainnet => unlockers.insert(
                crate::transaction::handler::omnilock::MAINNET_OMNILOCK_SCRIPT_ID.clone(),
                Box::new(omnilock::OmnilockSigner {}) as Box<_>,
            ),
            NetworkType::Testnet => unlockers.insert(
                crate::transaction::handler::omnilock::get_testnet_omnilock_script_id().clone(),
                Box::new(omnilock::OmnilockSigner {}) as Box<_>,
            ),
            _ => unreachable!(),
        };

        Self { unlockers }
    }

    pub fn sign_transaction(
        &self,
        transaction: &mut TransactionWithScriptGroups,
        contexts: &SignContexts,
    ) -> Result<Vec<usize>, UnlockError> {
        let mut signed_groups_indices = vec![];
        if contexts.is_empty() {
            return Ok(signed_groups_indices);
        }
        let mut tx = transaction.get_tx_view().clone();
        for (idx, script_group) in transaction.get_script_groups().iter().enumerate() {
            let script_id = ScriptId::from(&script_group.script);
            if let Some(unlocker) = self.unlockers.get(&script_id) {
                for context in &contexts.contexts {
                    if !unlocker.match_context(context.as_ref()) {
                        continue;
                    }
                    tx = unlocker.sign_transaction(&tx, script_group, context.as_ref())?;
                    signed_groups_indices.push(idx);
                    break;
                }
            }
        }
        transaction.set_tx_view(tx);
        Ok(signed_groups_indices)
    }
}
