use std::collections::HashMap;

use crate::{
    constants::SIGHASH_TYPE_HASH,
    traits::{DefaultTransactionDependencyProvider, TransactionDependencyProvider},
    tx_builder::TransactionWithScriptGroups,
    NetworkInfo, ScriptId,
};

use super::{ScriptUnlocker, SecpSighashUnlocker, UnlockError};

pub trait UnlockContext {
    type Unloker: ScriptUnlocker;
    /// Check if this context match the script.
    fn match_script(&self, script: &SupportScript) -> bool;

    /// build ScriptUnlocker from context
    fn build(&self) -> Result<Self::Unloker, UnlockError>;
}

pub struct Context;
impl Context {
    /// make a default sighash unlock context
    pub fn make(private_keys: Vec<secp256k1::SecretKey>) -> impl UnlockContext {
        SecpSighashUnlockerContext::new(private_keys)
    }
}

/// supported lock script
pub enum SupportScript {
    /// default sighash script
    SigHash,
    /// script not implemented by this SDK, the internal value act as an id, so user can extend the support script list.
    Other(u32),
}

pub struct UnlockHandler {
    network_info: NetworkInfo,
    known_scripts: HashMap<ScriptId, SupportScript>,
}

impl UnlockHandler {
    fn new(network_info: NetworkInfo) -> Self {
        Self {
            network_info,
            known_scripts: HashMap::new(),
        }
    }

    fn build_tx_dep_provider(&self) -> Box<dyn TransactionDependencyProvider> {
        Box::new(DefaultTransactionDependencyProvider::new(
            &self.network_info.url,
            10,
        ))
    }

    fn register(&mut self, script_id: ScriptId, known_script: SupportScript) {
        self.known_scripts.insert(script_id, known_script);
    }

    pub fn unlock(
        &self,
        tx_with_groups: &mut TransactionWithScriptGroups,
        ctx: &impl UnlockContext,
    ) -> Result<Vec<usize>, UnlockError> {
        let mut signed_lock_hash = Vec::new();
        let tx_dep_provider = self.build_tx_dep_provider();
        for (i, script_group) in tx_with_groups.script_groups.iter().enumerate() {
            if crate::ScriptGroupType::Lock != script_group.group_type {
                continue;
            }
            let script_id = ScriptId::from(&script_group.script);
            if let Some(id) = self.known_scripts.get(&script_id) {
                if !ctx.match_script(id) {
                    continue;
                }
                let unlocker = ctx.build()?;
                if unlocker.is_unlocked(
                    &tx_with_groups.tx_view,
                    script_group,
                    tx_dep_provider.as_ref(),
                )? {
                    tx_with_groups.tx_view = unlocker
                        .clear_placeholder_witness(&tx_with_groups.tx_view, script_group)?;
                } else if unlocker.match_args(script_group.script.args().raw_data().as_ref()) {
                    tx_with_groups.tx_view = unlocker.unlock(
                        &tx_with_groups.tx_view,
                        script_group,
                        tx_dep_provider.as_ref(),
                    )?;
                    signed_lock_hash.push(i);
                }
            }
        }
        Ok(signed_lock_hash)
    }
}

pub struct UnlockerManager {
    handlers: HashMap<NetworkInfo, UnlockHandler>,
}

impl UnlockerManager {
    pub fn register(
        &mut self,
        network_info: &NetworkInfo,
        script_id: ScriptId,
        know_script: SupportScript,
    ) {
        self.handlers
            .get_mut(network_info)
            .expect("according handlers must be initialized before registering")
            .register(script_id, know_script);
    }

    pub fn init(&mut self, network_info: &NetworkInfo) {
        let mut handler = UnlockHandler::new(network_info.clone());
        // register system builders
        handler.register(
            ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
            SupportScript::SigHash,
        );
        self.handlers.insert(network_info.clone(), handler);
    }

    pub fn get_handler(&self, network_info: &NetworkInfo) -> Option<&UnlockHandler> {
        self.handlers.get(network_info)
    }
}
pub struct SecpSighashUnlockerContext {
    private_keys: Vec<secp256k1::SecretKey>,
}

impl UnlockContext for SecpSighashUnlockerContext {
    type Unloker = SecpSighashUnlocker;
    fn match_script(&self, script: &SupportScript) -> bool {
        matches!(script, SupportScript::SigHash)
    }

    fn build(&self) -> Result<SecpSighashUnlocker, UnlockError> {
        let sighash_unlocker = SecpSighashUnlocker::new_with_secret_keys(self.private_keys.clone());
        Ok(sighash_unlocker)
    }
}

impl SecpSighashUnlockerContext {
    pub fn new(private_keys: Vec<secp256k1::SecretKey>) -> Self {
        Self { private_keys }
    }
}

lazy_static::lazy_static! {
    pub static ref UNLOCKER_MANAGER: UnlockerManager = {
        let mut manager = UnlockerManager {handlers: HashMap::new()};
        let mainnet = NetworkInfo::mainnet();
        manager.init(&mainnet);

        let testnet = NetworkInfo::testnet();
        manager.init(&testnet);
        manager
    };
}

pub fn get_unlock_handler(network_info: &NetworkInfo) -> Option<&UnlockHandler> {
    UNLOCKER_MANAGER.get_handler(network_info)
}
