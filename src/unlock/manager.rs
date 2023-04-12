use std::collections::HashMap;

use crate::{
    constants::SIGHASH_TYPE_HASH,
    traits::{DefaultTransactionDependencyProvider, TransactionDependencyProvider},
    tx_builder::TransactionWithScriptGroups,
    NetworkInfo, ScriptId,
};

use super::{ScriptUnlocker, SecpSighashUnlocker, UnlockError};

pub trait UnlockContext: downcast_rs::Downcast {}
downcast_rs::impl_downcast!(UnlockContext);

pub struct ContextFactory;
impl ContextFactory {
    /// make a default sighash unlock context
    pub fn make(private_keys: Vec<secp256k1::SecretKey>) -> Box<dyn UnlockContext> {
        Box::new(SecpSighashUnlockerContext::new(private_keys))
    }
}

pub trait UnlockBuilder {
    /// build ScriptUnlocker from context
    fn build(&self, ctx: &dyn UnlockContext) -> Result<Box<dyn ScriptUnlocker>, UnlockError>;
}
pub struct UnlockHandler {
    network_info: NetworkInfo,
    builders: HashMap<ScriptId, Box<dyn UnlockBuilder>>,
}
unsafe impl Sync for UnlockHandler {}

impl UnlockHandler {
    fn new(network_info: NetworkInfo) -> Self {
        Self {
            network_info,
            builders: HashMap::new(),
        }
    }

    fn build_tx_dep_provider(&self) -> Box<dyn TransactionDependencyProvider> {
        Box::new(DefaultTransactionDependencyProvider::new(
            &self.network_info.url,
            10,
        ))
    }

    fn register(&mut self, script_id: ScriptId, builder: Box<dyn UnlockBuilder>) {
        self.builders.insert(script_id, builder);
    }

    pub fn unlock(
        &self,
        tx_with_groups: &mut TransactionWithScriptGroups,
        ctx: &dyn UnlockContext,
    ) -> Result<Vec<usize>, UnlockError> {
        let mut signed_lock_hash = Vec::new();
        let tx_dep_provider = self.build_tx_dep_provider();
        for (i, script_group) in tx_with_groups.script_groups.iter().enumerate() {
            if crate::ScriptGroupType::Lock != script_group.group_type {
                continue;
            }
            let script_id = ScriptId::from(&script_group.script);
            let script_args = script_group.script.args().raw_data();
            if let Some(builder) = self.builders.get(&script_id) {
                let unlocker = builder.build(ctx)?;
                if unlocker.is_unlocked(
                    &tx_with_groups.tx_view,
                    script_group,
                    tx_dep_provider.as_ref(),
                )? {
                    tx_with_groups.tx_view = unlocker
                        .clear_placeholder_witness(&tx_with_groups.tx_view, script_group)?;
                } else if unlocker.match_args(script_args.as_ref()) {
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
unsafe impl Sync for UnlockerManager {}

impl UnlockerManager {
    pub fn register(
        &mut self,
        network_info: &NetworkInfo,
        script_id: ScriptId,
        unlock_builder: Box<dyn UnlockBuilder>,
    ) {
        self.handlers
            .get_mut(network_info)
            .expect("according handlers must be initialized before registering")
            .register(script_id, unlock_builder);
    }

    fn init(&mut self, network_info: &NetworkInfo) {
        let mut handler = UnlockHandler::new(network_info.clone());
        // register system builders
        handler.register(
            ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
            Box::<SecpSighashUnlockerBuilder>::default(),
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
impl UnlockContext for SecpSighashUnlockerContext {}

impl SecpSighashUnlockerContext {
    pub fn new(private_keys: Vec<secp256k1::SecretKey>) -> Self {
        Self { private_keys }
    }
}

#[derive(Default)]
pub struct SecpSighashUnlockerBuilder {}

impl UnlockBuilder for SecpSighashUnlockerBuilder {
    fn build(&self, ctx: &dyn UnlockContext) -> Result<Box<dyn ScriptUnlocker>, UnlockError> {
        let sig_ctx =
            ctx.downcast_ref::<SecpSighashUnlockerContext>()
                .ok_or(UnlockError::InvalidContext(
                    "invalid SecpSighashUnlockerContext context".to_string(),
                ))?;

        let sighash_unlocker =
            SecpSighashUnlocker::new_with_secret_keys(sig_ctx.private_keys.clone());
        Ok(Box::new(sighash_unlocker))
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
