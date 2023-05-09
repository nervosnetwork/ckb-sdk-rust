use ckb_types::packed::Script;

use crate::{tx_builder::TxBuilderError, NetworkInfo};

use self::{builder::FeeCalculator, handler::ScriptHandler};

pub mod builder;
pub mod handler;
pub mod input;
pub mod signer;

pub struct TransactionBuilderConfiguration {
    pub network: NetworkInfo,
    pub script_handlers: Vec<Box<dyn ScriptHandler>>,
    pub fee_rate: u64,
    pub small_change_action: SmallChangeAction,
}

/// Define what to do when change capacity is to small to create a new cell.
/// If the change capacity is lower than `threshold` in shannons, it is small.
pub enum SmallChangeAction {
    /// Find another input cell, and put it's capacity to change.
    /// It's the default action.
    FindMoreInput,
    /// Put the change capacity to the first output cell with target address.
    /// If change capacity lower than threshold, add it to output cell,
    /// or it will act as `FindMoreInput`
    ToOutput { target: Script, threshold: u64 },
    /// Put the small change capacity to fee.
    /// If change capacity lower than threshold, add it to fee, or it will act as `FindMoreInput`.
    /// *Note*:
    /// If the threshold is 61CKB (6100000000 shannons) and assume the mimimum capacity for a cell is 61 bytes,
    /// the transaction fee might bigger than 61 CKBs, because to create a change cell,
    /// will need extra transaction fee for the change cell.
    AsFee { threshold: u64 },
}

impl SmallChangeAction {
    pub fn to_output(target: Script, threshold: u64) -> Self {
        Self::ToOutput { target, threshold }
    }

    pub fn as_fee(threshold: u64) -> Self {
        Self::AsFee { threshold }
    }
}

impl TransactionBuilderConfiguration {
    pub fn new() -> Result<Self, TxBuilderError> {
        Self::new_with_network(NetworkInfo::mainnet())
    }
    pub fn new_testnet() -> Result<Self, TxBuilderError> {
        Self::new_with_network(NetworkInfo::testnet())
    }

    pub fn new_with_network(network: NetworkInfo) -> Result<Self, TxBuilderError> {
        let script_handlers = Self::generate_system_handlers(&network)?;
        Ok(Self {
            network,
            script_handlers,
            fee_rate: 1000,
            small_change_action: SmallChangeAction::FindMoreInput,
        })
    }
    pub fn generate_system_handlers(
        network: &NetworkInfo,
    ) -> Result<Vec<Box<dyn ScriptHandler>>, TxBuilderError> {
        let ret = vec![Box::new(
            handler::sighash::Secp256k1Blake160SighashAllScriptHandler::new_with_network(network)?,
        ) as Box<_>];
        Ok(ret)
    }

    #[inline]
    pub fn network_info(&self) -> &NetworkInfo {
        &self.network
    }
    pub fn register_script_handler(&mut self, script_handler: Box<dyn ScriptHandler>) {
        self.script_handlers.push(script_handler);
    }
    #[inline]
    pub fn get_script_handlers(&self) -> &Vec<Box<dyn ScriptHandler>> {
        &self.script_handlers
    }
    #[inline]
    pub fn get_fee_rate(&self) -> u64 {
        self.fee_rate
    }

    pub fn fee_calculator(&self) -> FeeCalculator {
        FeeCalculator::new(self.fee_rate)
    }
}
