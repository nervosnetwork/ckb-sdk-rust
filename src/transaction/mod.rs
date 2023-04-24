use crate::{tx_builder::TxBuilderError, NetworkInfo};

use self::{builder::FeeCalculator, handler::ScriptHandler};

pub mod builder;
pub mod handler;
pub mod input;

pub struct TransactionBuilderConfiguration {
    network: NetworkInfo,
    script_handlers: Vec<Box<dyn ScriptHandler>>,
    fee_rate: u64,
}

impl TransactionBuilderConfiguration {
    pub fn new() -> Result<Self, TxBuilderError> {
        Self::new_with_network(NetworkInfo::mainnet())
    }
    pub fn new_testnet() -> Result<Self, TxBuilderError> {
        Self::new_with_network(NetworkInfo::testnet())
    }

    fn new_with_network(network: NetworkInfo) -> Result<Self, TxBuilderError> {
        let script_handlers = Self::generate_system_handlers(&network)?;
        Ok(Self {
            network,
            script_handlers,
            fee_rate: 1000,
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
