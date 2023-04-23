use crate::NetworkType;

use self::{builder::FeeCalculator, handler::ScriptHandler};

pub mod builder;
pub mod handler;
pub(crate) mod input;

pub struct TransactionBuilderConfiguration {
    network: NetworkType,
    script_handlers: Vec<Box<dyn ScriptHandler>>,
    fee_rate: u64,
}

impl TransactionBuilderConfiguration {
    pub fn new() -> Self {
        Self::new_with_network(NetworkType::Mainnet)
    }
    pub fn new_testnet() -> Self {
        Self::new_with_network(NetworkType::Testnet)
    }

    fn new_with_network(network: NetworkType) -> Self {
        Self {
            network,
            script_handlers: Self::generate_system_handlers(network),
            fee_rate: 1000,
        }
    }
    pub fn generate_system_handlers(network: NetworkType) -> Vec<Box<dyn ScriptHandler>> {
        vec![Box::new(
            handler::sighash::Secp256k1Blake160SighashAllScriptHandler::new_with_network(network),
        ) as Box<_>]
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
