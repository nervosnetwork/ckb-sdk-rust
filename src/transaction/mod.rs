use crate::{tx_builder::TxBuilderError, NetworkInfo};

use self::{builder::FeeCalculator, handler::ScriptHandler};

pub mod builder;
pub mod handler;
pub mod input;
pub mod signer;

pub struct TransactionBuilderConfiguration {
    /// The network for transaction builder.
    pub network: NetworkInfo,
    /// The script handlers for transaction builder, user can add their own script handlers.
    pub script_handlers: Vec<Box<dyn ScriptHandler>>,
    /// The fee rate for transaction builder, the default value is 1000 shannons/KB.
    pub fee_rate: u64,
    /// The estimate tx size in bytes, the maximum size of the tx-pool to accept transactions is 512000,
    /// a typical TWO_IN_TWO_OUT secp256k1-sig-hash-all transaction size is about 597 bytes,
    /// we set the default value to 128000, it's enough for most cases, and user can change it if needed.
    pub estimate_tx_size: u64,
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
            estimate_tx_size: 128000,
        })
    }

    fn generate_system_handlers(
        network: &NetworkInfo,
    ) -> Result<Vec<Box<dyn ScriptHandler>>, TxBuilderError> {
        let ret = vec![
            Box::new(
                handler::sighash::Secp256k1Blake160SighashAllScriptHandler::new_with_network(
                    network,
                )?,
            ) as Box<_>,
            Box::new(
                handler::multisig::Secp256k1Blake160MultisigAllScriptHandler::new_with_network(
                    network,
                )?,
            ) as Box<_>,
            Box::new(handler::sudt::SudtHandler::new_with_network(network)?) as Box<_>,
            Box::new(handler::typeid::TypeIdHandler) as Box<_>,
            Box::new(handler::omnilock::OmnilockScriptHandler::new_with_network(
                network,
            )?) as Box<_>,
        ];
        Ok(ret)
    }

    pub fn network_info(&self) -> &NetworkInfo {
        &self.network
    }

    pub fn register_script_handler(&mut self, script_handler: Box<dyn ScriptHandler>) {
        self.script_handlers.push(script_handler);
    }

    pub fn get_script_handlers(&self) -> &Vec<Box<dyn ScriptHandler>> {
        &self.script_handlers
    }

    pub fn get_fee_rate(&self) -> u64 {
        self.fee_rate
    }

    pub fn fee_calculator(&self) -> FeeCalculator {
        FeeCalculator::new(self.fee_rate)
    }
}
