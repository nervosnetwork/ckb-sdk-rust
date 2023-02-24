use crate::{
    parser::Parser,
    traits::SecpCkbRawKeySigner,
    tx_builder::{
        builder::{impl_default_builder, BaseTransactionBuilder, CkbTransactionBuilder},
        TxBuilder, TxBuilderError,
    },
    unlock::AcpUnlocker,
    Address, NetworkInfo, ScriptGroup,
};

use ckb_types::core::TransactionView;

use std::ops::{Deref, DerefMut};

use super::{get_default_script_id, AcpTransferBuilder, AcpTransferReceiver};

pub struct DefaultAcpTransferBuilder {
    pub base_builder: BaseTransactionBuilder,
    pub receivers: Vec<AcpTransferReceiver>,
}

impl DefaultAcpTransferBuilder {
    pub fn new(network_info: NetworkInfo, sender_addr: &str) -> Result<Self, TxBuilderError> {
        let sender_address = Address::parse(sender_addr).map_err(TxBuilderError::AddressFormat)?;
        Self::new_with_address(network_info, sender_address)
    }

    pub fn new_mainnet(sender_addr: &str) -> Result<Self, TxBuilderError> {
        Self::new(NetworkInfo::mainnet(), sender_addr)
    }

    pub fn new_with_address(
        network_info: NetworkInfo,
        sender_addr: Address,
    ) -> Result<Self, TxBuilderError> {
        let network_type = network_info.network_type;
        let mut v = Self {
            base_builder: BaseTransactionBuilder::new_with_address(network_info, sender_addr)?,
            receivers: vec![],
        };

        let acp_unlocker = AcpUnlocker::from(Box::new(SecpCkbRawKeySigner::default()) as Box<_>);

        v.add_unlocker(get_default_script_id(network_type), Box::new(acp_unlocker));
        Ok(v)
    }

    pub fn set_receivers(&mut self, receivers: Vec<AcpTransferReceiver>) {
        self.receivers = receivers;
    }

    pub fn add_receiver(&mut self, receiver: AcpTransferReceiver) {
        self.receivers.push(receiver);
    }

    pub fn add_receiver_addr(&mut self, receiver_addr: &Address, capacity: u64) {
        let receiver = AcpTransferReceiver::from_address(receiver_addr, capacity);
        self.receivers.push(receiver);
    }
}

impl From<&DefaultAcpTransferBuilder> for AcpTransferBuilder {
    fn from(val: &DefaultAcpTransferBuilder) -> Self {
        AcpTransferBuilder::new(val.receivers.clone())
    }
}

impl_default_builder!(DefaultAcpTransferBuilder, AcpTransferBuilder);
