use ckb_types::core::TransactionView;

use crate::{
    constants::{SUDT_CODE_HASH_MAINNET, SUDT_CODE_HASH_TESTNET},
    parser::Parser,
    tx_builder::{
        builder::{impl_default_builder, BaseTransactionBuilder, CkbTransactionBuilder},
        TxBuilderError,
    },
    Address, NetworkInfo, NetworkType, ScriptGroup,
};

use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use super::*;

pub struct DefaultUdtIssueBuilder {
    pub base_builder: BaseTransactionBuilder,
    /// list of receiver's address and amount tuples
    pub receivers: Vec<(Address, u128)>,
    pub type_script_id: ScriptId,
}

impl DefaultUdtIssueBuilder {
    /// Make a builder with empty reciver list and default type script mentioned in the RFC:
    /// https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md
    pub fn new(network_info: NetworkInfo, sender_addr: &str) -> Result<Self, TxBuilderError> {
        let type_script = match network_info.network_type {
            NetworkType::Mainnet => ScriptId::new_type(SUDT_CODE_HASH_MAINNET.clone()),
            NetworkType::Testnet => ScriptId::new_type(SUDT_CODE_HASH_TESTNET.clone()),
            _ => ScriptId::default(),
        };
        Self::new_with_type_script(network_info, sender_addr, type_script)
    }

    pub fn new_mainnet(sender_addr: &str) -> Result<Self, TxBuilderError> {
        Self::new(NetworkInfo::mainnet(), sender_addr)
    }

    /// create a DefaultUdtIssueBuilder with user specified typescript
    pub fn new_with_type_script(
        network_info: NetworkInfo,
        sender_addr: &str,
        type_script_id: ScriptId,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender_addr)?,
            type_script_id,
            receivers: Default::default(),
        })
    }

    pub fn set_type_script_id(&mut self, type_script: ScriptId) {
        self.type_script_id = type_script;
    }

    pub fn add_sudt_output_str(
        &mut self,
        receiver: &str,
        amount: u128,
    ) -> Result<(), TxBuilderError> {
        let receiver_addr = Address::from_str(receiver).map_err(TxBuilderError::AddressFormat)?;
        self.add_sudt_output(receiver_addr, amount);
        Ok(())
    }

    pub fn add_sudt_output(&mut self, address: Address, amount: u128) {
        self.receivers.push((address, amount));
    }
}

impl From<&DefaultUdtIssueBuilder> for UdtIssueBuilder {
    fn from(val: &DefaultUdtIssueBuilder) -> Self {
        let owner = Script::from(&val.base_builder.sender);
        let receivers = val
            .receivers
            .iter()
            .map(|(address, amount)| {
                let receiver_script = Script::from(address);
                UdtTargetReceiver::new(TransferAction::Create, receiver_script, *amount)
            })
            .collect();
        UdtIssueBuilder {
            udt_type: UdtType::Sudt,
            script_id: val.type_script_id.clone(),
            owner,
            receivers,
        }
    }
}
impl_default_builder!(DefaultUdtIssueBuilder, UdtIssueBuilder);

pub struct DefaultUdtTransferBuilder {
    pub base_builder: BaseTransactionBuilder,
    /// list of receiver's address and amount tuples
    pub receivers: Vec<(TransferAction, Address, u128)>,
    pub type_script: Script,
}

impl DefaultUdtTransferBuilder {
    /// Make a builder with empty reciver list and default type script mentioned in the RFC:
    /// https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md
    pub fn new(
        network_info: NetworkInfo,
        sender_addr: &str,
        type_script_args: &str,
    ) -> Result<Self, TxBuilderError> {
        let type_script_id = match network_info.network_type {
            NetworkType::Mainnet => ScriptId::new_type(SUDT_CODE_HASH_MAINNET.clone()),
            NetworkType::Testnet => ScriptId::new_type(SUDT_CODE_HASH_TESTNET.clone()),
            _ => ScriptId::default(),
        };

        let args = ckb_types::packed::Bytes::parse(type_script_args)
            .map_err(|e| TxBuilderError::InvalidParameter(anyhow!("{}", e)))?;

        let type_script = type_script_id.build_script(args);
        Self::new_with_type_script(network_info, sender_addr, type_script)
    }

    pub fn new_mainnet(sender_addr: &str, type_script_args: &str) -> Result<Self, TxBuilderError> {
        Self::new(NetworkInfo::mainnet(), sender_addr, type_script_args)
    }
    /// create a DefaultUdtIssueBuilder with user specified typescript
    pub fn new_with_type_script(
        network_info: NetworkInfo,
        sender_addr: &str,
        type_script: Script,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender_addr)?,
            type_script,
            receivers: Default::default(),
        })
    }

    pub fn set_type_script(&mut self, type_script: Script) {
        self.type_script = type_script;
    }

    pub fn add_sudt_output_str(
        &mut self,
        receiver_addr: &str,
        amount: u128,
    ) -> Result<(), TxBuilderError> {
        let receiver_addr =
            Address::from_str(receiver_addr).map_err(TxBuilderError::AddressFormat)?;
        self.add_sudt_output(receiver_addr, amount);
        Ok(())
    }

    pub fn add_sudt_output(&mut self, address: Address, amount: u128) {
        self.receivers
            .push((TransferAction::Create, address, amount));
    }

    pub fn add_update_sudt_output_str(
        &mut self,
        receiver: &str,
        amount: u128,
    ) -> Result<(), TxBuilderError> {
        let receiver_addr = Address::from_str(receiver).map_err(TxBuilderError::AddressFormat)?;
        self.add_update_sudt_output(receiver_addr, amount);
        Ok(())
    }

    pub fn add_update_sudt_output(&mut self, address: Address, amount: u128) {
        self.receivers
            .push((TransferAction::Update, address, amount));
    }
}

impl From<&DefaultUdtTransferBuilder> for UdtTransferBuilder {
    fn from(val: &DefaultUdtTransferBuilder) -> Self {
        let sender = Script::from(&val.base_builder.sender);
        let receivers = val
            .receivers
            .iter()
            .map(|(action, address, amount)| {
                let receiver_script = Script::from(address);
                UdtTargetReceiver::new(*action, receiver_script, *amount)
            })
            .collect();
        UdtTransferBuilder {
            type_script: val.type_script.clone(),
            sender,
            receivers,
        }
    }
}

impl_default_builder!(DefaultUdtTransferBuilder, UdtTransferBuilder);
