use ckb_types::{core::TransactionView, H256};

use crate::{
    constants::{SUDT_CODE_HASH_MAINNET, SUDT_CODE_HASH_TESTNET},
    tx_builder::{
        builder::{BaseTransactionBuilder, CkbTransactionBuilder},
        TxBuilderError,
    },
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    util::{parse_hex_str, parse_packed_bytes},
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
    /// create a DefaultUdtIssueBuilder with user specified typescript
    pub fn new_with_type_script(
        network_info: NetworkInfo,
        sender_addr: &str,
        type_script_id: ScriptId,
    ) -> Result<Self, TxBuilderError> {
        let network_type = network_info.network_type;
        let mut v = Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender_addr)?,
            type_script_id,
            receivers: Default::default(),
        };

        add_default_sudt_dep(v.cell_dep_resolver.as_mut(), network_type);
        Ok(v)
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

    pub fn add_sighash_unlocker_from_str(&mut self, key: &str) -> Result<(), TxBuilderError> {
        let sender_key = parse_hex_str(key).map_err(TxBuilderError::KeyFormat)?;
        self.add_sighash_unlocker(sender_key)
    }

    /// add a sighash unlocker with private key
    pub fn add_sighash_unlocker(&mut self, sign_key: H256) -> Result<(), TxBuilderError> {
        let sighash_unlocker = SecpSighashUnlocker::new_with_secret_h256(&[sign_key])
            .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
        let sighash_script_id = SecpSighashUnlocker::script_id();
        self.unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );
        Ok(())
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

impl Deref for DefaultUdtIssueBuilder {
    type Target = BaseTransactionBuilder;

    fn deref(&self) -> &Self::Target {
        &self.base_builder
    }
}

impl DerefMut for DefaultUdtIssueBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base_builder
    }
}

impl CkbTransactionBuilder for DefaultUdtIssueBuilder {
    fn build_base(&mut self) -> Result<TransactionView, TxBuilderError> {
        let builder = UdtIssueBuilder::from(&*self);
        builder.build_base(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
        )
    }

    fn build_balanced(&mut self) -> Result<TransactionView, TxBuilderError> {
        let builder = UdtIssueBuilder::from(&*self);
        builder.build_balanced(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }

    fn build_unlocked(&mut self) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let builder = UdtIssueBuilder::from(&*self);
        builder.build_unlocked(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }

    fn build_balance_unlocked(
        &mut self,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let builder = UdtIssueBuilder::from(&*self);
        builder.build_balance_unlocked(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }
}

pub struct DefaultUdtTransferBuilder {
    pub base_builder: BaseTransactionBuilder,
    /// list of receiver's address and amount tuples
    pub receivers: Vec<(Address, u128)>,
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

        let args = parse_packed_bytes(type_script_args)
            .map_err(|e| TxBuilderError::InvalidParameter(anyhow!("{}", e)))?;

        let type_script = type_script_id.build_script(args);
        Self::new_with_type_script(network_info, sender_addr, type_script)
    }

    /// create a DefaultUdtIssueBuilder with user specified typescript
    pub fn new_with_type_script(
        network_info: NetworkInfo,
        sender_addr: &str,
        type_script: Script,
    ) -> Result<Self, TxBuilderError> {
        let network_type = network_info.network_type;
        let mut v = Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender_addr)?,
            type_script,
            receivers: Default::default(),
        };

        add_default_sudt_dep(v.cell_dep_resolver.as_mut(), network_type);
        Ok(v)
    }

    pub fn set_type_script(&mut self, type_script: Script) {
        self.type_script = type_script;
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

    pub fn add_sighash_unlocker_from_str(&mut self, key: &str) -> Result<(), TxBuilderError> {
        let sender_key = parse_hex_str(key).map_err(TxBuilderError::KeyFormat)?;
        self.add_sighash_unlocker(sender_key)
    }

    /// add a sighash unlocker with private key
    pub fn add_sighash_unlocker(&mut self, sign_key: H256) -> Result<(), TxBuilderError> {
        let sighash_unlocker = SecpSighashUnlocker::new_with_secret_h256(&[sign_key])
            .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
        let sighash_script_id = SecpSighashUnlocker::script_id();
        self.unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );
        Ok(())
    }
}

impl From<&DefaultUdtTransferBuilder> for UdtTransferBuilder {
    fn from(val: &DefaultUdtTransferBuilder) -> Self {
        let sender = Script::from(&val.base_builder.sender);
        let receivers = val
            .receivers
            .iter()
            .map(|(address, amount)| {
                let receiver_script = Script::from(address);
                UdtTargetReceiver::new(TransferAction::Create, receiver_script, *amount)
            })
            .collect();
        UdtTransferBuilder {
            type_script: val.type_script.clone(),
            sender,
            receivers,
        }
    }
}

impl Deref for DefaultUdtTransferBuilder {
    type Target = BaseTransactionBuilder;

    fn deref(&self) -> &Self::Target {
        &self.base_builder
    }
}

impl DerefMut for DefaultUdtTransferBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base_builder
    }
}

impl CkbTransactionBuilder for DefaultUdtTransferBuilder {
    fn build_base(&mut self) -> Result<TransactionView, TxBuilderError> {
        let builder = UdtTransferBuilder::from(&*self);
        builder.build_base(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
        )
    }

    fn build_balanced(&mut self) -> Result<TransactionView, TxBuilderError> {
        let builder = UdtTransferBuilder::from(&*self);
        builder.build_balanced(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }

    fn build_unlocked(&mut self) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let builder = UdtTransferBuilder::from(&*self);
        builder.build_unlocked(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }

    fn build_balance_unlocked(
        &mut self,
    ) -> Result<(TransactionView, Vec<ScriptGroup>), TxBuilderError> {
        let builder = UdtTransferBuilder::from(&*self);
        builder.build_balance_unlocked(
            self.base_builder.cell_collector.as_mut(),
            self.base_builder.cell_dep_resolver.as_ref(),
            self.base_builder.header_dep_resolver.as_ref(),
            self.base_builder.tx_dep_provider.as_ref(),
            &self.base_builder.balancer,
            &self.base_builder.unlockers,
        )
    }
}
