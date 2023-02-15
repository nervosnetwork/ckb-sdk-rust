use ckb_types::{core::TransactionView, H256};

use crate::{
    tx_builder::{
        builder::{impl_default_builder, BaseTransactionBuilder, CkbTransactionBuilder},
        TxBuilderError,
    },
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    util::parse_hex_str,
    Address, NetworkInfo, ScriptGroup,
};

use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use super::*;

pub struct DefaultDaoDepositBuilder {
    pub base_builder: BaseTransactionBuilder,
    /// The deposit targets
    pub receivers: Vec<DaoDepositReceiver>,
}

impl DefaultDaoDepositBuilder {
    /// Make a builder with empty reciver list and default type script mentioned in the RFC:
    /// https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md
    pub fn new(network_info: NetworkInfo, sender_addr: &str) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender_addr)?,
            receivers: Default::default(),
        })
    }
    pub fn new_with_address(
        network_info: NetworkInfo,
        sender_address: Address,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new_with_address(network_info, sender_address)?,
            receivers: Default::default(),
        })
    }

    pub fn add_dao_output_str(
        &mut self,
        receiver_addr: &str,
        capacity: u64,
    ) -> Result<(), TxBuilderError> {
        let receiver_addr =
            Address::from_str(receiver_addr).map_err(TxBuilderError::AddressFormat)?;
        self.add_dao_output_addr(receiver_addr, capacity);
        Ok(())
    }

    pub fn add_dao_output_addr(&mut self, address: Address, capacity: u64) {
        let script = Script::from(address.payload());
        self.add_dao_output(script, capacity);
    }

    pub fn add_dao_output(&mut self, lock_script: Script, capacity: u64) {
        self.receivers
            .push(DaoDepositReceiver::new(lock_script, capacity));
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

impl From<&DefaultDaoDepositBuilder> for DaoDepositBuilder {
    fn from(val: &DefaultDaoDepositBuilder) -> Self {
        DaoDepositBuilder {
            receivers: val.receivers.clone(),
        }
    }
}
impl_default_builder!(DefaultDaoDepositBuilder, DaoDepositBuilder);
