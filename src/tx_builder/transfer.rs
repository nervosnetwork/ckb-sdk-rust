use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use super::{
    builder::{impl_default_builder, BaseTransactionBuilder, CkbTransactionBuilder},
    TxBuilder, TxBuilderError,
};
use crate::{
    constants::MULTISIG_TYPE_HASH,
    traits::{
        CellCollector, CellDepResolver, HeaderDepResolver, SecpCkbRawKeySigner,
        TransactionDependencyProvider,
    },
    unlock::{MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker},
    util::parse_hex_str,
    Address, ScriptGroup,
};
use crate::{types::ScriptId, NetworkInfo};
use ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::CellOutput,
    prelude::*,
    H256,
};

/// A builder to build a transaction simply transfer capcity to an address. It
/// will resolve the type script's cell_dep if given.
pub struct CapacityTransferBuilder {
    pub outputs: Vec<(CellOutput, Bytes)>,
}

impl CapacityTransferBuilder {
    pub fn new(outputs: Vec<(CellOutput, Bytes)>) -> CapacityTransferBuilder {
        CapacityTransferBuilder { outputs }
    }
}

impl TxBuilder for CapacityTransferBuilder {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for (output, output_data) in &self.outputs {
            outputs.push(output.clone());
            outputs_data.push(output_data.pack());
            if let Some(type_script) = output.type_().to_opt() {
                let script_id = ScriptId::from(&type_script);
                if !script_id.is_type_id() {
                    let cell_dep = cell_dep_resolver
                        .resolve(&type_script)
                        .ok_or(TxBuilderError::ResolveCellDepFailed(type_script))?;
                    cell_deps.insert(cell_dep);
                }
            }
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}

pub struct DefaultCapacityTransferBuilder {
    pub base_builder: BaseTransactionBuilder,
}

impl DefaultCapacityTransferBuilder {
    pub fn new(network_info: NetworkInfo, sender: &str) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new(network_info, sender)?,
        })
    }

    pub fn new_with_address(
        network_info: NetworkInfo,
        sender: Address,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            base_builder: BaseTransactionBuilder::new_with_address(network_info, sender)?,
        })
    }
}

impl From<&DefaultCapacityTransferBuilder> for CapacityTransferBuilder {
    fn from(val: &DefaultCapacityTransferBuilder) -> Self {
        CapacityTransferBuilder::new(val.base_builder.outputs.clone())
    }
}

impl_default_builder!(DefaultCapacityTransferBuilder, CapacityTransferBuilder);

pub struct DefaultMultisigCapacityTransferBuilder {
    pub base_builder: DefaultCapacityTransferBuilder,
    multisig_config: MultisigConfig,
}

impl DefaultMultisigCapacityTransferBuilder {
    pub fn new_with_config(
        network_info: NetworkInfo,
        multisig_config: MultisigConfig,
    ) -> Result<Self, TxBuilderError> {
        let sender_addr = multisig_config.to_address(network_info.network_type);
        let mut base_builder =
            DefaultCapacityTransferBuilder::new_with_address(network_info, sender_addr)?;
        base_builder.set_sender_placeholder_witness(multisig_config.placeholder_witness());
        Ok(Self {
            base_builder,
            multisig_config,
        })
    }

    /// add a multisig unlocker with private keys
    pub fn add_unlocker_from_str<T: AsRef<str>>(
        &mut self,
        keys: &[T],
    ) -> Result<(), TxBuilderError> {
        let mut sign_keys = vec![];
        for key in keys.iter() {
            let sender_key = parse_hex_str(key.as_ref()).map_err(TxBuilderError::KeyFormat)?;
            sign_keys.push(sender_key);
        }
        self.add_unlocker(sign_keys)
    }

    /// add a multisig unlocker with private keys
    pub fn add_unlocker(&mut self, sign_keys: Vec<H256>) -> Result<(), TxBuilderError> {
        let mut secrect_keys = vec![];
        for key in sign_keys.iter() {
            let sender_key = secp256k1::SecretKey::from_slice(key.as_bytes())
                .map_err(|e| TxBuilderError::KeyFormat(e.to_string()))?;
            secrect_keys.push(sender_key);
        }
        self.add_unlocker_from_secrect_keys(secrect_keys)
    }
    /// add
    pub fn add_unlocker_from_secrect_keys(
        &mut self,
        secrect_keys: Vec<secp256k1::SecretKey>,
    ) -> Result<(), TxBuilderError> {
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(secrect_keys);
        let multisig_signer =
            SecpMultisigScriptSigner::new(Box::new(signer), self.multisig_config.clone());
        let multisig_unlocker = SecpMultisigUnlocker::new(multisig_signer);
        let multisig_script_id = ScriptId::new_type(MULTISIG_TYPE_HASH.clone());

        self.unlockers.insert(
            multisig_script_id,
            Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
        );
        Ok(())
    }
}

impl Deref for DefaultMultisigCapacityTransferBuilder {
    type Target = DefaultCapacityTransferBuilder;

    fn deref(&self) -> &Self::Target {
        &self.base_builder
    }
}

impl DerefMut for DefaultMultisigCapacityTransferBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base_builder
    }
}
