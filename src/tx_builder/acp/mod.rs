use std::collections::HashSet;

use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use ckb_types::{
    core::{DepType, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H160,
};

use super::{TxBuilder, TxBuilderError};
use crate::{
    constants::{self, ACP_TYPE_HASH_AGGRON, ACP_TYPE_HASH_LINA},
    traits::{
        CellCollector, CellDepResolver, CellQueryOptions, HeaderDepResolver,
        TransactionDependencyProvider,
    },
    Address, AddressPayload, NetworkType, ScriptId,
};

#[derive(Clone, Debug)]
pub struct AcpCreateReceiver {
    pub lock_script: Script,
    pub capacity: u64,
    /// value of udt
    pub amount: Option<u128>,
    /// The udt type script
    pub type_script: Option<Script>,
}
#[derive(Clone, Debug, Default)]
pub struct AcpLockBuilder {
    pub lock_public_key_hash: H160,
    /// value range [0, 19], actual mini ckb is 10^mini_ckb_exponent
    pub mini_ckb_exponent: Option<u8>,
    /// value range [0, 38], actual mini udt is 10^mini_udt_exponent
    pub mini_udt_exponent: Option<u8>,
}

impl AcpLockBuilder {
    pub fn key_hash(&mut self, hash: H160) -> &mut Self {
        self.lock_public_key_hash = hash;
        self
    }
    pub fn mini_ckb(&mut self, exponent: Option<u8>) -> &mut Self {
        self.mini_ckb_exponent = exponent;
        self
    }

    pub fn mini_udt(&mut self, exponent: Option<u8>) -> &mut Self {
        self.mini_udt_exponent = exponent;
        self
    }

    pub fn build_args(&self) -> bytes::Bytes {
        let mut bytes = BytesMut::with_capacity(22);

        bytes.put(self.lock_public_key_hash.as_bytes());
        if let Some(exp) = self.mini_ckb_exponent.as_ref() {
            bytes.put_u8(*exp);

            if let Some(exp) = self.mini_udt_exponent.as_ref() {
                bytes.put_u8(*exp);
            }
        }
        bytes.freeze()
    }

    pub fn build_lock_script(&self, network_type: NetworkType) -> Script {
        let args = self.build_args();
        let code_hash = match network_type {
            NetworkType::Mainnet => ACP_TYPE_HASH_LINA.clone().pack(),
            NetworkType::Testnet => ACP_TYPE_HASH_AGGRON.clone().pack(),
            _ => panic!("network type must be `mainnet` or `testnet` when build lock script"),
        };
        let payload = AddressPayload::new_full(ScriptHashType::Type, code_hash, args);
        Script::from(&payload)
    }
}

impl AcpCreateReceiver {
    /// Create a new acp create receiver, without udt requirements
    pub fn new(lock_script: Script, capacity: u64) -> Self {
        Self {
            lock_script,
            capacity,
            amount: None,
            type_script: None,
        }
    }

    pub fn new_udt(lock_script: Script, capacity: u64, type_script: Option<Script>) -> Self {
        Self {
            lock_script,
            capacity,
            amount: Some(0u128),
            type_script,
        }
    }

    pub fn build_output_data(&self) -> bytes::Bytes {
        let mut bytes = BytesMut::with_capacity(16);
        if let Some(amount) = self.amount.as_ref() {
            bytes.put(&amount.to_le_bytes()[..]);
        }
        bytes.freeze()
    }

    pub fn build_output(&self) -> (CellOutput, bytes::Bytes) {
        let cell_output = CellOutput::new_builder()
            .lock(self.lock_script.clone())
            .capacity(self.capacity.pack())
            .type_(self.type_script.pack())
            .build();
        let output_data = self.build_output_data();
        (cell_output, output_data)
    }
}

#[derive(Clone, Debug)]
pub struct AcpTransferReceiver {
    pub lock_script: Script,
    pub capacity: u64,
}
impl AcpTransferReceiver {
    pub fn new(lock_script: Script, capacity: u64) -> AcpTransferReceiver {
        AcpTransferReceiver {
            lock_script,
            capacity,
        }
    }

    pub fn from_address(address: &Address, capacity: u64) -> AcpTransferReceiver {
        let script = Script::from(address);
        Self::new(script, capacity)
    }
}
/// Transfer capacity to already exists acp cell, the type script and cell data
/// will be copied.
pub struct AcpTransferBuilder {
    pub receivers: Vec<AcpTransferReceiver>,
}
impl AcpTransferBuilder {
    pub fn new(receivers: Vec<AcpTransferReceiver>) -> AcpTransferBuilder {
        AcpTransferBuilder { receivers }
    }
}

impl TxBuilder for AcpTransferBuilder {
    fn build_base(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        _header_dep_resolver: &dyn HeaderDepResolver,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        #[allow(clippy::mutable_key_type)]
        let mut cell_deps = HashSet::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        for receiver in &self.receivers {
            let query = CellQueryOptions::new_lock(receiver.lock_script.clone());
            let (cells, input_capacity) = cell_collector.collect_live_cells(&query, true)?;
            if cells.is_empty() {
                return Err(TxBuilderError::Other(anyhow!(
                    "can not found cell by lock script: {:?}",
                    receiver.lock_script
                )));
            }
            let input_cell = &cells[0];
            let input = CellInput::new(input_cell.out_point.clone(), 0);
            let output_capacity = input_capacity + receiver.capacity;
            let output = input_cell
                .output
                .clone()
                .as_builder()
                .capacity(output_capacity.pack())
                .build();
            let output_data = input_cell.output_data.clone();

            let lock_cell_dep = cell_dep_resolver
                .resolve(&receiver.lock_script)
                .ok_or_else(|| {
                    TxBuilderError::ResolveCellDepFailed(receiver.lock_script.clone())
                })?;
            cell_deps.insert(lock_cell_dep);
            if let Some(type_script) = input_cell.output.type_().to_opt() {
                let cell_dep = cell_dep_resolver
                    .resolve(&type_script)
                    .ok_or_else(|| TxBuilderError::ResolveCellDepFailed(type_script.clone()))?;
                cell_deps.insert(cell_dep);
            }

            inputs.push(input);
            outputs.push(output);
            outputs_data.push(output_data.pack());
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}

/// Add default acp cell dependencies, the dependent cells are metioned in the RFC.
pub fn add_default_acp_dep(dep_resolver: &mut dyn CellDepResolver, network_type: NetworkType) {
    let (code_hash, tx_hash, idx) = if network_type == NetworkType::Mainnet {
        (
            constants::ACP_TYPE_HASH_LINA,
            constants::ACP_TX_HASH_LINA,
            constants::ACP_TX_INDEX_LINA,
        )
    } else if network_type == NetworkType::Testnet {
        (
            constants::ACP_TYPE_HASH_AGGRON,
            constants::ACP_TX_HASH_AGGRON,
            constants::ACP_TX_INDEX_AGGRON,
        )
    } else {
        return;
    };

    let out_point = OutPoint::new(Byte32::from_slice(tx_hash.as_bytes()).unwrap(), idx);
    let cell_dep = CellDep::new_builder()
        .out_point(out_point)
        .dep_type(DepType::DepGroup.into())
        .build();
    let script_id = ScriptId::new_type(code_hash);
    dep_resolver.insert(script_id, cell_dep);
}

pub fn get_default_script_id(network_type: NetworkType) -> ScriptId {
    let code_hash = if network_type == NetworkType::Mainnet {
        constants::ACP_TYPE_HASH_LINA
    } else if network_type == NetworkType::Testnet {
        constants::ACP_TYPE_HASH_AGGRON
    } else {
        panic!("can only handle mainnet and testnet");
    };
    ScriptId::new_type(code_hash)
}

mod builder;
pub use builder::DefaultAcpTransferBuilder;
