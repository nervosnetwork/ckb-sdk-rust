use std::collections::HashSet;

use ckb_types::core::ScriptHashType;
use ckb_types::packed::{Script, Byte32};
use ckb_types::{
    bytes::Bytes, core::TransactionBuilder, core::TransactionView, packed::CellOutput, prelude::*,
};

use crate::constants::SIGHASH_TYPE_HASH;
use crate::traits::{
    CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider,
};
use crate::unlock::omni_lock::IDENTITY_FLAGS_PUBKEY_HASH;
use crate::ScriptId;

use super::{TxBuilder, TxBuilderError};

/// A builder to build a transaction simply transfer capcity to an address. It
/// will resolve the type script's cell_dep if given.
pub struct OmniLockTransferBuilder {
    pub outputs: Vec<(CellOutput, Bytes)>,
    pub id_flags: u8,
}

impl OmniLockTransferBuilder {
    pub fn new(outputs: Vec<(CellOutput, Bytes)>, id_flags: u8) -> OmniLockTransferBuilder {
        OmniLockTransferBuilder { outputs, id_flags }
    }
}

impl TxBuilder for OmniLockTransferBuilder {
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

        if self.id_flags == IDENTITY_FLAGS_PUBKEY_HASH {
            let sig_script = Script::default().as_builder()
                .code_hash(Byte32::from_slice(SIGHASH_TYPE_HASH.as_bytes()).map_err(|_|TxBuilderError::ResolveCellDepFailed(Script::default()))?)
                .hash_type(ScriptHashType::Type.into()).build();
            let cell_dep = cell_dep_resolver
                .resolve(&sig_script)
                .ok_or(TxBuilderError::ResolveCellDepFailed(Script::default()))?;
            cell_deps.insert(cell_dep);
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .build())
    }
}
