use ckb_hash::new_blake2b;
use ckb_types::{
    packed::{CellInput, Script},
    prelude::*,
};

use crate::{
    core::TransactionBuilder, tx_builder::TxBuilderError, NetworkInfo, ScriptGroup, ScriptId,
};

use super::{HandlerContext, ScriptHandler};

pub struct TypeIdHandler;

pub struct TypeIdContext {}

impl HandlerContext for TypeIdContext {}

impl TypeIdHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        ScriptId::from(script).is_type_id()
    }
}

// copy from https://github.com/nervosnetwork/ckb-cli/blob/develop/src/utils/other.rs#L325
pub fn calculate_type_id(first_cell_input: &CellInput, output_index: u64) -> [u8; 32] {
    let mut blake2b = new_blake2b();
    blake2b.update(first_cell_input.as_slice());
    blake2b.update(&output_index.to_le_bytes());
    let mut ret = [0u8; 32];
    blake2b.finalize(&mut ret);
    ret
}

impl ScriptHandler for TypeIdHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if !self.is_match(&script_group.script) || script_group.output_indices.is_empty() {
            return Ok(false);
        }
        if let Some(_args) = context.as_any().downcast_ref::<TypeIdContext>() {
            let index = script_group.output_indices.last().unwrap();
            let output = tx_builder.get_outputs()[*index].clone();
            if let Some(type_) = output.type_().to_opt() {
                if self.is_match(&type_) && type_.args().is_empty() {
                    let type_ = type_
                        .as_builder()
                        .args(bytes::Bytes::from(vec![0u8; 32]).pack())
                        .build();
                    let output = output.as_builder().type_(Some(type_).pack()).build();
                    tx_builder.set_output(*index, output);
                }

                return Ok(true);
            }
        }
        Ok(false)
    }

    fn init(&mut self, _network: &NetworkInfo) -> Result<(), TxBuilderError> {
        Ok(())
    }

    fn post_build(
        &self,
        index: usize,
        tx_builder: &mut TransactionBuilder,
        _context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if let Some(output) = tx_builder.get_outputs().get(index) {
            if let Some(type_) = output.type_().to_opt() {
                if self.is_match(&type_) && type_.args().raw_data()[..] == [0u8; 32] {
                    let input = tx_builder
                        .get_inputs()
                        .get(0)
                        .ok_or(TxBuilderError::InvalidInputIndex(0))?;
                    let args = calculate_type_id(input, index as u64);
                    let type_ = type_
                        .as_builder()
                        .args(bytes::Bytes::from(args.to_vec()).pack())
                        .build();
                    let output = output
                        .clone()
                        .as_builder()
                        .type_(Some(type_).pack())
                        .build();
                    tx_builder.set_output(index, output);
                }
            }
        }
        Ok(true)
    }
}
