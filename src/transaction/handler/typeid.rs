use ckb_hash::new_blake2b;
use ckb_types::{
    packed::{Bytes, CellInput},
    prelude::*,
};

use crate::{
    core::TransactionBuilder, tx_builder::TxBuilderError, NetworkInfo, ScriptGroup, ScriptId,
};

use super::{HandlerContext, ScriptHandler};

/// Type ID script handler, it will setup the [Type ID](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#type-id) script's args automatically.
pub struct TypeIdHandler;

pub struct TypeIdContext;

impl HandlerContext for TypeIdContext {}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptHandler for TypeIdHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if context.as_any().is::<TypeIdContext>()
            && ScriptId::from(&script_group.script).is_type_id()
            && script_group.input_indices.is_empty()
            && script_group.output_indices.len() == 1
        {
            let input = tx_builder.get_inputs().first().unwrap();
            let index = *script_group.output_indices.last().unwrap();
            let args: Bytes = calculate_type_id(input, index as u64).to_vec().pack();
            let output = tx_builder.get_outputs().get(index).unwrap().clone();
            let output_type_script = output
                .type_()
                .to_opt()
                .unwrap()
                .as_builder()
                .args(args)
                .build();
            let updated_output = output
                .as_builder()
                .type_(Some(output_type_script.clone()).pack())
                .build();
            tx_builder.set_output(index, updated_output);
            script_group.script = output_type_script;
            return Ok(true);
        }
        Ok(false)
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn init(&mut self, _network: &NetworkInfo) -> Result<(), TxBuilderError> {
        Ok(())
    }
    async fn init_async(&mut self, _network: &NetworkInfo) -> Result<(), TxBuilderError> {
        Ok(())
    }
}

fn calculate_type_id(first_cell_input: &CellInput, output_index: u64) -> [u8; 32] {
    let mut blake2b = new_blake2b();
    blake2b.update(first_cell_input.as_slice());
    blake2b.update(&output_index.to_le_bytes());
    let mut ret = [0u8; 32];
    blake2b.finalize(&mut ret);
    ret
}
