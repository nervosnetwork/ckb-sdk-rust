use ckb_types::{
    packed,
    prelude::{Builder, Entity, Pack},
};

use crate::traits::LiveCell;

#[derive(Clone, Debug)]
pub struct TransactionInput {
    pub output: packed::CellOutput,
    pub output_data: bytes::Bytes,
    pub out_point: packed::OutPoint,
}

impl TransactionInput {
    pub fn new(
        output: packed::CellOutput,
        output_data: bytes::Bytes,
        out_point: packed::OutPoint,
    ) -> Self {
        Self {
            output,
            output_data,
            out_point,
        }
    }

    pub fn cell_input(&self, since: u64) -> packed::CellInput {
        packed::CellInput::new_builder()
            .since(since.pack())
            .previous_output(self.out_point.clone())
            .build()
    }

    pub fn previous_output(&self) -> &packed::CellOutput {
        &self.output
    }
}

impl From<LiveCell> for TransactionInput {
    fn from(live_cell: LiveCell) -> Self {
        Self {
            output: live_cell.output,
            output_data: live_cell.output_data,
            out_point: live_cell.out_point,
        }
    }
}
