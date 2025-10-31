use ckb_types::{
    packed,
    prelude::{Builder, Entity},
};

use crate::traits::LiveCell;

#[derive(Clone, Debug)]
pub struct TransactionInput {
    pub live_cell: LiveCell,
    pub since: u64,
}

impl TransactionInput {
    pub fn new(live_cell: LiveCell, since: u64) -> Self {
        Self { live_cell, since }
    }

    #[inline]
    pub fn set_since(&mut self, since: u64) {
        self.since = since;
    }

    pub fn cell_input(&self) -> packed::CellInput {
        packed::CellInput::new_builder()
            .since(self.since)
            .previous_output(self.live_cell.out_point.clone())
            .build()
    }

    pub fn previous_output(&self) -> &packed::CellOutput {
        &self.live_cell.output
    }
}
