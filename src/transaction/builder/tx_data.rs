use std::collections::HashSet;

use ckb_types::{
    core::{self, TransactionBuilder},
    packed::{self, CellDep, CellInput, CellOutput},
    prelude::*,
};

use crate::tx_builder::TxBuilderError;

#[derive(Default)]
pub struct TxData {
    version: u32,
    pub cell_deps: HashSet<CellDep>,
    pub header_deps: Vec<packed::Byte32>,
    pub inputs: Vec<CellInput>,
    pub outputs: Vec<CellOutput>,
    pub outputs_data: Vec<packed::Bytes>,
    pub witnesses: Vec<packed::Bytes>,
}

impl TxData {
    #[inline]
    pub fn add_header_dep(&mut self, header_hash: packed::Byte32) {
        self.header_deps.push(header_hash);
    }

    #[inline]
    pub fn set_outputs(&mut self, outputs: Vec<CellOutput>) {
        self.outputs = outputs;
    }

    #[inline]
    pub fn set_outputs_data(&mut self, outputs_data: Vec<packed::Bytes>) {
        self.outputs_data = outputs_data;
    }

    #[inline]
    pub fn add_output(&mut self, output: CellOutput) {
        self.outputs.push(output);
    }

    #[inline]
    pub fn add_input(&mut self, input: CellInput) {
        self.inputs.push(input);
    }

    #[inline]
    pub fn add_output_data(&mut self, data: packed::Bytes) {
        self.outputs_data.push(data);
    }
    #[inline]
    pub fn outputs_len(&self) -> usize {
        self.outputs.len()
    }
    #[inline]
    pub fn add_witness(&mut self, witness: packed::Bytes) {
        self.witnesses.push(witness);
    }

    pub fn set_witnesses(
        &mut self,
        i: usize,
        witness: packed::Bytes,
    ) -> Result<(), TxBuilderError> {
        self.witnesses[i] = witness;
        Ok(())
    }

    #[inline]
    pub fn build_tx_view(&self) -> core::TransactionView {
        TransactionBuilder::default()
            .version(self.version.pack())
            .set_cell_deps(self.cell_deps.clone().into_iter().collect())
            .set_header_deps(self.header_deps.clone())
            .set_inputs(self.inputs.clone())
            .set_outputs(self.outputs.clone())
            .set_outputs_data(self.outputs_data.clone())
            .set_witnesses(self.witnesses.clone())
            .build()
    }

    pub fn add_cell_deps(&mut self, cell_deps: Vec<CellDep>) {
        self.cell_deps.extend(cell_deps);
    }
}
