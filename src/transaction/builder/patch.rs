use std::collections::HashSet;

use ckb_types::{
    core,
    packed::{self, CellDep, CellInput, CellOutput, Script},
    prelude::*,
};

use crate::tx_builder::TxBuilderError;

#[derive(Default, Clone)]
pub struct TransactionBuilder {
    builder: core::TransactionBuilder,
    cell_deps: HashSet<CellDep>,
    header_deps: HashSet<packed::Byte32>,
    outputs: Vec<packed::CellOutput>,
    outputs_data: Vec<packed::Bytes>,
    witnesses: Vec<packed::Bytes>,
}

impl std::ops::Deref for TransactionBuilder {
    type Target = core::TransactionBuilder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl TransactionBuilder {
    #[inline]
    pub fn dedup_header_dep(&mut self, header_hash: packed::Byte32) {
        self.header_deps.insert(header_hash);
    }

    pub fn set_header_deps(&mut self, header_deps: Vec<packed::Byte32>) {
        self.header_deps = header_deps.into_iter().collect();
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
    pub fn output(&mut self, output: CellOutput) {
        self.outputs.push(output);
    }

    #[inline]
    pub fn input(&mut self, input: CellInput) {
        self.builder = self.builder.clone().input(input);
    }

    #[inline]
    pub fn output_data(&mut self, data: packed::Bytes) {
        self.outputs_data.push(data);
    }
    pub fn get_outputs(&self) -> &Vec<packed::CellOutput> {
        &self.outputs
    }

    pub fn get_outputs_data(&self) -> &Vec<packed::Bytes> {
        &self.outputs_data
    }
    #[inline]
    pub fn witness(&mut self, witness: packed::Bytes) {
        self.witnesses.push(witness);
    }

    pub fn set_witness(&mut self, i: usize, witness: packed::Bytes) {
        while self.witnesses.len() <= i {
            self.witnesses.push(Default::default());
        }
        self.witnesses[i] = witness;
    }

    pub fn set_witnesses(&mut self, witnesses: Vec<packed::Bytes>) {
        self.witnesses = witnesses;
    }

    pub fn add_output_capacity(
        &mut self,
        script: &Script,
        delta_capacity: u64,
    ) -> Result<(), TxBuilderError> {
        let target_script = script.calc_script_hash();
        let (idx, output) = self
            .outputs
            .iter()
            .enumerate()
            .find(|(_, output)| target_script == output.lock().calc_script_hash())
            .ok_or(TxBuilderError::NoOutputForSmallChange)?;
        let capacity: u64 = output.capacity().unpack();
        let output = output
            .clone()
            .as_builder()
            .capacity((capacity + delta_capacity).pack())
            .build();
        self.outputs[idx] = output;
        Ok(())
    }

    #[inline]
    pub fn build(self) -> core::TransactionView {
        self.builder
            .set_cell_deps(self.cell_deps.into_iter().collect())
            .set_header_deps(self.header_deps.into_iter().collect())
            .set_outputs(self.outputs)
            .set_outputs_data(self.outputs_data)
            .set_witnesses(self.witnesses)
            .build()
    }

    pub fn dedup_cell_deps(&mut self, cell_deps: Vec<CellDep>) {
        self.cell_deps.extend(cell_deps.into_iter());
    }
}
