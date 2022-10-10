use std::cmp::Ordering;
use std::convert::TryFrom;

use ckb_hash::blake2b_256;
use ckb_types::{
    core::{Capacity, TransactionView},
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::Entity,
};

use super::OpenTxError;
use crate::traits::TransactionDependencyProvider;

#[derive(Copy, Clone, PartialEq)]
pub enum OpenTxSource {
    Input,
    GroupInput,
    Outpout,
    GroupOutpout,
    CellDep,
}

#[derive(Copy, Clone)]
pub enum OpenTxCellField {
    Capacity,
    DataHash,
    Lock,
    LockHash,
    Type,
    TypeHash,
    OccupiedCapacity,
}

#[derive(Copy, Clone)]
pub enum OpenTxInputField {
    OutPoint,
    Since,
}

pub struct OpenTxReader {
    pub transaction: TransactionView,
    pub provider: Box<dyn TransactionDependencyProvider>,
    /// map group input index to input index
    group_input_index: Vec<usize>,
    /// map group output index to output index
    group_output_index: Vec<usize>,
    /// open tx lock hash
    script_hash: Byte32,
}

impl OpenTxReader {
    pub fn new(
        transaction: &TransactionView,
        provider: Box<dyn TransactionDependencyProvider>,
        script_hash: Byte32,
    ) -> Result<Self, OpenTxError> {
        let mut group_input_index = Vec::new();
        // all lock
        for index in 0..transaction.inputs().len() {
            let lock_hash = provider
                .get_cell(&transaction.inputs().get(index).unwrap().previous_output())?
                .lock()
                .calc_script_hash();
            if lock_hash.cmp(&script_hash) == Ordering::Equal {
                group_input_index.push(index);
            }
        }
        let mut group_output_index = Vec::new();
        for index in 0..transaction.outputs().len() {
            let lock_hash = transaction.output(index).unwrap().lock().calc_script_hash();
            if lock_hash.cmp(&script_hash) == Ordering::Equal {
                group_output_index.push(index);
            }
        }
        Ok(OpenTxReader {
            transaction: transaction.clone(),
            provider,
            group_input_index,
            group_output_index,
            script_hash,
        })
    }

    /// get the group input length.
    pub fn group_input_len(&self) -> Result<u64, OpenTxError> {
        let len = self.group_input_index.len();
        let len = u64::try_from(len).map_err(|_e| OpenTxError::LenOverflow(len))?;
        Ok(len)
    }

    /// get the group output length
    pub fn group_output_len(&self) -> Result<u64, OpenTxError> {
        let len = self.group_output_index.len();
        let len = u64::try_from(len).map_err(|_e| OpenTxError::LenOverflow(len))?;
        Ok(len)
    }

    /// Get input at absolute index
    pub fn input(&self, index: usize) -> Result<CellInput, OpenTxError> {
        self.transaction
            .inputs()
            .get(index)
            .ok_or(OpenTxError::OutOfBound)
    }
    /// Get previous output of input
    /// # Arguments
    /// * `index` absolute index of inputs.
    fn input_previous_output(&self, index: usize) -> Result<OutPoint, OpenTxError> {
        let cell = self.input(index)?;
        Ok(cell.previous_output())
    }

    /// Get CellOutput of input's cell
    /// # Arguments
    /// * `index` absolute index of inputs.
    fn input_cell(&self, index: usize) -> Result<CellOutput, OpenTxError> {
        let previous_output = self.input_previous_output(index)?;
        let cell_output = self.provider.get_cell(&previous_output).unwrap();
        Ok(cell_output)
    }

    /// Get CellOutput of input's cell
    /// # Arguments
    /// * `index` absolute index of inputs.
    fn group_input_cell(&self, index: usize) -> Result<CellOutput, OpenTxError> {
        if self.group_input_index.len() <= index {
            return Result::Err(OpenTxError::OutOfBound);
        }
        let index = self.group_input_index[index];
        self.input_cell(index)
    }
    /// Get cell data of input's cell
    /// # Arguments
    /// * `index` absolute index of inputs.
    fn input_cell_data(&self, index: usize) -> Result<bytes::Bytes, OpenTxError> {
        let previous_output = self.input_previous_output(index)?;
        let cell_data = self.provider.get_cell_data(&previous_output)?;
        Ok(cell_data)
    }
    /// Get cell data of input's cell
    /// # Arguments
    /// * `index` absolute index of output.
    fn output_cell(&self, index: usize) -> Result<CellOutput, OpenTxError> {
        self.transaction
            .output(index)
            .ok_or(OpenTxError::OutOfBound)
    }
    /// Get cell data of input's cell
    /// # Arguments
    /// * `index` absolute index of output group.
    fn group_output_cell(&self, index: usize) -> Result<CellOutput, OpenTxError> {
        if self.group_output_index.len() <= index {
            return Result::Err(OpenTxError::OutOfBound);
        }
        let index = self.group_output_index[index];
        self.output_cell(index)
    }
    /// Get cell raw data of output's cell
    /// # Arguments
    /// * `index` absolute index of output.
    fn output_cell_data(&self, index: usize) -> Result<bytes::Bytes, OpenTxError> {
        Ok(self
            .transaction
            .outputs_data()
            .get(index)
            .ok_or(OpenTxError::OutOfBound)?
            .raw_data())
    }
    /// Get CellDep of cell depends
    /// # Arguments
    /// * `index` absolute index of cell deps.
    fn cell_dep(&self, index: usize) -> Result<CellDep, OpenTxError> {
        self.transaction
            .cell_deps()
            .get(index)
            .ok_or(OpenTxError::OutOfBound)
    }
    /// Get CellOutput of cell depend
    /// # Arguments
    /// * `index` absolute index of cell deps.
    fn cell_dep_cell(&self, index: usize) -> Result<CellOutput, OpenTxError> {
        let outpoint = self.cell_dep(index)?;
        let cell = self.provider.get_cell(&outpoint.out_point())?;
        Ok(cell)
    }
    fn cell_dep_cell_data(&self, index: usize) -> Result<bytes::Bytes, OpenTxError> {
        let outpoint = self.cell_dep(index)?;
        let cell = self.provider.get_cell_data(&outpoint.out_point())?;

        Ok(cell)
    }
    /// fetch the hash of the current running transaction
    pub fn tx_hash(&self) -> Byte32 {
        self.transaction.hash()
    }

    pub fn load_transaction(&self) -> Vec<u8> {
        self.transaction.data().as_slice().to_vec()
    }

    pub fn load_script_hash(&self) -> Byte32 {
        self.script_hash.clone()
    }

    pub fn load_cell(&self, index: usize, source: OpenTxSource) -> Result<Vec<u8>, OpenTxError> {
        let cell = match source {
            OpenTxSource::Input => self.input_cell(index),
            OpenTxSource::Outpout => self.output_cell(index),
            OpenTxSource::CellDep => self.cell_dep_cell(index),
            _ => Err(OpenTxError::UnsupportSource),
        };
        Ok(cell?.as_slice().to_vec())
    }

    pub fn load_cell_data(
        &self,
        index: usize,
        source: OpenTxSource,
    ) -> Result<Vec<u8>, OpenTxError> {
        let data = match source {
            OpenTxSource::Input => self.input_cell_data(index)?.to_vec(),
            OpenTxSource::Outpout => self.output_cell_data(index)?.to_vec(),
            OpenTxSource::CellDep => self.cell_dep_cell_data(index)?.to_vec(),
            _ => return Err(OpenTxError::UnsupportSource),
        };
        Ok(data.to_vec())
    }

    pub fn load_input(&self, index: usize) -> Result<Vec<u8>, OpenTxError> {
        let input = self.input(index)?;
        Result::Ok(input.as_slice().to_vec())
    }

    fn load_field_capacity(
        &self,
        index: usize,
        source: OpenTxSource,
    ) -> Result<Vec<u8>, OpenTxError> {
        let cell = match source {
            OpenTxSource::Input => self.input_cell(index)?,
            OpenTxSource::Outpout => self.output_cell(index)?,
            OpenTxSource::GroupInput => self.group_input_cell(index)?,
            OpenTxSource::GroupOutpout => self.group_output_cell(index)?,
            OpenTxSource::CellDep => self.cell_dep_cell(index)?,
        };
        Ok(cell.capacity().raw_data().to_vec())
    }

    fn load_field_data_hash(
        &self,
        index: usize,
        source: OpenTxSource,
    ) -> Result<Vec<u8>, OpenTxError> {
        match source {
            OpenTxSource::Input => {
                let input = self.input_cell_data(index)?;

                let data = input.to_vec();
                Result::Ok(if data.is_empty() {
                    [0u8; 32].to_vec()
                } else {
                    blake2b_256(data).to_vec()
                })
            }
            OpenTxSource::Outpout => {
                let output = self
                    .transaction
                    .outputs_data()
                    .get(index)
                    .ok_or(OpenTxError::OutOfBound)?;
                // TODO: why split here?
                let data = output.as_slice().split_at(4).1.to_vec();
                if data.is_empty() {
                    Result::Ok([0u8; 32].to_vec())
                } else {
                    Result::Ok(data)
                }
            }
            OpenTxSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(OpenTxError::OutOfBound);
                }
                let data = self
                    .provider
                    .get_cell_data(&outpoint.unwrap().out_point())?;
                Result::Ok(if data.is_empty() {
                    [0u8; 32].to_vec()
                } else {
                    blake2b_256(&data).to_vec()
                })
            }
            _ => Err(OpenTxError::UnsupportSource),
        }
    }

    fn load_field_lock(&self, index: usize, source: OpenTxSource) -> Result<Vec<u8>, OpenTxError> {
        match source {
            OpenTxSource::Input => {
                let input = self.input_cell(index)?;
                Result::Ok(input.lock().as_bytes().to_vec())
            }
            OpenTxSource::Outpout => {
                let output = self
                    .transaction
                    .output(index)
                    .ok_or(OpenTxError::OutOfBound)?;
                Result::Ok(output.lock().as_bytes().to_vec())
            }
            OpenTxSource::CellDep => {
                let outpoint = self
                    .transaction
                    .cell_deps()
                    .get(index)
                    .ok_or(OpenTxError::OutOfBound)?;
                let cell = self.provider.get_cell(&outpoint.out_point())?;
                Result::Ok(cell.lock().as_bytes().to_vec())
            }
            _ => Err(OpenTxError::UnsupportSource),
        }
    }

    fn load_field_lock_hash(
        &self,
        index: usize,
        source: OpenTxSource,
    ) -> Result<Vec<u8>, OpenTxError> {
        match source {
            OpenTxSource::Input => {
                let input = self.input_cell(index)?;
                Result::Ok(input.calc_lock_hash().as_bytes().to_vec())
            }
            OpenTxSource::Outpout => {
                let output = self
                    .transaction
                    .output(index)
                    .ok_or(OpenTxError::OutOfBound)?;

                Result::Ok(output.calc_lock_hash().as_bytes().to_vec())
            }
            OpenTxSource::CellDep => {
                let outpoint = self
                    .transaction
                    .cell_deps()
                    .get(index)
                    .ok_or(OpenTxError::OutOfBound)?;

                let cell = self.provider.get_cell(&outpoint.out_point())?;
                Result::Ok(cell.calc_lock_hash().as_bytes().to_vec())
            }
            _ => Err(OpenTxError::UnsupportSource),
        }
    }

    fn load_field_type(&self, index: usize, source: OpenTxSource) -> Result<Vec<u8>, OpenTxError> {
        match source {
            OpenTxSource::Input => {
                let input = self.input_cell(index)?;
                let d = input.type_();
                if d.is_none() {
                    Result::Err(OpenTxError::ItemMissing)
                } else {
                    Result::Ok(d.as_bytes().to_vec())
                }
            }
            OpenTxSource::Outpout => {
                let output = self
                    .transaction
                    .output(index)
                    .ok_or(OpenTxError::OutOfBound)?;

                let d = output.type_();
                if d.is_none() {
                    Result::Err(OpenTxError::ItemMissing)
                } else {
                    Result::Ok(d.as_bytes().to_vec())
                }
            }
            OpenTxSource::CellDep => {
                let outpoint = self
                    .transaction
                    .cell_deps()
                    .get(index)
                    .ok_or(OpenTxError::OutOfBound)?;

                let cell = self.provider.get_cell(&outpoint.out_point())?;
                let d = cell.type_();
                if d.is_none() {
                    Result::Err(OpenTxError::ItemMissing)
                } else {
                    Result::Ok(d.as_bytes().to_vec())
                }
            }
            _ => Err(OpenTxError::UnsupportSource),
        }
    }

    fn load_field_type_hash(
        &self,
        index: usize,
        source: OpenTxSource,
    ) -> Result<Vec<u8>, OpenTxError> {
        match source {
            OpenTxSource::Input => {
                let input = self.input_cell(index)?;
                let d = input.type_();
                if d.is_none() {
                    Result::Err(OpenTxError::ItemMissing)
                } else {
                    let d = Script::from_slice(d.as_slice()).unwrap();
                    Result::Ok(d.calc_script_hash().as_slice().to_vec())
                }
            }
            OpenTxSource::Outpout => {
                let output = self
                    .transaction
                    .output(index)
                    .ok_or(OpenTxError::OutOfBound)?;

                let d = output.type_().to_opt().ok_or(OpenTxError::ItemMissing)?;

                Result::Ok(d.calc_script_hash().as_slice().to_vec())
            }
            OpenTxSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(OpenTxError::OutOfBound);
                }
                let cell = self.provider.get_cell(&outpoint.unwrap().out_point())?;
                let d = cell.type_().to_opt().ok_or(OpenTxError::ItemMissing)?;

                Result::Ok(d.calc_script_hash().as_slice().to_vec())
            }
            _ => Err(OpenTxError::UnsupportSource),
        }
    }

    fn load_field_occupied_capacity(
        &self,
        index: usize,
        source: OpenTxSource,
    ) -> Result<Vec<u8>, OpenTxError> {
        match source {
            OpenTxSource::Input => {
                let input = self.input_cell(index)?;
                let data = self.input_cell_data(index)?;
                Result::Ok(
                    input
                        .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                        .unwrap()
                        .as_u64()
                        .to_le_bytes()
                        .to_vec(),
                )
            }
            OpenTxSource::Outpout => {
                let output = self.output_cell(index)?;
                let output_data = self
                    .transaction
                    .outputs_data()
                    .get(index)
                    .ok_or(OpenTxError::OutOfBound)?;

                Result::Ok(
                    output
                        .occupied_capacity(Capacity::bytes(output_data.len()).unwrap())
                        .unwrap()
                        .as_u64()
                        .to_le_bytes()
                        .to_vec(),
                )
            }
            OpenTxSource::CellDep => {
                let cell = self
                    .transaction
                    .cell_deps()
                    .get(index)
                    .ok_or(OpenTxError::OutOfBound)?;
                let cell_output = self.provider.get_cell(&cell.out_point())?;
                let cell_data = self.provider.get_cell_data(&cell.out_point())?;
                Result::Ok(
                    cell_output
                        .occupied_capacity(Capacity::bytes(cell_data.len()).unwrap())
                        .unwrap()
                        .as_u64()
                        .to_le_bytes()
                        .to_vec(),
                )
            }
            _ => Err(OpenTxError::UnsupportSource),
        }
    }

    pub fn load_cell_field(
        &self,
        index: usize,
        source: OpenTxSource,
        field: OpenTxCellField,
    ) -> Result<Vec<u8>, OpenTxError> {
        match field {
            OpenTxCellField::Capacity => self.load_field_capacity(index, source),
            OpenTxCellField::DataHash => self.load_field_data_hash(index, source),
            OpenTxCellField::Lock => self.load_field_lock(index, source),
            OpenTxCellField::LockHash => self.load_field_lock_hash(index, source),
            OpenTxCellField::Type => self.load_field_type(index, source),
            OpenTxCellField::TypeHash => self.load_field_type_hash(index, source),
            OpenTxCellField::OccupiedCapacity => self.load_field_occupied_capacity(index, source),
        }
    }

    pub fn load_input_field_out_point(&self, index: usize) -> Result<Vec<u8>, OpenTxError> {
        Ok(self.input(index)?.previous_output().as_slice().to_vec())
    }

    pub fn load_input_field_since(&self, index: usize) -> Result<Vec<u8>, OpenTxError> {
        Ok(self.input(index)?.since().as_slice().to_vec())
    }

    pub fn get_cell(&self, index: usize, is_input: bool) -> Result<CellOutput, OpenTxError> {
        let cell = if is_input {
            self.input_cell(index)?
        } else {
            self.output_cell(index)?
        };
        Ok(cell)
    }
}
