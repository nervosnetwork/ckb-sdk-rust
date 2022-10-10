use anyhow::anyhow;
use bitflags::bitflags;
use bytes::Bytes;
use ckb_hash::Blake2b;
use ckb_types::{bytes::BytesMut, core::TransactionView, prelude::*};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use enum_repr_derive::{FromEnumToRepr, TryFromReprToEnum};

use super::reader::{OpenTxCellField, OpenTxReader, OpenTxSource};
use super::OpenTxError;

const ARG1_MASK: u16 = 0xFFF;
const ARG2_MASK: u16 = 0xFFF;

/// Open transaction signature input command.
#[derive(
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Debug,
    Hash,
    Eq,
    PartialEq,
    TryFromReprToEnum,
    FromEnumToRepr,
)]
#[repr(u8)]
pub enum OpentxCommand {
    /// Hash the full current transaction hash
    TxHash = 0x00,
    /// Hash length of input & output cells in current script group
    GroupInputOutputLen = 0x01,
    /// Hash part or the whole output cell. arg1 is index of output cell, arg2 is cell mask.
    IndexOutput = 0x11,
    /// Hash part or the whole output cell. arg1 is offset of output cell, arg2 is cell mask.
    OffsetOutput = 0x12,
    /// Hash part or the whole input cell. arg1 is index of input cell, arg2 is cell mask.
    IndexInput = 0x13,
    /// Hash part or the whole input cell. arg1 is offset of input cell, arg2 is cell mask.
    OffsetInput = 0x14,
    /// Hash part or the whole cell input structure, arg1 is index of input cell, arg2 is input mask.
    CellInputIndex = 0x15,
    /// Hash part or the whole cell input structure, arg1 is offset of input cell, arg2 is input mask.`
    CellInputOffset = 0x16,
    /// Concatenate ARG 1 and ARG 2, arg1 is lower 12 bit, arg2 is higher 12 bit.
    /// The purpose of this command is to add salt for hash.
    ConcatArg1Arg2 = 0x20,
    /// Terminate and generate the final blake2b hash
    End = 0xF0,
}

impl OpentxCommand {
    pub fn is_index(&self) -> bool {
        matches!(
            self,
            OpentxCommand::IndexOutput | OpentxCommand::IndexInput | OpentxCommand::CellInputIndex
        )
    }
}

bitflags! {
    /// The bits control the data to generate from a cell.
    #[derive(Serialize, Deserialize)]
    pub struct CellMask: u16 {
        /// capacity
        const CAPACITY = 0x1;
        /// lock.code_hash
        const LOCK_CODE_HASH = 0x2;
        /// lock.hash_type
        const LOCK_HASH_TYPE = 0x4;
        /// lock.args
        const LOCK_ARGS = 0x8;
        /// type.code_hash
        const TYPE_CODE_HASH = 0x10;
        /// type.hash_type
        const TYPE_HASH_TYPE = 0x20;
        /// type.args
        const TYPE_ARGS = 0x40;
        /// Cell data
        const CELL_DATA = 0x80;
        /// Lock script hash
        const TYPE_SCRIPT_HASH = 0x100;
        /// Type script hash
        const LOCK_SCRIPT_HASH = 0x200;
        /// The whole cell
        const WHOLE_CELL = 0x400;
    }
}

bitflags! {
    /// The bits control the data to generate from a CellInput structure.
    #[derive(Serialize, Deserialize)]
    pub struct InputMask: u16 {
        /// previous_output.tx_hash
        const TX_HASH = 0x1;
        /// previous_output.index
        const INDEX = 0x2;
        /// since
        const SINCE = 0x4;
        /// previous_output
        const PREVIOUS_OUTPUT = 0x8;
        /// The whole CellInput structure
        const WHOLE = 0x10;
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct OpenTxSigInput {
    pub cmd: OpentxCommand,
    pub arg1: u16,
    pub arg2: u16,
}

impl OpenTxSigInput {
    pub fn compose(&self) -> u32 {
        (self.cmd as u32)
            + (((self.arg1 & ARG1_MASK) as u32) << 8)
            + (((self.arg2 & ARG2_MASK) as u32) << 20)
    }

    /// new OpentxCommand::TxHash OpenTxSigInput, command 0x00
    pub fn new_tx_hash() -> OpenTxSigInput {
        OpenTxSigInput {
            cmd: OpentxCommand::TxHash,
            arg1: 0,
            arg2: 0,
        }
    }
    // new OpentxCommand::GroupInputOutputLen OpenTxSigInput, command 0x01
    pub fn new_group_input_output_len() -> OpenTxSigInput {
        OpenTxSigInput {
            cmd: OpentxCommand::GroupInputOutputLen,
            arg1: 0,
            arg2: 0,
        }
    }
    /// new OpentxCommand::IndexOutput OpenTxSigInput, command 0x11
    pub fn new_index_output(arg1: u16, arg2: CellMask) -> Result<OpenTxSigInput, OpenTxError> {
        Self::new_cell_command(OpentxCommand::IndexOutput, arg1, arg2)
    }
    /// new OpentxCommand::OffsetOutput OpenTxSigInput, command 0x12
    pub fn new_offset_output(arg1: u16, arg2: CellMask) -> Result<OpenTxSigInput, OpenTxError> {
        Self::new_cell_command(OpentxCommand::OffsetOutput, arg1, arg2)
    }
    /// new OpentxCommand::IndexInput OpenTxSigInput, command 0x13
    pub fn new_index_input(arg1: u16, arg2: CellMask) -> Result<OpenTxSigInput, OpenTxError> {
        Self::new_cell_command(OpentxCommand::IndexInput, arg1, arg2)
    }
    /// new OpentxCommand::OffsetInput OpenTxSigInput, command 0x14
    pub fn new_offset_input(arg1: u16, arg2: CellMask) -> Result<OpenTxSigInput, OpenTxError> {
        Self::new_cell_command(OpentxCommand::OffsetInput, arg1, arg2)
    }
    /// new OpenTxSigInput to handle part or the whole input/output cell
    pub fn new_cell_command(
        cmd: OpentxCommand,
        arg1: u16,
        arg2: CellMask,
    ) -> Result<OpenTxSigInput, OpenTxError> {
        if arg1 > ARG1_MASK {
            return Err(OpenTxError::Arg1OutOfRange(arg1));
        }

        Ok(OpenTxSigInput {
            cmd,
            arg1,
            arg2: arg2.bits,
        })
    }
    /// new OpentxCommand::ConcatArg1Arg2 OpenTxSigInput, command 0x15
    pub fn new_cell_input_index(arg1: u16, arg2: InputMask) -> Result<OpenTxSigInput, OpenTxError> {
        Self::new_input_command(OpentxCommand::CellInputIndex, arg1, arg2)
    }
    //// new OpentxCommand::CellInputOffset OpenTxSigInput, command 0x16
    pub fn new_cell_input_offset(
        arg1: u16,
        arg2: InputMask,
    ) -> Result<OpenTxSigInput, OpenTxError> {
        Self::new_input_command(OpentxCommand::CellInputOffset, arg1, arg2)
    }
    /// new OpenTxSigInput to hash  part or the whole cell input structure
    pub fn new_input_command(
        cmd: OpentxCommand,
        arg1: u16,
        arg2: InputMask,
    ) -> Result<OpenTxSigInput, OpenTxError> {
        if arg1 > ARG1_MASK {
            return Err(OpenTxError::Arg1OutOfRange(arg1));
        }

        Ok(OpenTxSigInput {
            cmd,
            arg1,
            arg2: arg2.bits,
        })
    }

    /// new OpentxCommand::ConcatArg1Arg2 OpenTxSigInput, command 0x20
    pub fn new_concat_arg1_arg2(arg1: u16, arg2: u16) -> OpenTxSigInput {
        OpenTxSigInput {
            cmd: OpentxCommand::ConcatArg1Arg2,
            arg1: arg1 & ARG1_MASK,
            arg2: arg2 & ARG2_MASK,
        }
    }
    /// new OpentxCommand::End OpenTxSigInput, command 0xF0
    pub fn new_end() -> OpenTxSigInput {
        OpenTxSigInput {
            cmd: OpentxCommand::End,
            arg1: 0,
            arg2: 0,
        }
    }
    fn hash_cell(
        &self,
        cache: &mut OpentxCache,
        reader: &OpenTxReader,
        is_input: bool,
        with_offset: bool,
        base_index: u32,
    ) -> Result<(), OpenTxError> {
        let mut index = self.arg1 as usize;
        if with_offset {
            index += base_index as usize;
        }
        let source = if is_input {
            OpenTxSource::Input
        } else {
            OpenTxSource::Outpout
        };
        let cell_mask = CellMask::from_bits_truncate(self.arg2);
        if cell_mask.contains(CellMask::CAPACITY) {
            let data = reader.load_cell_field(index, source, OpenTxCellField::Capacity)?;
            cache.update(&data);
        }
        if cell_mask.intersects(
            CellMask::LOCK_CODE_HASH
                | CellMask::LOCK_HASH_TYPE
                | CellMask::LOCK_ARGS
                | CellMask::TYPE_CODE_HASH
                | CellMask::TYPE_HASH_TYPE
                | CellMask::TYPE_ARGS,
        ) {
            let cell = reader.get_cell(index, is_input)?;
            let lock = cell.lock();
            if cell_mask.contains(CellMask::LOCK_CODE_HASH) {
                cache.update(lock.code_hash().as_slice());
            }
            if cell_mask.contains(CellMask::LOCK_HASH_TYPE) {
                cache.update(lock.hash_type().as_slice());
            }
            if cell_mask.contains(CellMask::LOCK_ARGS) {
                let args = lock.args().raw_data().to_vec();
                cache.update(args.as_slice());
            }

            if let Some(type_) = cell.type_().to_opt() {
                if cell_mask.contains(CellMask::TYPE_CODE_HASH) {
                    cache.update(type_.code_hash().as_slice());
                }
                if cell_mask.contains(CellMask::TYPE_HASH_TYPE) {
                    cache.update(type_.hash_type().as_slice());
                }
                if cell_mask.contains(CellMask::TYPE_ARGS) {
                    let args = type_.args().raw_data().to_vec();
                    cache.update(&args);
                }
            }
        }
        if cell_mask.contains(CellMask::CELL_DATA) {
            let data = reader.load_cell_data(index, source)?;
            cache.update(data.as_slice());
        }

        if cell_mask.contains(CellMask::TYPE_SCRIPT_HASH) {
            let cell = reader.get_cell(index, is_input)?;
            if let Some(script) = cell.type_().to_opt() {
                let hash = script.calc_script_hash();
                cache.update(hash.as_slice());
            }
        }

        if cell_mask.contains(CellMask::LOCK_SCRIPT_HASH) {
            let cell = reader.get_cell(index, is_input)?;
            let hash = cell.lock().calc_script_hash();
            cache.update(hash.as_slice());
        }

        if cell_mask.contains(CellMask::WHOLE_CELL) {
            let data = reader.load_cell(index, source)?;
            cache.update(data.as_slice());
        }
        Result::Ok(())
    }

    fn hash_input(
        &self,
        cache: &mut OpentxCache,
        reader: &OpenTxReader,
        with_offset: bool,
        base_index: u32,
    ) -> Result<(), OpenTxError> {
        let index = if with_offset {
            usize::try_from(base_index)
                .map_err(|e| anyhow!(e))?
                .checked_add(self.arg1 as usize)
                .ok_or_else(|| anyhow!("add {} and {} overflow", base_index, self.arg1))?
        } else {
            self.arg1 as usize
        };

        let input_mask = InputMask::from_bits_truncate(self.arg2);
        if input_mask.contains(InputMask::TX_HASH) {
            let cell = reader.input(index)?;
            let data = cell.previous_output().tx_hash();
            cache.update(data.as_slice());
        }

        if input_mask.contains(InputMask::INDEX) {
            let cell = reader.input(index)?;
            let data = cell.previous_output().index();
            cache.update(data.as_slice());
        }

        if input_mask.contains(InputMask::SINCE) {
            let data = reader.load_input_field_since(index)?;

            cache.update(&data);
        }

        if input_mask.contains(InputMask::PREVIOUS_OUTPUT) {
            let data = reader.load_input_field_out_point(index)?;

            cache.update(&data);
        }

        if input_mask.contains(InputMask::WHOLE) {
            let data = reader.load_input(index)?;
            cache.update(&data);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct OpentxWitness {
    pub base_input_index: u32,
    pub base_output_index: u32,
    pub inputs: Vec<OpenTxSigInput>,
}

impl OpentxWitness {
    pub fn new_empty() -> Self {
        OpentxWitness {
            base_input_index: 0,
            base_output_index: 0,
            inputs: vec![],
        }
    }
    pub fn new(base_input_index: u32, base_output_index: u32, inputs: Vec<OpenTxSigInput>) -> Self {
        OpentxWitness {
            base_input_index,
            base_output_index,
            inputs,
        }
    }

    /// Build new OpentxWitness which will sign all data.
    ///
    /// It will first generate the TxHash(0x00), GroupInputOutputLen(0x01),
    /// then iterate the inputs to generate the relative index OpenTxSigInput with all CellMask on, and InputMask on,
    /// then iterate each output to generate the relative index OpenTxSigInput with all CellMask on.
    ///
    /// If salt provided, it will add low 24 bits with ConcatArg1Arg2(0x20),
    /// if high 8 bits not all 0, it will add another ConcatArg1Arg2 OpenTxSigInput.
    ///
    /// Then it will add an End(0xF0) OpenTxSigInput.
    ///
    /// The range of inputs/outputs are [base_input_index, end_input_index), [base_output_index, end_output_index).
    /// If end_input_index bigger than the transaction inputs length, the inputs length will be used, same thing to end_output_index.
    ///
    pub fn new_sig_range_relative(
        transaction: &TransactionView,
        salt: Option<u32>,
        base_input_index: usize,
        end_input_index: usize,
        base_output_index: usize,
        end_output_index: usize,
    ) -> Result<Self, OpenTxError> {
        let mut inputs = vec![
            OpenTxSigInput::new_tx_hash(),
            OpenTxSigInput::new_group_input_output_len(),
        ];

        let start_input_idx = base_input_index;
        let end_input_idx = end_input_index.min(transaction.inputs().len());
        if start_input_idx >= end_input_idx {
            return Err(OpenTxError::BaseIndexOverFlow(
                start_input_idx,
                end_input_idx,
            ));
        }

        let start_output_idx = base_output_index;
        let out_put_idx = end_output_index.min(transaction.outputs().len());
        if start_output_idx >= out_put_idx {
            return Err(OpenTxError::BaseIndexOverFlow(
                start_output_idx,
                out_put_idx,
            ));
        }
        let base_input_index = u32::try_from(base_input_index).map_err(|e| anyhow!(e))?;
        let base_output_index = u32::try_from(base_output_index).map_err(|e| anyhow!(e))?;
        for input_idx in start_input_idx..end_input_idx {
            let idx = u16::try_from(input_idx - start_input_idx).map_err(|e| anyhow!(e))?;
            inputs.push(OpenTxSigInput::new_offset_input(
                idx as u16,
                CellMask::all(),
            )?);
            inputs.push(OpenTxSigInput::new_cell_input_offset(
                idx as u16,
                InputMask::all(),
            )?);
        }
        for output_idx in start_output_idx..out_put_idx {
            let idx = u16::try_from(output_idx - start_output_idx).map_err(|e| anyhow!(e))?;
            inputs.push(OpenTxSigInput::new_offset_output(
                idx as u16,
                CellMask::all(),
            )?);
        }
        if let Some(mut salt) = salt {
            while salt > 0 {
                inputs.push(OpenTxSigInput::new_concat_arg1_arg2(
                    salt as u16 & ARG1_MASK,
                    (salt >> 12) as u16 & ARG2_MASK,
                ));
                salt >>= 24;
            }
        }

        inputs.push(OpenTxSigInput::new_end());
        Ok(OpentxWitness::new(
            base_input_index,
            base_output_index,
            inputs,
        ))
    }
    /// Same to `new_sig_range_relative`, except end_input_index and end_output_index are all usize::MAX,
    /// which will be changed to the length of inputs/outputs list.
    pub fn new_sig_to_end_relative(
        transaction: &TransactionView,
        salt: Option<u32>,
        base_input_index: usize,
        base_output_index: usize,
    ) -> Result<Self, OpenTxError> {
        Self::new_sig_range_relative(
            transaction,
            salt,
            base_input_index,
            usize::MAX,
            base_output_index,
            usize::MAX,
        )
    }

    /// Same to `new_sig_to_end_relative`, except base_input_index and base_output_index are all 0
    pub fn new_sig_all_relative(
        transaction: &TransactionView,
        salt: Option<u32>,
    ) -> Result<Self, OpenTxError> {
        Self::new_sig_range_relative(transaction, salt, 0, usize::MAX, 0, usize::MAX)
    }

    /// Same to new_sig_to_end_relative, but the will use the index commands.
    /// The length will be limit to 0x1000, index range:[0, 4095].
    pub fn new_sig_range_absolute(
        transaction: &TransactionView,
        salt: Option<u32>,
        base_input_index: usize,
        end_input_index: usize,
        base_output_index: usize,
        end_output_index: usize,
    ) -> Result<Self, OpenTxError> {
        let mut inputs = vec![
            OpenTxSigInput::new_tx_hash(),
            OpenTxSigInput::new_group_input_output_len(),
        ];

        let start_input_idx = base_input_index;
        let end_input_idx =
            ((ARG1_MASK + 1) as usize).min(end_input_index.min(transaction.inputs().len()));
        if start_input_idx >= end_input_idx {
            return Err(OpenTxError::BaseIndexOverFlow(
                start_input_idx,
                end_input_idx,
            ));
        }

        let start_output_idx = base_output_index;
        let out_put_idx =
            ((ARG1_MASK + 1) as usize).min(end_output_index.min(transaction.outputs().len()));
        if start_output_idx >= out_put_idx {
            return Err(OpenTxError::BaseIndexOverFlow(
                start_output_idx,
                out_put_idx,
            ));
        }
        let base_input_index = u32::try_from(base_input_index).map_err(|e| anyhow!(e))?;
        let base_output_index = u32::try_from(base_output_index).map_err(|e| anyhow!(e))?;
        for input_idx in start_input_idx..end_input_idx {
            inputs.push(OpenTxSigInput::new_index_input(
                input_idx as u16,
                CellMask::all(),
            )?);
            inputs.push(OpenTxSigInput::new_cell_input_index(
                input_idx as u16,
                InputMask::all(),
            )?);
        }
        for output_idx in start_output_idx..out_put_idx {
            inputs.push(OpenTxSigInput::new_index_output(
                output_idx as u16,
                CellMask::all(),
            )?);
        }
        if let Some(mut salt) = salt {
            while salt > 0 {
                inputs.push(OpenTxSigInput::new_concat_arg1_arg2(
                    salt as u16 & ARG1_MASK,
                    (salt >> 12) as u16 & ARG2_MASK,
                ));
                salt >>= 24;
            }
        }

        inputs.push(OpenTxSigInput::new_end());
        Ok(OpentxWitness::new(
            base_input_index,
            base_output_index,
            inputs,
        ))
    }

    pub fn set_base_input_index(&mut self, index: u32) {
        self.base_input_index = index;
    }

    pub fn set_base_output_index(&mut self, index: u32) {
        self.base_output_index = index;
    }

    pub fn to_witness_data(&self) -> Vec<u8> {
        let capacity = 4 + 4 + 4 * self.inputs.len();
        let mut witness_data = Vec::with_capacity(capacity);
        witness_data.extend_from_slice(&self.base_input_index.to_le_bytes());
        witness_data.extend_from_slice(&self.base_output_index.to_le_bytes());
        for inpt in &self.inputs {
            witness_data.extend_from_slice(&inpt.compose().to_le_bytes());
        }
        witness_data
    }

    pub fn generate_message(
        &self,
        reader: &OpenTxReader,
    ) -> Result<([u8; 32], Bytes), OpenTxError> {
        let (is_input, is_output) = (true, false);
        let (relative_idx, absolute_idx) = (true, false);

        let mut cache = OpentxCache::new();
        let mut s_data = BytesMut::with_capacity(self.inputs.len() * 4);
        for si in &self.inputs {
            match si.cmd {
                OpentxCommand::TxHash => {
                    let tx_hash = reader.tx_hash();
                    cache.update(tx_hash.as_slice());
                }
                OpentxCommand::GroupInputOutputLen => {
                    let input_len = reader.group_input_len()?;
                    cache.update(&input_len.to_le_bytes());
                    let output_len = reader.group_output_len()?;
                    cache.update(&output_len.to_le_bytes());
                }
                OpentxCommand::IndexOutput => {
                    si.hash_cell(&mut cache, reader, is_output, absolute_idx, 0)?;
                }
                OpentxCommand::OffsetOutput => {
                    si.hash_cell(
                        &mut cache,
                        reader,
                        is_output,
                        relative_idx,
                        self.base_output_index,
                    )?;
                }
                OpentxCommand::IndexInput => {
                    si.hash_cell(&mut cache, reader, is_input, absolute_idx, 0)?;
                }
                OpentxCommand::OffsetInput => {
                    si.hash_cell(
                        &mut cache,
                        reader,
                        is_input,
                        relative_idx,
                        self.base_input_index,
                    )?;
                }
                OpentxCommand::CellInputIndex => {
                    si.hash_input(&mut cache, reader, absolute_idx, 0)?;
                }
                OpentxCommand::CellInputOffset => {
                    si.hash_input(&mut cache, reader, is_input, self.base_input_index)?;
                }
                OpentxCommand::ConcatArg1Arg2 => {
                    let data = (si.arg1 & 0xfff) as u32 | ((si.arg2 & 0xfff) << 12) as u32;
                    let data = data.to_le_bytes();
                    cache.update(&data[0..3]);
                }
                OpentxCommand::End => {
                    break;
                }
            }
            s_data.extend_from_slice(&si.compose().to_le_bytes());
        }
        let s_data = s_data.freeze();
        cache.update(s_data.to_vec().as_slice());

        let msg = cache.finalize();
        Ok((msg, s_data))
    }
}

struct OpentxCache {
    blake2b: Blake2b,
}

impl OpentxCache {
    pub fn new() -> Self {
        OpentxCache {
            blake2b: ckb_hash::new_blake2b(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.blake2b.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        self.blake2b.finalize(&mut msg);
        msg
    }
}
