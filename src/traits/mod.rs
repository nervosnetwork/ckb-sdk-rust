//! The traits defined here is intent to describe the requirements of current
//!  library code and only implemented the trait in upper level code.

mod default_impls;
pub use default_impls::{
    DefaultCellCollector, DefaultCellDepResolver, DefaultTransactionDependencyProvider,
};

use thiserror::Error;

use ckb_chain_spec::consensus::Consensus;
use ckb_hash::blake2b_256;
use ckb_traits::{BlockEpoch, CellDataProvider, EpochProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, CellProvider, CellStatus, HeaderChecker},
        error::OutPointError,
        EpochExt, HeaderView, TransactionView,
    },
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction},
    prelude::*,
};

use crate::types::ScriptId;
use crate::util::is_mature;

/// Wallet errors
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("the id is not found in the wallet")]
    IdNotFound,

    #[error("invalid message, reason: `{0}`")]
    InvalidMessage(String),

    #[error("get transaction dependency failed: `{0}`")]
    TxDep(#[from] TransactionDependencyError),

    // maybe hardware wallet error or io error
    #[error("other error: `{0}`")]
    Other(#[from] Box<dyn std::error::Error>),
}

/// A wallet abstraction, support wallet type:
///    * secp256k1 ckb wallet
///    * secp256k1 eth wallet
///    * RSA wallet
///    * Hardware wallet
pub trait Wallet {
    /// typecial id are blake160(pubkey) and keccak256(pubkey)[12..20]
    fn match_id(&self, id: &[u8]) -> bool;

    /// `message` type is Bytes, because different algorithm have different length of message.
    ///   * secp256k1 => 256bits
    ///   * RSA       => 512bits (when key size is 1024bits)
    ///
    ///  For keystore case, `password` may read from prompt.
    ///  For ledger case, `password` will read from ledger device.
    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        tx: &TransactionView,
        // This is mainly for hardware wallet.
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<Bytes, WalletError>;

    /// Verify a signature
    fn verify(&self, id: &[u8], message: &[u8], signature: Bytes) -> Result<bool, WalletError>;
}

/// Transaction dependency provider errors
#[derive(Error, Debug)]
pub enum TransactionDependencyError {
    #[error("the resource is not found in the provider: `{0}`")]
    NotFound(String),

    #[error("other error: `{0}`")]
    Other(#[from] Box<dyn std::error::Error>),
}

/// Provider dependency information of a transaction:
///   * inputs
///   * cell_deps
///   * header_deps
pub trait TransactionDependencyProvider {
    /// Please note that follow consensus fields are dummy values:
    ///   * `genesis_block`               (due to its big size, please load genesis block by your need)
    ///   * `pow`                         (not included in jsonrpc result)
    ///   * `genesis_epoch_ext`           (not included in jsonrpc result)
    ///   * `satoshi_pubkey_hash`         (not included in jsonrpc result)
    ///   * `satoshi_cell_occupied_ratio` (not included in jsonrpc result)
    fn get_consensus(&self) -> Result<Consensus, TransactionDependencyError>;
    // For verify certain cell belong to certain transaction
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError>;
    // For get the output information of inputs or cell_deps, those cell should be live cell
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError>;
    // For get the output data information of inputs or cell_deps
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError>;
    // For get the header information of header_deps
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError>;
}

// Implement CellDataProvider trait is currently for `DaoCalculator`
impl CellDataProvider for &dyn TransactionDependencyProvider {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        TransactionDependencyProvider::get_cell_data(*self, out_point).ok()
    }
    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        TransactionDependencyProvider::get_cell_data(*self, out_point)
            .ok()
            .map(|data| blake2b_256(data.as_ref()).pack())
    }
}
// Implement CellDataProvider trait is currently for `DaoCalculator`
impl EpochProvider for &dyn TransactionDependencyProvider {
    fn get_epoch_ext(&self, _block_header: &HeaderView) -> Option<EpochExt> {
        None
    }
    fn get_block_epoch(&self, _block_header: &HeaderView) -> Option<BlockEpoch> {
        None
    }
}
// Implement CellDataProvider trait is currently for `DaoCalculator`
impl HeaderProvider for &dyn TransactionDependencyProvider {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        TransactionDependencyProvider::get_header(*self, hash).ok()
    }
}
impl HeaderChecker for &dyn TransactionDependencyProvider {
    fn check_valid(&self, block_hash: &Byte32) -> Result<(), OutPointError> {
        TransactionDependencyProvider::get_header(*self, block_hash)
            .map(|_| ())
            .map_err(|_| OutPointError::InvalidHeader(block_hash.clone()))
    }
}
impl CellProvider for &dyn TransactionDependencyProvider {
    fn cell(&self, out_point: &OutPoint, _eager_load: bool) -> CellStatus {
        match self.get_transaction(&out_point.tx_hash()) {
            Ok(tx) => tx
                .outputs()
                .get(out_point.index().unpack())
                .map(|cell| {
                    let data = tx
                        .outputs_data()
                        .get(out_point.index().unpack())
                        .expect("output data");

                    let cell_meta = CellMetaBuilder::from_cell_output(cell, data.unpack())
                        .out_point(out_point.to_owned())
                        .build();

                    CellStatus::live_cell(cell_meta)
                })
                .unwrap_or(CellStatus::Unknown),
            Err(_err) => CellStatus::Unknown,
        }
    }
}

/// Cell collector errors
#[derive(Error, Debug)]
pub enum CellCollectorError {
    #[error("internal error: `{0}`")]
    Internal(Box<dyn std::error::Error>),

    #[error("other error: `{0}`")]
    Other(Box<dyn std::error::Error>),
}

#[derive(Debug, Clone)]
pub struct LiveCell {
    pub output: CellOutput,
    pub output_data: Bytes,
    pub out_point: OutPoint,
    pub block_number: u64,
    pub tx_index: u32,
}

/// The value range option: `start <= value < end`
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ValueRangeOption {
    pub start: u64,
    pub end: u64,
}
impl ValueRangeOption {
    pub fn new(start: u64, end: u64) -> ValueRangeOption {
        ValueRangeOption { start, end }
    }
    pub fn new_exact(value: u64) -> ValueRangeOption {
        ValueRangeOption {
            start: value,
            end: value + 1,
        }
    }
    pub fn new_min(start: u64) -> ValueRangeOption {
        ValueRangeOption {
            start,
            end: u64::max_value(),
        }
    }
    pub fn match_value(&self, value: u64) -> bool {
        self.start <= value && value < self.end
    }
}

/// The primary serach script type
///   * if primary script type is `lock` then secondary script type is `type`
///   * if primary script type is `type` then secondary script type is `lock`
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PrimaryScriptType {
    Lock,
    Type,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum MaturityOption {
    Mature,
    Immature,
    Both,
}
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CellQueryOptions {
    pub primary_script: Script,
    pub primary_type: PrimaryScriptType,
    pub secondary_script: Option<Script>,
    pub data_len_range: Option<ValueRangeOption>,
    pub capacity_range: Option<ValueRangeOption>,
    pub block_range: Option<ValueRangeOption>,

    /// Filter cell by its maturity
    pub maturity: MaturityOption,
    /// Try to collect at least `min_total_capacity` shannons of cells
    pub min_total_capacity: u64,
}
impl CellQueryOptions {
    pub fn new(primary_script: Script, primary_type: PrimaryScriptType) -> CellQueryOptions {
        CellQueryOptions {
            primary_script,
            primary_type,
            secondary_script: None,
            data_len_range: None,
            capacity_range: None,
            block_range: None,
            maturity: MaturityOption::Mature,
            min_total_capacity: 1,
        }
    }
    pub fn new_lock(primary_script: Script) -> CellQueryOptions {
        CellQueryOptions::new(primary_script, PrimaryScriptType::Lock)
    }
    pub fn new_type(primary_script: Script) -> CellQueryOptions {
        CellQueryOptions::new(primary_script, PrimaryScriptType::Type)
    }
    pub fn match_cell(&self, cell: &LiveCell, max_mature_number: Option<u64>) -> bool {
        fn extract_raw_data(script: &Script) -> Vec<u8> {
            [
                script.code_hash().as_slice(),
                script.hash_type().as_slice(),
                &script.args().raw_data(),
            ]
            .concat()
        }
        let filter_prefix = self.secondary_script.as_ref().map(|script| {
            if script != &Script::default() {
                extract_raw_data(script)
            } else {
                Vec::new()
            }
        });
        match self.primary_type {
            PrimaryScriptType::Lock => {
                // check primary script
                if cell.output.lock() != self.primary_script {
                    return false;
                }

                // if primary is `lock`, secondary is `type`
                if let Some(prefix) = filter_prefix {
                    if prefix.is_empty() {
                        if cell.output.type_().is_some() {
                            return false;
                        }
                    } else if cell
                        .output
                        .type_()
                        .to_opt()
                        .as_ref()
                        .map(extract_raw_data)
                        .filter(|data| data.starts_with(&prefix))
                        .is_none()
                    {
                        return false;
                    }
                }
            }
            PrimaryScriptType::Type => {
                // check primary script
                if cell.output.type_().to_opt().as_ref() != Some(&self.primary_script) {
                    return false;
                }

                // if primary is `type`, secondary is `lock`
                if let Some(prefix) = filter_prefix {
                    if !extract_raw_data(&cell.output.lock()).starts_with(&prefix) {
                        return false;
                    }
                }
            }
        }

        if let Some(range) = self.data_len_range {
            if !range.match_value(cell.output_data.len() as u64) {
                return false;
            }
        }
        if let Some(range) = self.capacity_range {
            let capacity: u64 = cell.output.capacity().unpack();
            if !range.match_value(capacity) {
                return false;
            }
        }
        if let Some(range) = self.block_range {
            if !range.match_value(cell.block_number) {
                return false;
            }
        }
        if let Some(max_mature_number) = max_mature_number {
            let cell_is_mature = is_mature(cell, max_mature_number);
            match self.maturity {
                MaturityOption::Mature if cell_is_mature => {}
                MaturityOption::Immature if !cell_is_mature => {}
                MaturityOption::Both => {}
                // Skip this live cell
                _ => return false,
            }
        }

        true
    }
}
pub trait CellCollector {
    /// Collect live cells by query options, if `apply_changes` is true will
    /// mark all collected cells as dead cells.
    fn collect_live_cells(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError>;

    /// Mark this cell as dead cell
    fn lock_cell(&mut self, out_point: OutPoint) -> Result<(), CellCollectorError>;
    /// Mark all inputs as dead cells and outputs as live cells in the transaction.
    fn apply_tx(&mut self, tx: Transaction) -> Result<(), CellCollectorError>;

    /// Clear cache and locked cells
    fn reset(&mut self);
}

pub trait CellDepResolver {
    fn resolve(&self, script_id: &ScriptId) -> Option<CellDep>;
}
