//! The traits defined here is intent to describe the requirements of current
//!  library code and only implemented the trait in upper level code.

pub mod default_impls;
pub mod dummy_impls;
pub mod light_client_impls;
pub mod offchain_impls;

pub use default_impls::{
    DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
    DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
};
pub use light_client_impls::{
    LightClientCellCollector, LightClientHeaderDepResolver,
    LightClientTransactionDependencyProvider,
};
pub use offchain_impls::{
    OffchainCellCollector, OffchainCellDepResolver, OffchainHeaderDepResolver,
    OffchainTransactionDependencyProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use ckb_hash::blake2b_256;
#[cfg(not(target_arch = "wasm32"))]
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
#[cfg(not(target_arch = "wasm32"))]
use ckb_types::core::{
    cell::{CellMetaBuilder, CellProvider, CellStatus, HeaderChecker},
    error::OutPointError,
};
use dyn_clone::DynClone;
use thiserror::Error;

use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, Transaction},
    prelude::*,
};

use crate::{rpc::ckb_indexer::SearchMode, util::is_mature};

/// Signer errors
#[derive(Error, Debug)]
pub enum SignerError {
    #[error("the id is not found in the signer")]
    IdNotFound,

    #[error("invalid message, reason: `{0}`")]
    InvalidMessage(String),

    #[error("invalid transaction, reason: `{0}`")]
    InvalidTransaction(String),

    // maybe hardware wallet error or io error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// A signer abstraction, support signer type:
///    * secp256k1 ckb signer
///    * secp256k1 eth signer
///    * RSA signer
///    * Hardware wallet signer
pub trait Signer: Send + Sync {
    /// typecial id are blake160(pubkey) and keccak256(pubkey)[12..20]
    fn match_id(&self, id: &[u8]) -> bool;

    /// `message` type is variable length, because different algorithm have
    /// different length of message:
    ///   * secp256k1 => 256bits
    ///   * RSA       => 512bits (when key size is 1024bits)
    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        tx: &TransactionView,
    ) -> Result<Bytes, SignerError>;
}

/// Transaction dependency provider errors
#[derive(Error, Debug)]
pub enum TransactionDependencyError {
    #[error("the resource is not found in the provider: `{0}`")]
    NotFound(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Provider dependency information of a transaction:
///   * inputs
///   * cell_deps
///   * header_deps
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait TransactionDependencyProvider: Sync + Send {
    async fn get_transaction_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError>;
    /// For get the output information of inputs or cell_deps, those cell should be live cell
    async fn get_cell_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<CellOutput, TransactionDependencyError>;
    /// For get the output data information of inputs or cell_deps
    async fn get_cell_data_async(
        &self,
        out_point: &OutPoint,
    ) -> Result<Bytes, TransactionDependencyError>;
    /// For get the header information of header_deps
    async fn get_header_async(
        &self,
        block_hash: &Byte32,
    ) -> Result<HeaderView, TransactionDependencyError>;

    /// For get_block_extension
    async fn get_block_extension_async(
        &self,
        block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError>;
    /// For verify certain cell belong to certain transaction
    #[cfg(not(target_arch = "wasm32"))]
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        crate::rpc::block_on(self.get_transaction_async(tx_hash))
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// For get the output information of inputs or cell_deps, those cell should be live cell
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError> {
        crate::rpc::block_on(self.get_cell_async(out_point))
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// For get the output data information of inputs or cell_deps
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError> {
        crate::rpc::block_on(self.get_cell_data_async(out_point))
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// For get the header information of header_deps
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError> {
        crate::rpc::block_on(self.get_header_async(block_hash))
    }

    /// For get_block_extension
    #[cfg(not(target_arch = "wasm32"))]
    fn get_block_extension(
        &self,
        block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError> {
        crate::rpc::block_on(self.get_block_extension_async(block_hash))
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
#[cfg(not(target_arch = "wasm32"))]
// Implement CellDataProvider trait is currently for `DaoCalculator`
impl HeaderProvider for &dyn TransactionDependencyProvider {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        TransactionDependencyProvider::get_header(*self, hash).ok()
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl HeaderChecker for &dyn TransactionDependencyProvider {
    fn check_valid(&self, block_hash: &Byte32) -> Result<(), OutPointError> {
        TransactionDependencyProvider::get_header(*self, block_hash)
            .map(|_| ())
            .map_err(|_| OutPointError::InvalidHeader(block_hash.clone()))
    }
}
#[cfg(not(target_arch = "wasm32"))]
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
#[cfg(not(target_arch = "wasm32"))]
impl ExtensionProvider for &dyn TransactionDependencyProvider {
    fn get_block_extension(&self, hash: &Byte32) -> Option<ckb_types::packed::Bytes> {
        match TransactionDependencyProvider::get_block_extension(*self, hash).ok() {
            Some(Some(bytes)) => Some(bytes),
            _ => None,
        }
    }
}

/// Cell collector errors
#[derive(Error, Debug)]
pub enum CellCollectorError {
    #[error(transparent)]
    Internal(anyhow::Error),

    #[error(transparent)]
    Other(anyhow::Error),
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
            end: u64::MAX,
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
pub enum QueryOrder {
    Desc,
    Asc,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CellQueryOptions {
    pub primary_script: Script,
    pub primary_type: PrimaryScriptType,
    pub with_data: Option<bool>,

    // Options for SearchKeyFilter
    pub secondary_script: Option<Script>,
    pub secondary_script_len_range: Option<ValueRangeOption>,
    pub data_len_range: Option<ValueRangeOption>,
    pub capacity_range: Option<ValueRangeOption>,
    pub block_range: Option<ValueRangeOption>,

    pub order: QueryOrder,
    pub limit: Option<u32>,
    /// Filter cell by its maturity
    pub maturity: MaturityOption,
    /// Try to collect at least `min_total_capacity` shannons of cells, if
    /// satisfied will stop collecting. The default value is 1 shannon means
    /// collect only one cell at most.
    pub min_total_capacity: u64,
    pub script_search_mode: Option<SearchMode>,
}
impl CellQueryOptions {
    pub fn new(primary_script: Script, primary_type: PrimaryScriptType) -> CellQueryOptions {
        CellQueryOptions {
            primary_script,
            primary_type,
            secondary_script: None,
            secondary_script_len_range: None,
            data_len_range: None,
            capacity_range: None,
            block_range: None,
            with_data: None,
            order: QueryOrder::Asc,
            limit: None,
            maturity: MaturityOption::Mature,
            min_total_capacity: 1,
            script_search_mode: None,
        }
    }
    pub fn new_lock(primary_script: Script) -> CellQueryOptions {
        CellQueryOptions::new(primary_script, PrimaryScriptType::Lock)
    }
    pub fn new_type(primary_script: Script) -> CellQueryOptions {
        CellQueryOptions::new(primary_script, PrimaryScriptType::Type)
    }
    pub fn match_cell(&self, cell: &LiveCell, max_mature_number: u64) -> bool {
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
        if let Some(range) = self.secondary_script_len_range {
            match self.primary_type {
                PrimaryScriptType::Lock => {
                    let script_len = cell
                        .output
                        .type_()
                        .to_opt()
                        .map(|script| extract_raw_data(&script).len())
                        .unwrap_or_default();
                    if !range.match_value(script_len as u64) {
                        return false;
                    }
                }
                PrimaryScriptType::Type => {
                    let script_len = extract_raw_data(&cell.output.lock()).len();
                    if !range.match_value(script_len as u64) {
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
        let cell_is_mature = is_mature(cell, max_mature_number);
        match self.maturity {
            MaturityOption::Mature => cell_is_mature,
            MaturityOption::Immature => !cell_is_mature,
            MaturityOption::Both => true,
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait CellCollector: DynClone + Send + Sync {
    /// Collect live cells by query options, if `apply_changes` is true will
    /// mark all collected cells as dead cells.
    async fn collect_live_cells_async(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError>;
    /// Collect live cells by query options, if `apply_changes` is true will
    /// mark all collected cells as dead cells.
    #[cfg(not(target_arch = "wasm32"))]
    fn collect_live_cells(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        crate::rpc::block_on(self.collect_live_cells_async(query, apply_changes))
    }

    /// Mark this cell as dead cell
    fn lock_cell(
        &mut self,
        out_point: OutPoint,
        tip_block_number: u64,
    ) -> Result<(), CellCollectorError>;
    /// Mark all inputs as dead cells and outputs as live cells in the transaction.
    fn apply_tx(
        &mut self,
        tx: Transaction,
        tip_block_number: u64,
    ) -> Result<(), CellCollectorError>;

    /// Clear cache and locked cells
    fn reset(&mut self);
}

pub trait CellDepResolver: Send + Sync {
    /// Resolve cell dep by script.
    ///
    /// When a new script is added, transaction builders use CellDepResolver to find the corresponding cell deps and add them to the transaction.
    fn resolve(&self, script: &Script) -> Option<CellDep>;
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait HeaderDepResolver: Send + Sync {
    /// Resolve header dep by trancation hash
    async fn resolve_by_tx_async(
        &self,
        tx_hash: &Byte32,
    ) -> Result<Option<HeaderView>, anyhow::Error>;

    /// Resolve header dep by block number
    async fn resolve_by_number_async(
        &self,
        number: u64,
    ) -> Result<Option<HeaderView>, anyhow::Error>;
    #[cfg(not(target_arch = "wasm32"))]
    /// Resolve header dep by trancation hash
    fn resolve_by_tx(&self, tx_hash: &Byte32) -> Result<Option<HeaderView>, anyhow::Error> {
        crate::rpc::block_on(self.resolve_by_tx_async(tx_hash))
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// Resolve header dep by block number
    fn resolve_by_number(&self, number: u64) -> Result<Option<HeaderView>, anyhow::Error> {
        crate::rpc::block_on(self.resolve_by_number_async(number))
    }
}

// test cases make sure new added exception won't breadk `anyhow!(e_variable)` usage,
#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_signer_error() {
        use super::SignerError;
        let error = anyhow!(SignerError::IdNotFound);
        assert_eq!("the id is not found in the signer", error.to_string());
        let error = anyhow!(SignerError::InvalidMessage("InvalidMessage".to_string()));
        assert_eq!(
            "invalid message, reason: `InvalidMessage`",
            error.to_string()
        );
        let error = anyhow!(SignerError::InvalidTransaction(
            "InvalidTransaction".to_string()
        ));
        assert_eq!(
            "invalid transaction, reason: `InvalidTransaction`",
            error.to_string()
        );
        let error = anyhow!(SignerError::Other(anyhow::anyhow!("Other")));
        assert_eq!("Other", error.to_string());
    }

    #[test]
    fn test_transaction_dependency_error() {
        use super::TransactionDependencyError;
        let error = TransactionDependencyError::NotFound("NotFound".to_string());
        let error = anyhow!(error);

        assert_eq!(
            "the resource is not found in the provider: `NotFound`",
            error.to_string()
        );
    }

    #[test]
    fn test_cell_collector_error() {
        use super::CellCollectorError;
        let error = CellCollectorError::Internal(anyhow!("Internel"));
        let error = anyhow!(error);
        assert_eq!("Internel", error.to_string());

        let error = CellCollectorError::Other(anyhow!("Other"));
        let error = anyhow!(error);
        assert_eq!("Other", error.to_string());
    }
}
