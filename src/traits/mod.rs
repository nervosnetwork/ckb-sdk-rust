//! The traits defined here is intent to describe the requirements of current
//!  library code and only implemented the trait in upper level code.

pub mod default_impls;
pub mod dummy_impls;


pub use default_impls:: SecpCkbRawKeySigner;
use thiserror::Error;

use ckb_hash::blake2b_256;
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, CellProvider, CellStatus, HeaderChecker},
        error::OutPointError,
        HeaderView, TransactionView,
    },
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script},
    prelude::*,
};

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
pub trait Signer {
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
pub trait TransactionDependencyProvider: Sync + Send {
    /// For verify certain cell belong to certain transaction
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError>;
    /// For get the output information of inputs or cell_deps, those cell should be live cell
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError>;
    /// For get the output data information of inputs or cell_deps
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError>;
    /// For get the header information of header_deps
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError>;

    /// For get_block_extension
    fn get_block_extension(
        &self,
        block_hash: &Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, TransactionDependencyError>;
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


pub trait CellDepResolver {
    /// Resolve cell dep by script.
    ///
    /// When a new script is added, transaction builders use CellDepResolver to find the corresponding cell deps and add them to the transaction.
    fn resolve(&self, script: &Script) -> Option<CellDep>;
}
pub trait HeaderDepResolver {
    /// Resolve header dep by trancation hash
    fn resolve_by_tx(&self, tx_hash: &Byte32) -> Result<Option<HeaderView>, anyhow::Error>;

    /// Resolve header dep by block number
    fn resolve_by_number(&self, number: u64) -> Result<Option<HeaderView>, anyhow::Error>;
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
