//! The traits defined here is intent to describe the requirements of current
//!  library code and only implemented the trait in upper level code.

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
    packed::{Byte32, CellOutput, Header, OutPoint, Transaction},
    prelude::*,
};
use thiserror::Error;

/// Wallet errors
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("the id is not found in the wallet")]
    IdNotFound,
    #[error("invalid message, reason: `{0}`")]
    InvalidMessage(String),
    #[error("get transaction dependency failed: `{0}`")]
    TxDep(#[from] TxDepProviderError),

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
pub enum TxDepProviderError {
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
    fn get_consensus(&self) -> Result<Consensus, TxDepProviderError>;
    // For verify certain cell belong to certain transaction
    fn get_transaction(&self, tx_hash: &Byte32) -> Result<Transaction, TxDepProviderError>;
    // For get the output information of inputs or cell_deps, those cell should be live cell
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TxDepProviderError>;
    // For get the output data information of inputs or cell_deps
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TxDepProviderError>;
    // For get the header information of header_deps
    fn get_header(&self, block_hash: &Byte32) -> Result<Header, TxDepProviderError>;
    // Gets corresponding `EpochExt` by block hash (NOTE: for dao calculation)
    fn get_epoch_ext(&self, block_hash: &Byte32) -> Result<EpochExt, TxDepProviderError>;
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
    fn get_epoch_ext(&self, block_header: &HeaderView) -> Option<EpochExt> {
        TransactionDependencyProvider::get_epoch_ext(*self, &block_header.hash()).ok()
    }
    fn get_block_epoch(&self, _block_header: &HeaderView) -> Option<BlockEpoch> {
        None
    }
}
// Implement CellDataProvider trait is currently for `DaoCalculator`
impl HeaderProvider for &dyn TransactionDependencyProvider {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        TransactionDependencyProvider::get_header(*self, hash)
            .map(|header| header.into_view())
            .ok()
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
        match self
            .get_transaction(&out_point.tx_hash())
            .map(|tx| tx.into_view())
        {
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

/// An empty transaction dependency provider, this provider will return Err(NotFound) in all cases.
/// This struct may useful for sign a transaction
pub struct EmptyTxDepProvider;

impl TransactionDependencyProvider for EmptyTxDepProvider {
    fn get_consensus(&self) -> Result<Consensus, TxDepProviderError> {
        unimplemented!()
    }
    fn get_transaction(&self, tx_hash: &Byte32) -> Result<Transaction, TxDepProviderError> {
        Err(TxDepProviderError::NotFound(format!(
            "transaction: {}",
            tx_hash
        )))
    }
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TxDepProviderError> {
        Err(TxDepProviderError::NotFound(format!("cell: {}", out_point)))
    }
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TxDepProviderError> {
        Err(TxDepProviderError::NotFound(format!(
            "cell data: {}",
            out_point
        )))
    }
    fn get_header(&self, block_hash: &Byte32) -> Result<Header, TxDepProviderError> {
        Err(TxDepProviderError::NotFound(format!(
            "header: {}",
            block_hash
        )))
    }
    fn get_epoch_ext(&self, block_hash: &Byte32) -> Result<EpochExt, TxDepProviderError> {
        Err(TxDepProviderError::NotFound(format!(
            "epoch ext: {}",
            block_hash
        )))
    }
}
