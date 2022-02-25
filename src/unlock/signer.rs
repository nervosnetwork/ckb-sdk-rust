use ckb_hash::new_blake2b;
use ckb_script::ScriptGroup;
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    error::VerificationError,
    packed::{self, WitnessArgs},
    prelude::*,
};
use thiserror::Error;

use crate::traits::{TransactionDependencyProvider, TxDepProviderError, WalletError};

#[derive(Error, Debug)]
pub enum SignError {
    #[error("wallet error: `{0}`")]
    Wallet(#[from] WalletError),

    #[error("transaction dependency error: `{0}`")]
    TxDep(#[from] TxDepProviderError),

    #[error("witness count in current transaction not enough to cover current script group")]
    WitnessNotEnough,

    #[error("the witness is not empty and not WitnessArgs format: `{0}`")]
    InvalidWitnessArgs(#[from] VerificationError),

    #[error("other error: `{0}`")]
    Other(#[from] Box<dyn std::error::Error>),
}

/// Script signer logic:
///   * Generate message to sign
///   * Sign the message by wallet
///   * Put the signature into tx.witnesses
pub trait ScriptSigner {
    fn match_args(&self, args: Bytes) -> bool;

    /// Add signature information to witnesses
    fn sign_tx(
        &self,
        tx: TransactionView,
        script_group: ScriptGroup,
        // This argument is for inner wallet to use
        tx_dep_provider: &mut dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, SignError>;

    /// Common logic of generate message for certain script group. Overwrite
    /// this method to support special use case.
    fn genrate_message(
        &self,
        tx: TransactionView,
        script_group: ScriptGroup,
        zero_lock: Bytes,
    ) -> Result<Bytes, SignError> {
        if tx.witnesses().item_count() <= script_group.input_indices[0] {
            return Err(SignError::WitnessNotEnough);
        }

        let witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        let witness_data = witnesses[script_group.input_indices[0]].raw_data();
        let mut init_witness = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };
        init_witness = init_witness
            .as_builder()
            .lock(Some(zero_lock).pack())
            .build();
        // Other witnesses in current script group
        let other_witnesses: Vec<([u8; 8], Bytes)> = script_group
            .input_indices
            .iter()
            .skip(1)
            .filter_map(|idx| witnesses.get(*idx))
            .map(|witness| {
                (
                    (witness.item_count() as u64).to_le_bytes(),
                    witness.raw_data(),
                )
            })
            .collect();
        // The witnesses not covered by any inputs
        let outter_witnesses: Vec<([u8; 8], Bytes)> = if tx.inputs().len() < witnesses.len() {
            witnesses[tx.inputs().len()..witnesses.len()]
                .iter()
                .map(|witness| {
                    (
                        (witness.item_count() as u64).to_le_bytes(),
                        witness.raw_data(),
                    )
                })
                .collect()
        } else {
            Default::default()
        };

        let mut blake2b = new_blake2b();
        blake2b.update(tx.hash().as_slice());
        blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
        blake2b.update(&init_witness.as_bytes());
        for (len_le, data) in other_witnesses {
            blake2b.update(&len_le);
            blake2b.update(&data);
        }
        for (len_le, data) in outter_witnesses {
            blake2b.update(&len_le);
            blake2b.update(&data);
        }
        let mut message = vec![0u8; 32];
        blake2b.finalize(&mut message);
        Ok(Bytes::from(message))
    }
}
