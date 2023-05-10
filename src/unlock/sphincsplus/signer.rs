use ckb_types::{
    core::TransactionView,
    packed::{self, WitnessArgs},
    prelude::{Builder, Entity, Pack},
};

use crate::{
    traits::Signer,
    unlock::{generate_message, ScriptSignError, ScriptSigner},
    ScriptGroup,
};

use super::SphincsPlus;

/// Signer for spincs plus lock script
pub struct SphincsPlusSigner {
    signer: Box<dyn Signer>,
}

impl SphincsPlusSigner {
    pub fn new(signer: Box<dyn Signer>) -> Self {
        SphincsPlusSigner { signer }
    }

    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    fn sign_tx_with_owner_id(
        &self,
        owner_id: &[u8],
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        let tx_new = tx
            .as_advanced_builder()
            .set_witnesses(witnesses.clone())
            .build();

        let zero_lock = SphincsPlus::zero_lock();
        let message = generate_message(&tx_new, script_group, zero_lock)?;

        let signature = self.signer.sign(owner_id, message.as_ref(), true, tx)?;

        // Put signature into witness
        let witness_data = witnesses[witness_idx].raw_data();
        let mut current_witness: WitnessArgs = if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref())?
        };
        current_witness = current_witness
            .as_builder()
            .lock(Some(signature).pack())
            .build();
        witnesses[witness_idx] = current_witness.as_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }
}

impl ScriptSigner for SphincsPlusSigner {
    fn match_args(&self, args: &[u8]) -> bool {
        args.len() == 32 && self.signer.match_id(args)
    }

    fn sign_tx(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, ScriptSignError> {
        let args = script_group.script.args().raw_data();
        self.sign_tx_with_owner_id(args.as_ref(), tx, script_group)
    }
}
