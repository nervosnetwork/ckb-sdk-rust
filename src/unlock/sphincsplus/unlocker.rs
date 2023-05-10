use ckb_types::core::TransactionView;

use crate::{
    traits::{Signer, TransactionDependencyProvider},
    unlock::{fill_witness_lock, ScriptSigner, ScriptUnlocker, UnlockError},
    ScriptGroup,
};

use super::{signer::SphincsPlusSigner, SphincsPlus};

pub struct SphincsPlusUnlocker {
    signer: SphincsPlusSigner,
}
impl SphincsPlusUnlocker {
    pub fn new(signer: SphincsPlusSigner) -> Self {
        Self { signer }
    }
}
impl From<Box<dyn Signer>> for SphincsPlusUnlocker {
    fn from(signer: Box<dyn Signer>) -> SphincsPlusUnlocker {
        SphincsPlusUnlocker::new(SphincsPlusSigner::new(signer))
    }
}

impl ScriptUnlocker for SphincsPlusUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group)?)
    }

    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        fill_witness_lock(tx, script_group, SphincsPlus::zero_lock())
    }
}
