use std::collections::HashMap;

use ckb_types::{core, packed};

use crate::{
    traits::SecpCkbRawKeySigner,
    unlock::{
        OmniLockConfig, OmniLockScriptSigner, OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker,
        UnlockError,
    },
};

use super::{CKBScriptSigner, SignContext};

pub struct OmnilockSigner {}

pub struct OmnilockSignerContext {
    keys: Vec<secp256k1::SecretKey>,
    cfg: OmniLockConfig,
    unlock_mode: OmniUnlockMode,
}

impl OmnilockSignerContext {
    pub fn new(keys: Vec<secp256k1::SecretKey>, cfg: OmniLockConfig) -> Self {
        Self {
            keys,
            cfg,
            unlock_mode: OmniUnlockMode::Normal,
        }
    }

    pub fn build_omnilock_unlocker(&self) -> OmniLockUnlocker {
        let signer = if self.cfg.is_ethereum() {
            SecpCkbRawKeySigner::new_with_ethereum_secret_keys(self.keys.clone())
        } else {
            SecpCkbRawKeySigner::new_with_secret_keys(self.keys.clone())
        };
        let omnilock_signer =
            OmniLockScriptSigner::new(Box::new(signer), self.cfg.clone(), self.unlock_mode);
        OmniLockUnlocker::new(omnilock_signer, self.cfg.clone())
    }
}

impl SignContext for OmnilockSignerContext {}

impl CKBScriptSigner for OmnilockSigner {
    fn match_context(&self, context: &dyn SignContext) -> bool {
        context.as_any().is::<OmnilockSignerContext>()
    }
    fn sign_transaction(
        &self,
        transaction: &core::TransactionView,
        script_group: &crate::ScriptGroup,
        context: &dyn super::SignContext,
        inputs: &HashMap<packed::OutPoint, (packed::CellOutput, bytes::Bytes)>,
    ) -> Result<core::TransactionView, UnlockError> {
        if let Some(args) = context.as_any().downcast_ref::<OmnilockSignerContext>() {
            let unlocker = args.build_omnilock_unlocker();
            let tx = unlocker.unlock(transaction, script_group, &InputsProvider { inputs } as _)?;
            Ok(tx)
        } else {
            Err(UnlockError::SignContextTypeIncorrect)
        }
    }
}

struct InputsProvider<'a> {
    inputs: &'a HashMap<packed::OutPoint, (packed::CellOutput, bytes::Bytes)>,
}

impl<'a> crate::traits::TransactionDependencyProvider for InputsProvider<'a> {
    /// For verify certain cell belong to certain transaction
    fn get_transaction(
        &self,
        _tx_hash: &packed::Byte32,
    ) -> Result<core::TransactionView, crate::traits::TransactionDependencyError> {
        Err(crate::traits::TransactionDependencyError::NotFound(
            "not support".to_string(),
        ))
    }
    /// For get the output information of inputs or cell_deps, those cell should be live cell
    fn get_cell(
        &self,
        out_point: &packed::OutPoint,
    ) -> Result<packed::CellOutput, crate::traits::TransactionDependencyError> {
        self.inputs.get(out_point).map(|a| a.0.clone()).ok_or(
            crate::traits::TransactionDependencyError::NotFound("not found".to_string()),
        )
    }
    /// For get the output data information of inputs or cell_deps
    fn get_cell_data(
        &self,
        out_point: &packed::OutPoint,
    ) -> Result<bytes::Bytes, crate::traits::TransactionDependencyError> {
        self.inputs.get(out_point).map(|a| a.1.clone()).ok_or(
            crate::traits::TransactionDependencyError::NotFound("not found".to_string()),
        )
    }
    /// For get the header information of header_deps
    fn get_header(
        &self,
        _block_hash: &packed::Byte32,
    ) -> Result<core::HeaderView, crate::traits::TransactionDependencyError> {
        Err(crate::traits::TransactionDependencyError::NotFound(
            "not support".to_string(),
        ))
    }

    /// For get_block_extension
    fn get_block_extension(
        &self,
        _block_hash: &packed::Byte32,
    ) -> Result<Option<ckb_types::packed::Bytes>, crate::traits::TransactionDependencyError> {
        Err(crate::traits::TransactionDependencyError::NotFound(
            "not support".to_string(),
        ))
    }
}
