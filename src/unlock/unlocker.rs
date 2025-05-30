use anyhow::anyhow;
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, Byte32, BytesOpt, WitnessArgs},
    prelude::*,
};
use thiserror::Error;

use super::{
    omni_lock::{ConfigError, OmniLockFlags},
    signer::{
        AcpScriptSigner, ChequeAction, ChequeScriptSigner, MultisigConfig, ScriptSignError,
        ScriptSigner, SecpMultisigScriptSigner, SecpSighashScriptSigner,
    },
    OmniLockConfig, OmniLockScriptSigner, OmniUnlockMode,
};
use crate::traits::{Signer, TransactionDependencyError, TransactionDependencyProvider};
use crate::types::ScriptGroup;

const CHEQUE_CLAIM_SINCE: u64 = 0;
const CHEQUE_WITHDRAW_SINCE: u64 = 0xA000000000000006;

#[derive(Error, Debug)]
pub enum UnlockError {
    #[error("sign script error: `{0}`")]
    ScriptSigner(#[from] ScriptSignError),

    #[error("transaction dependency error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),

    #[error("invalid witness args: witness index=`{0}`")]
    InvalidWitnessArgs(usize),

    #[error("there is an configuration error: `{0}`")]
    InvalidConfig(#[from] ConfigError),

    #[error("sign context is incorrect")]
    SignContextTypeIncorrect,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Script unlock logic:
///   * Parse the script.args
///   * Sign the transaction
///   * Put extra unlock information into transaction (e.g. SMT proof in omni-lock case)
///
/// See example in `examples/script_unlocker_example.rs`
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ScriptUnlocker: Sync + Send {
    fn match_args(&self, args: &[u8]) -> bool;

    /// Check if the script group is already unlocked
    async fn is_unlocked_async(
        &self,
        _tx: &TransactionView,
        _script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        Ok(false)
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn is_unlocked(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        crate::rpc::block_on(self.is_unlocked_async(tx, script_group, tx_dep_provider))
    }

    /// Add signature or other information to witnesses, when the script is
    /// already unlocked should reset the witness instead.
    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError>;
    #[cfg(not(target_arch = "wasm32"))]
    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        crate::rpc::block_on(self.unlock_async(tx, script_group, tx_dep_provider))
    }

    fn clear_placeholder_witness(
        &self,
        tx: &TransactionView,
        _script_group: &ScriptGroup,
    ) -> Result<TransactionView, UnlockError> {
        Ok(tx.clone())
    }

    /// Fill a placehodler witness before balance the transaction capacity
    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError>;
    #[cfg(not(target_arch = "wasm32"))]
    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        crate::rpc::block_on(self.fill_placeholder_witness_async(tx, script_group, tx_dep_provider))
    }
}

pub fn fill_witness_lock(
    tx: &TransactionView,
    script_group: &ScriptGroup,
    lock_field: Bytes,
) -> Result<TransactionView, UnlockError> {
    let witness_idx = script_group.input_indices[0];
    let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    while witnesses.len() <= witness_idx {
        witnesses.push(Default::default());
    }
    let witness_data = witnesses[witness_idx].raw_data();
    let mut witness = if witness_data.is_empty() {
        WitnessArgs::default()
    } else {
        WitnessArgs::from_slice(witness_data.as_ref())
            .map_err(|_| UnlockError::InvalidWitnessArgs(witness_idx))?
    };
    if witness.lock().is_none() {
        witness = witness.as_builder().lock(Some(lock_field).pack()).build();
    }
    witnesses[witness_idx] = witness.as_bytes().pack();
    Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
}

pub fn reset_witness_lock(
    tx: TransactionView,
    witness_idx: usize,
) -> Result<TransactionView, usize> {
    let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    if let Some(witness_data) = witnesses
        .get(witness_idx)
        .map(|data| data.raw_data())
        .filter(|data| !data.is_empty())
    {
        let witness = WitnessArgs::from_slice(witness_data.as_ref()).map_err(|_| witness_idx)?;
        let data = if witness.input_type().is_none() && witness.output_type().is_none() {
            Bytes::default()
        } else {
            witness
                .as_builder()
                .lock(BytesOpt::default())
                .build()
                .as_bytes()
        };
        witnesses[witness_idx] = data.pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    } else {
        Ok(tx)
    }
}

pub struct SecpSighashUnlocker {
    signer: SecpSighashScriptSigner,
}
impl SecpSighashUnlocker {
    pub fn new(signer: SecpSighashScriptSigner) -> SecpSighashUnlocker {
        SecpSighashUnlocker { signer }
    }
}
impl From<Box<dyn Signer>> for SecpSighashUnlocker {
    fn from(signer: Box<dyn Signer>) -> SecpSighashUnlocker {
        SecpSighashUnlocker::new(SecpSighashScriptSigner::new(signer))
    }
}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptUnlocker for SecpSighashUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group)?)
    }

    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        fill_witness_lock(tx, script_group, Bytes::from(vec![0u8; 65]))
    }
}

pub struct SecpMultisigUnlocker {
    signer: SecpMultisigScriptSigner,
}
impl SecpMultisigUnlocker {
    pub fn new(signer: SecpMultisigScriptSigner) -> SecpMultisigUnlocker {
        SecpMultisigUnlocker { signer }
    }
}
impl From<(Box<dyn Signer>, MultisigConfig)> for SecpMultisigUnlocker {
    fn from((signer, config): (Box<dyn Signer>, MultisigConfig)) -> SecpMultisigUnlocker {
        SecpMultisigUnlocker::new(SecpMultisigScriptSigner::new(signer, config))
    }
}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptUnlocker for SecpMultisigUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        (args.len() == 20 || args.len() == 28) && self.signer.match_args(args)
    }

    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group)?)
    }

    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        let config = self.signer.config();
        let config_data = config.to_witness_data();
        let mut zero_lock = vec![0u8; config_data.len() + 65 * (config.threshold() as usize)];
        zero_lock[0..config_data.len()].copy_from_slice(&config_data);
        fill_witness_lock(tx, script_group, Bytes::from(zero_lock))
    }
}

pub struct AcpUnlocker {
    signer: AcpScriptSigner,
}

impl AcpUnlocker {
    pub fn new(signer: AcpScriptSigner) -> AcpUnlocker {
        AcpUnlocker { signer }
    }
}
impl From<Box<dyn Signer>> for AcpUnlocker {
    fn from(signer: Box<dyn Signer>) -> AcpUnlocker {
        AcpUnlocker::new(AcpScriptSigner::new(signer))
    }
}

async fn acp_is_unlocked(
    tx: &TransactionView,
    script_group: &ScriptGroup,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    acp_args: &[u8],
) -> Result<bool, UnlockError> {
    const POW10: [u64; 20] = [
        1,
        10,
        100,
        1000,
        10000,
        100000,
        1000000,
        10000000,
        100000000,
        1000000000,
        10000000000,
        100000000000,
        1000000000000,
        10000000000000,
        100000000000000,
        1000000000000000,
        10000000000000000,
        100000000000000000,
        1000000000000000000,
        10000000000000000000,
    ];
    let min_ckb_amount = if acp_args.is_empty() {
        0
    } else {
        let idx = acp_args[0];
        if idx >= 20 {
            return Err(UnlockError::Other(anyhow!("invalid min ckb amount config in script.args, got: {}, expected: value >=0 and value < 20", idx)));
        }
        POW10[idx as usize]
    };
    let min_udt_amount = if acp_args.len() > 1 {
        let idx = acp_args[1];
        if idx >= 39 {
            return Err(UnlockError::Other(anyhow!("invalid min udt amount config in script.args, got: {}, expected: value >=0 and value < 39", idx)));
        }
        if idx >= 20 {
            (POW10[19] as u128) * (POW10[idx as usize - 19] as u128)
        } else {
            POW10[idx as usize] as u128
        }
    } else {
        0
    };

    struct InputWallet {
        type_hash_opt: Option<Byte32>,
        ckb_amount: u64,
        udt_amount: u128,
        output_cnt: usize,
    }
    let mut input_wallets = Vec::new();

    for idx in script_group.input_indices.iter() {
        let input = tx
            .inputs()
            .get(*idx)
            .ok_or_else(|| anyhow!("input index in script group is out of bound: {}", idx))?;
        let output = tx_dep_provider
            .get_cell_async(&input.previous_output())
            .await?;
        let output_data = tx_dep_provider
            .get_cell_data_async(&input.previous_output())
            .await?;

        let type_hash_opt = output
            .type_()
            .to_opt()
            .map(|script| script.calc_script_hash());
        if type_hash_opt.is_some() && output_data.len() < 16 {
            return Err(UnlockError::Other(anyhow!(
                "invalid udt output data in input cell: {:?}",
                input
            )));
        }
        let udt_amount = if type_hash_opt.is_some() {
            let mut amount_bytes = [0u8; 16];
            amount_bytes.copy_from_slice(&output_data[0..16]);
            u128::from_le_bytes(amount_bytes)
        } else {
            0
        };
        input_wallets.push(InputWallet {
            type_hash_opt,
            ckb_amount: output.capacity().unpack(),
            udt_amount,
            output_cnt: 0,
        })
    }

    for (output_idx, output) in tx.outputs().into_iter().enumerate() {
        if output.lock() != script_group.script {
            continue;
        }
        let output_data: Bytes = tx
            .outputs_data()
            .get(output_idx)
            .map(|data| data.raw_data())
            .ok_or_else(|| {
                anyhow!(
                    "output data index in script group is out of bound: {}",
                    output_idx
                )
            })?;
        let type_hash_opt = output
            .type_()
            .to_opt()
            .map(|script| script.calc_script_hash());
        if type_hash_opt.is_some() && output_data.len() < 16 {
            return Err(UnlockError::Other(anyhow!(
                "invalid udt output data in output cell: index={}",
                output_idx
            )));
        }
        let ckb_amount: u64 = output.capacity().unpack();
        let udt_amount = if type_hash_opt.is_some() {
            let mut amount_bytes = [0u8; 16];
            amount_bytes.copy_from_slice(&output_data[0..16]);
            u128::from_le_bytes(amount_bytes)
        } else {
            0
        };
        let mut found_inputs = 0;
        for input_wallet in &mut input_wallets {
            if input_wallet.type_hash_opt == type_hash_opt {
                let (min_output_ckb_amount, ckb_overflow) =
                    input_wallet.ckb_amount.overflowing_add(min_ckb_amount);
                let meet_ckb_cond = !ckb_overflow && ckb_amount >= min_output_ckb_amount;
                let (min_output_udt_amount, udt_overflow) =
                    input_wallet.udt_amount.overflowing_add(min_udt_amount);
                let meet_udt_cond = !udt_overflow && udt_amount >= min_output_udt_amount;
                if !(meet_ckb_cond || meet_udt_cond) {
                    // ERROR_OUTPUT_AMOUNT_NOT_ENOUGH
                    return Ok(false);
                }
                if (!meet_ckb_cond && ckb_amount != input_wallet.ckb_amount)
                    || (!meet_udt_cond && udt_amount != input_wallet.udt_amount)
                {
                    // ERROR_OUTPUT_AMOUNT_NOT_ENOUGH
                    return Ok(false);
                }
                found_inputs += 1;
                input_wallet.output_cnt += 1;
                if found_inputs > 1 {
                    // ERROR_DUPLICATED_INPUTS
                    return Ok(false);
                }
                if input_wallet.output_cnt > 1 {
                    // ERROR_DUPLICATED_OUTPUTS
                    return Ok(false);
                }
            }
        }
        if found_inputs != 1 {
            // ERROR_NO_PAIR + ERROR_DUPLICATED_INPUTS
            return Ok(false);
        }
    }
    for input_wallet in &input_wallets {
        if input_wallet.output_cnt != 1 {
            // ERROR_NO_PAIR + ERROR_DUPLICATED_OUTPUTS
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptUnlocker for AcpUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    async fn is_unlocked_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        let raw_data = script_group.script.args().raw_data();
        let acp_args = {
            let data = raw_data.as_ref();
            if data.len() > 20 {
                &data[20..]
            } else {
                &[]
            }
        };
        acp_is_unlocked(tx, script_group, tx_dep_provider, acp_args).await
    }

    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self
            .is_unlocked_async(tx, script_group, tx_dep_provider)
            .await?
        {
            self.clear_placeholder_witness(tx, script_group)
        } else {
            Ok(self.signer.sign_tx(tx, script_group)?)
        }
    }

    fn clear_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, UnlockError> {
        reset_witness_lock(tx.clone(), script_group.input_indices[0])
            .map_err(UnlockError::InvalidWitnessArgs)
    }

    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self
            .is_unlocked_async(tx, script_group, tx_dep_provider)
            .await?
        {
            Ok(tx.clone())
        } else {
            fill_witness_lock(tx, script_group, Bytes::from(vec![0u8; 65]))
        }
    }
}

pub struct ChequeUnlocker {
    signer: ChequeScriptSigner,
}
impl ChequeUnlocker {
    pub fn new(signer: ChequeScriptSigner) -> ChequeUnlocker {
        ChequeUnlocker { signer }
    }
}
impl From<(Box<dyn Signer>, ChequeAction)> for ChequeUnlocker {
    fn from((signer, action): (Box<dyn Signer>, ChequeAction)) -> ChequeUnlocker {
        ChequeUnlocker::new(ChequeScriptSigner::new(signer, action))
    }
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptUnlocker for ChequeUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    async fn is_unlocked_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        let args = script_group.script.args().raw_data();
        if args.len() != 40 {
            return Err(UnlockError::Other(anyhow!(
                "invalid script args length, expected: 40, got: {}",
                args.len()
            )));
        }
        let inputs: Vec<_> = tx.inputs().into_iter().collect();
        let group_since_list: Vec<u64> = script_group
            .input_indices
            .iter()
            .map(|idx| inputs[*idx].since().unpack())
            .collect();

        // Check if unlocked via lock hash in inputs
        let receiver_lock_hash = &args.as_ref()[0..20];
        let sender_lock_hash = &args.as_ref()[20..40];
        let mut receiver_lock_witness = None;
        let mut sender_lock_witness = None;
        for (input_idx, input) in inputs.into_iter().enumerate() {
            let output = tx_dep_provider
                .get_cell_async(&input.previous_output())
                .await?;
            let lock_hash = output.lock().calc_script_hash();
            let lock_hash_prefix = &lock_hash.as_slice()[0..20];
            let witness = tx
                .witnesses()
                .get(input_idx)
                .map(|witness| witness.raw_data())
                .unwrap_or_default();

            #[allow(clippy::collapsible_if)]
            if lock_hash_prefix == receiver_lock_hash {
                if receiver_lock_witness.is_none() {
                    receiver_lock_witness = Some((input_idx, witness));
                }
            } else if lock_hash_prefix == sender_lock_hash {
                if sender_lock_witness.is_none() {
                    sender_lock_witness = Some((input_idx, witness));
                }
            }
        }
        // NOTE: receiver has higher priority than sender
        if self.signer.action() == ChequeAction::Claim {
            if let Some((_input_idx, witness)) = receiver_lock_witness {
                if group_since_list
                    .iter()
                    .any(|since| *since != CHEQUE_CLAIM_SINCE)
                {
                    return Err(UnlockError::Other(anyhow!(
                        "claim action must have all zero since in cheque inputs"
                    )));
                }
                let witness_args = match WitnessArgs::from_slice(witness.as_ref()) {
                    Ok(args) => args,
                    Err(_) => {
                        return Ok(false);
                    }
                };
                if witness_args.lock().to_opt().is_none() {
                    return Ok(false);
                }
                return Ok(true);
            }
        } else if let Some((_input_idx, witness)) = sender_lock_witness {
            if group_since_list
                .iter()
                .any(|since| *since != CHEQUE_WITHDRAW_SINCE)
            {
                return Err(UnlockError::Other(anyhow!(
                    "withdraw action must have all relative 6 epochs since in cheque inputs"
                )));
            }
            let witness_args = match WitnessArgs::from_slice(witness.as_ref()) {
                Ok(args) => args,
                Err(_) => {
                    return Ok(false);
                }
            };
            if witness_args.lock().to_opt().is_none() {
                return Ok(false);
            }
            return Ok(true);
        }
        Ok(false)
    }

    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self
            .is_unlocked_async(tx, script_group, tx_dep_provider)
            .await?
        {
            self.clear_placeholder_witness(tx, script_group)
        } else {
            Ok(self.signer.sign_tx(tx, script_group)?)
        }
    }

    fn clear_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
    ) -> Result<TransactionView, UnlockError> {
        reset_witness_lock(tx.clone(), script_group.input_indices[0])
            .map_err(UnlockError::InvalidWitnessArgs)
    }

    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self
            .is_unlocked_async(tx, script_group, tx_dep_provider)
            .await?
        {
            Ok(tx.clone())
        } else {
            fill_witness_lock(tx, script_group, Bytes::from(vec![0u8; 65]))
        }
    }
}

pub struct OmniLockUnlocker {
    signer: OmniLockScriptSigner,
    config: OmniLockConfig,
}
impl OmniLockUnlocker {
    pub fn new(signer: OmniLockScriptSigner, config: OmniLockConfig) -> OmniLockUnlocker {
        OmniLockUnlocker { signer, config }
    }
}
impl From<(Box<dyn Signer>, OmniLockConfig, OmniUnlockMode)> for OmniLockUnlocker {
    fn from(
        (signer, config, unlock_mode): (Box<dyn Signer>, OmniLockConfig, OmniUnlockMode),
    ) -> OmniLockUnlocker {
        let cfg = config.clone();
        OmniLockUnlocker::new(OmniLockScriptSigner::new(signer, config, unlock_mode), cfg)
    }
}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptUnlocker for OmniLockUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    /// Check if the script group is already unlocked
    async fn is_unlocked_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        if self.config.omni_lock_flags().contains(OmniLockFlags::ACP) {
            let raw_data = script_group.script.args().raw_data();
            let acp_args = {
                let mut offset = 22;
                if self.config.omni_lock_flags().contains(OmniLockFlags::ADMIN) {
                    offset += 32;
                }
                let data = raw_data.as_ref();
                if data.len() > offset {
                    &data[offset..]
                } else {
                    &[]
                }
            };
            let acp_unlocked = acp_is_unlocked(tx, script_group, tx_dep_provider, acp_args).await?;
            if acp_unlocked {
                return Ok(true);
            }
        }
        if !self.signer.config().is_ownerlock() {
            return Ok(false);
        }
        let args = script_group.script.args().raw_data();
        if args.len() < 22 {
            return Err(UnlockError::Other(anyhow!(
                "invalid script args length, expected not less than 22, got: {}",
                args.len()
            )));
        }
        // If use admin mode, should use the id in admin configuration
        let auth_content = if self.config.omni_lock_flags().contains(OmniLockFlags::ADMIN) {
            self.config
                .get_admin_config()
                .unwrap()
                .get_auth()
                .auth_content()
        } else {
            self.config.id().auth_content()
        };

        let inputs = tx.inputs();
        if tx.inputs().len() < 2 {
            return Err(UnlockError::Other(anyhow!(
                "expect more than 1 input, got: {}",
                inputs.len()
            )));
        }
        let mut matched = false;
        for (_idx, input) in tx
            .inputs()
            .into_iter()
            .enumerate()
            .filter(|(idx, _input)| !script_group.input_indices.contains(idx))
        {
            if let Ok(output) = tx_dep_provider
                .get_cell_async(&input.previous_output())
                .await
            {
                let lock_hash = output.calc_lock_hash();
                let h = &lock_hash.as_slice()[0..20];
                if h == auth_content.as_bytes() {
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            return Err(UnlockError::Other(anyhow!(
                "can not find according owner lock input"
            )));
        }
        Ok(matched)
    }

    async fn unlock_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(self.signer.sign_tx(tx, script_group)?)
    }

    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        let config = self.signer.config();
        let lock_field = config.placeholder_witness_lock(self.signer.unlock_mode())?;
        fill_witness_lock(tx, script_group, lock_field)
    }
}
#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_unlock_error() {
        let error = super::UnlockError::InvalidWitnessArgs(0);
        let error = anyhow!(error);
        assert_eq!("invalid witness args: witness index=`0`", error.to_string());
    }
}
