use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, Byte32, BytesOpt, WitnessArgs},
    prelude::*,
};
use thiserror::Error;

use super::signer::{
    AcpScriptSigner, ChequeAction, ChequeScriptSigner, ScriptSignError, ScriptSigner,
    SecpMultisigScriptSigner, SecpSighashScriptSigner,
};
use crate::traits::{TransactionDependencyError, TransactionDependencyProvider};
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

    #[error("other error: `{0}`")]
    Other(#[from] Box<dyn std::error::Error>),
}

/// Script unlock logic:
///   * Parse the script.args
///   * Sign the transaction
///   * Put extra unlock information into transaction (e.g. SMT proof in omni-lock case)
pub trait ScriptUnlocker {
    fn match_args(&self, args: &[u8]) -> bool;

    /// Check if the script group is already unlocked
    fn is_unlocked(
        &self,
        _tx: &TransactionView,
        _script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        Ok(false)
    }

    /// Add signature or other information to witnesses, when the script is
    /// already unlocked should reset the witness instead.
    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError>;

    fn clear_placeholder_witness(
        &self,
        tx: &TransactionView,
        _script_group: &ScriptGroup,
    ) -> Result<TransactionView, UnlockError> {
        Ok(tx.clone())
    }

    /// Fill a placehodler witness before balance the transaction capacity
    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError>;
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
impl ScriptUnlocker for SecpSighashUnlocker {
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
impl ScriptUnlocker for SecpMultisigUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        (args.len() == 20 || args.len() == 28) && self.signer.match_args(args)
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
impl ScriptUnlocker for AcpUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    fn is_unlocked(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
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
        let script_args = script_group.script.args().raw_data();
        let min_ckb_amount = if script_args.len() > 20 {
            let idx = script_args.as_ref()[20];
            if idx >= 20 {
                return Err(UnlockError::Other(format!("invalid min ckb amount config in script.args, got: {}, expected: value >=0 and value < 20", idx).into()));
            }
            POW10[idx as usize]
        } else {
            0
        };
        let min_udt_amount = if script_args.len() > 21 {
            let idx = script_args.as_ref()[21];
            if idx >= 39 {
                return Err(UnlockError::Other(format!("invalid min udt amount config in script.args, got: {}, expected: value >=0 and value < 39", idx).into()));
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
        let mut input_wallets = script_group
            .input_indices
            .iter()
            .map(|idx| {
                let input = tx.inputs().get(*idx).ok_or_else(|| {
                    UnlockError::Other(
                        format!("input index in script group is out of bound: {}", idx).into(),
                    )
                })?;
                let output = tx_dep_provider.get_cell(&input.previous_output())?;
                let output_data = tx_dep_provider.get_cell_data(&input.previous_output())?;

                let type_hash_opt = output
                    .type_()
                    .to_opt()
                    .map(|script| script.calc_script_hash());
                if type_hash_opt.is_some() && output_data.len() < 16 {
                    return Err(UnlockError::Other(
                        format!("invalid udt output data in input cell: {:?}", input).into(),
                    ));
                }
                let udt_amount = if type_hash_opt.is_some() {
                    let mut amount_bytes = [0u8; 16];
                    amount_bytes.copy_from_slice(&output_data[0..16]);
                    u128::from_le_bytes(amount_bytes)
                } else {
                    0
                };
                Ok(InputWallet {
                    type_hash_opt,
                    ckb_amount: output.capacity().unpack(),
                    udt_amount,
                    output_cnt: 0,
                })
            })
            .collect::<Result<Vec<InputWallet>, UnlockError>>()?;

        for (output_idx, output) in tx.outputs().into_iter().enumerate() {
            if output.lock() != script_group.script {
                continue;
            }
            let output_data: Bytes = tx
                .outputs_data()
                .get(output_idx)
                .map(|data| data.raw_data())
                .ok_or_else(|| {
                    UnlockError::Other(
                        format!(
                            "output data index in script group is out of bound: {}",
                            output_idx
                        )
                        .into(),
                    )
                })?;
            let type_hash_opt = output
                .type_()
                .to_opt()
                .map(|script| script.calc_script_hash());
            if type_hash_opt.is_some() && output_data.len() < 16 {
                return Err(UnlockError::Other(
                    format!(
                        "invalid udt output data in output cell: index={}",
                        output_idx
                    )
                    .into(),
                ));
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

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self.is_unlocked(tx, script_group, tx_dep_provider)? {
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

    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self.is_unlocked(tx, script_group, tx_dep_provider)? {
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

impl ScriptUnlocker for ChequeUnlocker {
    fn match_args(&self, args: &[u8]) -> bool {
        self.signer.match_args(args)
    }

    fn is_unlocked(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<bool, UnlockError> {
        let args = script_group.script.args().raw_data();
        if args.len() != 40 {
            return Err(UnlockError::Other(
                format!(
                    "invalid script args length, expected: 40, got: {}",
                    args.len()
                )
                .into(),
            ));
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
            let output = tx_dep_provider.get_cell(&input.previous_output())?;
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
                    return Err(UnlockError::Other(
                        "claim action must have all zero since in cheque inputs"
                            .to_string()
                            .into(),
                    ));
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
                return Err(UnlockError::Other(
                    "withdraw action must have all relative 6 epochs since in cheque inputs"
                        .to_string()
                        .into(),
                ));
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

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self.is_unlocked(tx, script_group, tx_dep_provider)? {
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

    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        if self.is_unlocked(tx, script_group, tx_dep_provider)? {
            Ok(tx.clone())
        } else {
            fill_witness_lock(tx, script_group, Bytes::from(vec![0u8; 65]))
        }
    }
}

#[cfg(feature = "test")]
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ckb_jsonrpc_types as json_types;
    use ckb_types::{
        bytes::Bytes,
        core::{BlockView, ScriptHashType},
        h160, h256,
        packed::{CellOutput, Script, WitnessArgs},
        prelude::*,
        H160, H256,
    };

    use crate::constants::{ONE_CKB, SIGHASH_TYPE_HASH};
    use crate::traits::SecpCkbRawKeySigner;
    use crate::tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder};
    use crate::ScriptId;

    use crate::test_util::{random_out_point, Context};

    use super::*;

    const ACCOUNT1_KEY: H256 =
        h256!("0xdbb62c0f0dd23088dba5ade3b4ed2279f733780de1985d344bf398c1c757ef49");
    const ACCOUNT1_ARG: H160 = h160!("0x9943f8613bd23d45631265ccef19a6edff7dac4d");
    // const ACCOUNT2_KEY: H256 =
    //     h256!("0x5f9eceb1af9fe48b97e2df350450d7416887ccca62f537733f1377ee9efb8906");
    const ACCOUNT2_ARG: H160 = h160!("0x507736d8f98c779ee47294d5d061d9eaa0dbf856");
    const GENESIS_JSON: &str = include_str!("../test-data/genesis_block.json");

    #[test]
    fn test_sighash_unlocker() {
        let genesis_block: json_types::BlockView = serde_json::from_str(GENESIS_JSON).unwrap();
        let genesis_block: BlockView = genesis_block.into();
        let mut ctx = Context::from_genesis_block(&genesis_block);

        let sender = Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(ACCOUNT1_ARG.0.to_vec()).pack())
            .build();
        let receiver = Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(ACCOUNT2_ARG.0.to_vec()).pack())
            .build();

        for capacity_ckb in [100, 200, 300] {
            ctx.add_simple_live_cell(
                random_out_point(),
                sender.clone(),
                Some(capacity_ckb * ONE_CKB),
            );
        }
        let output = CellOutput::new_builder()
            .capacity((120 * ONE_CKB).pack())
            .lock(receiver)
            .build();
        let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();
        let balancer =
            CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), 1000);

        let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
        let script_signer = SecpSighashScriptSigner::new(Box::new(signer));
        let script_unlocker = SecpSighashUnlocker::new(script_signer);
        let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
        unlockers.insert(
            ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
            Box::new(script_unlocker),
        );

        let mut cell_collector = ctx.to_live_cells_context();
        let (tx, unlocked_groups) = builder
            .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
            .unwrap();

        assert!(unlocked_groups.is_empty());
        assert_eq!(tx.header_deps().len(), 0);
        assert_eq!(tx.cell_deps().len(), 1);
        assert_eq!(tx.inputs().len(), 2);
        for out_point in tx.input_pts_iter() {
            assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
        }
        assert_eq!(tx.outputs().len(), 2);
        assert_eq!(tx.output(1).unwrap().lock(), sender);
        let witnesses = tx
            .witnesses()
            .into_iter()
            .map(|w| w.raw_data())
            .collect::<Vec<_>>();
        assert_eq!(witnesses.len(), 2);
        assert_eq!(witnesses[0].len(), placeholder_witness.as_slice().len());
        assert_eq!(witnesses[1].len(), 0);
        ctx.verify(tx, 1000).unwrap();
    }
}
