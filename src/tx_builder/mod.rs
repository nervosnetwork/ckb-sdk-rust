use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::anyhow;
use ckb_chain_spec::consensus::Consensus;
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use thiserror::Error;

use ckb_types::core::cell::{CellProvider, HeaderChecker};
use ckb_types::core::HeaderView;
use ckb_types::{
    core::{
        cell::resolve_transaction, error::OutPointError, Capacity, CapacityError,
        TransactionView,
    },
    packed::{Byte32, Script, WitnessArgs},
    prelude::*,
};

use crate::types::ScriptGroup;
use crate::types::{ScriptId};
use crate::unlock::{ScriptUnlocker, UnlockError};
use crate::util::calculate_dao_maximum_withdraw4;
use crate::{constants::DAO_TYPE_HASH, NetworkType};
use crate::traits::{
        CellCollectorError, HeaderDepResolver,
        TransactionDependencyError, TransactionDependencyProvider,
    };

/// Transaction builder errors
#[derive(Error, Debug)]
pub enum TxBuilderError {
    #[error("invalid parameter: `{0}`")]
    InvalidParameter(anyhow::Error),

    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),
    #[error("ChangeIndex alread set: `{0}`")]
    ChangeIndex(usize),

    #[error("cell collector error: `{0}`")]
    CellCollector(#[from] CellCollectorError),

    #[error("balance capacity error: `{0}`")]
    BalanceCapacity(#[from] BalanceTxCapacityError),

    #[error("resolve cell dep failed: `{0}`")]
    ResolveCellDepFailed(Script),

    #[error("resolve header dep by transaction hash failed: `{0}`")]
    ResolveHeaderDepByTxHashFailed(Byte32),

    #[error("resolve header dep by block number failed: `{0}`")]
    ResolveHeaderDepByNumberFailed(u64),

    #[error("unlock error: `{0}`")]
    Unlock(#[from] UnlockError),

    #[error("build_balance_unlocked exceed max loop times, current is: `{0}`")]
    ExceedCycleMaxLoopTimes(u32),
    #[error("witness idx `{0}` is out of bound `{1}")]
    WitnessOutOfBound(usize, usize),
    #[error("unsupported networktype `{0}")]
    UnsupportedNetworkType(NetworkType),
    #[error("can not find specifed output to put small change")]
    NoOutputForSmallChange,

    #[error("other error: `{0}`")]
    Other(anyhow::Error),
}

/// Transaction Builder interface

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum TransferAction {
    /// This action will crate a new cell, typecial lock script: cheque, sighash, multisig
    Create,
    /// This action will query the exists cell and update the amount, typecial lock script: acp
    Update,
}

#[derive(Error, Debug)]
pub enum TransactionFeeError {
    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),

    #[error("header dependency provider error: `{0}`")]
    HeaderDep(#[from] anyhow::Error),

    #[error("out point error: `{0}`")]
    OutPoint(#[from] OutPointError),

    #[error("unexpected dao withdraw cell in inputs")]
    UnexpectedDaoWithdrawInput,

    #[error("capacity error: `{0}`")]
    CapacityError(#[from] CapacityError),

    #[error("capacity sub overflow, delta: `{0}`")]
    CapacityOverflow(u64),
}

/// Calculate the actual transaction fee of the transaction, include dao
/// withdraw capacity.
#[allow(clippy::unnecessary_lazy_evaluations)]
pub fn tx_fee(
    tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    header_dep_resolver: &dyn HeaderDepResolver,
) -> Result<u64, TransactionFeeError> {
    let mut input_total: u64 = 0;
    for input in tx.inputs() {
        let mut is_withdraw = false;
        let since: u64 = input.since().unpack();
        let cell = tx_dep_provider.get_cell(&input.previous_output())?;
        if since != 0 {
            if let Some(type_script) = cell.type_().to_opt() {
                if type_script.code_hash().as_slice() == DAO_TYPE_HASH.as_bytes() {
                    is_withdraw = true;
                }
            }
        }
        let capacity: u64 = if is_withdraw {
            let tx_hash = input.previous_output().tx_hash();
            let prepare_header = header_dep_resolver
                .resolve_by_tx(&tx_hash)
                .map_err(TransactionFeeError::HeaderDep)?
                .ok_or_else(|| {
                    TransactionFeeError::HeaderDep(anyhow!(
                        "resolve prepare header by transaction hash failed: {}",
                        tx_hash
                    ))
                })?;
            let data = tx_dep_provider.get_cell_data(&input.previous_output())?;
            assert_eq!(data.len(), 8);
            let deposit_number = {
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(data.as_ref());
                u64::from_le_bytes(number_bytes)
            };
            let deposit_header = header_dep_resolver
                .resolve_by_number(deposit_number)
                .map_err(TransactionFeeError::HeaderDep)?
                .ok_or_else(|| {
                    TransactionFeeError::HeaderDep(anyhow!(
                        "resolve deposit header by block number failed: {}",
                        deposit_number
                    ))
                })?;
            let occupied_capacity = cell
                .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                .unwrap();
            calculate_dao_maximum_withdraw4(
                &deposit_header,
                &prepare_header,
                &cell,
                occupied_capacity.as_u64(),
            )
        } else {
            cell.capacity().unpack()
        };
        input_total += capacity;
    }
    let output_total = tx.outputs_capacity()?.as_u64();
    #[allow(clippy::unnecessary_lazy_evaluations)]
    input_total
        .checked_sub(output_total)
        .ok_or_else(|| TransactionFeeError::CapacityOverflow(output_total - input_total))
}

#[derive(Debug, Clone)]
pub enum SinceSource {
    /// The vaule in the tuple is offset of the args, and the `since` is stored in `lock.args[offset..offset+8]`
    LockArgs(usize),
    /// raw since value
    Value(u64),
}

impl Default for SinceSource {
    fn default() -> SinceSource {
        SinceSource::Value(0)
    }
}

/// Provide capacity locked by a list of lock scripts.
///
/// The cells collected by `lock_script` will filter out those have type script
/// or data length is not `0` or is not mature.
#[derive(Debug, Clone)]
pub struct CapacityProvider {
    /// The lock scripts provider capacity. The second field of the tuple is the
    /// placeholder witness of the lock script.
    pub lock_scripts: Vec<(Script, WitnessArgs, SinceSource)>,
}

impl CapacityProvider {
    /// create a new capacity provider.
    pub fn new(lock_scripts: Vec<(Script, WitnessArgs, SinceSource)>) -> CapacityProvider {
        CapacityProvider { lock_scripts }
    }

    /// create a new capacity provider with the default since source.
    pub fn new_simple(lock_scripts: Vec<(Script, WitnessArgs)>) -> CapacityProvider {
        let lock_scripts = lock_scripts
            .into_iter()
            .map(|(script, witness)| (script, witness, SinceSource::default()))
            .collect();
        CapacityProvider { lock_scripts }
    }
}

#[derive(Error, Debug)]
pub enum BalanceTxCapacityError {
    #[error("calculate transaction fee error: `{0}`")]
    TxFee(#[from] TransactionFeeError),

    #[error("transaction dependency provider error: `{0}`")]
    TxDep(#[from] TransactionDependencyError),

    #[error("capacity not enough: `{0}`")]
    CapacityNotEnough(String),

    #[error("Force small change as fee failed, fee: `{0}`")]
    ForceSmallChangeAsFeeFailed(u64),

    #[error("empty capacity provider")]
    EmptyCapacityProvider,

    #[error("cell collector error: `{0}`")]
    CellCollector(#[from] CellCollectorError),

    #[error("resolve cell dep failed: `{0}`")]
    ResolveCellDepFailed(Script),

    #[error("invalid witness args: `{0}`")]
    InvalidWitnessArgs(anyhow::Error),

    #[error("Fail to parse since value from args, offset: `{0}`, args length: `{1}`")]
    InvalidSinceValue(usize, usize),

    #[error("change index not found at given index: `{0}`")]
    ChangeIndexNotFound(usize),

    #[error("verify script error: {0}")]
    VerifyScript(String),

    #[error("should not try to rebalance, orignal fee {0}, required fee: {1},")]
    AlreadyBalance(u64, u64),
}

const DEFAULT_BYTES_PER_CYCLE: f64 = 0.000_170_571_4;
pub const fn bytes_per_cycle() -> f64 {
    DEFAULT_BYTES_PER_CYCLE
}

pub struct CycleResolver<DL> {
    tx_dep_provider: DL,
    tip_header: HeaderView,
    consensus: Arc<Consensus>,
}

impl<
        DL: CellDataProvider
            + HeaderProvider
            + ExtensionProvider
            + CellProvider
            + HeaderChecker
            + Send
            + Sync
            + Clone
            + 'static,
    > CycleResolver<DL>
{
    pub fn new(tx_dep_provider: DL) -> Self {
        CycleResolver {
            tx_dep_provider,
            tip_header: HeaderView::new_advanced_builder().build(), // TODO
            consensus: Default::default(),                          // TODO
        }
    }

    fn estimate_cycles(&self, tx: &TransactionView) -> Result<u64, BalanceTxCapacityError> {
        let rtx = resolve_transaction(
            tx.clone(),
            &mut HashSet::new(),
            &self.tx_dep_provider,
            &self.tx_dep_provider,
        )
        .map_err(|err| {
            BalanceTxCapacityError::VerifyScript(format!("Resolve transaction error: {:?}", err))
        })?;

        let mut verifier = TransactionScriptsVerifier::new(
            Arc::new(rtx),
            self.tx_dep_provider.clone(),
            Arc::clone(&self.consensus),
            Arc::new(TxVerifyEnv::new_submit(&self.tip_header)),
        );
        verifier.set_debug_printer(|script_hash, message| {
            println!("script: {:x}, debug: {}", script_hash, message);
        });
        verifier.verify(u64::max_value()).map_err(|err| {
            BalanceTxCapacityError::VerifyScript(format!("Verify script error : {:?}", err))
        })
    }
}

pub struct ScriptGroups {
    pub lock_groups: HashMap<Byte32, ScriptGroup>,
    pub type_groups: HashMap<Byte32, ScriptGroup>,
}

pub fn gen_script_groups(
    tx: &TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
) -> Result<ScriptGroups, TransactionDependencyError> {
    #[allow(clippy::mutable_key_type)]
    let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
    #[allow(clippy::mutable_key_type)]
    let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
    for (i, input) in tx.inputs().into_iter().enumerate() {
        let output = tx_dep_provider.get_cell(&input.previous_output())?;
        let lock_group_entry = lock_groups
            .entry(output.calc_lock_hash())
            .or_insert_with(|| ScriptGroup::from_lock_script(&output.lock()));
        lock_group_entry.input_indices.push(i);
        if let Some(t) = &output.type_().to_opt() {
            let type_group_entry = type_groups
                .entry(t.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(t));
            type_group_entry.input_indices.push(i);
        }
    }
    for (i, output) in tx.outputs().into_iter().enumerate() {
        if let Some(t) = &output.type_().to_opt() {
            let type_group_entry = type_groups
                .entry(t.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_type_script(t));
            type_group_entry.output_indices.push(i);
        }
    }
    Ok(ScriptGroups {
        lock_groups,
        type_groups,
    })
}

/// Fill placeholder lock script witnesses
///
/// Return value:
///   * The updated transaction
///   * The script groups that not matched by given `unlockers`
pub fn fill_placeholder_witnesses(
    balanced_tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
) -> Result<(TransactionView, Vec<ScriptGroup>), UnlockError> {
    let ScriptGroups { lock_groups, .. } = gen_script_groups(&balanced_tx, tx_dep_provider)?;
    let mut tx = balanced_tx;
    let mut not_matched = Vec::new();
    for script_group in lock_groups.values() {
        let script_id = ScriptId::from(&script_group.script);
        let script_args = script_group.script.args().raw_data();
        if let Some(unlocker) = unlockers.get(&script_id) {
            if !unlocker.is_unlocked(&tx, script_group, tx_dep_provider)? {
                if unlocker.match_args(script_args.as_ref()) {
                    tx = unlocker.fill_placeholder_witness(&tx, script_group, tx_dep_provider)?;
                } else {
                    not_matched.push(script_group.clone());
                }
            }
        } else {
            not_matched.push(script_group.clone());
        }
    }
    Ok((tx, not_matched))
}

/// Build unlocked transaction that ready to send or for further unlock.
///
/// Return value:
///   * The built transaction
///   * The script groups that not unlocked by given `unlockers`
pub fn unlock_tx(
    balanced_tx: TransactionView,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    unlockers: &HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
) -> Result<(TransactionView, Vec<ScriptGroup>), UnlockError> {
    let ScriptGroups { lock_groups, .. } = gen_script_groups(&balanced_tx, tx_dep_provider)?;
    let mut tx = balanced_tx;
    let mut not_unlocked = Vec::new();
    for script_group in lock_groups.values() {
        let script_id = ScriptId::from(&script_group.script);
        let script_args = script_group.script.args().raw_data();
        if let Some(unlocker) = unlockers.get(&script_id) {
            if unlocker.is_unlocked(&tx, script_group, tx_dep_provider)? {
                tx = unlocker.clear_placeholder_witness(&tx, script_group)?;
            } else if unlocker.match_args(script_args.as_ref()) {
                tx = unlocker.unlock(&tx, script_group, tx_dep_provider)?;
            } else {
                not_unlocked.push(script_group.clone());
            }
        } else {
            not_unlocked.push(script_group.clone());
        }
    }
    Ok((tx, not_unlocked))
}

#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_signer_error() {
        use super::TxBuilderError;
        let error = TxBuilderError::ResolveHeaderDepByNumberFailed(0);
        let error = anyhow!(error);
        assert_eq!(
            "resolve header dep by block number failed: `0`",
            error.to_string()
        );
    }

    #[test]
    fn test_transaction_fee_error() {
        let error = super::TransactionFeeError::CapacityOverflow(0);
        let error = anyhow!(error);
        assert_eq!("capacity sub overflow, delta: `0`", error.to_string());
    }

    #[test]
    fn test_balance_tx_capacity_error() {
        let eror = super::BalanceTxCapacityError::EmptyCapacityProvider;
        let error = anyhow!(eror);
        assert_eq!("empty capacity provider", error.to_string())
    }
}
