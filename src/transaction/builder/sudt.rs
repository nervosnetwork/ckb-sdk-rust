use std::convert::TryInto;

use crate::{
    core::TransactionBuilder,
    transaction::{
        handler::HandlerContexts, input::InputIterator, TransactionBuilderConfiguration,
    },
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    NetworkInfo, NetworkType, TransactionWithScriptGroups,
};

use ckb_types::{
    core::{Capacity, ScriptHashType},
    h256,
    packed::{self, Bytes, CellOutput, Script},
    prelude::*,
};

use super::{inner_build, CkbTransactionBuilder, DefaultChangeBuilder};

/// A sUDT transaction builder implementation
pub struct SudtTransactionBuilder {
    /// The change lock script, the default change lock script is the last lock script of the input iterator
    change_lock: Script,
    /// The transaction builder configuration
    configuration: TransactionBuilderConfiguration,
    /// The input iterator, used for building transaction with cell collector
    input_iter: InputIterator,
    /// The identifier of the sUDT
    sudt_owner_lock_script: Script,
    /// Whether we are in owner mode
    owner_mode: bool,
    /// The inner transaction builder
    tx: TransactionBuilder,
}

impl SudtTransactionBuilder {
    pub fn new<S: Into<Script>>(
        configuration: TransactionBuilderConfiguration,
        input_iter: InputIterator,
        sudt_owner_lock_script: S,
        owner_mode: bool,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            change_lock: input_iter
                .lock_scripts()
                .last()
                .expect("input iter should not be empty")
                .clone(),
            configuration,
            input_iter,
            sudt_owner_lock_script: sudt_owner_lock_script.into(),
            owner_mode,
            tx: TransactionBuilder::default(),
        })
    }

    /// Update the change lock script.
    pub fn set_change_lock(&mut self, lock_script: Script) {
        self.change_lock = lock_script;
    }

    /// Add an output cell and output data to the transaction.
    pub fn add_output_and_data(&mut self, output: CellOutput, data: packed::Bytes) {
        self.tx.output(output);
        self.tx.output_data(data);
    }

    /// Add an output cell with the given lock script and sudt amount
    pub fn add_output<S: Into<Script>>(&mut self, output_lock_script: S, sudt_amount: u64) {
        let type_script = build_sudt_type_script(
            self.configuration.network_info(),
            &self.sudt_owner_lock_script,
        );
        let output_data = sudt_amount.to_le_bytes().pack();
        let dummy_output = CellOutput::new_builder()
            .lock(output_lock_script.into())
            .type_(Some(type_script).pack())
            .build();
        let required_capacity = dummy_output
            .occupied_capacity(Capacity::bytes(output_data.len()).unwrap())
            .unwrap()
            .pack();
        let output = dummy_output
            .as_builder()
            .capacity(required_capacity)
            .build();
        self.add_output_and_data(output, output_data);
    }
}

impl CkbTransactionBuilder for SudtTransactionBuilder {
    fn build(
        mut self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError> {
        if !self.owner_mode {
            // Add change output for sudt with zero amount as placeholder
            self.add_output(self.change_lock.clone(), 0);
        }

        let Self {
            change_lock,
            configuration,
            mut input_iter,
            sudt_owner_lock_script,
            owner_mode,
            mut tx,
        } = self;

        let change_builder = DefaultChangeBuilder {
            configuration: &configuration,
            change_lock,
            inputs: Vec::new(),
        };

        if owner_mode {
            inner_build(tx, change_builder, input_iter, &configuration, contexts)
        } else {
            let sudt_type_script =
                build_sudt_type_script(configuration.network_info(), &sudt_owner_lock_script);
            let mut sudt_input_iter = input_iter.clone();
            sudt_input_iter.set_type_script(Some(sudt_type_script));

            let outputs_sudt_amount: u64 = tx
                .outputs_data
                .iter()
                .map(|data| u64::from_le_bytes(data.raw_data().as_ref().try_into().unwrap()))
                .sum();

            let mut inputs_sudt_amount = 0;

            for input in sudt_input_iter {
                let input = input?;
                let input_amount =
                    u64::from_le_bytes(input.live_cell.output_data.as_ref().try_into().unwrap());
                inputs_sudt_amount += input_amount;
                input_iter.push_input(input);
                if inputs_sudt_amount >= outputs_sudt_amount {
                    let change_output_data: Bytes = (inputs_sudt_amount - outputs_sudt_amount)
                        .to_le_bytes()
                        .pack();
                    tx.set_output_data(tx.outputs_data.len() - 1, change_output_data);
                    return inner_build(tx, change_builder, input_iter, &configuration, contexts);
                }
            }

            Err(
                BalanceTxCapacityError::CapacityNotEnough("can not find enough inputs".to_string())
                    .into(),
            )
        }
    }
}

fn build_sudt_type_script(network_info: &NetworkInfo, sudt_owner_lock_script: &Script) -> Script {
    // code_hash from https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md#notes
    let code_hash = match network_info.network_type {
        NetworkType::Mainnet => {
            h256!("0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5")
        }
        NetworkType::Testnet => {
            h256!("0xc5e5dcf215925f7ef4dfaf5f4b4f105bc321c02776d6e7d52a1db3fcd9d011a4")
        }
        _ => panic!("Unsupported network type"),
    };

    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(sudt_owner_lock_script.calc_script_hash().as_bytes().pack())
        .build()
}
