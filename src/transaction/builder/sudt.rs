use std::convert::TryInto;

use crate::{
    core::TransactionBuilder,
    transaction::{
        handler::HandlerContexts, input::InputIterator, TransactionBuilderConfiguration,
    },
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    NetworkInfo, NetworkType, TransactionWithScriptGroups,
};
use anyhow::anyhow;

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
    /// The sUDT type script, by default we will set default type script for `Mainnet` and `Testnet`
    /// in the scenario of Dev enviornment, we may need to manually override type script
    sudt_type_script: Option<Script>,
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
            sudt_type_script: None,
            owner_mode,
            tx: TransactionBuilder::default(),
        })
    }

    /// Update the change lock script.
    pub fn set_change_lock(&mut self, lock_script: Script) {
        self.change_lock = lock_script;
    }

    /// Manually set the sUDT type script
    pub fn set_sudt_type_script(&mut self, sudt_type_script: Script) {
        self.sudt_type_script = Some(sudt_type_script);
    }

    /// Add an output cell and output data to the transaction.
    pub fn add_output_and_data(&mut self, output: CellOutput, data: packed::Bytes) {
        self.tx.output(output);
        self.tx.output_data(data);
    }

    /// Add an output cell with the given lock script and sudt amount
    pub fn add_output<S: Into<Script>>(&mut self, output_lock_script: S, sudt_amount: u128) {
        let type_script = build_sudt_type_script(
            self.configuration.network_info(),
            &self.sudt_owner_lock_script,
            self.sudt_type_script.clone(),
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

#[test]
fn test_parse_u128_from_sudt_tx_output_data() {
    use crate::Address;
    use std::str::FromStr;

    let network_info = NetworkInfo::testnet();
    let configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone()).unwrap();

    let sender = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r").unwrap();

    let iterator = InputIterator::new_with_address(&[sender.clone()], &network_info);

    let test_sudt_amount = 9999_u128;
    let mut builder = SudtTransactionBuilder::new(configuration, iterator, &sender, false).unwrap();

    builder.add_output(&sender, test_sudt_amount);

    let outputs_sudt_amount: u128 = builder
        .tx
        .outputs_data
        .iter()
        .map(|data| parse_u128(data.raw_data().as_ref()))
        .collect::<Result<Vec<u128>, TxBuilderError>>()
        .map(|u128_vec| u128_vec.iter().sum())
        .expect("parse u128 failed");
    assert_eq!(outputs_sudt_amount, test_sudt_amount);
}

fn parse_u128(data: &[u8]) -> Result<u128, TxBuilderError> {
    if data.len() > std::mem::size_of::<u128>() {
        return Err(TxBuilderError::Other(anyhow!(
            "stdt_amount bytes length greater than 128"
        )));
    }

    let mut data_bytes: Vec<u8> = data.into();
    data_bytes.extend(std::iter::repeat(0_u8).take(std::mem::size_of::<u128>() - data.len()));
    Ok(u128::from_le_bytes(data_bytes.try_into().unwrap()))
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
            sudt_type_script,
            owner_mode,
            mut tx,
            ..
        } = self;

        let change_builder = DefaultChangeBuilder {
            configuration: &configuration,
            change_lock,
            inputs: Vec::new(),
        };

        if owner_mode {
            inner_build(
                tx,
                change_builder,
                input_iter,
                &configuration,
                contexts,
                Default::default(),
            )
        } else {
            let sudt_type_script = build_sudt_type_script(
                configuration.network_info(),
                &sudt_owner_lock_script,
                sudt_type_script,
            );
            let mut sudt_input_iter = input_iter.clone();
            sudt_input_iter.set_type_script(Some(sudt_type_script));

            let outputs_sudt_amount: u128 = tx
                .outputs_data
                .iter()
                .map(|data| parse_u128(data.raw_data().as_ref()))
                .collect::<Result<Vec<u128>, TxBuilderError>>()
                .map(|u128_vec| u128_vec.iter().sum())?;

            let mut inputs_sudt_amount = 0;

            for input in sudt_input_iter {
                let input = input?;
                let input_amount = parse_u128(input.live_cell.output_data.as_ref())?;
                inputs_sudt_amount += input_amount;
                input_iter.push_input(input);
                if inputs_sudt_amount >= outputs_sudt_amount {
                    let change_output_data: Bytes = (inputs_sudt_amount - outputs_sudt_amount)
                        .to_le_bytes()
                        .pack();
                    tx.set_output_data(tx.outputs_data.len() - 1, change_output_data);
                    return inner_build(
                        tx,
                        change_builder,
                        input_iter,
                        &configuration,
                        contexts,
                        Default::default(),
                    );
                }
            }

            Err(
                BalanceTxCapacityError::CapacityNotEnough("can not find enough inputs".to_string())
                    .into(),
            )
        }
    }
}

fn build_sudt_type_script(
    network_info: &NetworkInfo,
    sudt_owner_lock_script: &Script,
    override_sudt_type_script: Option<Script>,
) -> Script {
    if let Some(sudt_type_script) = override_sudt_type_script {
        return sudt_type_script;
    }
    // code_hash from https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md#notes
    let code_hash = match network_info.network_type {
        NetworkType::Mainnet => {
            h256!("0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5")
        }
        NetworkType::Testnet => {
            h256!("0xc5e5dcf215925f7ef4dfaf5f4b4f105bc321c02776d6e7d52a1db3fcd9d011a4")
        }
        NetworkType::Dev => {
            panic!("You may need to manually set `sudt_type_script` with `set_sudt_type_script` method");
        }
        _ => panic!("Unsupported network type"),
    };

    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(sudt_owner_lock_script.calc_script_hash().as_bytes().pack())
        .build()
}
