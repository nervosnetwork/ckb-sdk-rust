use ckb_sdk::{
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::{core::Capacity, h256};
use std::{error::Error as StdErr, str::FromStr};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
    let iterator = InputIterator::new_with_address(&[sender], configuration.network_info())?;
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    let addr = Address::from_str(sender)?;
    builder.add_output_from_addr(&addr, Capacity::shannons(50100000000u64));
    builder.set_change_addr(addr);
    let mut tx_with_groups = builder.build(&Default::default())?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(vec![h256!(
            "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a"
        )])?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.tx_view);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let outputs_validator = Some(ckb_jsonrpc_types::OutputsValidator::Passthrough);
    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    // example tx: 18b97d9531b6413690ca976d9bba8961cd8e1f65f3df5f8b212fb3b8886192a0
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}