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
    let receiver="ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche";

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
    // set small change action instead of default
    // use ckb_sdk::transaction::SmallChangeAction;
    // configuration.small_change_action = SmallChangeAction::AsFee { threshold: Capacity::bytes(61)?.as_u64() };
    // configuration.small_change_action = SmallChangeAction::to_output(&sender.parse()?, Capacity::bytes(1)?.as_u64());

    let addr = Address::from_str(sender)?;
    let receiver = Address::from_str(receiver)?;
    let iterator = InputIterator::new_with_address(&[addr], configuration.network_info());
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    let addr = Address::from_str(sender)?;
    builder.add_output_from_addr(&receiver, Capacity::shannons(510_0000_0000u64));
    builder.set_change_addr(&addr);
    let mut tx_with_groups = builder.build(&mut Default::default())?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let private_keys = vec![h256!(
        "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a"
    )];
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");
    // example tx: 0x9ce266d45600abbd56467c9be59febe7b07336d7c1f439b9c06379f080bf0552
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
