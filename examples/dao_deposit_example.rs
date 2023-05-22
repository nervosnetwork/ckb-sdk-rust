use ckb_sdk::{
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        handler::{dao, HandlerContexts},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::h256;
use std::{error::Error as StdErr, str::FromStr};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r")?;
    let receiver=Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche")?;

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let iterator = InputIterator::new(vec![(&sender).into()], configuration.network_info());
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let context = dao::DepositContext::new((&receiver).into(), 510_0000_0000u64);
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    builder.set_change_lock((&sender).into());
    let mut tx_with_groups = builder.build(&mut contexts)?;

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
    // example tx: 8b7ab7770c821fa8dc70738d5d6ef43da46706541c258b9a02edf66948039798
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
