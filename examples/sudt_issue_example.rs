use ckb_sdk::{
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        handler::{udt, HandlerContexts},
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
    let owner = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up")?;
    let receiver=Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche")?;

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let iterator = InputIterator::new(vec![(&owner).into()], configuration.network_info());
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let context = udt::UdtIssueContext::new_default(
        (&owner).into(),
        (&receiver).into(),
        10u128,
        &network_info,
    );
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    builder.set_change_lock((&owner).into());
    let mut tx_with_groups = builder.build(&mut contexts)?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let private_keys = vec![h256!(
        "0x0c982052ffd4af5f3bbf232301dcddf468009161fc48ba1426e3ce0929fb59f8"
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
    // example tx: e992819c59233c05eb83552203695840b5e76a2c3faf606adee4a1d1df4837d9
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
