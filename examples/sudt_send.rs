use ckb_sdk::{
    transaction::{
        builder::{sudt::SudtTransactionBuilder, CkbTransactionBuilder},
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
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let sender = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r")?;
    let receiver= Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche")?;
    let iterator = InputIterator::new_with_address(&[sender.clone()], &network_info);
    let mut builder = SudtTransactionBuilder::new(configuration, iterator, &sender, false)?;
    builder.add_output(&receiver, 50);

    let mut tx_with_groups = builder.build(&Default::default())?;

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

    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
