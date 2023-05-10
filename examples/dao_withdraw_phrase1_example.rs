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

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let iterator = InputIterator::new(vec![(&sender).into()], configuration.network_info());
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let mut context = dao::WithdrawPhrase1Context::new(network_info.url.clone());
    let input_outpoint = serde_json::from_str::<ckb_jsonrpc_types::OutPoint>(
        r#"
   {
      "tx_hash": "0x2aba579894cdf5f6c4afd3ada52792c4405fe6ba64d05226fb63fa5c1ec6f666",
      "index": "0x0"
   }
   "#,
    )
    .unwrap();
    context.add_input_outpoint(input_outpoint.into(), None);
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    builder.set_change_lock((&sender).into());
    let mut tx_with_groups = builder.build(&contexts)?;

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
    // example tx: b615b9cbb566af18dd2d860836b89e07a86dfcc7af510595dcb404f1b19e6d7e
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
