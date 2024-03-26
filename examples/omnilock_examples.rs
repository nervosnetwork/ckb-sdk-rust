use ckb_sdk::{
    constants::ONE_CKB,
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        handler::{omnilock, HandlerContexts},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    unlock::OmniLockConfig,
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::{
    h256,
    packed::CellOutput,
    prelude::{Builder, Entity, Pack},
};
use std::{error::Error as StdErr, str::FromStr};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender = Address::from_str("ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqgpy7m88v3gxnn3apazvlpkkt32xz3tg5qq3kzjf3")?;
    let receiver = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche")?;

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let iterator = InputIterator::new_with_address(&[sender.clone()], configuration.network_info());
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let output = CellOutput::new_builder()
        .capacity((128 * ONE_CKB).pack())
        .lock((&receiver).into())
        .build();
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock((&sender).into());

    let omni_cfg = OmniLockConfig::from_addr(&sender).unwrap();
    let context = omnilock::OmnilockScriptContext::new(omni_cfg.clone(), network_info.url.clone());

    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&mut contexts)?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let private_key = h256!("0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a");
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_omnilock(
            [secp256k1::SecretKey::from_slice(private_key.as_bytes())?].to_vec(),
            omni_cfg,
        ),
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");
    // example tx: 0xc0c9954a3299b540e63351146a301438372abf93682d96c7cce691c334dd5757
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
