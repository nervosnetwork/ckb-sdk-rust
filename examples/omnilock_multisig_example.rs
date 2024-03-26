use ckb_sdk::{
    constants::ONE_CKB,
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        handler::{omnilock, HandlerContexts},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    unlock::{MultisigConfig, OmniLockConfig},
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::{
    h160, h256,
    packed::CellOutput,
    prelude::{Builder, Entity, Pack},
};
use std::{error::Error as StdErr, str::FromStr};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender = Address::from_str("ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgxhjvp3k9pf88upngryvuxc346q7fq5qmlqqlrhr0p")?;
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

    let mut omni_cfg = OmniLockConfig::from_addr(&sender).unwrap();
    let multisig_config = MultisigConfig::new_with(
        vec![
            h160!("0x7336b0ba900684cb3cb00f0d46d4f64c0994a562"),
            h160!("0x5724c1e3925a5206944d753a6f3edaedf977d77f"),
        ],
        0,
        2,
    )
    .unwrap();
    omni_cfg.set_multisig_config(Some(multisig_config));
    let context = omnilock::OmnilockScriptContext::new(omni_cfg.clone(), network_info.url.clone());

    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&mut contexts)?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let signer = TransactionSigner::new(&network_info);
    let private_key = h256!("0x7438f7b35c355e3d2fb9305167a31a72d22ddeafb80a21cc99ff6329d92e8087");
    signer.sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_omnilock(
            [secp256k1::SecretKey::from_slice(private_key.as_bytes())?].to_vec(),
            omni_cfg.clone(),
        ),
    )?;
    let private_key = h256!("0x4fd809631a6aa6e3bb378dd65eae5d71df895a82c91a615a1e8264741515c79c");
    signer.sign_transaction(
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
    // example tx: 3c5062f75f8c9dc799a3286ebef070cd3aa1b51575244c912076b90cb915a374
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
