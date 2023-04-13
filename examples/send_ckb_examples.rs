use std::{error::Error as StdErr, str::FromStr};

use ckb_sdk::{
    constants::ONE_CKB,
    tx_builder::{builder::CkbTransactionBuilder, transfer::DefaultCapacityTransferBuilder},
    unlock::{get_unlock_handler, Context},
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::h256;

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender =  Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r")?;
    // this should be another address
    let receiver = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r")?;
    let mut builder = DefaultCapacityTransferBuilder::new_with_address(&network_info, sender)?;

    builder.add_output(&receiver, (501 * ONE_CKB).into());

    let mut tx_with_groups = builder.build().unwrap();

    let handler = get_unlock_handler(&network_info).unwrap();
    let private_key = h256!("0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a");
    let sender_key = secp256k1::SecretKey::from_slice(private_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    handler
        .unlock(&mut tx_with_groups, &Context::make(vec![sender_key]))
        .unwrap();

    let signed_tx_json = serde_json::to_string_pretty(&tx_with_groups)?;
    println!("signed tx_json: {}", signed_tx_json);

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.tx_view);
    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");
    // sample tx: 3035453616883f857c0f4170b74f2cfaa01ce86b0c542bb0cd8199d49cb9e28c
    // sample tx: 6a8680a80d7758a3846b472fb2ced62d9237641912835697cb162205b771f765
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
