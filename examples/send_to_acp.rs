use std::error::Error as StdErr;

use ckb_sdk::{
    parser::Parser,
    tx_builder::{acp::DefaultAcpTransferBuilder, builder::CkbTransactionBuilder},
    Address, NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();

    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";
    let mut builder = DefaultAcpTransferBuilder::new(network_info, sender).unwrap();

    builder.add_receiver_addr(&Address::parse("ckt1qq6pngwqn6e9vlm92th84rk0l4jp2h8lurchjmnwv8kq3rt5psf4vq2qf8keemy2p5uu0g0gn8cd4ju23s5269q8dwpnrp").unwrap(), 10_000_000);
    builder.add_sighash_unlocker_from_str(&[
        "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a",
    ])?;
    let (tx, unsigned_group) = builder.build_unlocked().unwrap();

    println!("unsigned_group len:{}", unsigned_group.len());
    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&ckb_jsonrpc_types::TransactionView::from(tx.clone()))
            .unwrap()
    );
    let tx_hash = builder.send_transaction(tx)?;
    // example tx_hash: bba8a69c9b5d1947a8022019fb2ce8c847d59df9e1b7e879f923a4a1f5a9f3ff
    println!("tx {} sent", tx_hash);
    Ok(())
}
