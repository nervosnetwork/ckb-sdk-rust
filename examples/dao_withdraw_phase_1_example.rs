use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    tx_builder::{builder::CkbTransactionBuilder, dao::DefaultDaoWithdrawPhase1Builder},
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";

    let mut builder = DefaultDaoWithdrawPhase1Builder::new(network_info, sender).unwrap();
    let tx_hash = "eb4276a664a8d11a32b52642bf275748ac14e6b993199ab3ef57d318eee82090";
    builder.add_simple_input(tx_hash, 0, None).unwrap();
    builder
        .add_sighash_unlocker_from_str(&[
            "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a",
        ])
        .unwrap();

    let (tx, unsigned_group) = builder.build_unlocked().unwrap();
    // let (tx, unsigned_group) = builder.build_balance_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    // example tx_hash : 770f930ed3bf35664cb6a112edce3287712f0613c74c1f1176e099ee51268489
    println!("tx {} sent", tx_hash);
    Ok(())
}
