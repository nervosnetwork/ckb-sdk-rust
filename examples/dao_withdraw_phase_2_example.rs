use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    tx_builder::{
        builder::CkbTransactionBuilder,
        dao::{DaoWithdrawReceiver, DefaultDaoWithdrawPhase2Builder},
    },
    NetworkInfo,
};
use ckb_types::{core::FeeRate, packed::WitnessArgs};

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";

    let receiver =
        DaoWithdrawReceiver::new_lock_script_from_str(sender, Some(FeeRate(1000))).unwrap();
    let mut builder = DefaultDaoWithdrawPhase2Builder::new(network_info, sender, receiver).unwrap();
    let tx_hash = "0xf01e9134a90341cffbd92939ae2969efdf2d5b501f509facc4275489b82805f4";
    builder
        .add_withdraw_item(tx_hash, 0, Some(WitnessArgs::default()))
        .unwrap();
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
    // example tx_hash : b83b0779f118f20de0a7746f6d547171725de92eec1f87e62bff35ab7eb80182
    println!("tx {} sent", tx_hash);
    Ok(())
}
