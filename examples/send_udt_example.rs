use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    tx_builder::{builder::CkbTransactionBuilder, udt::DefaultUdtTransferBuilder},
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up";
    let receiver = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqd0pdquvfuq077aemn447shf4d8u5f4a0glzz2g4";
    let owner_lock_script_hash =
        "0x9d2dab815b9158b2344827749d769fd66e2d3ebdfca32e5628ba0454651851f5";
    let mut builder =
        DefaultUdtTransferBuilder::new(network_info, sender, owner_lock_script_hash).unwrap();
    builder.add_sudt_output_str(receiver, 1).unwrap();

    // if receiver already have a cell, then can update to save ckb.
    // builder.add_update_sudt_output_str(receiver, 1).unwrap();

    // if sender and receiver are not the same address, and called function `add_update_sudt_output_str`, 2 keys must be provided
    // to unlock 2 cells, one is the sender's cell, the other is the receiver's cell that to be updated.
    builder
        .add_sighash_unlocker_from_str(&[
            "0x0c982052ffd4af5f3bbf232301dcddf468009161fc48ba1426e3ce0929fb59f8",
        ])
        .unwrap();

    let (tx, unsigned_group) = builder.build_balance_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    // example : ec00e1f0171c140610cb1d0c44a7cbd1300f580cfbb644205e27a7c18f4cd1ab
    println!("tx {} sent", tx_hash);
    Ok(())
}
