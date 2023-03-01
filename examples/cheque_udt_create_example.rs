use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    tx_builder::{
        builder::CkbTransactionBuilder, cheque::build_cheque_address_str,
        udt::DefaultUdtTransferBuilder,
    },
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up";
    let receiver = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqd0pdquvfuq077aemn447shf4d8u5f4a0glzz2g4";
    let cheque_address =
        build_cheque_address_str(network_info.network_type, sender, receiver).unwrap();
    // cheque address: ckt1qpsdtuu7lnjqn3v8ew02xkwwlh4dv5x2z28shkwt8p2nfruccux4kq2h7h2ln2w035d2lnh32ylk5ydmjq5ypwya9k4czku3tzergjp8wjwhd87kdckna0game073
    println!("cheque_address: {:?}", cheque_address);
    let owner_lock_script_hash =
        "0x9d2dab815b9158b2344827749d769fd66e2d3ebdfca32e5628ba0454651851f5";
    let mut builder =
        DefaultUdtTransferBuilder::new(network_info, sender, owner_lock_script_hash).unwrap();
    builder.add_sudt_output_str(&cheque_address, 1).unwrap();

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
    // example : 858d8a2986926085b95812585e949357b92b0a3414e2b811aa68bd34bc66f1c9 for withdraw
    // example : e7aa1e0dfe775639c12928a768dff094debcf5fedbb2ceaa0facfaf25d10dbbe for ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche claim
    println!("tx {} sent", tx_hash);
    Ok(())
}
