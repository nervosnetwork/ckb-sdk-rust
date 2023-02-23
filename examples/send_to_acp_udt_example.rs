use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    tx_builder::{
        acp::get_default_script_id, builder::CkbTransactionBuilder, udt::DefaultUdtTransferBuilder,
    },
    unlock::AcpUnlocker,
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up";
    // create_acp_udt_cell.rs shows how to create the receiver address
    let receiver = "ckt1qq6pngwqn6e9vlm92th84rk0l4jp2h8lurchjmnwv8kq3rt5psf4vqdamwzrffgc54ef48493nfd2sd0h4cjnxg8qya376yj";
    let owner_lock_script_hash =
        "0x9d2dab815b9158b2344827749d769fd66e2d3ebdfca32e5628ba0454651851f5";
    let mut builder =
        DefaultUdtTransferBuilder::new(network_info, sender, owner_lock_script_hash).unwrap();
    // if receiver already have a cell, then can update to save ckb.
    builder.add_update_sudt_output_str(receiver, 10).unwrap();

    // if sender and receiver are not the same address, and called function `add_update_sudt_output_str`, 2 keys must be provided
    // to unlock 2 cells, one is the sender's cell, the other is the receiver's cell that to be updated.
    builder
        .add_sighash_unlocker_from_str(&[
            "0x0c982052ffd4af5f3bbf232301dcddf468009161fc48ba1426e3ce0929fb59f8",
        ])
        .unwrap();
    // add acp unlocker, this unlocker will not change the tx, but will make unsigned_group empty.
    let acp_unlocker = AcpUnlocker::default();
    builder.add_unlocker(
        get_default_script_id(ckb_sdk::NetworkType::Testnet),
        Box::new(acp_unlocker),
    );

    let (tx, unsigned_group) = builder.build_balance_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    // example : 7975a255031294577ce2a943e5535f3a9eac71765b1896497f0ff3b22e0a69db
    println!("tx {} sent", tx_hash);
    Ok(())
}
