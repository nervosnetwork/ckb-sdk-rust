use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    parser::Parser,
    tx_builder::{
        acp::AcpLockBuilder, builder::CkbTransactionBuilder, udt::DefaultUdtTransferBuilder,
    },
    Address, AddressPayload, NetworkInfo,
};
use ckb_types::H160;

/// create a receiver address, with minimal 0.1 CKB, and minimal 10 amount of udt
/// # Arguments
/// `sender` - is a sighash address, will use it to build a acp address by append the 2 minimum limits
fn create_receiver(sender: &str) -> Address {
    let sender_address = Address::parse(sender).unwrap();
    let args = sender_address.payload().args();
    let key_hash = args.as_ref();
    let key_hash = H160::from_slice(&key_hash[0..20]).unwrap();
    let lock = AcpLockBuilder::default()
        .key_hash(key_hash)
        .mini_ckb(Some(7))
        .mini_udt(Some(1))
        .build_lock_script(sender_address.network());
    let payload = AddressPayload::from(lock);
    let address = Address::new(sender_address.network(), payload, true);
    // address: ckt1qq6pngwqn6e9vlm92th84rk0l4jp2h8lurchjmnwv8kq3rt5psf4vqdamwzrffgc54ef48493nfd2sd0h4cjnxg8qya376yj
    println!("address {}", address);
    address
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up";
    let receiver = create_receiver(sender);
    let owner_lock_script_hash =
        "0x9d2dab815b9158b2344827749d769fd66e2d3ebdfca32e5628ba0454651851f5";
    let mut builder =
        DefaultUdtTransferBuilder::new(network_info, sender, owner_lock_script_hash).unwrap();
    builder.add_sudt_output(receiver, 10);

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
    // example : 8d12b6e8eb2db6d1a3b866433d2fd7092d8c501d3dda0802e920384535a440db
    println!("tx {} sent", tx_hash);
    Ok(())
}
