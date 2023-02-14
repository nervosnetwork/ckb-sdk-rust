use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    tx_builder::{builder::CkbTransactionBuilder, udt::DefaultUdtIssueBuilder},
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up";
    let receiver = sender;
    let mut builder = DefaultUdtIssueBuilder::new(network_info, sender).unwrap();
    builder.add_sudt_output_str(receiver, 10).unwrap();
    builder
        .add_sighash_unlocker_from_str(
            "0x0c982052ffd4af5f3bbf232301dcddf468009161fc48ba1426e3ce0929fb59f8",
        )
        .unwrap();

    let (tx, unsigned_group) = builder.build_balance_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    println!("tx {} sent", tx_hash);
    Ok(())
}
