use std::error::Error as StdErr;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::ONE_CKB,
    tx_builder::{builder::CkbTransactionBuilder, dao::DefaultDaoDepositBuilder},
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";
    let receiver = sender;

    let mut builder = DefaultDaoDepositBuilder::new(network_info, sender).unwrap();
    builder.add_dao_output_str(receiver, 510 * ONE_CKB).unwrap();
    builder
        .add_sighash_unlocker_from_str(&[
            "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a",
        ])
        .unwrap();

    let (tx, unsigned_group) = builder.build_balance_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&json_types::TransactionView::from(tx.clone())).unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    // example tx_hash : eb4276a664a8d11a32b52642bf275748ac14e6b993199ab3ef57d318eee82090
    println!("tx {} sent", tx_hash);
    Ok(())
}
