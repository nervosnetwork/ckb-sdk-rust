use std::error::Error as StdErr;

use ckb_sdk::{
    constants::ONE_CKB,
    tx_builder::{builder::CkbTransactionBuilder, cheque::DefaultChequeClaimBuilder},
    unlock::SecpSighashUnlocker,
    NetworkInfo,
};

// This example shows when receiver not exist, this transaction will create a target cell with specified capacity, and update the sudt data in it.
// So the transaction will find a normal cell to provide the transaction fee and capacity for the target cell.
fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let capacity_provider_addr =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche";

    let mut builder = DefaultChequeClaimBuilder::new(network_info, capacity_provider_addr).unwrap();
    builder
        .add_cheque_output_cell_str(
            "291ecd09e23e886dbf839aa350c9993b7e770f32f96084fa8877cd20a30fc5c9",
            1,
        )
        .unwrap();

    builder
        .add_sighash_unlocker_from_str(&[
            "d2d1e192b341ccb9fe94f68fae1e687e2916eb6edd92039522088468dd7582d6",
        ])
        .unwrap();
    builder.build_sudt_receiver_target_by_addr_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche", Some(500 * ONE_CKB)).unwrap();
    let sender_lock_script = SecpSighashUnlocker::script_id()
        .build_script_from_arg_str("0xbddb8434a518a5729a9ea58cd2d541afbd712999")
        .unwrap();
    builder.set_sender_lock_script(sender_lock_script);

    let (tx, unsigned_group) = builder.build_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&ckb_jsonrpc_types::TransactionView::from(tx.clone()))
            .unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    // example :90a01e955cecb79bfac9925bedd44ffa377e2de0876413692eb6e702b2845396
    println!("tx {} sent", tx_hash);
    Ok(())
}
