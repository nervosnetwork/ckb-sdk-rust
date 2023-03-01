use std::error::Error as StdErr;

use ckb_sdk::{
    tx_builder::{builder::CkbTransactionBuilder, cheque::DefaultChequeClaimBuilder},
    unlock::SecpSighashUnlocker,
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let capacity_provider_addr =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche";

    let mut builder = DefaultChequeClaimBuilder::new(network_info, capacity_provider_addr).unwrap();
    builder
        .add_cheque_output_cell_str(
            "e7aa1e0dfe775639c12928a768dff094debcf5fedbb2ceaa0facfaf25d10dbbe",
            1,
        )
        .unwrap();

    builder
        .add_sighash_unlocker_from_str(&[
            "d2d1e192b341ccb9fe94f68fae1e687e2916eb6edd92039522088468dd7582d6",
        ])
        .unwrap();
    builder.build_sudt_receiver_target_by_addr_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche").unwrap();
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
    // example :74227f5c816f316871f06c35c572d2c093c8edee0c5c1b9f76135544cb165368
    println!("tx {} sent", tx_hash);
    Ok(())
}
