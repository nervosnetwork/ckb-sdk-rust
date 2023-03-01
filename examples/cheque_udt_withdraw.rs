use std::error::Error as StdErr;

use ckb_sdk::{
    tx_builder::{builder::CkbTransactionBuilder, cheque::DefaultChequeWithdrawBuilder},
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdamwzrffgc54ef48493nfd2sd0h4cjnxg4850up";

    let mut builder = DefaultChequeWithdrawBuilder::new(network_info, sender).unwrap();
    builder
        .add_cheque_outpoint_str(
            "858d8a2986926085b95812585e949357b92b0a3414e2b811aa68bd34bc66f1c9",
            1,
        )
        .unwrap();

    builder
        .add_sighash_unlocker_from_str(&[
            "0x0c982052ffd4af5f3bbf232301dcddf468009161fc48ba1426e3ce0929fb59f8",
        ])
        .unwrap();

    let (tx, unsigned_group) = builder.build_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&ckb_jsonrpc_types::TransactionView::from(tx.clone()))
            .unwrap()
    );

    println!("unsigned_group len:{}", unsigned_group.len());
    let tx_hash = builder.send_transaction(tx)?;
    // example :f90727df608be2a6fe412e9d96f7127631a41b675e1af35a0e8b22361a894055
    println!("tx {} sent", tx_hash);
    Ok(())
}
