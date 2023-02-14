use std::error::Error as StdErr;

use ckb_sdk::{
    tx_builder::{builder::CkbTransactionBuilder, transfer::DefaultCapacityTransferBuilder},
    NetworkInfo,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";
    let mut builder = DefaultCapacityTransferBuilder::new(network_info, sender)?;
    builder.add_output_raw("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r", 50100000000u64)?;
    builder.add_sighash_unlocker_from_str(
        "0x0c982052ffd4af5f3bbf232301dcddf468009161fc48ba1426e3ce0929fb59f8",
    )?;
    let (tx, _unsigned_group) = builder.build_balance_unlocked().unwrap();

    let tx_hash = builder.send_transaction(tx)?;
    println!("tx {} sent", tx_hash);
    Ok(())
}
