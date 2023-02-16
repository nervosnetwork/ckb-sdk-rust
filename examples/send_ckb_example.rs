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
    builder.add_sighash_unlocker_from_str(&[
        "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a",
    ])?;
    let (tx, _unsigned_group) = builder.build_balance_unlocked().unwrap();

    let tx_hash = builder.send_transaction(tx)?;
    // example tx_hash: caf1fa259764a207ebdc0531a0ede37b3d2a31f16378f249a9eb7449392867d1
    println!("tx {} sent", tx_hash);
    Ok(())
}
