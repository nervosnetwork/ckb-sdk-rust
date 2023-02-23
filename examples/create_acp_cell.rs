use std::error::Error as StdErr;

use bytes::Bytes;
use ckb_sdk::{
    constants::ONE_CKB,
    parser::Parser,
    tx_builder::{
        acp::{AcpCreateReceiver, AcpLockBuilder},
        builder::CkbTransactionBuilder,
        transfer::DefaultCapacityTransferBuilder,
    },
    Address, AddressPayload, NetworkInfo,
};
use ckb_types::{packed::CellOutput, H160};

/// create a acp cell with 90 CKB, 0.1 CKB minimum
/// # Arguments
/// `sender` - is a sighash address, will use it's args as the acp pub key hash
fn create_output(sender: &str) -> (CellOutput, Bytes) {
    let sender_address = Address::parse(sender).unwrap();
    let key_hash = sender_address.payload().args();
    let key_hash = H160::from_slice(&key_hash).unwrap();
    let lock = AcpLockBuilder::default()
        .key_hash(key_hash)
        .mini_ckb(Some(7))
        .build_lock_script(sender_address.network());
    let acp_cell = AcpCreateReceiver::new(lock.clone(), 90 * ONE_CKB);

    let payload = AddressPayload::from(lock);
    let address = Address::new(sender_address.network(), payload, true);
    // address: ckt1qq6pngwqn6e9vlm92th84rk0l4jp2h8lurchjmnwv8kq3rt5psf4vq2qf8keemy2p5uu0g0gn8cd4ju23s5269q8dwpnrp
    println!("address {}", address);
    acp_cell.build_output()
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let network_info = NetworkInfo::testnet();
    let sender =  "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r";
    let mut builder = DefaultCapacityTransferBuilder::new(network_info, sender)?;
    builder.outputs.push(create_output(sender));

    builder.add_sighash_unlocker_from_str(&[
        "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a",
    ])?;
    let (tx, _unsigned_group) = builder.build_balance_unlocked().unwrap();

    println!(
        "> tx: {}",
        serde_json::to_string_pretty(&ckb_jsonrpc_types::TransactionView::from(tx.clone()))
            .unwrap()
    );

    let tx_hash = builder.send_transaction(tx)?;
    // example tx_hash: c2f0d70cbd3421398559575311ddcee9d310a4f69f236d70ad62ab1ad950b6d0
    // example tx_hash: 0cf52aeb068fdc780ca602f4fb9fbead2f6dc74fe78e591e488ef2cbda81191b
    println!("tx {} sent", tx_hash);
    Ok(())
}
