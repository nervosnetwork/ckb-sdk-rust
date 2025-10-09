use ckb_sdk::{
    constants,
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    Address, CkbRpcClient, NetworkInfo, ScriptId,
};
use ckb_types::{
    core::Capacity,
    h256,
    packed::{Bytes, CellOutput},
    prelude::*,
};
use std::{
    error::Error as StdErr,
    fs::File,
    io::{BufReader, Read},
    str::FromStr,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let deployer = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r")?;
    let (output, data) = build_output_and_data(&deployer);

    let iterator = InputIterator::new_with_address(&[deployer], &network_info);
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    builder.add_output_and_data(output, data);

    let mut tx_with_groups = builder.build(&Default::default())?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let private_keys = vec![h256!(
        "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a"
    )];
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");

    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}

fn build_output_and_data(deployer: &Address) -> (CellOutput, Bytes) {
    let script_binary = File::open("./src/test-data/always_success").unwrap();
    let mut reader = BufReader::new(script_binary);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    let data_capacity = Capacity::bytes(buffer.len()).unwrap();

    let type_script =
        ScriptId::new_type(constants::TYPE_ID_CODE_HASH.clone()).dummy_type_id_script();
    let dummy_output = CellOutput::new_builder()
        .lock(deployer)
        .type_(Some(type_script).pack())
        .build();
    let required_capacity = dummy_output
        .occupied_capacity(data_capacity)
        .unwrap()
        .pack();
    let output = dummy_output
        .as_builder()
        .capacity(required_capacity)
        .build();
    (output, buffer.pack())
}
