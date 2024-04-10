use ckb_jsonrpc_types::CellOutput;
use ckb_sdk::{
    core::{convert_transaction_builder, TransactionBuilder},
    transaction::{
        builder::{offline::OfflineTransactionBuilder, CkbTransactionBuilder, SimpleTransactionBuilder},
        input::InputIterator,
        psbt::PSBTransaction,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::{core, packed, prelude::*, H256};
use ckb_types::{core::Capacity, h256};
use std::{error::Error as StdErr, str::FromStr};

use ckb_types::{
    core::{ScriptHashType, TransactionView as CoreTransactionView},
    packed::Script,
    prelude::*,
};

fn main() -> Result<(), Box<dyn StdErr>> {
    let test_str = r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf05188e5f3a6767fc4687faf45ba5f1a6e25d3ada6129dae8722cb282f262493"}}],"hash":"0x4c57aee399e0852f260c0c5510aa3e3e40c88cbd17e6a1408ae1861f6b8e461d","header_deps":[],"inputs":[{"previous_output":{"index":"0x1","tx_hash":"0x00c62760a04ff20a4371f9b6158d3e04867edeb0c9ef0fb1614dbb8e4c91f9d3"},"since":"0x0"}],"outputs":[{"capacity":"0x30e4f9b400","lock":{"args":"0x0001d30d061925592e3827abbadf46db388da6343312","code_hash":"0xd00c84f0ec8fd441c38bc3f87a371f547190f2fcff88e642bc5bf54b9e318323","hash_type":"type"},"type":null},{"capacity":"0x6b6bb86839d","lock":{"args":"0x0001f524aa8c5021e35fff3732c5b657984a75013f05","code_hash":"0xd00c84f0ec8fd441c38bc3f87a371f547190f2fcff88e642bc5bf54b9e318323","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"previous_output_cells":[{"capacity":"0x6e7a0803ec5","lock":{"args":"0x0001f524aa8c5021e35fff3732c5b657984a75013f05","code_hash":"0xd00c84f0ec8fd441c38bc3f87a371f547190f2fcff88e642bc5bf54b9e318323","hash_type":"type"},"type":null}],"version":"0x0","witnesses":[]}"#;
    let test_str_1 = r#"{"version":"0x0","cell_deps":[{"out_point":{"tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37","index":"0x0"},"dep_type":"dep_group"}],"header_deps":[],"inputs":[{"since":"0x0","previous_output":{"tx_hash":"0xf8fec06d19a23952fc2575d473bff189f0b711f6d9b617798f985c6a5f461c38","index":"0x1"}}],"previous_output_cells":[{"capacity":"0x2d4e49e05b","lock":{"args":"0x4049ed9cec8a0d39c7a1e899f0dacb8a8c28ad14","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs":[{"capacity":"0xbdfd63e00","lock":{"code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type","args":"0x946c32d287a3544d5450f0cf5d43ca24dd37f55e"},"type":null},{"capacity":"0x216e73a08b","lock":{"code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type","args":"0x4049ed9cec8a0d39c7a1e899f0dacb8a8c28ad14"},"type":null}],"outputs_data":["0x","0x"],"witnesses":["0x55000000100000005500000055000000410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],"hash":"0x7e6e1afbb688de22eb316c1813e0ae1123326e0a4493f88b563c01d3501839d3"}"#;
    let a = serde_json::from_str::<PSBTransaction>(test_str_1).unwrap();
    println!("psbt transaction:{:?}", a);
    let c: packed::Transaction = a.inner.into();
    let cells: Vec<ckb_types::packed::CellOutput> = a.previous_output_cells.iter().map(|v| packed::CellOutput::from(v.clone())).collect();
    let tb = convert_transaction_builder(c);


    let network_info = NetworkInfo::testnet();
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let mut builder = OfflineTransactionBuilder::new(configuration, tb);
    let mut tx_with_groups = builder.build(&Default::default(), cells)?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // // let json_scriptGroup = ckb_jsonrpc_types::ScriptGroup::from(tx_with_groups.get_script_groups().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());


    let private_keys = vec![h256!(
        "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a"
    )];
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("==============================");
    println!(" sigend tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    println!("==============================");
    // tb.build();

    // let tv = tb.build();

    // let d  = packed::Byte32::from_slice(a.hash.as_bytes()).unwrap();
    // let TransactionView =

    // let witness =

    // let c = packed::Transaction::from(a.inner);

    // let network_info = NetworkInfo::testnet();
    // let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    // let sender = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2qf8keemy2p5uu0g0gn8cd4ju23s5269qk8rg4r")?;
    // let receiver= Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche")?;

    // let iterator = InputIterator::new_with_address(&[sender], &network_info);
    // let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    // builder.add_output(&receiver, Capacity::shannons(510_0000_0000u64));

    // let mut tx_with_groups = builder.build(&Default::default())?;

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // // let json_scriptGroup = ckb_jsonrpc_types::ScriptGroup::from(tx_with_groups.get_script_groups().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    // let private_keys = vec![h256!(
    //     "0x6c9ed03816e3111e49384b8d180174ad08e29feb1393ea1b51cef1c505d4e36a"
    // )];
    // TransactionSigner::new(&network_info).sign_transaction(
    //     &mut tx_with_groups,
    //     &SignContexts::new_sighash_h256(private_keys)?,
    // )?;

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    // let tx_hash = CkbRpcClient::new(network_info.url.as_str())
    //     .send_transaction(json_tx.inner, None)
    //     .expect("send transaction");
    // // example tx: 0x9ce266d45600abbd56467c9be59febe7b07336d7c1f439b9c06379f080bf0552
    // println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
