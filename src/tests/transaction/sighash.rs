use ckb_types::{packed::CellOutput, prelude::*};

use crate::{
    constants::ONE_CKB,
    tests::{
        build_sighash_script, init_context, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, FEE_RATE,
    },
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    NetworkInfo,
};

#[test]
fn test_transfer_from_sighash() {
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let ctx = init_context(
        Vec::new(),
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let network_info = NetworkInfo::testnet();

    let output = CellOutput::new_builder()
        .capacity(120 * ONE_CKB)
        .lock(receiver)
        .build();
    let configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone()).unwrap();

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender.clone());
    let mut tx_with_groups = builder.build(&Default::default()).expect("build failed");

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    TransactionSigner::new(&network_info)
        .sign_transaction(
            &mut tx_with_groups,
            &SignContexts::new_sighash_h256(vec![ACCOUNT1_KEY.clone()]).unwrap(),
        )
        .unwrap();

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx = tx_with_groups.get_tx_view().clone();
    let script_groups = tx_with_groups.script_groups.clone();
    assert_eq!(script_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (100 + 200 - 120) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);

    ctx.verify(tx, FEE_RATE).unwrap();
}
