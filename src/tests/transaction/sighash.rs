use ckb_types::{core::Capacity, packed::CellOutput, prelude::*};

use crate::{
    constants::ONE_CKB,
    tests::{
        build_sighash_script, init_context, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, FEE_RATE,
    },
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        SmallChangeAction, TransactionBuilderConfiguration,
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
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone()).unwrap();

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    builder.add_output(output.clone(), ckb_types::packed::Bytes::default());
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

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_transfer_from_sighash_samll_to_fee() {
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
        .capacity((299 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone()).unwrap();
    configuration.small_change_action = SmallChangeAction::AsFee {
        threshold: Capacity::bytes(1).unwrap().as_u64(),
    };

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    builder.add_output(output.clone(), ckb_types::packed::Bytes::default());
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
    assert_eq!(tx.outputs().len(), 1);
    assert_eq!(tx.output(0).unwrap(), output);

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_transfer_from_sighash_samll_to_receiver() {
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
        .capacity((299 * ONE_CKB).pack())
        .lock(receiver.clone())
        .build();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone()).unwrap();
    configuration.small_change_action =
        SmallChangeAction::to_output(receiver, Capacity::bytes(1).unwrap().as_u64());

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    builder.add_output(output, ckb_types::packed::Bytes::default());
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
    assert_eq!(tx.outputs().len(), 1);
    let actual_output_capacity: u64 = tx.output(0).unwrap().capacity().unpack();
    assert!(actual_output_capacity > 299 * ONE_CKB);

    ctx.verify(tx, FEE_RATE).unwrap();
}
