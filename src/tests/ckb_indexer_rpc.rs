use crate::{
    rpc::{
        ckb_indexer::{Order, ScriptSearchMode, SearchKey},
        CkbRpcClient,
    },
    traits::{CellQueryOptions, ValueRangeOption},
};
use ckb_types::{core::ScriptHashType, h256, prelude::*, H256};
// use serde_json;

const TEST_CKB_RPC_URL: &str = "https://testnet.ckb.dev";

const CODE_HASH: H256 = h256!("0x00000000000000000000000000000000000000000000000000545950455f4944");
// 8536c9d5d908bd89fc70099e4284870708b6632356aad98734fcf43f6f71c304
const ARGS: [u8; 32] = [
    0x85, 0x36, 0xc9, 0xd5, 0xd9, 0x08, 0xbd, 0x89, 0xfc, 0x70, 0x09, 0x9e, 0x42, 0x84, 0x87, 0x07,
    0x08, 0xb6, 0x63, 0x23, 0x56, 0xaa, 0xd9, 0x87, 0x34, 0xfc, 0xf4, 0x3f, 0x6f, 0x71, 0xc3, 0x04,
];
#[test]
fn test_get_indexer_tip() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let indexer_tip = ckb_client.get_indexer_tip().unwrap().unwrap();
    let tip_block_number = ckb_client.get_tip_block_number().unwrap().value();
    assert!(indexer_tip.block_number.value() - tip_block_number <= 1);
}

#[test]
fn test_cells_search_mode_default_partitial() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    // default with partitial args
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.block_range = block_range;
    query.script_search_mode = None;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_cells(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(page.objects.len(), 1);
}
#[test]
fn test_cells_search_mode_prefix_partitial() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    // prefix with partitial args
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.block_range = block_range;
    query.script_search_mode = Some(ScriptSearchMode::Prefix);
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_cells(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(page.objects.len(), 1);
}
#[test]
fn test_cells_search_mode_exact_partitial() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();
    // exact with partitial args
    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.script_search_mode = Some(ScriptSearchMode::Exact);
    query.block_range = block_range;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_cells(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(0, page.objects.len());
}
#[test]
fn test_cells_search_mode_exact() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[..].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.script_search_mode = Some(ScriptSearchMode::Exact);
    query.block_range = block_range;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_cells(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(page.objects.len(), 1);
}

#[test]
fn test_get_transactions_search_mode_default() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.block_range = block_range;
    query.script_search_mode = None;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_transactions(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(page.objects.len(), 1);
}

#[test]
fn test_get_transactions_search_mode_prefix_partial() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.block_range = block_range;
    query.script_search_mode = Some(ScriptSearchMode::Prefix);
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_transactions(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(page.objects.len(), 1);
}
#[test]
fn test_get_transactions_search_mode_exact_partitial() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.script_search_mode = Some(ScriptSearchMode::Exact);
    query.block_range = block_range;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_transactions(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(0, page.objects.len());
}
#[test]
fn test_get_transactions_search_mode_exact_full() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    // exact search
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[..].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.script_search_mode = Some(ScriptSearchMode::Exact);
    query.block_range = block_range;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let page = ckb_client
        .get_transactions(search_key, Order::Desc, 10u32.into(), None)
        .unwrap();
    assert_eq!(page.objects.len(), 1);
}
#[test]
fn test_get_cells_capacity_search_mode_default() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.block_range = block_range;
    query.script_search_mode = None;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let cells_capacity = ckb_client.get_cells_capacity(search_key).unwrap().unwrap();
    assert_eq!(cells_capacity.capacity.value(), 0x9184e72a000);
}

#[test]
fn test_get_cells_capacity_search_mode_prefix_partial() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.block_range = block_range;
    query.script_search_mode = Some(ScriptSearchMode::Prefix);
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let cells_capacity = ckb_client.get_cells_capacity(search_key).unwrap().unwrap();
    assert_eq!(cells_capacity.capacity.value(), 0x9184e72a000);
}

#[test]
fn test_get_cells_capacity_search_mode_exact_partital() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[0..2].pack())
        .build();
    // exact with partitial args
    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.script_search_mode = Some(ScriptSearchMode::Exact);
    query.block_range = block_range;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let cells_capacity = ckb_client.get_cells_capacity(search_key).unwrap().unwrap();
    assert_eq!(cells_capacity.capacity.value(), 0);
}

#[test]
fn test_get_cells_capacity_search_mode_exact() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);

    let block_range = Some(ValueRangeOption::new(0, 1));
    let script = ckb_types::packed::Script::new_builder()
        .code_hash(CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ARGS[..].pack())
        .build();

    let mut query = CellQueryOptions::new(script, crate::traits::PrimaryScriptType::Type);
    query.script_search_mode = Some(ScriptSearchMode::Exact);
    query.block_range = block_range;
    query.min_total_capacity = u64::MAX;

    let search_key = SearchKey::from(query);
    let cells_capacity = ckb_client.get_cells_capacity(search_key).unwrap().unwrap();
    assert_eq!(cells_capacity.capacity.value(), 0x9184e72a000);
}
