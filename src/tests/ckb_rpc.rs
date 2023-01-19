use crate::rpc::CkbRpcClient;
use ckb_types::{core, h256, prelude::Entity, H256};
use serde_json;

const TEST_CKB_RPC_URL: &str = "https://testnet.ckb.dev";

const BLOCK_HASH: H256 =
    h256!("0xd88eb0cf9f6e6f123c733e9aba29dec9cb449965a8adc98216c50d5083b909b1");
const BLOCK_NUMBER: u64 = 7981482;
// python code:    "block_hash_that_does_not_exist".encode("utf-8").hex()
// output   '626c6f636b5f686173685f746861745f646f65735f6e6f745f6578697374'
const BLOCK_HASH_NOT_EXIST: H256 =
    h256!("0x626c6f636b5f686173685f746861745f646f65735f6e6f745f65786973740000");
const BLOCK_NUMBER_NOT_EXIST: u64 = u64::max_value();

#[test]
fn test_get_block() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_block(BLOCK_HASH.clone()).unwrap();
    let block = block.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());
    let block_from_json = core::BlockView::from(block);

    let block = ckb_client.get_packed_block(BLOCK_HASH.clone()).unwrap();
    assert!(block.is_some());
    let block = block.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());

    let block_from_types = ckb_types::packed::Block::new_unchecked(block.into_bytes()).into_view();

    assert_eq!(block_from_json, block_from_types);

    // by number
    let block = ckb_client.get_block_by_number(BLOCK_NUMBER.into()).unwrap();
    let block = block.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());
    let block_from_json_n = core::BlockView::from(block);

    let block = ckb_client
        .get_packed_block_by_number(BLOCK_NUMBER.into())
        .unwrap();
    assert!(block.is_some());
    let block = block.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());

    let block_from_types_n =
        ckb_types::packed::Block::new_unchecked(block.into_bytes()).into_view();

    assert_eq!(block_from_json_n, block_from_types_n);
    assert_eq!(block_from_json, block_from_json_n);
}

#[test]
fn test_get_block_with_cycles() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block_cycle = ckb_client.get_block_with_cycles(BLOCK_HASH.clone());
    let block_cycle = block_cycle.unwrap();
    let block = block_cycle.0.unwrap();
    let cycles_0 = block_cycle.1.unwrap();
    println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());
    let block_from_json = core::BlockView::from(block);

    let block_cycles = ckb_client
        .get_packed_block_with_cycles(BLOCK_HASH.clone())
        .unwrap();

    assert!(block_cycles.0.is_some());
    let block = block_cycles.0.unwrap();
    let cycles_1 = block_cycles.1.unwrap();
    println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());

    let block_from_types = ckb_types::packed::Block::new_unchecked(block.into_bytes()).into_view();

    assert_eq!(block_from_json, block_from_types);
    assert_eq!(cycles_0, cycles_1);

    let block_cycle_n = ckb_client.get_block_by_number_with_cycles(BLOCK_NUMBER.into());
    let block_cycle_n = block_cycle_n.unwrap();
    let block = block_cycle_n.0.unwrap();
    let cycles_0_n = block_cycle_n.1.unwrap();
    println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());
    let block_from_json_n = core::BlockView::from(block);

    let block_cycles = ckb_client
        .get_packed_block_by_number_with_cycles(BLOCK_NUMBER.into())
        .unwrap();

    assert!(block_cycles.0.is_some());
    let block = block_cycles.0.unwrap();
    let cycles_1_n = block_cycles.1.unwrap();
    println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());

    let block_from_types_n =
        ckb_types::packed::Block::new_unchecked(block.into_bytes()).into_view();

    assert_eq!(block_from_json_n, block_from_types_n);
    assert_eq!(block_from_json, block_from_types_n);
    assert_eq!(cycles_0_n, cycles_1_n);
    assert_eq!(cycles_0, cycles_1_n);

    assert_eq!(cycles_0.len() + 1, block_from_json.transactions().len());
}

#[test]
fn test_get_packed_block_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_block(BLOCK_HASH_NOT_EXIST.clone());
    let block = block.unwrap();
    assert!(block.is_none());
}

#[test]
fn test_get_block_with_cycles_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_block_with_cycles(BLOCK_HASH_NOT_EXIST.clone());
    let block = block.unwrap();
    assert!(block.0.is_none());
    assert!(block.1.is_none());
}

#[test]
fn test_get_packed_block_with_cycles_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_block_with_cycles(BLOCK_HASH_NOT_EXIST.clone());
    let block = block.unwrap();
    assert!(block.0.is_none());
    assert!(block.1.is_none());
}

#[test]
fn test_get_packed_block_by_number_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_block_by_number(BLOCK_NUMBER_NOT_EXIST.into());
    let block = block.unwrap();
    assert!(block.is_none());
}

#[test]
fn test_get_block_by_number_with_cycles_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_block_by_number_with_cycles(BLOCK_NUMBER_NOT_EXIST.into());
    let block = block.unwrap();
    assert!(block.0.is_none());
    assert!(block.1.is_none());
}

#[test]
fn test_get_packed_block_by_number_with_cycles_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_block_by_number_with_cycles(BLOCK_NUMBER_NOT_EXIST.into());
    let block = block.unwrap();
    assert!(block.0.is_none());
    assert!(block.1.is_none());
}
