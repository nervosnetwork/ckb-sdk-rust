use crate::rpc::{CkbRpcClient, ResponseFormatGetter};
use ckb_types::{core, h256, prelude::Entity, H256};
// use serde_json;

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
    let (block, cycles_0) = block_cycle.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());
    let block_from_json = core::BlockView::from(block);

    let block_cycles = ckb_client
        .get_packed_block_with_cycles(BLOCK_HASH.clone())
        .unwrap();

    assert!(block_cycles.is_some());
    let (block, cycles_1) = block_cycles.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());

    let block_from_types = ckb_types::packed::Block::new_unchecked(block.into_bytes()).into_view();

    assert_eq!(block_from_json, block_from_types);
    assert_eq!(cycles_0, cycles_1);

    let block_cycle_n = ckb_client.get_block_by_number_with_cycles(BLOCK_NUMBER.into());
    let block_cycle_n = block_cycle_n.unwrap();
    let (block, cycles_0_n) = block_cycle_n.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());
    let block_from_json_n = core::BlockView::from(block);

    let block_cycles = ckb_client
        .get_packed_block_by_number_with_cycles(BLOCK_NUMBER.into())
        .unwrap();

    assert!(block_cycles.is_some());
    let (block, cycles_1_n) = block_cycles.unwrap();
    // println!("> block: {}", serde_json::to_string_pretty(&block).unwrap());

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
    assert!(block.is_none());
}

#[test]
fn test_get_packed_block_with_cycles_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_block_with_cycles(BLOCK_HASH_NOT_EXIST.clone());
    let block = block.unwrap();
    assert!(block.is_none());
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
    assert!(block.is_none());
}

#[test]
fn test_get_packed_block_by_number_with_cycles_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_block_by_number_with_cycles(BLOCK_NUMBER_NOT_EXIST.into());
    let block = block.unwrap();
    assert!(block.is_none());
}

#[test]
fn test_get_header() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let header = ckb_client.get_header(BLOCK_HASH.clone());
    let header = header.unwrap();
    let header = header.unwrap();
    let header_from_json = core::HeaderView::from(header);

    let header = ckb_client.get_packed_header(BLOCK_HASH.clone());
    let header = header.unwrap();
    let header_bytes_0 = header.unwrap();

    let header_from_bytes =
        ckb_types::packed::Header::new_unchecked(header_bytes_0.clone().into_bytes()).into_view();

    assert_eq!(header_from_json, header_from_bytes);

    let header = ckb_client.get_packed_header_by_number(BLOCK_NUMBER.into());
    let header = header.unwrap();
    let header_bytes_1 = header.unwrap();

    assert_eq!(header_bytes_0, header_bytes_1);
}

#[test]
fn test_get_packed_header_fail() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let header = ckb_client.get_header(BLOCK_HASH_NOT_EXIST.clone());
    let header = header.unwrap();
    assert!(header.is_none());
}

#[test]
fn test_get_packed_header_by_number_not_exist() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let header = ckb_client.get_packed_header_by_number(BLOCK_NUMBER_NOT_EXIST.into());
    let header = header.unwrap();
    assert!(header.is_none());
}
const TRANSACTION_HASH: H256 =
    h256!("0xd713b21bbdeae7ae1fe0050be61afcfdd9335a1ccbfbf7f916be4a45d6e5d012");

// python code: "transaction_hash_does_not_exist_".encode("utf-8").hex()
// '7472616e73616374696f6e5f686173685f646f65735f6e6f745f65786973745f'
const TRANSACTION_HASH_NOT_EXIST: H256 =
    h256!("0x7472616e73616374696f6e5f686173685f646f65735f6e6f745f65786973745f");

#[test]
fn test_get_packed_transaction() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let trans_resp0 = ckb_client.get_transaction(TRANSACTION_HASH.clone());
    let trans_resp0 = trans_resp0.unwrap();
    let trans_resp0 = trans_resp0.unwrap();
    let transaction_view_from_json = trans_resp0.transaction.unwrap().get_value().unwrap();

    let transaction_resp = ckb_client.get_packed_transaction(TRANSACTION_HASH.clone());
    let transaction_1 = transaction_resp.unwrap();

    let json_bytes = transaction_1.transaction.unwrap().get_json_bytes().unwrap();

    let transaction_from_bytes =
        ckb_types::packed::Transaction::new_unchecked(json_bytes.into_bytes()).into_view();
    let transaction_view_from_bytes =
        ckb_jsonrpc_types::TransactionView::from(transaction_from_bytes);
    assert_eq!(transaction_view_from_json, transaction_view_from_bytes);
    assert_eq!(trans_resp0.cycles, transaction_1.cycles);
    assert_eq!(trans_resp0.tx_status, transaction_1.tx_status);
}

#[test]
fn test_get_packed_transaction_not_exist() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let transaction = ckb_client.get_packed_transaction(TRANSACTION_HASH_NOT_EXIST.clone());
    let transaction = transaction.unwrap();
    assert!(transaction.transaction.is_none());
    assert!(transaction.cycles.is_none());
    assert_eq!(
        transaction.tx_status.status,
        ckb_jsonrpc_types::Status::Unknown
    );
    assert!(transaction.tx_status.block_hash.is_none());
    assert!(transaction.tx_status.reason.is_none());
}

#[test]
fn test_get_packed_transaction_verbosity_1() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let trans_resp0 = ckb_client.get_transaction(TRANSACTION_HASH.clone());
    let trans_resp0 = trans_resp0.unwrap();
    let trans_resp0 = trans_resp0.unwrap();

    let transaction_resp = ckb_client.get_transaction_status(TRANSACTION_HASH.clone());
    let transaction_1 = transaction_resp.unwrap();

    assert!(transaction_1.transaction.is_none());

    assert_eq!(trans_resp0.cycles, transaction_1.cycles);
    assert_eq!(trans_resp0.tx_status, transaction_1.tx_status);
}

#[test]
fn test_get_packed_transaction_verbosity_1_not_exist() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let transaction = ckb_client.get_transaction_status(TRANSACTION_HASH_NOT_EXIST.clone());
    let transaction = transaction.unwrap();
    assert!(transaction.transaction.is_none());
    assert!(transaction.cycles.is_none());
    assert_eq!(
        transaction.tx_status.status,
        ckb_jsonrpc_types::Status::Unknown
    );
    assert!(transaction.tx_status.block_hash.is_none());
    assert!(transaction.tx_status.reason.is_none());
}

#[test]
fn test_get_tip_header() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let header_bytes = ckb_client.get_packed_tip_header();
    let header_bytes = header_bytes.unwrap();

    let header_view = ckb_types::packed::Header::from_slice(header_bytes.as_bytes());
    assert!(header_view.is_ok())
}

#[test]
fn test_get_packed_fork_block_not_exist() {
    let mut ckb_client = CkbRpcClient::new(TEST_CKB_RPC_URL);
    let block = ckb_client.get_packed_fork_block(BLOCK_HASH.clone());
    let block = block.unwrap();
    assert!(block.is_none());

    let block = ckb_client.get_packed_fork_block(BLOCK_HASH_NOT_EXIST.clone());
    let block = block.unwrap();
    assert!(block.is_none());
}
