use serde::{Deserialize, Serialize};

use ckb_jsonrpc_types::{
    BlockNumber, BlockView, HeaderView, JsonBytes, NodeAddress, RemoteNodeProtocol, Script,
    Transaction, TransactionView, Uint32, Uint64,
};
use ckb_types::H256;

pub use crate::rpc::ckb_indexer::{
    Cell, CellType, CellsCapacity, Order, Pagination, ScriptType, SearchKey, SearchKeyFilter,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScriptStatus {
    pub script: Script,
    pub script_type: ScriptType,
    pub block_number: BlockNumber,
}

#[derive(Deserialize, Serialize, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SetScriptsCommand {
    // Replace all scripts with new scripts, non-exist scripts will be deleted
    All,
    // Update partial scripts with new scripts, non-exist scripts will be ignored
    Partial,
    // Delete scripts, non-exist scripts will be ignored
    Delete,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(tag = "status")]
#[serde(rename_all = "snake_case")]
pub enum FetchStatus<T> {
    Added { timestamp: Uint64 },
    Fetching { first_sent: Uint64 },
    Fetched { data: T },
    NotFound,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransactionWithStatus {
    pub(crate) transaction: Option<TransactionView>,
    pub(crate) cycles: Option<Cycle>,
    pub(crate) tx_status: TxStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum Tx {
    Ungrouped(TxWithCell),
    Grouped(TxWithCells),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxWithCell {
    transaction: TransactionView,
    block_number: BlockNumber,
    tx_index: Uint32,
    io_index: Uint32,
    io_type: CellType,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxWithCells {
    transaction: TransactionView,
    block_number: BlockNumber,
    tx_index: Uint32,
    cells: Vec<(CellType, Uint32)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteNode {
    /// The remote node version.
    pub version: String,
    /// The remote node ID which is derived from its P2P private key.
    pub node_id: String,
    /// The remote node addresses.
    pub addresses: Vec<NodeAddress>,
    /// Elapsed time in milliseconds since the remote node is connected.
    pub connected_duration: Uint64,
    /// Null means chain sync has not started with this remote node yet.
    pub sync_state: Option<PeerSyncState>,
    /// Active protocols.
    ///
    /// CKB uses Tentacle multiplexed network framework. Multiple protocols are running
    /// simultaneously in the connection.
    pub protocols: Vec<RemoteNodeProtocol>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerSyncState {
    /// Requested best known header of remote peer.
    ///
    /// This is the best known header yet to be proved.
    pub requested_best_known_header: Option<HeaderView>,
    /// Proved best known header of remote peer.
    pub proved_best_known_header: Option<HeaderView>,
}

crate::jsonrpc!(pub struct LightClientRpcClient {
    // BlockFilter
    pub fn set_scripts(&self, scripts: Vec<ScriptStatus>, command: Option<SetScriptsCommand>) -> ();
    pub fn get_scripts(&self) -> Vec<ScriptStatus>;
    pub fn get_cells(&self, search_key: SearchKey, order: Order, limit: Uint32, after: Option<JsonBytes>) -> Pagination<Cell>;
    pub fn get_transactions(&self, search_key: SearchKey, order: Order, limit: Uint32, after: Option<JsonBytes>) -> Pagination<Tx>;
    pub fn get_cells_capacity(&self, search_key: SearchKey) -> CellsCapacity;

    // Transaction
    pub fn send_transaction(&self, tx: Transaction) -> H256;

    // Chain
    pub fn get_tip_header(&self) -> HeaderView;
    pub fn get_genesis_block(&self) -> BlockView;
    pub fn get_header(&self, block_hash: H256) -> Option<HeaderView>;
    pub fn get_transaction(&self, tx_hash: H256) -> Option<TransactionWithHeader>;
    /// Fetch a header from remote node. If return status is `not_found` will re-sent fetching request immediately.
    ///
    /// Returns: FetchStatus<HeaderView>
    pub fn fetch_header(&self, block_hash: H256) -> FetchStatus<HeaderView>;

    /// Fetch a transaction from remote node. If return status is `not_found` will re-sent fetching request immediately.
    ///
    /// Returns: FetchStatus<TransactionWithHeader>
    pub fn fetch_transaction(&self, tx_hash: H256) -> FetchStatus<TransactionWithHeader>;

    // Net
    pub fn get_peers(&self) -> Vec<RemoteNode>;
});
