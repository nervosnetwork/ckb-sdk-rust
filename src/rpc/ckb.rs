use ckb_jsonrpc_types::{
    Alert, BannedAddr, Block, BlockEconomicState, BlockFilter, BlockNumber, BlockResponse,
    BlockTemplate, BlockView, Capacity, CellWithStatus, ChainInfo, Consensus,
    DaoWithdrawingCalculationKind, DeploymentsInfo, EntryCompleted, EpochNumber,
    EpochNumberWithFraction, EpochView, EstimateCycles, ExtraLoggerConfig, FeeRateStatistics,
    HeaderView, JsonBytes, LocalNode, MainLoggerConfig, OutPoint, OutputsValidator,
    PoolTxDetailInfo, RawTxPool, RemoteNode, SyncState, Timestamp, Transaction,
    TransactionAndWitnessProof, TransactionProof, TransactionWithStatusResponse, TxPoolInfo,
    Uint32, Uint64, Version,
};
use ckb_types::{core::Cycle, H256};

use super::{ckb_indexer::CellsCapacity, ResponseFormatGetter};

pub use super::ckb_indexer::{Cell, Order, Pagination, SearchKey, Tip, Tx};

crate::jsonrpc!(pub struct CkbRpcClient {
    // Chain
    pub fn get_block(&self, hash: H256) -> Option<BlockView>;
    pub fn get_block_by_number(&self, number: BlockNumber) -> Option<BlockView>;
    pub fn get_block_hash(&self, number: BlockNumber) -> Option<H256>;
    pub fn get_block_filter(&self, block_hash: H256) -> Option<BlockFilter>;
    pub fn get_current_epoch(&self) -> EpochView;
    pub fn get_epoch_by_number(&self, number: EpochNumber) -> Option<EpochView>;
    pub fn get_header(&self, hash: H256) -> Option<HeaderView>;
    pub fn get_header_by_number(&self, number: BlockNumber) -> Option<HeaderView>;
    pub fn get_live_cell(&self, out_point: OutPoint, with_data: bool) -> CellWithStatus;
    pub fn get_tip_block_number(&self) -> BlockNumber;
    pub fn get_tip_header(&self) -> HeaderView;
    pub fn get_transaction(&self, hash: H256) -> Option<TransactionWithStatusResponse>;
    pub fn get_transaction_proof(
        &self,
        tx_hashes: Vec<H256>,
        block_hash: Option<H256>
    ) -> TransactionProof;
    pub fn verify_transaction_proof(&self, tx_proof: TransactionProof) -> Vec<H256>;
    pub fn get_transaction_and_witness_proof(&self, tx_hashes: Vec<H256>,
        block_hash: Option<H256>) -> TransactionAndWitnessProof;
    pub fn verify_transaction_and_witness_proof(&self, tx_proof: TransactionAndWitnessProof) -> Vec<H256>;
    pub fn get_fork_block(&self, block_hash: H256) -> Option<BlockView>;
    pub fn get_consensus(&self) -> Consensus;
    pub fn get_deployments_info(&self) -> DeploymentsInfo;
    pub fn get_block_median_time(&self, block_hash: H256) -> Option<Timestamp>;
    pub fn get_block_economic_state(&self, block_hash: H256) -> Option<BlockEconomicState>;
    pub fn estimate_cycles(&self, tx: Transaction)-> EstimateCycles;
    pub fn get_fee_rate_statics(&self, target:Option<Uint64>) -> Option<FeeRateStatistics>;
    pub fn get_fee_rate_statistics(&self, target:Option<Uint64>) -> Option<FeeRateStatistics>;

    // Indexer
    pub fn get_indexer_tip(&self) -> Option<Tip>;
    pub fn get_cells(&self, search_key: SearchKey, order: Order, limit: Uint32, after: Option<JsonBytes>) -> Pagination<Cell>;
    pub fn get_transactions(&self, search_key: SearchKey, order: Order, limit: Uint32, after: Option<JsonBytes>) -> Pagination<Tx>;
    pub fn get_cells_capacity(&self, search_key: SearchKey) -> Option<CellsCapacity>;

    // Net
    pub fn get_banned_addresses(&self) -> Vec<BannedAddr>;
    pub fn get_peers(&self) -> Vec<RemoteNode>;
    pub fn local_node_info(&self) -> LocalNode;
    pub fn set_ban(
        &self,
        address: String,
        command: String,
        ban_time: Option<Timestamp>,
        absolute: Option<bool>,
        reason: Option<String>
    ) -> ();
    pub fn sync_state(&self) -> SyncState;
    pub fn set_network_active(&self, state: bool) -> ();
    pub fn add_node(&self, peer_id: String, address: String) -> ();
    pub fn remove_node(&self, peer_id: String) -> ();
    pub fn clear_banned_addresses(&self) -> ();
    pub fn ping_peers(&self) -> ();

    // Pool
    pub fn send_transaction(&self, tx: Transaction, outputs_validator: Option<OutputsValidator>) -> H256;
    pub fn remove_transaction(&self, tx_hash: H256) -> bool;
    pub fn tx_pool_info(&self) -> TxPoolInfo;
    pub fn get_pool_tx_detail_info(&self, tx_hash: H256) -> PoolTxDetailInfo;
    pub fn clear_tx_pool(&self) -> ();
    pub fn get_raw_tx_pool(&self, verbose: Option<bool>) -> RawTxPool;
    pub fn tx_pool_ready(&self) -> bool;
    pub fn test_tx_pool_accept(&self, tx: Transaction, outputs_validator: Option<OutputsValidator>) -> EntryCompleted;
    pub fn clear_tx_verify_queue(&self) -> ();

    // Stats
    pub fn get_blockchain_info(&self) -> ChainInfo;

    // Miner
    pub fn get_block_template(&self, bytes_limit: Option<Uint64>, proposals_limit: Option<Uint64>, max_version: Option<Version>) -> BlockTemplate;
    pub fn submit_block(&self, _work_id: String, _data: Block) -> H256;

    // Alert
    pub fn send_alert(&self, alert: Alert) -> ();

    // IntegrationTest
    pub fn process_block_without_verify(&self, data: Block, broadcast: bool) -> Option<H256>;
    pub fn truncate(&self, target_tip_hash: H256) -> ();
    pub fn generate_block(&self) -> H256;
    pub fn generate_epochs(&self, num_epochs: EpochNumberWithFraction) -> EpochNumberWithFraction;
    pub fn notify_transaction(&self, tx: Transaction) -> H256;
    pub fn calculate_dao_field(&self, block_template: BlockTemplate) -> JsonBytes;
    pub fn generate_block_with_template(&self, block_template: BlockTemplate) -> H256;

    // Debug
    pub fn jemalloc_profiling_dump(&self) -> String;
    pub fn update_main_logger(&self, config: MainLoggerConfig) -> ();
    pub fn set_extra_logger(&self, name: String, config_opt: Option<ExtraLoggerConfig>) -> ();

    // Experimental
    pub fn calculate_dao_maximum_withdraw(&self, out_point: OutPoint, kind: DaoWithdrawingCalculationKind) -> Capacity;
});

crate::jsonrpc_async!(pub struct CkbRpcAsyncClient {
    // Chain
    pub fn get_block(&self, hash: H256) -> Option<BlockView>;
    pub fn get_block_by_number(&self, number: BlockNumber) -> Option<BlockView>;
    pub fn get_block_hash(&self, number: BlockNumber) -> Option<H256>;
    pub fn get_block_filter(&self, block_hash: H256) -> Option<BlockFilter>;
    pub fn get_current_epoch(&self) -> EpochView;
    pub fn get_epoch_by_number(&self, number: EpochNumber) -> Option<EpochView>;
    pub fn get_header(&self, hash: H256) -> Option<HeaderView>;
    pub fn get_header_by_number(&self, number: BlockNumber) -> Option<HeaderView>;
    pub fn get_live_cell(&self, out_point: OutPoint, with_data: bool) -> CellWithStatus;
    pub fn get_tip_block_number(&self) -> BlockNumber;
    pub fn get_tip_header(&self) -> HeaderView;
    pub fn get_transaction(&self, hash: H256) -> Option<TransactionWithStatusResponse>;
    pub fn get_transaction_proof(
        &self,
        tx_hashes: Vec<H256>,
        block_hash: Option<H256>
    ) -> TransactionProof;
    pub fn verify_transaction_proof(&self, tx_proof: TransactionProof) -> Vec<H256>;
    pub fn get_transaction_and_witness_proof(&self, tx_hashes: Vec<H256>,
        block_hash: Option<H256>) -> TransactionAndWitnessProof;
    pub fn verify_transaction_and_witness_proof(&self, tx_proof: TransactionAndWitnessProof) -> Vec<H256>;
    pub fn get_fork_block(&self, block_hash: H256) -> Option<BlockView>;
    pub fn get_consensus(&self) -> Consensus;
    pub fn get_deployments_info(&self) -> DeploymentsInfo;
    pub fn get_block_median_time(&self, block_hash: H256) -> Option<Timestamp>;
    pub fn get_block_economic_state(&self, block_hash: H256) -> Option<BlockEconomicState>;
    pub fn estimate_cycles(&self, tx: Transaction)-> EstimateCycles;
    pub fn get_fee_rate_statics(&self, target:Option<Uint64>) -> Option<FeeRateStatistics>;
    pub fn get_fee_rate_statistics(&self, target:Option<Uint64>) -> Option<FeeRateStatistics>;

    // Indexer
    pub fn get_indexer_tip(&self) -> Option<Tip>;
    pub fn get_cells(&self, search_key: SearchKey, order: Order, limit: Uint32, after: Option<JsonBytes>) -> Pagination<Cell>;
    pub fn get_transactions(&self, search_key: SearchKey, order: Order, limit: Uint32, after: Option<JsonBytes>) -> Pagination<Tx>;
    pub fn get_cells_capacity(&self, search_key: SearchKey) -> Option<CellsCapacity>;

    // Net
    pub fn get_banned_addresses(&self) -> Vec<BannedAddr>;
    pub fn get_peers(&self) -> Vec<RemoteNode>;
    pub fn local_node_info(&self) -> LocalNode;
    pub fn set_ban(
        &self,
        address: String,
        command: String,
        ban_time: Option<Timestamp>,
        absolute: Option<bool>,
        reason: Option<String>
    ) -> ();
    pub fn sync_state(&self) -> SyncState;
    pub fn set_network_active(&self, state: bool) -> ();
    pub fn add_node(&self, peer_id: String, address: String) -> ();
    pub fn remove_node(&self, peer_id: String) -> ();
    pub fn clear_banned_addresses(&self) -> ();
    pub fn ping_peers(&self) -> ();

    // Pool
    pub fn send_transaction(&self, tx: Transaction, outputs_validator: Option<OutputsValidator>) -> H256;
    pub fn remove_transaction(&self, tx_hash: H256) -> bool;
    pub fn tx_pool_info(&self) -> TxPoolInfo;
    pub fn get_pool_tx_detail_info(&self, tx_hash: H256) -> PoolTxDetailInfo;
    pub fn clear_tx_pool(&self) -> ();
    pub fn get_raw_tx_pool(&self, verbose: Option<bool>) -> RawTxPool;
    pub fn tx_pool_ready(&self) -> bool;
    pub fn test_tx_pool_accept(&self, tx: Transaction, outputs_validator: Option<OutputsValidator>) -> EntryCompleted;
    pub fn clear_tx_verify_queue(&self) -> ();

    // Stats
    pub fn get_blockchain_info(&self) -> ChainInfo;

    // Miner
    pub fn get_block_template(&self, bytes_limit: Option<Uint64>, proposals_limit: Option<Uint64>, max_version: Option<Version>) -> BlockTemplate;
    pub fn submit_block(&self, _work_id: String, _data: Block) -> H256;

    // Alert
    pub fn send_alert(&self, alert: Alert) -> ();

    // IntegrationTest
    pub fn process_block_without_verify(&self, data: Block, broadcast: bool) -> Option<H256>;
    pub fn truncate(&self, target_tip_hash: H256) -> ();
    pub fn generate_block(&self) -> H256;
    pub fn generate_epochs(&self, num_epochs: EpochNumberWithFraction) -> EpochNumberWithFraction;
    pub fn notify_transaction(&self, tx: Transaction) -> H256;
    pub fn calculate_dao_field(&self, block_template: BlockTemplate) -> JsonBytes;
    pub fn generate_block_with_template(&self, block_template: BlockTemplate) -> H256;

    // Debug
    pub fn jemalloc_profiling_dump(&self) -> String;
    pub fn update_main_logger(&self, config: MainLoggerConfig) -> ();
    pub fn set_extra_logger(&self, name: String, config_opt: Option<ExtraLoggerConfig>) -> ();

    // Experimental
    pub fn calculate_dao_maximum_withdraw(&self, out_point: OutPoint, kind: DaoWithdrawingCalculationKind) -> Capacity;
});

fn transform_cycles(cycles: Option<Vec<ckb_jsonrpc_types::Cycle>>) -> Vec<Cycle> {
    cycles
        .map(|c| c.into_iter().map(Into::into).collect())
        .unwrap_or_default()
}

impl From<&CkbRpcClient> for CkbRpcAsyncClient {
    fn from(value: &CkbRpcClient) -> Self {
        Self {
            client: value.client.clone(),
            id: 0.into(),
        }
    }
}

impl CkbRpcClient {
    pub fn get_packed_block(&self, hash: H256) -> Result<Option<JsonBytes>, crate::RpcError> {
        self.post("get_block", (hash, Some(Uint32::from(0u32))))
    }

    /// Same as get_block except with parameter with_cycles and return BlockResponse
    pub fn get_block_with_cycles(
        &self,
        hash: H256,
    ) -> Result<Option<(BlockView, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self.post::<_, Option<BlockResponse>>("get_block", (hash, None::<u32>, true))?;
        transform_block_view_with_cycle(res)
    }

    pub fn get_packed_block_with_cycles(
        &self,
        hash: H256,
    ) -> Result<Option<(JsonBytes, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self.post::<_, Option<BlockResponse>>(
            "get_block",
            (hash, Some(Uint32::from(0u32)), true),
        )?;
        blockresponse2bytes(res)
    }

    /// Same as get_block_by_number except with parameter with_cycles and return BlockResponse
    pub fn get_packed_block_by_number(
        &self,
        number: BlockNumber,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post("get_block_by_number", (number, Some(Uint32::from(0u32))))
    }

    pub fn get_block_by_number_with_cycles(
        &self,
        number: BlockNumber,
    ) -> Result<Option<(BlockView, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self
            .post::<_, Option<BlockResponse>>("get_block_by_number", (number, None::<u32>, true))?;
        transform_block_view_with_cycle(res)
    }

    pub fn get_packed_block_by_number_with_cycles(
        &self,
        number: BlockNumber,
    ) -> Result<Option<(JsonBytes, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self.post::<_, Option<BlockResponse>>(
            "get_block_by_number",
            (number, Some(Uint32::from(0u32)), true),
        )?;
        blockresponse2bytes(res)
    }

    pub fn get_packed_header(&self, hash: H256) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post::<_, Option<JsonBytes>>("get_header", (hash, Some(Uint32::from(0u32))))
    }

    pub fn get_packed_header_by_number(
        &self,
        number: BlockNumber,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post::<_, Option<JsonBytes>>(
            "get_header_by_number",
            (number, Some(Uint32::from(0u32))),
        )
    }

    pub fn get_live_cell_with_include_tx_pool(
        &self,
        out_point: OutPoint,
        with_data: bool,
        include_tx_pool: bool,
    ) -> Result<CellWithStatus, crate::rpc::RpcError> {
        self.post::<_, CellWithStatus>(
            "get_live_cell",
            (out_point, with_data, Some(include_tx_pool)),
        )
    }

    // get transaction with only_committed=true
    pub fn get_only_committed_transaction(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(2u32)), true),
        )
    }

    // get transaction with verbosity=0
    pub fn get_packed_transaction(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(0u32))),
        )
    }

    // get transaction with verbosity=0 and only_committed=true
    pub fn get_only_committed_packed_transaction(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(0u32)), true),
        )
    }

    // get transaction with verbosity=1, so the result transaction field is None
    pub fn get_transaction_status(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(1u32))),
        )
    }

    // get transaction with verbosity=1 and only_committed=true, so the result transaction field is None
    pub fn get_only_committed_transaction_status(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(1u32)), true),
        )
    }

    pub fn get_packed_tip_header(&self) -> Result<JsonBytes, crate::rpc::RpcError> {
        self.post::<_, JsonBytes>("get_tip_header", (Some(Uint32::from(0u32)),))
    }

    pub fn get_packed_fork_block(
        &self,
        block_hash: H256,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post::<_, Option<JsonBytes>>("get_fork_block", (block_hash, Some(Uint32::from(0u32))))
    }
}

impl CkbRpcAsyncClient {
    pub async fn get_packed_block(&self, hash: H256) -> Result<Option<JsonBytes>, crate::RpcError> {
        self.post("get_block", (hash, Some(Uint32::from(0u32))))
            .await
    }

    /// Same as get_block except with parameter with_cycles and return BlockResponse
    pub async fn get_block_with_cycles(
        &self,
        hash: H256,
    ) -> Result<Option<(BlockView, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self
            .post::<_, Option<BlockResponse>>("get_block", (hash, None::<u32>, true))
            .await?;
        transform_block_view_with_cycle(res)
    }

    pub async fn get_packed_block_with_cycles(
        &self,
        hash: H256,
    ) -> Result<Option<(JsonBytes, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self
            .post::<_, Option<BlockResponse>>("get_block", (hash, Some(Uint32::from(0u32)), true))
            .await?;
        blockresponse2bytes(res)
    }

    /// Same as get_block_by_number except with parameter with_cycles and return BlockResponse
    pub async fn get_packed_block_by_number(
        &self,
        number: BlockNumber,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post("get_block_by_number", (number, Some(Uint32::from(0u32))))
            .await
    }

    pub async fn get_block_by_number_with_cycles(
        &self,
        number: BlockNumber,
    ) -> Result<Option<(BlockView, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self
            .post::<_, Option<BlockResponse>>("get_block_by_number", (number, None::<u32>, true))
            .await?;
        transform_block_view_with_cycle(res)
    }

    pub async fn get_packed_block_by_number_with_cycles(
        &self,
        number: BlockNumber,
    ) -> Result<Option<(JsonBytes, Vec<Cycle>)>, crate::rpc::RpcError> {
        let res = self
            .post::<_, Option<BlockResponse>>(
                "get_block_by_number",
                (number, Some(Uint32::from(0u32)), true),
            )
            .await?;
        blockresponse2bytes(res)
    }

    pub async fn get_packed_header(
        &self,
        hash: H256,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post::<_, Option<JsonBytes>>("get_header", (hash, Some(Uint32::from(0u32))))
            .await
    }

    pub async fn get_packed_header_by_number(
        &self,
        number: BlockNumber,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post::<_, Option<JsonBytes>>(
            "get_header_by_number",
            (number, Some(Uint32::from(0u32))),
        )
        .await
    }

    pub async fn get_live_cell_with_include_tx_pool(
        &self,
        out_point: OutPoint,
        with_data: bool,
        include_tx_pool: bool,
    ) -> Result<CellWithStatus, crate::rpc::RpcError> {
        self.post::<_, CellWithStatus>(
            "get_live_cell",
            (out_point, with_data, Some(include_tx_pool)),
        )
        .await
    }

    // get transaction with only_committed=true
    pub async fn get_only_committed_transaction(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(2u32)), true),
        )
        .await
    }

    // get transaction with verbosity=0
    pub async fn get_packed_transaction(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(0u32))),
        )
        .await
    }

    // get transaction with verbosity=0 and only_committed=true
    pub async fn get_only_committed_packed_transaction(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(0u32)), true),
        )
        .await
    }

    // get transaction with verbosity=1, so the result transaction field is None
    pub async fn get_transaction_status(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(1u32))),
        )
        .await
    }

    // get transaction with verbosity=1 and only_committed=true, so the result transaction field is None
    pub async fn get_only_committed_transaction_status(
        &self,
        hash: H256,
    ) -> Result<TransactionWithStatusResponse, crate::rpc::RpcError> {
        self.post::<_, TransactionWithStatusResponse>(
            "get_transaction",
            (hash, Some(Uint32::from(1u32)), true),
        )
        .await
    }

    pub async fn get_packed_tip_header(&self) -> Result<JsonBytes, crate::rpc::RpcError> {
        self.post::<_, JsonBytes>("get_tip_header", (Some(Uint32::from(0u32)),))
            .await
    }

    pub async fn get_packed_fork_block(
        &self,
        block_hash: H256,
    ) -> Result<Option<JsonBytes>, crate::rpc::RpcError> {
        self.post::<_, Option<JsonBytes>>("get_fork_block", (block_hash, Some(Uint32::from(0u32))))
            .await
    }
}

// turn BlockResponse to JsonBytes and Cycle tuple
fn blockresponse2bytes(
    opt_resp: Option<BlockResponse>,
) -> Result<Option<(JsonBytes, Vec<Cycle>)>, crate::rpc::RpcError> {
    opt_resp
        .map(|resp| match resp {
            BlockResponse::Regular(block_view) => Ok((block_view.get_json_bytes()?, vec![])),
            BlockResponse::WithCycles(block_cycles) => {
                let cycles = transform_cycles(block_cycles.cycles);
                Ok((block_cycles.block.get_json_bytes()?, cycles))
            }
        })
        .transpose()
}

// turn block response into BlockView and cycle vec
fn transform_block_view_with_cycle(
    opt_resp: Option<BlockResponse>,
) -> Result<Option<(BlockView, Vec<Cycle>)>, crate::rpc::RpcError> {
    opt_resp
        .map(|resp| match resp {
            BlockResponse::Regular(block_view) => Ok((block_view.get_value()?, vec![])),
            BlockResponse::WithCycles(block_cycles) => {
                let cycles = transform_cycles(block_cycles.cycles);
                Ok((block_cycles.block.get_value()?, cycles))
            }
        })
        .transpose()
}
