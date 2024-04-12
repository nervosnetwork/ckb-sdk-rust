use alloc::vec::Vec;
use ckb_jsonrpc_types::{CellOutput, Transaction};
use ckb_types::H256;
use serde::{Deserialize, Serialize};



#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct PSBTransaction {
    /// All the fields in `Transaction` are included in `TransactionView` in JSON.
    #[serde(flatten)]
    pub inner: Transaction,
    /// extended view
    pub previous_output_cells: Vec<CellOutput>,
    /// The transaction hash.
    pub hash: H256,   
}

impl From<PSBTransaction> for Transaction {
    fn from(tx: PSBTransaction) -> Self {
        Self {
            version: tx.inner.version.clone(),
            cell_deps: tx.inner.cell_deps.clone(),
            header_deps: tx.inner.header_deps.clone(),
            inputs: tx.inner.inputs.clone(),
            outputs: tx.inner.outputs.clone(),
            outputs_data: tx.inner.outputs_data.clone(),
            witnesses: tx.inner.witnesses.clone()
        }
    }
}