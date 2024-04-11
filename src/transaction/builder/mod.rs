

use super::handler::HandlerContexts;
use crate::{
    tx_builder::TxBuilderError,
    TransactionWithScriptGroups,
};
pub mod offline;

/// CKB transaction builder trait.
pub trait CkbTransactionBuilder {
    fn build(
        self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError>;
}
