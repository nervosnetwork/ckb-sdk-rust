mod sudt;
mod xudt;

use super::{TransactionBuilder, TransactionBuilderError};
use ckb_types::{
    core::{FeeRate, TransactionView},
    packed::Script,
    H256,
};

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum UdtAction {
    Issue,
    Transfer,
}

// Owner lock shall be used for governance purposes, such as issuance/mint, burn as well as other operations.
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum UdtType {
    // The parameter is owner lock hash
    Sudt(H256),
    Xudt {
        // owner lock hash
        owner: H256,
        // The content is rce rule id (also the type script of RCData cell)
        rule_id: H256,
    },
}

pub struct UdtIssueBuilder {
    udt_type: UdtType,
    owner: Script,
    receivers: Vec<(Script, u128)>,
    capacity_provider: Script,
    change_receiver: Script,
    fee_rate: FeeRate,
    // Force small change as fee when live cell is not enough to adjust the tx fee
    force_small_change_as_fee: bool,
}

// impl TransactionBuilder for UdtIssueBuilder {
//     fn build(&self) -> Result<TransactionView, TransactionBuilderError> {
//     }
// }
