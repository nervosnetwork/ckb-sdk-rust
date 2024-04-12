#![cfg_attr(feature = "alloc", no_std)]
#![cfg_attr(feature = "alloc", feature(error_in_core))]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

pub mod constants;
pub mod core;
pub mod traits;
pub mod transaction;
pub mod tx_builder;
pub mod types;
pub mod unlock;
pub mod util;

#[cfg(feature = "test")]
pub mod test_util;

#[cfg(feature = "test")]
#[cfg(test)]
mod tests;

pub use types::{
    Address, AddressPayload, AddressType, CodeHashIndex, HumanCapacity, NetworkInfo, NetworkType,
    OldAddress, OldAddressFormat, ScriptGroup, ScriptGroupType, ScriptId, Since, SinceType,
    TransactionWithScriptGroups,
};

pub use ckb_crypto::secp::SECP256K1;
