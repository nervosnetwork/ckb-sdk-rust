pub mod constants;
pub mod core;
pub mod pubsub;
pub mod rpc;
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

pub use rpc::{CkbRpcAsyncClient, IndexerRpcAsyncClient, RpcError};
#[cfg(not(target_arch = "wasm32"))]
pub use rpc::{CkbRpcClient, IndexerRpcClient};
pub use types::{
    Address, AddressPayload, AddressType, CodeHashIndex, HumanCapacity, NetworkInfo, NetworkType,
    OldAddress, OldAddressFormat, ScriptGroup, ScriptGroupType, ScriptId, Since, SinceType,
    TransactionWithScriptGroups,
};

pub use ckb_crypto::secp::SECP256K1;

#[cfg(target_arch = "wasm32")]
mod target_specific {
    pub trait MaybeSend {}
    impl<T> MaybeSend for T {}
}
#[cfg(not(target_arch = "wasm32"))]
mod target_specific {
    pub trait MaybeSend: Send {}
    impl<T> MaybeSend for T where T: Send {}
}
pub use target_specific::MaybeSend;
