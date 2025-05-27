use std::convert::TryFrom;

use crate::{CkbRpcAsyncClient, NetworkInfo, NetworkType, ScriptId};
use ckb_system_scripts_v0_5_4::{
    CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL as CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL_LEGACY,
    CODE_HASH_SECP256K1_DATA,
};
use ckb_system_scripts_v0_6_0::CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL as CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL_V2;
use ckb_types::{
    core::EpochNumberWithFraction,
    h256,
    packed::{Byte32, CellOutput, OutPoint, OutPointVecReader},
    prelude::*,
    H256,
};

pub const PREFIX_MAINNET: &str = "ckb";
pub const PREFIX_TESTNET: &str = "ckt";

pub const NETWORK_MAINNET: &str = "ckb";
pub const NETWORK_TESTNET: &str = "ckb_testnet";
pub const NETWORK_STAGING: &str = "ckb_staging";
pub const NETWORK_PREVIEW: &str = "ckb_preview";
pub const NETWORK_DEV: &str = "ckb_dev";

pub const SECP_SIGNATURE_SIZE: usize = 65;

// Since relative mask
pub const LOCK_TYPE_FLAG: u64 = 1 << 63;
pub const METRIC_TYPE_FLAG_MASK: u64 = 0x6000_0000_0000_0000;
pub const VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
pub const REMAIN_FLAGS_BITS: u64 = 0x1f00_0000_0000_0000;

// Special cells in genesis transactions: (transaction-index, output-index)
pub const SIGHASH_OUTPUT_LOC: (usize, usize) = (0, 1);
pub const MULTISIG_LEGACY_OUTPUT_LOC: (usize, usize) = (0, 4);
pub const DAO_OUTPUT_LOC: (usize, usize) = (0, 2);
pub const SIGHASH_GROUP_OUTPUT_LOC: (usize, usize) = (1, 0);
pub const MULTISIG_LEGACY_GROUP_OUTPUT_LOC: (usize, usize) = (1, 1);

pub const ONE_CKB: u64 = 100_000_000;
pub const MIN_SECP_CELL_CAPACITY: u64 = 61 * ONE_CKB;
// mainnet,testnet cellbase maturity
pub const CELLBASE_MATURITY: EpochNumberWithFraction =
    EpochNumberWithFraction::new_unchecked(4, 0, 1);

/// "TYPE_ID" in hex (copied from ckb-chain-spec)
pub const TYPE_ID_CODE_HASH: H256 = h256!("0x545950455f4944");

pub const SIGHASH_TYPE_HASH: H256 =
    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");

pub const GENESIS_BLOCK_HASH_MAINNET: H256 =
    h256!("0x92b197aa1fba0f63633922c61c92375c9c074a93e85963554f5499fe1450d0e5");

pub const GENESIS_BLOCK_HASH_TESTNET: H256 =
    h256!("0x10639e0895502b5688a6be8cf69460d76541bfa4821629d86d62ba0aae3f9606");

pub const DAO_TYPE_HASH: H256 =
    h256!("0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e");

/// anyone can pay script mainnet code hash, see:
/// <https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay/0026-anyone-can-pay.md#notes>
pub const ACP_TYPE_HASH_LINA: H256 =
    h256!("0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354");
/// anyone can pay script testnet code hash
pub const ACP_TYPE_HASH_AGGRON: H256 =
    h256!("0x3419a1c09eb2567f6552ee7a8ecffd64155cffe0f1796e6e61ec088d740c1356");

/// cheque withdraw since value
pub const CHEQUE_CELL_SINCE: u64 = 0xA000000000000006;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigScript {
    /// Multisig Script deployed on Genesis Block
    /// https://explorer.nervos.org/script/0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8/type
    Legacy,

    /// Latest multisig script
    /// https://explorer.nervos.org/script/0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29/data1
    V2,
}

impl MultisigScript {
    pub const fn script_id(&self) -> ScriptId {
        match self {
            MultisigScript::Legacy => ScriptId::new_type(h256!(
                "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8"
            )),
            MultisigScript::V2 => ScriptId::new_data1(h256!(
                "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29"
            )),
        }
    }

    fn dep_group_from_env(&self, _network: NetworkInfo) -> Option<(H256, u32)> {
        let env_dep_group = match self {
            MultisigScript::Legacy => std::env::var("MULTISIG_LEGACY_DEP_GROUP"),
            MultisigScript::V2 => std::env::var("MULTISIG_V2_DEP_GROUP"),
        }
        .ok()?;

        let vars = env_dep_group.split(",").collect::<Vec<_>>();
        match (vars.first(), vars.get(1)) {
            (Some(hash), Some(index)) => {
                let index_u32: u32 = index.parse().ok()?;

                if !hash.starts_with("0x") {
                    return None;
                }
                let hash_bytes = hex::decode(&hash[2..]).ok()?;

                let hash = H256::from_slice(&hash_bytes).ok()?;
                Some((hash, index_u32))
            }
            _ => None,
        }
    }

    /// Get dep group from env first:
    /// 1. MULTISIG_LEGACY_DEP_GROUP=0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c,1
    /// 2. MULTISIG_V2_DEP_GROUP=0x6888aa39ab30c570c2c30d9d5684d3769bf77265a7973211a3c087fe8efbf738,2
    ///
    /// If env not set, then get it from dep_group_inner
    #[cfg(not(target_arch = "wasm32"))]
    pub fn dep_group(&self, network: NetworkInfo) -> Option<(H256, u32)> {
        self.dep_group_from_env(network.clone())
            .or(crate::rpc::block_on(self.dep_group_inner(network)))
    }

    /// Get dep group from env first:
    /// 1. MULTISIG_LEGACY_DEP_GROUP=0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c,1
    /// 2. MULTISIG_V2_DEP_GROUP=0x6888aa39ab30c570c2c30d9d5684d3769bf77265a7973211a3c087fe8efbf738,2
    ///
    /// If env not set, then get it from dep_group_inner
    pub async fn dep_group_async(&self, network: NetworkInfo) -> Option<(H256, u32)> {
        self.dep_group_from_env(network.clone())
            .or(self.dep_group_inner(network).await)
    }

    async fn dep_group_inner(&self, network: NetworkInfo) -> Option<(H256, u32)> {
        match network.network_type {
            NetworkType::Mainnet => Some(match self {
                MultisigScript::Legacy => (
                    h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
                    1,
                ),
                MultisigScript::V2 => (
                    h256!("0x6888aa39ab30c570c2c30d9d5684d3769bf77265a7973211a3c087fe8efbf738"),
                    0,
                ),
            }),
            NetworkType::Testnet => Some(match self {
                MultisigScript::Legacy => (
                    h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"),
                    1,
                ),
                MultisigScript::V2 => (
                    h256!("0x2eefdeb21f3a3edf697c28a52601b4419806ed60bb427420455cc29a090b26d5"),
                    0,
                ),
            }),
            NetworkType::Staging | NetworkType::Preview | NetworkType::Dev => {
                let client = CkbRpcAsyncClient::new(network.url.as_str());
                let json_genesis_block = client.get_block_by_number(0_u64.into()).await.ok()??;
                let genesis_block: ckb_types::core::BlockView = json_genesis_block.into();

                let secp256k1_data_outpoint =
                    find_cell_match_data_hash(&genesis_block, CODE_HASH_SECP256K1_DATA.pack())?;

                let target_data_hash = match self {
                    MultisigScript::Legacy => {
                        CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL_LEGACY.pack()
                    }
                    MultisigScript::V2 => CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL_V2.pack(),
                };
                let multisig_outpoint =
                    find_cell_match_data_hash(&genesis_block, target_data_hash)?;

                let (dep_hash, dep_index) = find_cell_match_data_hash_find_dep(
                    &genesis_block,
                    vec![secp256k1_data_outpoint, multisig_outpoint],
                )?;

                let dep_hash: H256 = dep_hash.unpack();
                Some((dep_hash, dep_index))
            }
        }
    }
}

fn find_cell_match_data_hash(
    genesis_block: &ckb_types::core::BlockView,
    target_data_hash: Byte32,
) -> Option<OutPoint> {
    genesis_block.transactions().iter().find_map(|tx| {
        let multisig_legacy_cell_index =
            tx.outputs_with_data_iter()
                .enumerate()
                .find_map(|(index, (_output, data))| {
                    let data_hash = CellOutput::calc_data_hash(&data);
                    data_hash.eq(&target_data_hash).then_some(index)
                });
        multisig_legacy_cell_index.map(|cell_index| OutPoint::new(tx.hash(), cell_index as u32))
    })
}

fn find_cell_match_data_hash_find_dep(
    genesis_block: &ckb_types::core::BlockView,
    target_points: Vec<OutPoint>,
) -> Option<(ckb_types::packed::Byte32, u32)> {
    genesis_block.transactions().iter().find_map(|tx| {
        let multisig_cell_index: Option<u32> =
            tx.outputs_with_data_iter()
                .enumerate()
                .find_map(|(index, (_output, data))| {
                    let he = hex_string(&data);
                    if he.len() > 200 {
                        return None;
                    }
                    let outpoint_vec = OutPointVecReader::from_slice(&data)
                        .map(|reader| reader.to_entity())
                        .ok()?;

                    target_points
                        .iter()
                        .all(|target_point| {
                            outpoint_vec
                                .clone()
                                .into_iter()
                                .any(|outpoint| outpoint.eq(target_point))
                        })
                        .then_some(index as u32)
                });

        multisig_cell_index.map(|cell_index| (tx.hash(), cell_index))
    })
}

impl TryFrom<H256> for MultisigScript {
    type Error = ();

    fn try_from(code_hash: H256) -> Result<Self, Self::Error> {
        if code_hash.eq(&MultisigScript::Legacy.script_id().code_hash) {
            Ok(MultisigScript::Legacy)
        } else if code_hash.eq(&MultisigScript::V2.script_id().code_hash) {
            Ok(MultisigScript::V2)
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_types::{
        core::Capacity,
        packed::{CellOutput, Script},
        H160,
    };

    #[test]
    fn test_min_capacity() {
        let min_secp_cell_capacity = CellOutput::new_builder()
            .lock(
                Script::new_builder()
                    .args(H160::default().as_bytes().pack())
                    .build(),
            )
            .build()
            .occupied_capacity(Capacity::zero())
            .unwrap()
            .as_u64();

        assert_eq!(min_secp_cell_capacity, MIN_SECP_CELL_CAPACITY);
    }

    #[test]
    fn test_multisig_deps() {
        assert_ne!(
            CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL_LEGACY,
            CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL_V2
        );

        let mainnet = NetworkInfo::mainnet();
        assert!(MultisigScript::Legacy.dep_group(mainnet.clone()).is_some());
        assert!(MultisigScript::V2.dep_group(mainnet).is_some());

        let testnet = NetworkInfo::testnet();
        assert!(MultisigScript::Legacy.dep_group(testnet.clone()).is_some());
        assert!(MultisigScript::V2.dep_group(testnet).is_some());

        // TODO: start ckb devchain in this unit test
        // let devnet = NetworkInfo::devnet();
        // assert!(MultisigScript::Legacy.dep_group(devnet.clone()).is_some());

        // TODO, let ckb devnet deploy multisig_v2 on genesis block
        // assert!(MultisigScript::V1.dep_group(devnet).is_some());
    }

    #[test]
    fn test_dep_group_from_env() {
        let legacy = MultisigScript::Legacy;
        std::env::set_var(
            "MULTISIG_LEGACY_DEP_GROUP",
            "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c,10000",
        );
        let dep_group = legacy.dep_group_from_env(NetworkInfo::devnet());
        assert!(dep_group.is_some());
        assert_eq!(dep_group.unwrap().1, 10000)
    }
}
