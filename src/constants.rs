use std::convert::TryFrom;

use ckb_types::{core::EpochNumberWithFraction, h256, H256};

use crate::{NetworkType, ScriptId};

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
pub const MULTISIG_OUTPUT_LOC: (usize, usize) = (0, 4);
pub const DAO_OUTPUT_LOC: (usize, usize) = (0, 2);
pub const SIGHASH_GROUP_OUTPUT_LOC: (usize, usize) = (1, 0);
pub const MULTISIG_GROUP_OUTPUT_LOC: (usize, usize) = (1, 1);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigScript {
    /// Multisig Script deployed on Genesis Block
    /// https://explorer.nervos.org/script/0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8/type
    Legacy,

    /// Latest multisig script
    /// https://explorer.nervos.org/script/0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29/data1
    V1,
}

impl MultisigScript {
    pub const fn script_id(&self) -> ScriptId {
        match self {
            MultisigScript::Legacy => ScriptId::new_type(h256!(
                "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8"
            )),
            MultisigScript::V1 => ScriptId::new_data1(h256!(
                "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29"
            )),
        }
    }

    pub const fn dep_group(&self, network: NetworkType) -> (H256, u32) {
        match self {
            MultisigScript::Legacy => match network {
                NetworkType::Mainnet => (
                    h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
                    1,
                ),
                NetworkType::Testnet => (
                    h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"),
                    1,
                ),
                NetworkType::Staging => todo!(),
                NetworkType::Preview => todo!(),
                NetworkType::Dev => todo!(),
            },
            MultisigScript::V1 => match network {
                // https://github.com/nervosnetwork/ckb-system-scripts/pull/99#issuecomment-2814285588
                NetworkType::Mainnet => (
                    h256!("0x6888aa39ab30c570c2c30d9d5684d3769bf77265a7973211a3c087fe8efbf738"),
                    0,
                ),
                // https://github.com/nervosnetwork/ckb-system-scripts/pull/99#issuecomment-2757175017
                NetworkType::Testnet => (
                    h256!("0x2eefdeb21f3a3edf697c28a52601b4419806ed60bb427420455cc29a090b26d5"),
                    0,
                ),
                NetworkType::Staging => todo!(),
                NetworkType::Preview => todo!(),
                NetworkType::Dev => todo!(),
            },
        }
    }
}
impl TryFrom<H256> for MultisigScript {
    type Error = ();

    fn try_from(code_hash: H256) -> Result<Self, Self::Error> {
        if code_hash.eq(&MultisigScript::Legacy.script_id().code_hash) {
            Ok(MultisigScript::Legacy)
        } else if code_hash.eq(&MultisigScript::V1.script_id().code_hash) {
            Ok(MultisigScript::V1)
        } else {
            Err(())
        }
    }
}

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

#[cfg(test)]
mod test {
    use super::*;
    use ckb_types::{
        core::Capacity,
        packed::{CellOutput, Script},
        prelude::*,
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
}
