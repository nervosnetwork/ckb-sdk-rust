use std::convert::TryFrom;
use std::fmt;

use crate::constants::{DAO_TYPE_HASH, TYPE_ID_CODE_HASH};
use ckb_types::{core::ScriptHashType, packed::Script, prelude::*, H256};

#[derive(Clone, Hash, Eq, PartialEq, Debug, Default)]
pub struct ScriptId {
    pub code_hash: H256,
    pub hash_type: ScriptHashType,
}

impl ScriptId {
    pub const fn new(code_hash: H256, hash_type: ScriptHashType) -> ScriptId {
        ScriptId {
            code_hash,
            hash_type,
        }
    }
    pub fn new_data(code_hash: H256) -> ScriptId {
        Self::new(code_hash, ScriptHashType::Data)
    }
    pub const fn new_data1(code_hash: H256) -> ScriptId {
        Self::new(code_hash, ScriptHashType::Data1)
    }
    pub const fn new_type(code_hash: H256) -> ScriptId {
        Self::new(code_hash, ScriptHashType::Type)
    }

    pub fn is_type_id(&self) -> bool {
        self.code_hash == TYPE_ID_CODE_HASH && self.hash_type == ScriptHashType::Type
    }

    pub fn is_dao(&self) -> bool {
        self.code_hash == DAO_TYPE_HASH && self.hash_type == ScriptHashType::Type
    }

    /// Generate a dummy TypeId script with a placeholder args
    pub fn dummy_type_id_script(&self) -> Script {
        Script::new_builder()
            .code_hash(self.code_hash.pack())
            .hash_type(self.hash_type.into())
            .args(<[u8]>::pack(&[0u8; 32]))
            .build()
    }
}

impl From<&Script> for ScriptId {
    fn from(script: &Script) -> ScriptId {
        let code_hash: H256 = script.code_hash().unpack();
        let hash_type = ScriptHashType::try_from(script.hash_type()).expect("hash type");
        ScriptId {
            code_hash,
            hash_type,
        }
    }
}

impl fmt::Display for ScriptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "code_hash={:?}, hash_type={:?}",
            self.code_hash, self.hash_type
        )
    }
}
