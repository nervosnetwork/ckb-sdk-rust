use std::convert::TryFrom;
use std::fmt;

use ckb_types::{core::ScriptHashType, packed::Script, prelude::*, H256};

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ScriptId {
    pub code_hash: H256,
    pub hash_type: ScriptHashType,
}

impl ScriptId {
    pub fn new(code_hash: H256, hash_type: ScriptHashType) -> ScriptId {
        ScriptId {
            code_hash,
            hash_type,
        }
    }
    pub fn new_data(code_hash: H256) -> ScriptId {
        Self::new(code_hash, ScriptHashType::Data)
    }
    pub fn new_data1(code_hash: H256) -> ScriptId {
        Self::new(code_hash, ScriptHashType::Data1)
    }
    pub fn new_type(code_hash: H256) -> ScriptId {
        Self::new(code_hash, ScriptHashType::Type)
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
