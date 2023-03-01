use std::convert::TryFrom;
use std::fmt;

use crate::{constants::TYPE_ID_CODE_HASH, parser::Parser, Address};
use ckb_types::{
    core::ScriptHashType,
    packed::{Bytes, Script},
    prelude::*,
    H256,
};

#[derive(Clone, Hash, Eq, PartialEq, Debug, Default)]
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

    pub fn is_type_id(&self) -> bool {
        self.code_hash == TYPE_ID_CODE_HASH && self.hash_type == ScriptHashType::Type
    }
    pub fn dummy_script(&self) -> Script {
        Script::new_builder()
            .code_hash(self.code_hash.pack())
            .hash_type(self.hash_type.into())
            .build()
    }

    pub fn build_script(&self, args: Bytes) -> Script {
        Script::new_builder()
            .code_hash(self.code_hash.pack())
            .hash_type(self.hash_type.into())
            .args(args)
            .build()
    }

    pub fn build_script_from_arg_str(self, args: &str) -> Result<Script, String> {
        let bytes = Bytes::parse(args)?;
        Ok(self.build_script(bytes))
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

impl From<&Address> for ScriptId {
    fn from(address: &Address) -> ScriptId {
        let script: Script = Script::from(address);
        ScriptId::from(&script)
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
