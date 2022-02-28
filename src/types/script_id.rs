use ckb_types::{core::ScriptHashType, H256};

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ScriptId {
    code_hash: H256,
    hash_type: ScriptHashType,
}
