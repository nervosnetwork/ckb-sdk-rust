use std::collections::HashMap;

use bytes::Bytes;
use ckb_types::{
    core::{DepType, ScriptHashType},
    packed::{Byte32, CellDep, OutPoint, Script},
    prelude::*,
    H256,
};

use crate::{
    traits::DefaultCellDepResolver,
    unlock::{
        sphincsplus::{SphincsPlusPrivateKey, SphincsPlusPublicKey},
        ScriptUnlocker, SphincsPlusRawKeysSigner, SphincsPlusUnlocker,
    },
    Address, AddressPayload, NetworkType, ScriptId,
};

#[derive(Debug, Clone)]
pub struct SphincsPlusEnv {
    /// transaction hash where the code is deployed
    pub tx_hash: H256,
    /// transaction index where the code is deployed
    pub tx_idx: u32,
    /// cell dependency type
    pub dep_type: DepType,
    /// the code hash
    pub code_hash: H256,
    /// the code hash's hash type,
    pub hash_type: ScriptHashType,
    /// the network type
    pub network_type: NetworkType,
}

impl SphincsPlusEnv {
    /// build script id
    pub fn script_id(&self) -> ScriptId {
        ScriptId {
            code_hash: self.code_hash.clone(),
            hash_type: self.hash_type,
        }
    }

    pub fn script(&self, pk: &SphincsPlusPublicKey) -> Script {
        Script::new_builder()
            .code_hash(self.code_hash.pack())
            .hash_type(self.hash_type.into())
            .args(Bytes::from(pk.lock_args().to_vec()).pack())
            .build()
    }
    /// add cell dependency to DefaultCellDepResolver
    pub fn add_cell_dep(&self, cell_dep_resolver: &mut DefaultCellDepResolver) {
        let out_point = OutPoint::new(
            Byte32::from_slice(self.tx_hash.as_bytes()).unwrap(),
            self.tx_idx,
        );

        let cell_dep = CellDep::new_builder().out_point(out_point).build();
        cell_dep_resolver.insert(self.script_id(), cell_dep, "Sphincs plus".to_string());
    }

    /// build address from public key
    pub fn build_address(&self, pk: &SphincsPlusPublicKey) -> Address {
        let args = Bytes::from(pk.lock_args().to_vec());
        let address_payload = AddressPayload::new_full(
            self.hash_type,
            Byte32::from_slice(self.code_hash.as_bytes()).unwrap(),
            args,
        );
        Address::new(self.network_type, address_payload, true)
    }

    /// build unlockers from private keys
    pub fn build_unlockers(
        &self,
        sks: Vec<SphincsPlusPrivateKey>,
    ) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
        let signer = SphincsPlusRawKeysSigner::new_with_private_keys(sks);
        let sighash_unlocker = SphincsPlusUnlocker::from(Box::new(signer) as Box<_>);
        let sighash_script_id = ScriptId::new_data1(self.code_hash.clone());
        let mut unlockers = HashMap::default();
        unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );
        unlockers
    }
}
