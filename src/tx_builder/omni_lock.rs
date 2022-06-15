use ckb_types::packed::CellDep;
use ckb_types::{core::TransactionView, prelude::*};

use crate::traits::{
    CellCollector, CellDepResolver, HeaderDepResolver, TransactionDependencyProvider,
};
use crate::unlock::omni_lock::IDENTITY_FLAGS_PUBKEY_HASH;

use super::{TxBuilder, TxBuilderError};

/// A builder to build a transaction simply transfer capcity to an address. It
/// will resolve the type script's cell_dep if given.
pub struct OmniLockTransferBuilder {
    pub tx_builder: Box<dyn TxBuilder>,
    pub id_flags: u8,
    pub secp256k1_data_dep: CellDep,
}

impl OmniLockTransferBuilder {
    pub fn new(
        tx_builder: Box<dyn TxBuilder>,
        id_flags: u8,
        secp256k1_data_dep: CellDep,
    ) -> OmniLockTransferBuilder {
        OmniLockTransferBuilder {
            tx_builder,
            id_flags,
            secp256k1_data_dep,
        }
    }
}

impl TxBuilder for OmniLockTransferBuilder {
    fn build_base(
        &self,
        cell_collector: &mut dyn CellCollector,
        cell_dep_resolver: &dyn CellDepResolver,
        header_dep_resolver: &dyn HeaderDepResolver,
        tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, TxBuilderError> {
        let mut tx = self.tx_builder.build_base(
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
        )?;

        if self.id_flags == IDENTITY_FLAGS_PUBKEY_HASH {
            let cell_deps = tx
                .cell_deps()
                .as_builder()
                .push(self.secp256k1_data_dep.clone())
                .build();
            tx = tx.as_advanced_builder().cell_deps(cell_deps).build();
        }

        Ok(tx)
    }
}
