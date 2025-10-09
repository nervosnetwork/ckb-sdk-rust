use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint},
    prelude::*,
};

use crate::{
    core::TransactionBuilder, tx_builder::TxBuilderError, NetworkInfo, NetworkType, ScriptGroup,
    ScriptId,
};

use super::{HandlerContext, ScriptHandler};

/// sUDT script handler, it will setup the [Simple UDT](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md) related data automatically.
pub struct SudtHandler {
    cell_deps: Vec<CellDep>,
    sudt_script_id: ScriptId,
}

pub struct SudtContext;

impl HandlerContext for SudtContext {}

impl SudtHandler {
    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let (out_point, sudt_script_id) = if network.network_type == NetworkType::Mainnet {
            (
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xc7813f6a415144643970c2e88e0bb6ca6a8edc5dd7c1022746f628284a9936d5")
                            .pack(),
                    )
                    .index(0u32)
                    .build(),
                ScriptId::new_type(h256!(
                    "0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5"
                )),
            )
        } else if network.network_type == NetworkType::Testnet {
            (
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xe12877ebd2c3c364dc46c5c992bcfaf4fee33fa13eebdf82c591fc9825aab769")
                            .pack(),
                    )
                    .index(0u32)
                    .build(),
                ScriptId::new_type(h256!(
                    "0xc5e5dcf215925f7ef4dfaf5f4b4f105bc321c02776d6e7d52a1db3fcd9d011a4"
                )),
            )
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::Code)
            .build();

        Ok(Self {
            cell_deps: vec![cell_dep],
            sudt_script_id,
        })
    }

    pub fn new_with_customize(cell_deps: Vec<CellDep>, sudt_script_id: ScriptId) -> Self {
        Self {
            cell_deps,
            sudt_script_id,
        }
    }
}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptHandler for SudtHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if context.as_any().is::<SudtContext>()
            && ScriptId::from(&script_group.script) == self.sudt_script_id
        {
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            if script_group.input_indices.is_empty() {
                // issue sudt, do nothing
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn init(&mut self, _network: &NetworkInfo) -> Result<(), TxBuilderError> {
        Ok(())
    }
    async fn init_async(&mut self, _network: &NetworkInfo) -> Result<(), TxBuilderError> {
        Ok(())
    }
}
