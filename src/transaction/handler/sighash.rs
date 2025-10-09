use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint, Script, WitnessArgs},
    prelude::{Builder, Entity, Pack},
};

use crate::{
    constants, core::TransactionBuilder, tx_builder::TxBuilderError, unlock::UnlockError,
    NetworkInfo, NetworkType, ScriptGroup,
};

use super::{HandlerContext, ScriptHandler};

pub struct Secp256k1Blake160SighashAllScriptHandler {
    cell_deps: Vec<CellDep>,
}

pub struct Secp256k1Blake160SighashAllScriptContext;

impl HandlerContext for Secp256k1Blake160SighashAllScriptContext {}

impl Secp256k1Blake160SighashAllScriptHandler {
    pub fn is_match(&self, script: &Script) -> bool {
        script.code_hash() == constants::SIGHASH_TYPE_HASH.pack()
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let mut ret = Self { cell_deps: vec![] };
        ret.init(network)?;
        Ok(ret)
    }
    pub async fn new_with_network_async(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let mut ret = Self { cell_deps: vec![] };
        ret.init_async(network).await?;
        Ok(ret)
    }

    pub fn new_with_customize(cell_deps: Vec<CellDep>) -> Self {
        Self { cell_deps }
    }
}
#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ScriptHandler for Secp256k1Blake160SighashAllScriptHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if !self.is_match(&script_group.script) {
            return Ok(false);
        }
        if let Some(_args) = context
            .as_any()
            .downcast_ref::<Secp256k1Blake160SighashAllScriptContext>()
        {
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            let index = *script_group.input_indices.first().unwrap();
            let witness = if let Some(witness) = tx_builder.get_witnesses().get(index) {
                let witness_data = witness.raw_data();
                if witness_data.is_empty() {
                    WitnessArgs::new_builder()
                } else {
                    WitnessArgs::from_slice(witness_data.as_ref())
                        .map_err(|_| UnlockError::InvalidWitnessArgs(index))?
                        .as_builder()
                }
            } else {
                WitnessArgs::new_builder()
            }
            .lock(Some(bytes::Bytes::from(vec![0u8; 65])).pack())
            .build();
            tx_builder.set_witness(index, witness.as_bytes().pack());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn init(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let out_point = if network.network_type == NetworkType::Mainnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c")
                        .pack(),
                )
                .index(0u32)
                .build()
        } else if network.network_type == NetworkType::Testnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
                        .pack(),
                )
                .index(0u32)
                .build()
        } else if network.network_type == NetworkType::Preview {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x0fab65924f2784f17ad7f86d6aef4b04ca1ca237102a68961594acebc5c77816")
                        .pack(),
                )
                .index(0u32)
                .build()
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::DepGroup)
            .build();
        self.cell_deps.push(cell_dep);
        Ok(())
    }
    async fn init_async(&mut self, network: &NetworkInfo) -> Result<(), TxBuilderError> {
        let out_point = if network.network_type == NetworkType::Mainnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c")
                        .pack(),
                )
                .index(0u32)
                .build()
        } else if network.network_type == NetworkType::Testnet {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
                        .pack(),
                )
                .index(0u32)
                .build()
        } else if network.network_type == NetworkType::Preview {
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x0fab65924f2784f17ad7f86d6aef4b04ca1ca237102a68961594acebc5c77816")
                        .pack(),
                )
                .index(0u32)
                .build()
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::DepGroup)
            .build();
        self.cell_deps.push(cell_dep);
        Ok(())
    }
}
