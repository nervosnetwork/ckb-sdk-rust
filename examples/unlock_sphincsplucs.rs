use bytes::Bytes;
use ckb_sdk::{
    constants::ONE_CKB,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider,
    },
    tx_builder::{
        sphincsplus::SphincsPlusEnv, transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder,
    },
    unlock::{sphincsplus::SphincsPlusPrivateKey, SphincsPlus},
    Address, CkbRpcClient, NetworkType,
};
use ckb_types::{
    core::{BlockView, DepType, ScriptHashType, TransactionView},
    h256,
    packed::{CellOutput, Script},
    prelude::*,
};

use std::{convert::TryFrom, error::Error as StdErr, str::FromStr};

pub const SK: [u8; 64] = [
    244, 229, 172, 97, 118, 43, 186, 182, 5, 191, 38, 224, 223, 57, 251, 84, // sk.seed
    29, 7, 44, 250, 108, 236, 220, 216, 161, 162, 99, 146, 46, 4, 34, 125, // sk.prf
    152, 145, 159, 50, 118, 81, 12, 134, 27, 52, 214, 210, 91, 84, 65, 42, // pubkey seed
    252, 12, 85, 58, 222, 186, 58, 189, 25, 133, 144, 79, 103, 177, 27, 76, // pubkey root
];

fn build_transfer_tx(
    env: &SphincsPlusEnv,
    sender: Script,
    sender_key: SphincsPlusPrivateKey,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build ScriptUnlocker
    let unlockers = env.build_unlockers(vec![sender_key]);

    // Build CapacityBalancer
    let placeholder_witness = SphincsPlus::placeholder_witness();
    let mut balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);
    balancer.force_small_change_as_fee = Some(ONE_CKB);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let ckb_rpc = "https://testnet.ckb.dev";
    let mut ckb_client = CkbRpcClient::new(ckb_rpc);
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        let mut cell_dep_resolver =
            DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?;
        env.add_cell_dep(&mut cell_dep_resolver);
        cell_dep_resolver
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    let receiver = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche").unwrap();
    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(Script::from(&receiver))
        .capacity(99_9990_0000u64.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let (tx, still_locked_groups) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

fn build_env() -> SphincsPlusEnv {
    SphincsPlusEnv {
        tx_hash: h256!("0x35f51257673c7a7edd009fa2166e6f8645156207c9da38202f04ba4d94d9e519"),
        tx_idx: 0,
        dep_type: DepType::Code,
        code_hash: h256!("0x989ab456455509a1c2ad1cb8116b7d209df228144445c741b101ec3e55ee8351"),
        hash_type: ScriptHashType::Data1,
        network_type: NetworkType::Testnet,
    }
}

/*
1. build address,
  ckt1qzvf4dzkg42sngwz45wtsytt05sfmu3gz3zyt36pkyq7c0j4a6p4zqkur4fuxjyh4fzphavynhdgptuwqsyhdjns028ugqy5jgnesdy8wslj3elk
2. transfer to address:
    wallet transfer --from-account 0x946c32d287a3544d5450f0cf5d43ca24dd37f55e \
                    --to-address ckt1qzvf4dzkg42sngwz45wtsytt05sfmu3gz3zyt36pkyq7c0j4a6p4zqkur4fuxjyh4fzphavynhdgptuwqsyhdjns028ugqy5jgnesdy8wslj3elk \
                    --capacity 100 --skip-check-to-address
    0x7fb5afa7c0bdc9cbbc2b65b523581c2bb3ed43ced114f759651ae407dee3d0c9
3. unlock the cell, and transfer the capacity to address ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv5dsed9par23x4g58seaw58j3ym5ml2hs8ztche
*/
fn main() -> Result<(), Box<dyn StdErr>> {
    let sk = SphincsPlusPrivateKey::try_from(SK.to_vec()).unwrap();
    let pk = sk.pub_key();
    let env = build_env();
    let address = env.build_address(&pk);
    let resp = serde_json::json!({
        "address": address.to_string(),
    });
    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
    let sender = env.script(&pk);

    let tx = build_transfer_tx(&env, sender, sk)?;

    // Send transaction
    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let outputs_validator = Some(ckb_jsonrpc_types::OutputsValidator::Passthrough);

    let ckb_rpc = "https://testnet.ckb.dev";
    let _tx_hash = CkbRpcClient::new(ckb_rpc)
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    // example tx_hash: 0xf83fd6c2fe511a9c39795624b7e0be2157e1543d9f1b1a1cbb676896e31c2b1b
    println!(">>> tx sent! <<<");

    Ok(())
}
