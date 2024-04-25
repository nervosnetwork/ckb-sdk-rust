use std::convert::TryInto;

use ckb_crypto::secp::{Pubkey, SECP256K1};
use ckb_hash::blake2b_256;
use ckb_types::{
    core::DepType,
    packed::{CellOutput, OutPoint},
    prelude::*,
    H160, H256,
};

use crate::{
    constants::ONE_CKB,
    tests::{
        build_omnilock_script, build_sighash_script, init_context, ACCOUNT0_ARG, ACCOUNT0_KEY,
        ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, FEE_RATE, OMNILOCK_BIN,
    },
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        handler::{
            multisig::Secp256k1Blake160MultisigAllScriptHandler,
            omnilock::{OmnilockScriptContext, OmnilockScriptHandler},
            sighash::Secp256k1Blake160SighashAllScriptHandler,
            typeid::TypeIdHandler,
            HandlerContexts,
        },
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    unlock::{MultisigConfig, OmniLockConfig},
    util::{blake160, keccak160},
    NetworkInfo,
};

fn test_omnilock_config(omnilock_outpoint: OutPoint) -> TransactionBuilderConfiguration {
    let network_info = NetworkInfo::testnet();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_empty_handlers(network_info.clone());
    let mut omni_lock_handler = OmnilockScriptHandler::new_with_network(&network_info).unwrap();

    omni_lock_handler.set_lock_script_id(crate::ScriptId::new_data1(H256::from(blake2b_256(
        OMNILOCK_BIN,
    ))));
    omni_lock_handler.set_cell_deps(vec![
        crate::transaction::handler::cell_dep!(
            "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
            0u32,
            DepType::DepGroup
        ),
        ckb_types::packed::CellDep::new_builder()
            .out_point(omnilock_outpoint)
            .dep_type(DepType::Code.into())
            .build(),
    ]);

    configuration.register_script_handler(Box::new(
        Secp256k1Blake160SighashAllScriptHandler::new_with_network(&network_info).unwrap(),
    ));
    configuration.register_script_handler(Box::new(
        Secp256k1Blake160MultisigAllScriptHandler::new_with_network(&network_info).unwrap(),
    ));
    configuration.register_script_handler(Box::new(TypeIdHandler));
    configuration.register_script_handler(Box::new(omni_lock_handler));

    configuration
}

#[test]
fn test_omnilock_ethereum() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_pubkeyhash() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()));

    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_multisign() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut cfg = OmniLockConfig::new_multisig(multi_cfg);
    let sign_context = SignContexts::new_omnilock(vec![account0_key, account1_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key, account1_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_ethereum_display() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum_display(keccak160(Pubkey::from(pubkey).as_ref()));
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_btc() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // compressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // segwitp2sh
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // segwitbech32
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_dog() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);

    // uncompress
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // compress
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // SegwitP2SH
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // SegwitBech32
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_eos() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);

    // uncompressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);

    // compressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_tron() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_tron_from_pubkey(&Pubkey::from(pubkey));
    let sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_solana() {
    let account0_key =
        ed25519_dalek::SigningKey::from_bytes(&ACCOUNT0_KEY.as_bytes().try_into().unwrap());
    let pubkey = account0_key.verifying_key();
    let mut cfg = OmniLockConfig::new_solana_from_pubkey(&pubkey);
    let sign_context = SignContexts::new_omnilock_solana(account0_key.clone(), cfg.clone());
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock_solana(account0_key, cfg.clone());
    omnilock_test(cfg, &sign_context_2);
}

fn omnilock_test(cfg: OmniLockConfig, sign_context: &SignContexts) {
    let network_info = NetworkInfo::testnet();

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let (ctx, mut outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let configuration = test_omnilock_config(outpoints.pop().unwrap());

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let output = CellOutput::new_builder()
        .capacity((120 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender.clone());

    let context = OmnilockScriptContext::new(cfg.clone(), network_info.url.clone());
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&contexts).expect("build failed");

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    TransactionSigner::new(&network_info)
        // use unitest lock to verify
        .insert_unlocker(
            crate::ScriptId::new_data1(H256::from(blake2b_256(OMNILOCK_BIN))),
            crate::transaction::signer::omnilock::OmnilockSigner {},
        )
        .sign_transaction(&mut tx_with_groups, sign_context)
        .unwrap();

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx = tx_with_groups.get_tx_view().clone();
    let script_groups = tx_with_groups.script_groups.clone();
    assert_eq!(script_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (100 + 200 - 120) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_owner_lock() {
    test_omnilock_owner_lock_tranfer(false);
    test_omnilock_owner_lock_tranfer(true)
}

fn test_omnilock_owner_lock_tranfer(cobuild: bool) {
    let network_info = NetworkInfo::testnet();
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let sender1 = build_sighash_script(ACCOUNT0_ARG);
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let hash = H160::from_slice(&sender1.calc_script_hash().as_slice()[0..20]).unwrap();
    let mut cfg = OmniLockConfig::new_ownerlock(hash);
    cfg.enable_cobuild(cobuild);
    let sender0 = build_omnilock_script(&cfg);
    let mut sign_context = SignContexts::new_omnilock(vec![account0_key.clone()], cfg.clone());
    let hashall_unlock =
        crate::transaction::signer::sighash::Secp256k1Blake160SighashAllSignerContext::new(vec![
            account0_key.clone(),
        ]);
    sign_context.add_context(Box::new(hashall_unlock));

    let (ctx, mut outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender0.clone(), Some(150 * ONE_CKB)),
            (sender1.clone(), Some(61 * ONE_CKB)),
        ],
    );

    let configuration = test_omnilock_config(outpoints.pop().unwrap());
    let iterator = InputIterator::new_with_cell_collector(
        vec![sender0.clone(), sender1.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver.clone())
        .build();
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender0.clone());

    let context = OmnilockScriptContext::new(cfg.clone(), network_info.url.clone());
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&contexts).expect("build failed");

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    TransactionSigner::new(&network_info)
        // use unitest lock to verify
        .insert_unlocker(
            crate::ScriptId::new_data1(H256::from(blake2b_256(OMNILOCK_BIN))),
            crate::transaction::signer::omnilock::OmnilockSigner {},
        )
        .sign_transaction(&mut tx_with_groups, &sign_context)
        .unwrap();

    let tx = tx_with_groups.get_tx_view().clone();
    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let script_groups = tx_with_groups.script_groups.clone();
    assert_eq!(script_groups.len(), 2);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    let mut senders = vec![sender0.clone(), sender1.clone()];
    for out_point in tx.input_pts_iter() {
        let sender = ctx.get_input(&out_point).unwrap().0.lock();
        assert!(senders.contains(&sender));
        senders.retain(|x| x != &sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender0);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (150 + 61 - 110) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);
    ctx.verify(tx, FEE_RATE).unwrap();
}
