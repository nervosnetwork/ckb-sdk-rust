use std::convert::TryInto;

use ckb_crypto::secp::{Pubkey, SECP256K1};
use ckb_hash::blake2b_256;
use ckb_types::{
    core::{DepType, TransactionView},
    packed::{CellOutput, OutPoint},
    prelude::*,
    H160, H256,
};

use crate::{
    constants::ONE_CKB,
    tests::{
        build_always_success_script, build_omnilock_script, build_sighash_script, init_context,
        random_out_point, ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG,
        ACCOUNT2_KEY, ACCOUNT3_ARG, ACCOUNT3_KEY, ALWAYS_SUCCESS_BIN, FEE_RATE, OMNILOCK_BIN,
    },
    traits::{LiveCell, Signer, SignerError},
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
    types::xudt_rce_mol::SmtProofEntryVec,
    unlock::{
        omni_lock::{AdminConfig, ExecDlConfig, Identity, Preimage},
        IdentityFlag, MultisigConfig, OmniLockAcpConfig, OmniLockConfig, OmniUnlockMode,
    },
    util::{blake160, btc_auth, eos_auth, keccak160},
    NetworkInfo,
};

fn test_omnilock_config(outpoints: Vec<OutPoint>) -> TransactionBuilderConfiguration {
    let network_info = NetworkInfo::testnet();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_empty_handlers(network_info.clone());
    let mut omni_lock_handler = OmnilockScriptHandler::new_with_network(&network_info).unwrap();

    omni_lock_handler.set_lock_script_id(crate::ScriptId::new_data1(H256::from(blake2b_256(
        OMNILOCK_BIN,
    ))));
    let dep_cells = {
        let mut cells = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints {
            cells.push(
                ckb_types::packed::CellDep::new_builder()
                    .out_point(outpoint)
                    .dep_type(DepType::Code.into())
                    .build(),
            )
        }
        cells
    };
    omni_lock_handler.set_cell_deps(dep_cells);

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
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_pubkeyhash() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_pubkey_hash(blake160(&pubkey.serialize()));

    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
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
    let sign_context = SignContexts::new_omnilock(
        vec![account0_key, account1_key],
        cfg.clone(),
        OmniUnlockMode::Normal,
    );
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 = SignContexts::new_omnilock(
        vec![account0_key, account1_key],
        cfg.clone(),
        OmniUnlockMode::Normal,
    );
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_ethereum_display() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum_display(keccak160(Pubkey::from(pubkey).as_ref()));
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
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
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // compressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // segwitp2sh
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // segwitbech32
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
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
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // compress
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // SegwitP2SH
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // SegwitBech32
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
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
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);

    // compressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_tron() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_tron_from_pubkey(&Pubkey::from(pubkey));
    let sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);
}

#[test]
fn test_omnilock_solana() {
    let account0_key =
        ed25519_dalek::SigningKey::from_bytes(&ACCOUNT0_KEY.as_bytes().try_into().unwrap());
    let pubkey = account0_key.verifying_key();
    let mut cfg = OmniLockConfig::new_solana_from_pubkey(&pubkey);
    let sign_context = SignContexts::new_omnilock_solana(
        vec![account0_key.clone()],
        cfg.clone(),
        OmniUnlockMode::Normal,
    );
    omnilock_test(cfg.clone(), &sign_context);

    cfg.enable_cobuild(true);
    let sign_context_2 =
        SignContexts::new_omnilock_solana(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    omnilock_test(cfg, &sign_context_2);
}

fn omnilock_test(cfg: OmniLockConfig, sign_context: &SignContexts) {
    let network_info = NetworkInfo::testnet();

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let (ctx, outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
        ],
    );

    let configuration = test_omnilock_config(outpoints);

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
    assert_eq!(tx.cell_deps().len(), 1);
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
    let mut sign_context =
        SignContexts::new_omnilock(vec![account0_key], cfg.clone(), OmniUnlockMode::Normal);
    let hashall_unlock =
        crate::transaction::signer::sighash::Secp256k1Blake160SighashAllSignerContext::new(vec![
            account0_key,
        ]);
    sign_context.add_context(Box::new(hashall_unlock));

    let (ctx, outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender0.clone(), Some(150 * ONE_CKB)),
            (sender1.clone(), Some(61 * ONE_CKB)),
        ],
    );

    let configuration = test_omnilock_config(outpoints);
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

#[cfg(unix)]
mod rsa_dl_test {
    use super::test_omnilock_dl_exec;
    use crate::{
        tests::build_rsa_script_dl,
        traits::{Signer, SignerError},
        unlock::omni_lock::{ExecDlConfig, Preimage},
        util::blake160,
    };

    use ckb_types::core::TransactionView;
    use openssl::{
        hash::MessageDigest,
        pkey::{PKey, Private, Public},
        rsa::Rsa,
        sign::Signer as RSASigner,
    };

    #[derive(Clone)]
    struct RSASinger {
        key: PKey<Private>,
    }

    impl Signer for RSASinger {
        fn match_id(&self, id: &[u8]) -> bool {
            let rsa_script = build_rsa_script_dl();
            let public_key_pem: Vec<u8> = self.key.public_key_to_pem().unwrap();
            let rsa_pubkey = PKey::public_key_from_pem(&public_key_pem).unwrap();
            let signning_pubkey = rsa_signning_prepare_pubkey(&rsa_pubkey);

            let preimage = Preimage::new_with_dl(rsa_script, blake160(&signning_pubkey));
            id.len() == 20 && id == preimage.auth().as_bytes()
        }

        fn sign(
            &self,
            id: &[u8],
            message: &[u8],
            _recoverable: bool,
            _tx: &TransactionView,
        ) -> Result<bytes::Bytes, SignerError> {
            if !self.match_id(id) {
                return Err(SignerError::IdNotFound);
            }
            Ok(bytes::Bytes::from(rsa_sign(message, &self.key)))
        }
    }

    fn rsa_signning_prepare_pubkey(pubkey: &PKey<Public>) -> Vec<u8> {
        let mut sig = vec![
            1, // algorithm id
            1, // key size, 1024
            0, // padding, PKCS# 1.5
            6, // hash type SHA256
        ];

        let pubkey2 = pubkey.rsa().unwrap();
        let mut e = pubkey2.e().to_vec();
        let mut n = pubkey2.n().to_vec();
        e.reverse();
        n.reverse();

        while e.len() < 4 {
            e.push(0);
        }
        while n.len() < 128 {
            n.push(0);
        }
        sig.append(&mut e); // 4 bytes E
        sig.append(&mut n); // N

        sig
    }

    pub fn rsa_sign(msg: &[u8], key: &PKey<Private>) -> Vec<u8> {
        let pem: Vec<u8> = key.public_key_to_pem().unwrap();
        let pubkey = PKey::public_key_from_pem(&pem).unwrap();

        let mut sig = rsa_signning_prepare_pubkey(&pubkey);

        let mut signer = RSASigner::new(MessageDigest::sha256(), key).unwrap();
        signer.update(msg).unwrap();
        sig.extend(signer.sign_to_vec().unwrap()); // sig

        sig
    }

    #[test]
    fn test_omnilock_dl() {
        let rsa_script = build_rsa_script_dl();
        let bits = 1024;
        let rsa = Rsa::generate(bits).unwrap();
        let rsa_private_key = PKey::from_rsa(rsa).unwrap();
        let public_key_pem: Vec<u8> = rsa_private_key.public_key_to_pem().unwrap();
        let rsa_pubkey = PKey::public_key_from_pem(&public_key_pem).unwrap();
        let signning_pubkey = rsa_signning_prepare_pubkey(&rsa_pubkey);

        let preimage = Preimage::new_with_dl(rsa_script, blake160(&signning_pubkey));
        let config = ExecDlConfig::new(preimage, 264);
        let signer = RSASinger {
            key: rsa_private_key,
        };
        test_omnilock_dl_exec(config.clone(), signer.clone(), false);
        test_omnilock_dl_exec(config, signer.clone(), true);
    }
}

#[derive(Clone)]
struct DummySinger {}

impl Signer for DummySinger {
    fn match_id(&self, id: &[u8]) -> bool {
        let (preimage, preimage_dl) = if cfg!(unix) {
            let always_success_script = build_always_success_script();

            (
                Preimage::new_with_exec(
                    always_success_script.clone(),
                    0,
                    [0; 8],
                    blake160(&[0u8; 20]),
                ),
                Preimage::new_with_exec(always_success_script, 0, [0; 8], blake160(&[0u8; 20])),
            )
        } else {
            #[cfg(not(unix))]
            {
                use crate::tests::build_always_success_dl_script;
                let always_success_script_dl = build_always_success_dl_script();
                let always_success_script = build_always_success_script();
                (
                    Preimage::new_with_exec(
                        always_success_script.clone(),
                        0,
                        [0; 8],
                        blake160(&[0u8; 20]),
                    ),
                    Preimage::new_with_dl(always_success_script_dl, H160::from([0u8; 20])),
                )
            }
            #[cfg(unix)]
            unreachable!()
        };

        id.len() == 20 && (id == preimage.auth().as_bytes() || id == preimage_dl.auth().as_bytes())
    }

    fn sign(
        &self,
        id: &[u8],
        _message: &[u8],
        _recoverable: bool,
        _tx: &TransactionView,
    ) -> Result<bytes::Bytes, SignerError> {
        if !self.match_id(id) {
            return Err(SignerError::IdNotFound);
        }
        Ok(bytes::Bytes::from(vec![0; 65]))
    }
}

#[test]
fn test_omnilock_exec() {
    let always_success_script = build_always_success_script();
    let preimage = Preimage::new_with_exec(always_success_script, 0, [0; 8], blake160(&[0u8; 20]));
    let config = ExecDlConfig::new(preimage, 65);

    test_omnilock_dl_exec(config.clone(), DummySinger {}, false);
    test_omnilock_dl_exec(config, DummySinger {}, true)
}

#[cfg(not(unix))]
#[test]
fn test_omnilock_dl() {
    use crate::tests::build_always_success_dl_script;
    let always_success_script = build_always_success_dl_script();
    let preimage = Preimage::new_with_dl(always_success_script, H160::from([0u8; 20]));
    let config = ExecDlConfig::new(preimage, 65);

    test_omnilock_dl_exec(config.clone(), DummySinger {}, false);
    test_omnilock_dl_exec(config, DummySinger {}, true)
}

#[cfg(unix)]
fn dl_exec_cfg(config: ExecDlConfig) -> (OmniLockConfig, &'static [u8]) {
    use crate::tests::RSA_DL_BIN;
    if config.preimage().len() == 32 + 1 + 1 + 8 + 20 {
        (
            OmniLockConfig::new_with_exec_preimage(config),
            ALWAYS_SUCCESS_BIN,
        )
    } else {
        (OmniLockConfig::new_with_dl_preimage(config), RSA_DL_BIN)
    }
}

#[cfg(not(unix))]
fn dl_exec_cfg(config: ExecDlConfig) -> (OmniLockConfig, &'static [u8]) {
    use crate::tests::ALWAYS_SUCCESS_DL_BIN;
    if config.preimage().len() == 32 + 1 + 1 + 8 + 20 {
        (
            OmniLockConfig::new_with_exec_preimage(config),
            ALWAYS_SUCCESS_BIN,
        )
    } else {
        (
            OmniLockConfig::new_with_dl_preimage(config),
            ALWAYS_SUCCESS_DL_BIN,
        )
    }
}

fn test_omnilock_dl_exec<T: Signer + 'static>(config: ExecDlConfig, signer: T, cobuild: bool) {
    let network_info = NetworkInfo::testnet();
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let (mut cfg, bin) = dl_exec_cfg(config);

    cfg.enable_cobuild(cobuild);
    let sender = build_omnilock_script(&cfg);
    let sign_context =
        SignContexts::new_omnilock_exec_dl_custom(signer, cfg.clone(), OmniUnlockMode::Normal);

    let (ctx, outpoints) = init_context(
        vec![(OMNILOCK_BIN, true), (bin, true)],
        vec![(sender.clone(), Some(300 * ONE_CKB))],
    );

    let configuration = test_omnilock_config(outpoints);

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
        .sign_transaction(&mut tx_with_groups, &sign_context)
        .unwrap();
    let tx = tx_with_groups.get_tx_view().clone();
    let script_groups = tx_with_groups.script_groups.clone();

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    assert_eq!(script_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 1);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (300 - 120) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_pubkeyhash_rc_dep() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_pubkey_hash(blake160(&pubkey.serialize()));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_ethereum_rc_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_ethereum_dispaly_rc_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    let mut cfg = OmniLockConfig::new_ethereum_display(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum_display(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_btc_rc_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // compressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // SegwitBech32
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // SegwitP2SH
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_dog_rc_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // compressed
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // SegwitBech32
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // SegwitP2SH
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_eos_rc_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_eos(H160::from(eos_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);

    // compressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let id = Identity::new_eos(H160::from(eos_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_tron_rc_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);

    let mut cfg = OmniLockConfig::new_tron_from_pubkey(&Pubkey::from(pubkey_0));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_tron(keccak160(Pubkey::from(pubkey_3).as_bytes()));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

#[test]
fn test_omnilock_solana_rc_dep() {
    let account0_key =
        ed25519_dalek::SigningKey::from_bytes(ACCOUNT0_KEY.as_bytes().try_into().unwrap());
    let pubkey_0 = account0_key.verifying_key();

    let mut cfg = OmniLockConfig::new_solana_from_pubkey(&pubkey_0);

    let account3_key =
        ed25519_dalek::SigningKey::from_bytes(ACCOUNT3_KEY.as_bytes().try_into().unwrap());
    let pubkey_3 = account3_key.verifying_key();
    let id = Identity::new(
        crate::unlock::IdentityFlag::Solana,
        blake160(pubkey_3.as_bytes()),
    );

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        false,
    ));
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Normal);
    cfg.enable_cobuild(true);
    test_omnilock_rc_dep(cfg.clone(), OmniUnlockMode::Admin);
    test_omnilock_rc_dep(cfg, OmniUnlockMode::Normal);
}

fn test_omnilock_rc_dep(mut cfg: OmniLockConfig, unlock_mode: OmniUnlockMode) {
    let network_info = NetworkInfo::testnet();
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let (mut ctx, mut outpoints) = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let (rce_cells, rce_cells_len) = match unlock_mode {
        OmniUnlockMode::Admin => {
            let mut admin_config = cfg.get_admin_config().unwrap().clone();
            let rc_args = match unlock_mode {
                OmniUnlockMode::Admin => ACCOUNT3_ARG,
                OmniUnlockMode::Normal => ACCOUNT0_ARG,
            };
            let (proof_vec, rc_type_id, rce_cells) =
                crate::tests::tx_builder::omni_lock_util::generate_rc(
                    &mut ctx,
                    admin_config.get_auth().to_smt_key().into(),
                    false,
                    rc_args,
                );
            admin_config.set_proofs(proof_vec);
            admin_config.set_rc_type_id(H256::from_slice(rc_type_id.as_ref()).unwrap());
            cfg.set_admin_config(admin_config);
            let rce_cells_len = rce_cells.len();
            (Some(rce_cells), rce_cells_len)
        }
        OmniUnlockMode::Normal => (None, 0),
    };
    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in [
        (sender.clone(), Some(300 * ONE_CKB)),
        (sender.clone(), Some(300 * ONE_CKB)),
    ] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    outpoints.extend(rce_cells.unwrap_or_default());

    let configuration = test_omnilock_config(outpoints);

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();

    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender.clone());

    let unlock_key = match unlock_mode {
        OmniUnlockMode::Admin => ACCOUNT3_KEY,
        OmniUnlockMode::Normal => ACCOUNT0_KEY,
    };

    let sign_context = if cfg.id().flag() == IdentityFlag::Solana {
        SignContexts::new_omnilock_solana(
            vec![ed25519_dalek::SigningKey::from_bytes(
                unlock_key.as_bytes().try_into().unwrap(),
            )],
            cfg.clone(),
            unlock_mode,
        )
    } else {
        SignContexts::new_omnilock(
            vec![secp256k1::SecretKey::from_slice(unlock_key.as_bytes()).unwrap()],
            cfg.clone(),
            unlock_mode,
        )
    };

    let context =
        OmnilockScriptContext::new(cfg.clone(), network_info.url.clone()).unlock_mode(unlock_mode);
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
    let script_groups = tx_with_groups.script_groups.clone();

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    assert_eq!(script_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1 + rce_cells_len);
    assert_eq!(tx.inputs().len(), 1);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (300 - 110) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_pubkeyhash_rc_input_and_dep() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_pubkey_hash(blake160(&pubkey.serialize()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_eth_rc_input_and_dep() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let mut cfg = OmniLockConfig::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_eth_display_rc_input_and_dep() {
    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
    let mut cfg = OmniLockConfig::new_ethereum_display(keccak160(Pubkey::from(pubkey).as_ref()));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_ethereum_display(keccak160(Pubkey::from(pubkey).as_ref()));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_btc_rc_input_and_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // P2PKHCompressed
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // SegwitBech32
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // SegwitP2SH
    let mut cfg = OmniLockConfig::new_btc_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let id = Identity::new_btc(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_dog_rc_input_and_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // P2PKHCompressed
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // SegwitBech32
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    );
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitBech32,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // SegwitP2SH
    let mut cfg = OmniLockConfig::new_dogcoin_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    );
    let id = Identity::new_dogcoin(H160::from(btc_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::SegwitP2SH,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_eos_rc_input_and_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);
    // uncompressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    );

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_eos(H160::from(eos_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHUncompressed,
    )));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);

    // P2PKHCompressed
    let mut cfg = OmniLockConfig::new_eos_from_pubkey(
        &Pubkey::from(pubkey_0),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    );
    let id = Identity::new_eos(H160::from(eos_auth(
        &pubkey_3.into(),
        crate::unlock::omni_lock::BTCSignVtype::P2PKHCompressed,
    )));
    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_tron_rc_input_and_dep() {
    let account0_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap();
    let pubkey_0 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account0_key);

    let mut cfg = OmniLockConfig::new_tron_from_pubkey(&Pubkey::from(pubkey_0));

    let account3_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey_3 = secp256k1::PublicKey::from_secret_key(&SECP256K1, &account3_key);
    let id = Identity::new_tron(keccak160(Pubkey::from(pubkey_3).as_bytes()));

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

#[test]
fn test_omnilock_solana_rc_input_and_dep() {
    let account0_key =
        ed25519_dalek::SigningKey::from_bytes(ACCOUNT0_KEY.as_bytes().try_into().unwrap());
    let pubkey_0 = account0_key.verifying_key();

    let mut cfg = OmniLockConfig::new_solana_from_pubkey(&pubkey_0);

    let account3_key =
        ed25519_dalek::SigningKey::from_bytes(ACCOUNT3_KEY.as_bytes().try_into().unwrap());
    let pubkey_3 = account3_key.verifying_key();
    let id = Identity::new(
        crate::unlock::IdentityFlag::Solana,
        blake160(pubkey_3.as_bytes()),
    );

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id.clone(),
        None,
        false,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg.clone());

    cfg.set_admin_config(AdminConfig::new(
        H256::default(),
        SmtProofEntryVec::default(),
        id,
        None,
        true,
    ));
    test_omnilock_rc_input_and_dep(cfg.clone());
    cfg.enable_cobuild(true);
    test_omnilock_rc_input_and_dep(cfg);
}

fn test_omnilock_rc_input_and_dep(mut cfg: OmniLockConfig) {
    let network_info = NetworkInfo::testnet();
    let unlock_mode = OmniUnlockMode::Admin;

    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let (mut ctx, mut outpoints) = init_context(
        vec![(OMNILOCK_BIN, true), (ALWAYS_SUCCESS_BIN, false)],
        vec![],
    );
    let mut admin_config = cfg.get_admin_config().unwrap().clone();
    let rc_input = admin_config.rce_in_input();

    let (proof_vec, rc_type_id, rce_cells) = crate::tests::tx_builder::omni_lock_util::generate_rc(
        &mut ctx,
        admin_config.get_auth().to_smt_key().into(),
        rc_input,
        ACCOUNT3_ARG,
    );
    admin_config.set_proofs(proof_vec);
    admin_config.set_rc_type_id(H256::from_slice(rc_type_id.as_ref()).unwrap());
    cfg.set_admin_config(admin_config);
    let sender = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in [(sender.clone(), Some(300 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    let rc_inputs = if rc_input {
        rce_cells
            .clone()
            .into_iter()
            .map(|outpoint| {
                let (output, output_data) = ctx.get_input(&outpoint).unwrap();
                LiveCell {
                    out_point: outpoint,
                    output,
                    output_data,
                    block_number: 0,
                    tx_index: 0,
                }
            })
            .collect()
    } else {
        // rc cell is dep cell
        outpoints.extend(rce_cells.clone());
        Vec::new()
    };
    let configuration = test_omnilock_config(outpoints);

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender.clone());

    if !rc_inputs.is_empty() {
        builder.set_rc_cells(rc_inputs)
    }

    let account_key = secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes()).unwrap();
    let mut sign_context = if cfg.id().flag() == IdentityFlag::Solana {
        SignContexts::new_omnilock_solana(
            vec![ed25519_dalek::SigningKey::from_bytes(
                ACCOUNT3_KEY.as_bytes().try_into().unwrap(),
            )],
            cfg.clone(),
            unlock_mode,
        )
    } else {
        SignContexts::new_omnilock(vec![account_key], cfg.clone(), unlock_mode)
    };
    let hashall_unlock =
        crate::transaction::signer::sighash::Secp256k1Blake160SighashAllSignerContext::new(vec![
            account_key,
        ]);
    sign_context.add_context(Box::new(hashall_unlock));

    let context =
        OmnilockScriptContext::new(cfg.clone(), network_info.url.clone()).unlock_mode(unlock_mode);
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
    let script_groups = tx_with_groups.script_groups.clone();

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    if rc_input {
        assert_eq!(script_groups.len(), 5);
        assert_eq!(tx.header_deps().len(), 0);
        assert_eq!(tx.cell_deps().len(), 3); // one is omnilock, one is sighash, one is always success
        assert_eq!(tx.inputs().len(), 4);
        for out_point in tx.input_pts_iter().skip(rce_cells.len()) {
            assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
        }
        assert_eq!(tx.outputs().len(), 2);
        assert_eq!(tx.output(0).unwrap(), output);
        assert_eq!(tx.output(1).unwrap().lock(), sender);
        let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
        let fee = (300 - 110) * ONE_CKB - change_capacity;
        assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);
    } else {
        assert_eq!(script_groups.len(), 1);
        assert_eq!(tx.header_deps().len(), 0);
        assert_eq!(tx.cell_deps().len(), 5);
        assert_eq!(tx.inputs().len(), 1);
        for out_point in tx.input_pts_iter() {
            assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
        }
        assert_eq!(tx.outputs().len(), 2);
        assert_eq!(tx.output(0).unwrap(), output);
        assert_eq!(tx.output(1).unwrap().lock(), sender);
        let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
        let fee = (300 - 110) * ONE_CKB - change_capacity;
        assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);
    }

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_multisign_rc_all() {
    test_omnilock_multisign_rc_dep(false, OmniUnlockMode::Admin);
    test_omnilock_multisign_rc_dep(false, OmniUnlockMode::Normal);
    test_omnilock_multisign_rc_dep(true, OmniUnlockMode::Admin);
    test_omnilock_multisign_rc_dep(true, OmniUnlockMode::Normal);
}

fn test_omnilock_multisign_rc_dep(cobuild: bool, unlock_mode: OmniUnlockMode) {
    let network_info = NetworkInfo::testnet();
    let lock_args = vec![
        ACCOUNT0_ARG.clone(),
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let mut cfg = OmniLockConfig::new_multisig(multi_cfg);

    let lock_args = vec![
        ACCOUNT3_ARG.clone(), // the different key
        ACCOUNT1_ARG.clone(),
        ACCOUNT2_ARG.clone(),
    ];
    let multi_cfg = MultisigConfig::new_with(lock_args, 0, 2).unwrap();
    let admin_id = Identity::new_multisig(multi_cfg.clone());

    let (mut ctx, mut outpoints) = init_context(vec![(OMNILOCK_BIN, true)], vec![]);
    let (proof_vec, rc_type_id, rce_cells) = crate::tests::tx_builder::omni_lock_util::generate_rc(
        &mut ctx,
        admin_id.to_smt_key().into(),
        false,
        ACCOUNT0_ARG,
    );
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        admin_id,
        Some(multi_cfg),
        false,
    ));
    cfg.enable_cobuild(cobuild);

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    for (lock, capacity_opt) in [
        (sender.clone(), Some(100 * ONE_CKB)),
        (sender.clone(), Some(200 * ONE_CKB)),
        (sender.clone(), Some(300 * ONE_CKB)),
    ] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    outpoints.extend(rce_cells);

    let configuration = test_omnilock_config(outpoints);

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

    let key0 = match unlock_mode {
        OmniUnlockMode::Admin => ACCOUNT3_KEY,
        OmniUnlockMode::Normal => ACCOUNT0_KEY,
    };

    let sign_context = SignContexts::new_omnilock(
        vec![
            secp256k1::SecretKey::from_slice(key0.as_bytes()).unwrap(),
            secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap(),
        ],
        cfg.clone(),
        unlock_mode,
    );

    let context =
        OmnilockScriptContext::new(cfg.clone(), network_info.url.clone()).unlock_mode(unlock_mode);
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&contexts).expect("build failed");

    TransactionSigner::new(&network_info)
        // use unitest lock to verify
        .insert_unlocker(
            crate::ScriptId::new_data1(H256::from(blake2b_256(OMNILOCK_BIN))),
            crate::transaction::signer::omnilock::OmnilockSigner {},
        )
        .sign_transaction(&mut tx_with_groups, &sign_context)
        .unwrap();
    let tx = tx_with_groups.get_tx_view().clone();
    let script_groups = tx_with_groups.script_groups.clone();

    assert_eq!(script_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 4);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (300 - 120) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);

    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn test_omnilock_owner_lock_rc_dep_all() {
    test_omnilock_owner_lock_rc_dep(false);
    test_omnilock_owner_lock_rc_dep(true);
}

fn test_omnilock_owner_lock_rc_dep(cobuild: bool) {
    let network_info = NetworkInfo::testnet();
    let unlock_mode = OmniUnlockMode::Admin;
    let receiver = build_sighash_script(ACCOUNT2_ARG);
    let sender1 = build_sighash_script(ACCOUNT1_ARG);
    let hash = H160::from_slice(&sender1.calc_script_hash().as_slice()[0..20]).unwrap();
    let mut cfg = OmniLockConfig::new_ownerlock(hash);

    let owner_sender = build_sighash_script(ACCOUNT3_ARG);
    let (mut ctx, mut outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![(owner_sender.clone(), Some(61 * ONE_CKB))],
    );

    let owner_hash = H160::from_slice(&owner_sender.calc_script_hash().as_slice()[0..20]).unwrap();
    let owner_id = Identity::new_ownerlock(owner_hash);
    let (proof_vec, rc_type_id, rce_cells) = crate::tests::tx_builder::omni_lock_util::generate_rc(
        &mut ctx,
        owner_id.to_smt_key().into(),
        false,
        ACCOUNT0_ARG,
    );
    cfg.set_admin_config(AdminConfig::new(
        H256::from_slice(rc_type_id.as_ref()).unwrap(),
        proof_vec,
        owner_id,
        None,
        false,
    ));
    cfg.enable_cobuild(cobuild);
    let sender0 = build_omnilock_script(&cfg);
    for (lock, capacity_opt) in [(sender0.clone(), Some(150 * ONE_CKB))] {
        ctx.add_simple_live_cell(random_out_point(), lock, capacity_opt);
    }

    outpoints.extend(rce_cells);

    let configuration = test_omnilock_config(outpoints);

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender0.clone(), owner_sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);
    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender0.clone());

    let mut sign_context = SignContexts::new_omnilock(
        vec![secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap()],
        cfg.clone(),
        unlock_mode,
    );
    let hashall_unlock =
        crate::transaction::signer::sighash::Secp256k1Blake160SighashAllSignerContext::new(vec![
            secp256k1::SecretKey::from_slice(ACCOUNT3_KEY.as_bytes()).unwrap(),
        ]);
    sign_context.add_context(Box::new(hashall_unlock));

    let context =
        OmnilockScriptContext::new(cfg.clone(), network_info.url.clone()).unlock_mode(unlock_mode);
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&contexts).expect("build failed");

    TransactionSigner::new(&network_info)
        // use unitest lock to verify
        .insert_unlocker(
            crate::ScriptId::new_data1(H256::from(blake2b_256(OMNILOCK_BIN))),
            crate::transaction::signer::omnilock::OmnilockSigner {},
        )
        .sign_transaction(&mut tx_with_groups, &sign_context)
        .unwrap();
    let tx = tx_with_groups.get_tx_view().clone();
    let script_groups = tx_with_groups.script_groups.clone();

    assert_eq!(script_groups.len(), 2);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 5);
    assert_eq!(tx.inputs().len(), 2);
    let mut senders = vec![sender0.clone(), owner_sender.clone()];
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

#[test]
fn test_omnilock_transfer_acp() {
    test_omnilock_transfer_from_acp(false);
    test_omnilock_transfer_from_acp(true);
    test_omnilock_transfer_to_acp(false);
    test_omnilock_transfer_to_acp(true);
}

fn test_omnilock_transfer_from_acp(cobuild: bool) {
    // account0 sender with acp
    // account2 receiver
    let unlock_mode = OmniUnlockMode::Normal;
    let network_info = NetworkInfo::testnet();

    let sender_key = secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);

    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);

    cfg.set_acp_config(OmniLockAcpConfig::new(0, 0));
    cfg.enable_cobuild(cobuild);

    let sender = build_omnilock_script(&cfg);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let (ctx, outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![(sender.clone(), Some(300 * ONE_CKB))],
    );

    let configuration = test_omnilock_config(outpoints);

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let output = CellOutput::new_builder()
        .capacity((110 * ONE_CKB).pack())
        .lock(receiver)
        .build();

    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender.clone());

    let sign_context = SignContexts::new_omnilock(vec![sender_key], cfg.clone(), unlock_mode);

    let context =
        OmnilockScriptContext::new(cfg.clone(), network_info.url.clone()).unlock_mode(unlock_mode);
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
    let script_groups = tx_with_groups.script_groups.clone();

    // let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    // println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    assert_eq!(script_groups.len(), 1);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 1);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (300 - 110) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);

    ctx.verify(tx, FEE_RATE).unwrap();
}

fn test_omnilock_transfer_to_acp(cobuild: bool) {
    // account0 sender
    // account2 receiver with acp
    let unlock_mode = OmniUnlockMode::Normal;
    let network_info = NetworkInfo::testnet();

    let sender = build_sighash_script(ACCOUNT0_ARG);
    let receiver_key = secp256k1::SecretKey::from_slice(ACCOUNT2_KEY.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &receiver_key);

    let pubkey_hash = blake160(&pubkey.serialize());
    let mut cfg = OmniLockConfig::new_pubkey_hash(pubkey_hash);
    cfg.set_acp_config(OmniLockAcpConfig::new(9, 5));
    cfg.enable_cobuild(cobuild);
    let receiver = build_omnilock_script(&cfg);

    let (ctx, outpoints) = init_context(
        vec![(OMNILOCK_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (receiver.clone(), Some(61 * ONE_CKB)),
        ],
    );

    let configuration = test_omnilock_config(outpoints);

    let iterator = InputIterator::new_with_cell_collector(
        vec![sender.clone(), receiver.clone()],
        Box::new(ctx.to_live_cells_context()) as Box<_>,
    );
    let mut builder = SimpleTransactionBuilder::new(configuration, iterator);

    let output = CellOutput::new_builder()
        .capacity(((61 + 10) * ONE_CKB).pack())
        .lock(receiver)
        .build();
    builder.add_output_and_data(output.clone(), ckb_types::packed::Bytes::default());
    builder.set_change_lock(sender.clone());

    let mut sign_context = SignContexts::new_omnilock(vec![receiver_key], cfg.clone(), unlock_mode);
    let hashall_unlock =
        crate::transaction::signer::sighash::Secp256k1Blake160SighashAllSignerContext::new(vec![
            secp256k1::SecretKey::from_slice(ACCOUNT0_KEY.as_bytes()).unwrap(),
        ]);
    sign_context.add_context(Box::new(hashall_unlock));

    let context = OmnilockScriptContext::new(cfg.clone(), network_info.url.clone());
    let mut contexts = HandlerContexts::default();
    contexts.add_context(Box::new(context) as Box<_>);

    let mut tx_with_groups = builder.build(&contexts).expect("build failed");

    TransactionSigner::new(&network_info)
        .insert_unlocker(
            crate::ScriptId::new_data1(H256::from(blake2b_256(OMNILOCK_BIN))),
            crate::transaction::signer::omnilock::OmnilockSigner {},
        )
        .sign_transaction(&mut tx_with_groups, &sign_context)
        .unwrap();

    let tx = tx_with_groups.get_tx_view().clone();
    let script_groups = tx_with_groups.script_groups.clone();

    assert_eq!(script_groups.len(), 2);
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 2);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);

    let change_capacity: u64 = tx.output(1).unwrap().capacity().unpack();
    let fee = (161 - 71) * ONE_CKB - change_capacity;
    assert_eq!(tx.data().as_reader().serialized_size_in_block() as u64, fee);

    ctx.verify(tx, FEE_RATE).unwrap();
}
