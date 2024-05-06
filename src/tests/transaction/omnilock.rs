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
        ACCOUNT0_ARG, ACCOUNT0_KEY, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ALWAYS_SUCCESS_BIN,
        FEE_RATE, OMNILOCK_BIN,
    },
    traits::{Signer, SignerError},
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
    unlock::{
        omni_lock::{ExecDlConfig, Preimage},
        MultisigConfig, OmniLockConfig,
    },
    util::{blake160, keccak160},
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
        let mut cells = Vec::with_capacity(outpoints.len() + 1);
        cells.push(crate::transaction::handler::cell_dep!(
            "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
            0u32,
            DepType::DepGroup
        ));
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
    let mut sign_context = SignContexts::new_omnilock(vec![account0_key], cfg.clone());
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
    let sign_context = SignContexts::new_omnilock_exec_dl_custom(signer, cfg.clone());

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
    assert_eq!(tx.cell_deps().len(), 3);
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
