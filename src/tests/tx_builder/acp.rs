use std::collections::HashMap;

use ckb_hash::blake2b_256;

use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};

use crate::constants::{ONE_CKB, SIGHASH_TYPE_HASH};
use crate::tests::{
    build_sighash_script, init_context, ACCOUNT1_ARG, ACCOUNT1_KEY, ACCOUNT2_ARG, ACP_BIN, FEE_RATE,
};
use crate::traits::SecpCkbRawKeySigner;
use crate::tx_builder::{
    acp::{AcpTransferBuilder, AcpTransferReceiver},
    CapacityBalancer, TxBuilder,
};
use crate::unlock::{AcpUnlocker, ScriptUnlocker};
use crate::ScriptId;

#[test]
fn test_transfer_to_acp() {
    let data_hash = H256::from(blake2b_256(ACP_BIN));
    let sender = build_sighash_script(ACCOUNT1_ARG);
    let receiver = Script::new_builder()
        .code_hash(data_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(ACCOUNT2_ARG.0.to_vec()).pack())
        .build();
    let ctx = init_context(
        vec![(ACP_BIN, true)],
        vec![
            (sender.clone(), Some(100 * ONE_CKB)),
            (sender.clone(), Some(200 * ONE_CKB)),
            (sender.clone(), Some(300 * ONE_CKB)),
            (receiver.clone(), Some(99 * ONE_CKB)),
        ],
    );

    let acp_receiver = AcpTransferReceiver::new(receiver.clone(), 150 * ONE_CKB);
    let builder = AcpTransferBuilder::new(vec![acp_receiver]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer =
        CapacityBalancer::new_simple(sender.clone(), placeholder_witness.clone(), FEE_RATE);

    let account1_key = secp256k1::SecretKey::from_slice(ACCOUNT1_KEY.as_bytes()).unwrap();
    let signer1 = SecpCkbRawKeySigner::new_with_secret_keys(vec![account1_key]);
    let sighash_unlocker = AcpUnlocker::from(Box::new(signer1) as Box<_>);
    let acp_unlocker = AcpUnlocker::from(Box::<SecpCkbRawKeySigner>::default() as Box<_>);
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH),
        Box::new(sighash_unlocker),
    );
    unlockers.insert(ScriptId::new_data1(data_hash), Box::new(acp_unlocker));

    let mut cell_collector = ctx.to_live_cells_context();
    let (tx, locked_groups) = builder
        .build_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
        .unwrap();

    assert!(locked_groups.is_empty());
    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 2);
    assert_eq!(tx.inputs().len(), 3);
    let input_cells = vec![
        CellOutput::new_builder()
            .capacity((99 * ONE_CKB).pack())
            .lock(receiver.clone())
            .build(),
        CellOutput::new_builder()
            .capacity((100 * ONE_CKB).pack())
            .lock(sender.clone())
            .build(),
        CellOutput::new_builder()
            .capacity((200 * ONE_CKB).pack())
            .lock(sender.clone())
            .build(),
    ];
    for (idx, out_point) in tx.input_pts_iter().enumerate() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0, input_cells[idx]);
    }
    assert_eq!(tx.outputs().len(), 2);
    let acp_output = CellOutput::new_builder()
        .capacity(((99 + 150) * ONE_CKB).pack())
        .lock(receiver)
        .build();
    assert_eq!(tx.output(0).unwrap(), acp_output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 3);
    assert_eq!(witnesses[0].len(), 0);
    assert_eq!(witnesses[1].len(), placeholder_witness.as_slice().len());
    assert_eq!(witnesses[2].len(), 0);
    ctx.verify(tx, FEE_RATE).unwrap();
}
