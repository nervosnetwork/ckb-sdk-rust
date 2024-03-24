use std::collections::HashMap;

use bytes::{Bytes, BytesMut};
use ckb_hash::blake2b_256;
use ckb_types::{
    core::{ScriptHashType, TransactionView},
    packed::{self, CellOutput, Script, WitnessArgs},
    prelude::{Builder, Entity, Pack},
    H256,
};

use crate::test_util::Context;
use crate::{
    constants::ONE_CKB,
    tests::{build_sighash_script, init_context, ACCOUNT2_ARG, FEE_RATE},
    traits::TransactionDependencyProvider,
    tx_builder::{
        fill_placeholder_witnesses, transfer::CapacityTransferBuilder, unlock_tx,
        BalanceTxCapacityError, CapacityBalancer, TxBuilder, TxBuilderError,
    },
    unlock::{ScriptUnlocker, UnlockError},
    ScriptGroup, ScriptId,
};

const CYCLE_BIN: &[u8] = include_bytes!("../../test-data/cycle");

pub struct CycleUnlocker {
    loops: u64,
}
impl ScriptUnlocker for CycleUnlocker {
    fn match_args(&self, _args: &[u8]) -> bool {
        true
    }

    fn unlock(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        let witness_idx = script_group.input_indices[0];
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        while witnesses.len() <= witness_idx {
            witnesses.push(Default::default());
        }
        witnesses[witness_idx] = self.loops.to_le_bytes().pack();
        Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
    }

    fn fill_placeholder_witness(
        &self,
        tx: &TransactionView,
        _script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Ok(tx.clone())
    }
}

pub fn build_args(loops: u64) -> Bytes {
    let mut bytes = BytesMut::with_capacity(8);

    bytes.extend(loops.to_le_bytes().iter());

    bytes.freeze()
}

fn build_script(loops: u64) -> Script {
    let cycle_data_hash = H256::from(blake2b_256(CYCLE_BIN));
    Script::new_builder()
        .code_hash(cycle_data_hash.pack())
        .hash_type(ScriptHashType::Data.into())
        .args(build_args(loops).pack())
        .build()
}

fn build_cycle_unlockers(loops: u64) -> HashMap<ScriptId, Box<dyn ScriptUnlocker>> {
    let script = build_script(loops);
    let cycle_unlockder = CycleUnlocker { loops };
    let cycle_script_id = ScriptId::from(&script);
    let mut unlockers = HashMap::default();
    unlockers.insert(
        cycle_script_id,
        Box::new(cycle_unlockder) as Box<dyn ScriptUnlocker>,
    );
    unlockers
}

#[test]
fn test_cycle_vsize_samll() {
    test_change_enough(3);
}
#[test]
fn test_cycle_vsize_big() {
    test_change_enough(512 * 1024);
}

fn test_change_enough(loops: u64) {
    let sender = build_script(loops);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx: &'static Context = Box::leak(Box::new(init_context(
        vec![(CYCLE_BIN, true)],
        vec![(sender.clone(), Some(200 * ONE_CKB))],
    )));

    let output = CellOutput::new_builder()
        .capacity((140 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = WitnessArgs::default();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, FEE_RATE);

    let mut cell_collector = ctx.to_live_cells_context();
    let unlockers = build_cycle_unlockers(loops);
    let (tx, new_locked_groups) = builder
        .build_balance_unlocked(&mut cell_collector, ctx, ctx, ctx, &balancer, &unlockers)
        .unwrap();

    assert!(new_locked_groups.is_empty());

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 1);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    assert_eq!(tx.output(1).unwrap().lock(), sender);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].len(), 8);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn vsize_big_and_fee_enough() {
    let loops = 640 * 1024;
    let sender = build_script(loops);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx: &'static Context = Box::leak(Box::new(init_context(
        vec![(CYCLE_BIN, true)],
        vec![(sender.clone(), Some(200 * ONE_CKB + 123_456))],
    )));

    let output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = WitnessArgs::default();
    let mut balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, FEE_RATE);
    balancer.set_max_fee(Some(ONE_CKB));

    let mut cell_collector = ctx.to_live_cells_context();
    let unlockers = build_cycle_unlockers(loops);
    let (tx, new_locked_groups) = builder
        .build_balance_unlocked(&mut cell_collector, ctx, ctx, ctx, &balancer, &unlockers)
        .unwrap();

    assert!(new_locked_groups.is_empty());

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 1);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 1);
    assert_eq!(tx.output(0).unwrap(), output);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].len(), 8);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn vsize_big_and_fee_not_enough() {
    let loops = 640 * 1024;
    let sender = build_script(loops);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx: &'static Context = Box::leak(Box::new(init_context(
        vec![(CYCLE_BIN, true)],
        vec![(sender.clone(), Some(200 * ONE_CKB + 456))],
    )));

    let output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let placeholder_witness = WitnessArgs::default();
    let mut balancer = CapacityBalancer::new_simple(sender, placeholder_witness, FEE_RATE);
    balancer.set_max_fee(Some(100_000));

    let mut cell_collector = ctx.to_live_cells_context();
    let unlockers = build_cycle_unlockers(loops);
    let result =
        builder.build_balance_unlocked(&mut cell_collector, ctx, ctx, ctx, &balancer, &unlockers);

    if let Err(TxBuilderError::BalanceCapacity(BalanceTxCapacityError::CapacityNotEnough(_msg))) =
        result
    {
    } else {
        panic!("not expected result: {:?}", result);
    }
}

#[test]
fn vsize_big_and_can_find_more_capacity() {
    let loops = 6400 * 1024;
    let sender = build_script(loops);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx: &'static Context = Box::leak(Box::new(init_context(
        vec![(CYCLE_BIN, true)],
        vec![
            (sender.clone(), Some(200 * ONE_CKB + 286)), // 286 is fee calculated from tx_size
            (sender.clone(), Some(70 * ONE_CKB)),
        ],
    )));

    let output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output.clone(), Bytes::default())]);
    let placeholder_witness = WitnessArgs::default();
    let mut balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, FEE_RATE);
    balancer.set_max_fee(Some(1000));

    let mut cell_collector = ctx.to_live_cells_context();
    let unlockers = build_cycle_unlockers(loops);
    // copy build_balance_unlocked here to make sure it runs as expected with assertions.
    // let (tx, new_locked_groups) = builder
    //     .build_balance_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
    //     .unwrap();
    let (tx, new_locked_groups) = {
        let base_tx = builder
            .build_base(&mut cell_collector, ctx, ctx, ctx)
            .unwrap();
        let (tx_filled_witnesses, _) =
            fill_placeholder_witnesses(base_tx, ctx, &unlockers).unwrap();
        let (balanced_tx, mut change_idx) = balancer
            .rebalance_tx_capacity(
                &tx_filled_witnesses,
                &mut cell_collector,
                ctx,
                ctx,
                ctx,
                0,
                None,
            )
            .unwrap();

        assert_eq!(balanced_tx.inputs().len(), 1);
        assert_eq!(balanced_tx.outputs().len(), 1);
        let (mut tx, unlocked_group) = unlock_tx(balanced_tx, ctx, &unlockers).unwrap();
        assert!(unlocked_group.is_empty());
        let mut ready = false;
        let mut loop_times = 0;
        while !ready {
            loop_times += 1;
            let (new_tx, new_change_idx, ok) = balancer
                .check_cycle_fee(tx, &mut cell_collector, ctx, ctx, ctx, change_idx)
                .unwrap();
            tx = new_tx;
            ready = ok;
            change_idx = new_change_idx;
            if !ready {
                let (new_tx, _) = unlock_tx(tx, ctx, &unlockers).unwrap();
                tx = new_tx
            }
        }
        assert_eq!(loop_times, 2);
        (tx, unlocked_group)
    };

    assert!(new_locked_groups.is_empty());

    assert_eq!(tx.header_deps().len(), 0);
    assert_eq!(tx.cell_deps().len(), 1);
    assert_eq!(tx.inputs().len(), 2);
    for out_point in tx.input_pts_iter() {
        assert_eq!(ctx.get_input(&out_point).unwrap().0.lock(), sender);
    }
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.output(0).unwrap(), output);
    let witnesses = tx
        .witnesses()
        .into_iter()
        .map(|w| w.raw_data())
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].len(), 8);
    ctx.verify(tx, FEE_RATE).unwrap();
}

#[test]
fn vsize_big_and_cannot_find_more_capacity() {
    let loops = 6400 * 1024;
    let sender = build_script(loops);
    let receiver = build_sighash_script(ACCOUNT2_ARG);

    let ctx: &'static Context = Box::leak(Box::new(init_context(
        vec![(CYCLE_BIN, true)],
        vec![
            (sender.clone(), Some(200 * ONE_CKB + 286)), // 286 is fee calculated from tx_size
            (sender.clone(), Some(49 * ONE_CKB)),
        ],
    )));

    let output = CellOutput::new_builder()
        .capacity((200 * ONE_CKB).pack())
        .lock(receiver)
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let placeholder_witness = WitnessArgs::default();
    let mut balancer = CapacityBalancer::new_simple(sender, placeholder_witness, FEE_RATE);
    balancer.set_max_fee(Some(1000));

    let mut cell_collector = ctx.to_live_cells_context();
    let unlockers = build_cycle_unlockers(loops);
    // copy build_balance_unlocked here to make sure it runs as expected with assertions.
    // let (tx, new_locked_groups) = builder
    //     .build_balance_unlocked(&mut cell_collector, &ctx, &ctx, &ctx, &balancer, &unlockers)
    //     .unwrap();
    let base_tx = builder
        .build_base(&mut cell_collector, ctx, ctx, ctx)
        .unwrap();
    let (tx_filled_witnesses, _) = fill_placeholder_witnesses(base_tx, ctx, &unlockers).unwrap();
    let (balanced_tx, change_idx) = balancer
        .rebalance_tx_capacity(
            &tx_filled_witnesses,
            &mut cell_collector,
            ctx,
            ctx,
            ctx,
            0,
            None,
        )
        .unwrap();

    assert_eq!(balanced_tx.inputs().len(), 1);
    assert_eq!(balanced_tx.outputs().len(), 1);
    let (tx, unlocked_group) = unlock_tx(balanced_tx, ctx, &unlockers).unwrap();
    assert!(unlocked_group.is_empty());
    let result = balancer.check_cycle_fee(tx, &mut cell_collector, ctx, ctx, ctx, change_idx);
    if let Err(BalanceTxCapacityError::ForceSmallChangeAsFeeFailed(_msg)) = result {
    } else {
        panic!("not expected result: {:?}", result);
    }
}
