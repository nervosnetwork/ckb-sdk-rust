use crate::constants::ONE_CKB;
use crate::test_util::{random_out_point, Context};
use crate::tests::{build_sighash_script, ALWAYS_SUCCESS_BIN};
use crate::types::xudt_rce_mol::{RCCellVecBuilder, RCDataBuilder, RCDataUnion, SmtProofEntryVec};
use crate::unlock::rc_data::ListType;
use crate::unlock::rc_data::{Mask, RcRuleVecBuilder};

use bytes::Bytes;
use ckb_types::core::{DepType, ScriptHashType};
use ckb_types::{packed::*, prelude::*, H160};
use sparse_merkle_tree::H256 as SmtH256;

pub fn generate_rc(
    ctx: &mut Context,
    smt_key: SmtH256,
    in_input_cell: bool,
    args: H160,
) -> (SmtProofEntryVec, Bytes, Vec<OutPoint>) {
    let mut builder = RcRuleVecBuilder::new();
    builder
        .build_single_proof_and_rule(&[smt_key], Mask::Input, ListType::White, false, true)
        .unwrap();
    builder
        .build_single_proof_and_rule(&[smt_key], Mask::Output, ListType::White, false, false)
        .unwrap();
    let proof_vec = builder.build_proofs();

    let rc_rules = builder.rc_rules();
    let mut rce_cells = vec![];
    let rc_type_id = generate_rce_cell(ctx, rc_rules, &mut rce_cells, in_input_cell, args);

    (proof_vec, rc_type_id.as_bytes(), rce_cells)
}

pub fn build_always_success_script() -> Script {
    let data_hash = CellOutput::calc_data_hash(ALWAYS_SUCCESS_BIN);
    Script::new_builder()
        .code_hash(data_hash)
        .hash_type(ScriptHashType::Data.into())
        .build()
}
//
// deploy "bin" to cell, then build a script to point it.
//
// it can:
// * build lock script, set is_type to false
// * build type script, set is_type to true
// * build type script without upgrading, set is_type to false
// * build extension script, set is_type to true
// * build extension script without upgrading, set is_type to false
// * build RCE cell, is_type = true. Only the Script.code_hash is kept for further use.
//   when in this case, to make "args" passed in unique
// when in_input_cell is on, the cell is not in deps but in input.
fn build_script(
    ctx: &mut Context,
    is_type: bool,
    in_input_cell: bool,
    bin: &Bytes,
    args: H160,
    rce_cells: &mut Vec<OutPoint>,
) -> Script {
    // this hash to make type script in code unique
    // then make "type script hash" unique, which will be code_hash in "type script"
    let hash = ckb_hash::blake2b_256(bin);
    let always_success = build_always_success_script();

    let type_script_in_code = {
        if in_input_cell {
            let hash: Bytes = Bytes::copy_from_slice(&hash);
            always_success.as_builder().args(hash.pack()).build()
        } else {
            // this args can be anything
            let args = vec![0u8; 32];
            Script::new_builder()
                .args(args.pack())
                .code_hash(hash.pack())
                .hash_type(ScriptHashType::Type.into())
                .build()
        }
    };

    let lock_script = build_sighash_script(args.clone());
    // it not needed to set "type script" when is_type is false
    let capacity = bin.len() as u64 * ONE_CKB;
    let output = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock_script)
        .type_(Some(type_script_in_code.clone()).pack())
        .build();
    let out_point = random_out_point();
    if in_input_cell {
        let input = CellInput::new(out_point.clone(), 0);
        ctx.add_live_cell(input, output, bin.clone(), None);
    } else {
        let cell_dep = CellDep::new_builder()
            .out_point(out_point.clone())
            .dep_type(DepType::Code.into())
            .build();
        ctx.add_cell_dep(cell_dep, output, bin.clone(), None);
    }
    rce_cells.push(out_point);

    let code_hash = if is_type {
        ckb_hash::blake2b_256(type_script_in_code.as_slice())
    } else {
        ckb_hash::blake2b_256(bin)
    };
    let hash_type = if is_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data
    };

    let args = Bytes::copy_from_slice(args.as_bytes());
    Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build()
}

// first generate N RCE cells with each contained one RCRule
// then collect all these RCE cell hash and create the final RCE cell.
pub fn generate_rce_cell(
    ctx: &mut Context,
    rc_rules: &Vec<Bytes>,
    rce_cells: &mut Vec<OutPoint>,
    in_input_cell: bool,
    args: H160,
) -> Byte32 {
    let mut cell_vec_builder = RCCellVecBuilder::default();

    for rc_rule in rc_rules {
        let rce_script = build_script(ctx, true, in_input_cell, rc_rule, args.clone(), rce_cells);

        let hash = rce_script.code_hash();

        cell_vec_builder =
            cell_vec_builder.push(Byte32::from_slice(hash.as_slice()).expect("Byte32::from_slice"));
    }

    let cell_vec = cell_vec_builder.build();

    let rce_cell_content = RCDataBuilder::default()
        .set(RCDataUnion::RCCellVec(cell_vec))
        .build();

    let bin = rce_cell_content.as_slice();
    let rce_script = build_script(
        ctx,
        true,
        in_input_cell,
        &Bytes::copy_from_slice(bin),
        args,
        rce_cells,
    );
    rce_script.code_hash()
}
