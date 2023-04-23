use ckb_types::{
    core::{ScriptHashType, TransactionView},
    packed::Script,
    prelude::*,
};

use crate::ScriptGroup;

pub struct TransactionWithScriptGroups {
    pub tx_view: TransactionView,
    pub script_groups: Vec<ScriptGroup>,
}

impl TransactionWithScriptGroups {
    pub fn new(tx_view: TransactionView, script_groups: Vec<ScriptGroup>)-> Self {
        Self {
            tx_view,
            script_groups,
        }
    }
    pub fn get_tx_view(&self) -> &TransactionView {
        &self.tx_view
    }

    pub fn set_tx_view(&mut self, tx_view: TransactionView) {
        self.tx_view = tx_view;
    }

    pub fn get_script_groups(&self) -> &[ScriptGroup] {
        &self.script_groups
    }

    pub fn set_script_groups(&mut self, script_groups: Vec<ScriptGroup>) {
        self.script_groups = script_groups;
    }
}

#[derive(Default, Clone)]
pub struct TransactionWithScriptGroupsBuilder {
    tx_view: Option<TransactionView>,
    script_groups: Vec<ScriptGroup>,
}

impl TransactionWithScriptGroupsBuilder {
    pub fn set_tx_view(mut self, tx_view: TransactionView) -> Self {
        self.tx_view = Some(tx_view);
        self
    }

    pub fn set_script_groups(mut self, script_groups: Vec<ScriptGroup>) -> Self {
        self.script_groups = script_groups;
        self
    }

    pub fn add_script_group(mut self, script_group: ScriptGroup) -> Self {
        self.script_groups.push(script_group);
        self
    }

    pub fn add_lock_script_group(mut self, script: &Script, input_indices: &[usize]) -> Self {
        let mut script_group = ScriptGroup::from_lock_script(script);
        script_group.input_indices = input_indices.to_vec();
        self.script_groups.push(script_group);
        self
    }

    pub fn add_lock_script_group_with_code_hash(
        self,
        code_hash: &[u8; 32],
        args: &[u8],
        input_indices: &[usize],
    ) -> Self {
        let script = Script::new_builder()
            .code_hash(code_hash.pack())
            .args(args.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        self.add_lock_script_group(&script, input_indices)
    }

    pub fn build(self) -> TransactionWithScriptGroups {
        TransactionWithScriptGroups {
            tx_view: self.tx_view.unwrap(),
            script_groups: self.script_groups,
        }
    }
}
