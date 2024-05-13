pub mod transaction_input;
use ckb_types::packed::Script;
pub use transaction_input::TransactionInput;

use crate::{
    rpc::ckb_indexer::SearchMode,
    traits::{
        CellCollector, CellCollectorError, CellQueryOptions, DefaultCellCollector, ValueRangeOption,
    },
    types::NetworkInfo,
    Address,
};

pub struct InputIterator {
    buffer_inputs: Vec<TransactionInput>,
    lock_scripts: Vec<Script>,
    cell_collector: Box<dyn CellCollector>,
    type_script: Option<Script>,
}

impl Clone for InputIterator {
    fn clone(&self) -> Self {
        Self {
            buffer_inputs: self.buffer_inputs.clone(),
            lock_scripts: self.lock_scripts.clone(),
            cell_collector: dyn_clone::clone_box(&*self.cell_collector),
            type_script: self.type_script.clone(),
        }
    }
}

impl InputIterator {
    pub fn new(lock_scripts: Vec<Script>, network_info: &NetworkInfo) -> Self {
        let mut lock_scripts = lock_scripts;
        lock_scripts.reverse();
        Self {
            buffer_inputs: vec![],
            lock_scripts,
            cell_collector: Box::new(DefaultCellCollector::new(&network_info.url)),
            type_script: None,
        }
    }

    pub fn new_with_cell_collector(
        lock_scripts: Vec<Script>,
        cell_collector: Box<dyn CellCollector>,
    ) -> Self {
        let mut lock_scripts = lock_scripts;
        lock_scripts.reverse();
        Self {
            buffer_inputs: vec![],
            lock_scripts,
            cell_collector,
            type_script: None,
        }
    }

    pub fn new_with_address(address: &[Address], network_info: &NetworkInfo) -> Self {
        let lock_scripts = address.iter().map(|addr| addr.into()).collect::<Vec<_>>();
        Self::new(lock_scripts, network_info)
    }

    pub fn lock_scripts(&self) -> &[Script] {
        &self.lock_scripts
    }

    pub fn set_type_script(&mut self, type_script: Option<Script>) {
        self.type_script = type_script;
    }

    pub fn push_input(&mut self, input: TransactionInput) {
        self.buffer_inputs.push(input);
    }

    fn collect_live_cells(&mut self) -> Result<(), CellCollectorError> {
        loop {
            if self.lock_scripts.is_empty() == 0 {
                return Ok(());
            }

            if let Some(lock_script) = self.lock_scripts.last() {
                let mut query = CellQueryOptions::new_lock(lock_script.clone());
                query.script_search_mode = Some(SearchMode::Exact);
                if let Some(type_script) = &self.type_script {
                    query.secondary_script = Some(type_script.clone());
                } else {
                    query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
                    query.data_len_range = Some(ValueRangeOption::new_exact(0));
                };
                let (live_cells, _capacity) =
                    self.cell_collector.collect_live_cells(&query, true)?;
                if live_cells.is_empty() {
                    self.lock_scripts.pop();
                } else {
                    self.buffer_inputs = live_cells
                        .into_iter()
                        .rev() // reverse the iter, so that the first cell will be consumed while pop
                        .map(|live_cell| TransactionInput::new(live_cell, 0))
                        .collect();
                    break;
                }
            }
        }
        Ok(())
    }
}

impl Iterator for InputIterator {
    type Item = Result<TransactionInput, CellCollectorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(input) = self.buffer_inputs.pop() {
            return Some(Ok(input));
        }

        let status = self.collect_live_cells();
        if let Err(status) = status {
            Some(Err(status))
        } else {
            self.buffer_inputs.pop().map(Ok)
        }
    }
}
