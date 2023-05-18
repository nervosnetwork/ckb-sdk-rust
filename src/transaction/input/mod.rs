pub mod transaction_input;
use ckb_types::packed;
pub use transaction_input::TransactionInput;

use crate::{
    traits::{
        CellCollector, CellCollectorError, CellQueryOptions, DefaultCellCollector, ValueRangeOption,
    },
    types::NetworkInfo,
    Address,
};

pub struct InputIterator {
    buffer_inputs: Vec<TransactionInput>,
    lock_scripts: Vec<packed::Script>,
    cell_collector: Box<dyn CellCollector>,
}

impl InputIterator {
    pub fn new(lock_scripts: Vec<packed::Script>, network_info: &NetworkInfo) -> Self {
        let mut lock_scripts = lock_scripts;
        lock_scripts.reverse();
        Self {
            buffer_inputs: vec![],
            lock_scripts,
            cell_collector: Box::new(DefaultCellCollector::new(&network_info.url)),
        }
    }

    pub fn new_with_cell_collector(
        lock_scripts: Vec<packed::Script>,
        cell_collector: Box<dyn CellCollector>,
    ) -> Self {
        let mut lock_scripts = lock_scripts;
        lock_scripts.reverse();
        Self {
            buffer_inputs: vec![],
            lock_scripts,
            cell_collector,
        }
    }

    pub fn new_with_address(address: &[Address], network_info: &NetworkInfo) -> Self {
        let lock_scripts = address.iter().map(|addr| addr.into()).collect::<Vec<_>>();
        Self::new(lock_scripts, network_info)
    }

    fn collect_live_cells_by_lock(
        cell_collector: &mut Box<dyn CellCollector>,
        buffer_inputs: &mut Vec<TransactionInput>,
        lock_script: &packed::Script,
    ) -> Result<bool, CellCollectorError> {
        let base_query = {
            let mut query = CellQueryOptions::new_lock(lock_script.clone());
            query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
            query.data_len_range = Some(ValueRangeOption::new_exact(0));
            query
        };
        let (live_cells, capacity) = cell_collector.collect_live_cells(&base_query, true)?;
        *buffer_inputs = live_cells
            .into_iter()
            .rev() // reverse the iter, so that the first cell will be consumed while pop
            .map(TransactionInput::from)
            .collect();
        Ok(capacity > 0)
    }

    fn collect_live_cells(&mut self) -> Result<bool, CellCollectorError> {
        while let Some(script) = self.lock_scripts.last() {
            if Self::collect_live_cells_by_lock(
                &mut self.cell_collector,
                &mut self.buffer_inputs,
                script,
            )? {
                return Ok(true);
            }
            self.lock_scripts.pop();
        }
        Ok(false)
    }
}

impl Iterator for InputIterator {
    type Item = Result<TransactionInput, CellCollectorError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(input) = self.buffer_inputs.pop() {
                return Some(Ok(input));
            }

            let status = self.collect_live_cells();
            if let Err(status) = status {
                return Some(Err(status));
            }
            if !status.unwrap() {
                return None;
            }
        }
    }
}
