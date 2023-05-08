pub mod transaction_input;
use std::str::FromStr;

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
    cell_collector: DefaultCellCollector,
}

impl InputIterator {
    pub fn new(lock_scripts: Vec<packed::Script>, network_info: &NetworkInfo) -> Self {
        let mut lock_scripts = lock_scripts;
        lock_scripts.reverse();
        Self {
            buffer_inputs: vec![],
            lock_scripts,
            cell_collector: DefaultCellCollector::new(&network_info.url),
        }
    }
    pub fn new_with_address<T: AsRef<str>>(
        address: &[T],
        network_info: &NetworkInfo,
    ) -> Result<Self, String> {
        address
            .iter()
            .map(|adr_str| Address::from_str(adr_str.as_ref()).map(|ref addr| addr.into()))
            .collect::<Result<Vec<_>, _>>()
            .map(|lock_scripts| Self::new(lock_scripts, network_info))
    }

    fn collect_live_cells_by_lock(
        cell_collector: &mut DefaultCellCollector,
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
            .map(|live_cell| TransactionInput::new(live_cell, 0))
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
