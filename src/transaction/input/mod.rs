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
    pub(crate) buffer_inputs: Vec<TransactionInput>,
    pub(crate) buffer_index: usize,
    pub(crate) script_index: usize,
    pub(crate) lock_scripts: Vec<packed::Script>,
    pub(crate) cell_collector: DefaultCellCollector,
}

impl InputIterator {
    pub fn new(lock_scripts: Vec<packed::Script>, network_info: NetworkInfo) -> Self {
        Self {
            buffer_inputs: vec![],
            buffer_index: 0,
            script_index: 0,
            lock_scripts,
            cell_collector: DefaultCellCollector::new(&network_info.url),
        }
    }
    pub fn new_with_address<T: AsRef<str>>(
        address: &[T],
        network_info: NetworkInfo,
    ) -> Result<Self, String> {
        let lock_sripts: Result<Vec<packed::Script>, String> = address
            .into_iter()
            .map(|adr_str| Address::from_str(adr_str.as_ref()))
            .map(|ad_r| ad_r.map(|t| Into::<packed::Script>::into(&t)))
            .collect();
        let lock_scripts = lock_sripts?;
        Ok(Self::new(lock_scripts, network_info))
    }

    fn collect_live_cells_by_lock(
        cell_collector: &mut DefaultCellCollector,
        buffer_inputs: &mut Vec<TransactionInput>,
        buffer_index: &mut usize,
        lock_script: &packed::Script,
    ) -> Result<bool, CellCollectorError> {
        let base_query = {
            let mut query = CellQueryOptions::new_lock(lock_script.clone());
            query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
            query.data_len_range = Some(ValueRangeOption::new_exact(0));
            query
        };
        let (live_cells, capacity) = cell_collector.collect_live_cells(&base_query, true)?;
        let inputs: Vec<_> = live_cells
            .into_iter()
            .map(|live_cell| TransactionInput::new(live_cell, 0))
            .collect();
        *buffer_inputs = inputs;
        *buffer_index = 0;
        Ok(capacity > 0)
    }

    fn collect_live_cells(&mut self) -> Result<bool, CellCollectorError> {
        while self.script_index < self.lock_scripts.len() {
            let script = self.lock_scripts.get(self.script_index).unwrap();
            let got = Self::collect_live_cells_by_lock(
                &mut self.cell_collector,
                &mut self.buffer_inputs,
                &mut self.buffer_index,
                script,
            )?;
            self.script_index += 1;
            if got {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Iterator for InputIterator {
    type Item = Result<TransactionInput, CellCollectorError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.buffer_index < self.buffer_inputs.len() {
                let input = self.buffer_inputs.get(self.buffer_index).unwrap();
                self.buffer_index += 1;
                return Some(Ok(input.clone()));
            }

            let status = self.collect_live_cells();
            if status.is_err() {
                return Some(Err(status.unwrap_err()));
            }
            if !status.unwrap() {
                return None;
            }
        }
    }
}
