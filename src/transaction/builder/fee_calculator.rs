use ckb_types::core::FeeRate;

use crate::{core::TransactionBuilder, tx_builder::bytes_per_cycle};

pub struct FeeCalculator {
    fee_rate: u64,
}

impl FeeCalculator {
    pub fn new(fee_rate: u64) -> Self {
        Self { fee_rate }
    }
    pub fn fee(&self, weight: u64) -> u64 {
        let fee_rate = FeeRate::from_u64(self.fee_rate);
        fee_rate.fee(weight).as_u64()
    }

    pub fn fee_with_cycle(&self, tx_size: u64, cycles: u64) -> u64 {
        let tx_size = tx_size.max((cycles as f64 * bytes_per_cycle()) as u64);
        self.fee(tx_size)
    }

    pub fn fee_with_tx_data(&self, tx_data: &TransactionBuilder) -> u64 {
        let tx_size = tx_data
            .clone()
            .build()
            .data()
            .as_reader()
            .serialized_size_in_block();
        self.fee(tx_size as u64)
    }
}
