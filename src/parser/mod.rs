use ckb_types::{H160, H256};
use std::str::FromStr;

use crate::Address;

pub mod packed;

pub trait Parser<T>: Sized {
    type Error;
    fn parse(input: T) -> Result<Self, Self::Error>;
}

macro_rules! impl_hash_parser {
    ($name:ident) => {
        impl Parser<&str> for $name {
            type Error = String;
            fn parse(input: &str) -> Result<Self, Self::Error> {
                let input = if input.starts_with("0x") || input.starts_with("0X") {
                    &input[2..]
                } else {
                    input
                };
                $name::from_str(input).map_err(|e| e.to_string())
            }
        }
    };
}

impl_hash_parser!(H160);
impl_hash_parser!(H256);

impl Parser<&str> for Address {
    type Error = String;

    fn parse(input: &str) -> Result<Self, Self::Error> {
        Address::from_str(input)
    }
}
