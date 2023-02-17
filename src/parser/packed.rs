use super::Parser;

use ckb_types::{packed::*, prelude::*, H256};

impl Parser<&str> for Vec<u8> {
    type Error = String;
    /// parse a hex string to a byte vector.
    /// # Arguments
    /// `input`: hex string start with 0x or not
    /// # Errors
    ///
    /// This function will return an error if fail to parse the string.
    fn parse(input: &str) -> Result<Self, Self::Error> {
        let input = if input.starts_with("0x") || input.starts_with("0X") {
            &input[2..]
        } else {
            input
        };
        let mut dst = vec![0u8; input.len() / 2];
        faster_hex::hex_decode(input.as_bytes(), &mut dst).map_err(|err| err.to_string())?;
        Ok(dst)
    }
}

impl Parser<&str> for ckb_types::packed::Bytes {
    type Error = String;
    fn parse(input: &str) -> Result<Self, Self::Error> {
        let bytes_vec = Vec::<u8>::parse(input)?;
        Ok(bytes_vec.pack())
    }
}

impl Parser<&str> for Byte32 {
    type Error = String;

    fn parse(input: &str) -> Result<Self, Self::Error> {
        let tx_hash = H256::parse(input)?;
        Byte32::from_slice(tx_hash.as_bytes()).map_err(|e| e.to_string())
    }
}

impl Parser<(&str, u32)> for ckb_types::packed::OutPoint {
    type Error = String;

    fn parse(input: (&str, u32)) -> Result<Self, Self::Error> {
        let tx_hash = H256::parse(input.0)?;

        Ok(OutPoint::new(
            Byte32::from_slice(tx_hash.as_bytes()).unwrap(),
            input.1,
        ))
    }
}
