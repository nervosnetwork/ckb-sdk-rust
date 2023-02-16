use super::Parser;

use ckb_types::prelude::*;

impl Parser for Vec<u8> {
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

impl Parser for ckb_types::packed::Bytes {
    type Error = String;
    fn parse(input: &str) -> Result<Self, Self::Error> {
        let bytes_vec = Vec::<u8>::parse(input)?;
        Ok(bytes_vec.pack())
    }
}
