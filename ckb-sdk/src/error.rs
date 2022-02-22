use std::io;

use failure::Fail;

use crate::wallet::KeyStoreError;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "IO error: {}", _0)]
    Io(io::Error),
    #[fail(display = "KeyStore error: {}", _0)]
    KeyStore(KeyStoreError),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Other(err)
    }
}
