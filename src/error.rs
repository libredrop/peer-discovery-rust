use async_std::io;
use err_derive::Error;
use std::str::Utf8Error;

#[derive(Debug, Error)]
/// `DiscoveryMsg` deserialization error.
pub enum DeserializeError {
    /// Not enough bytes to parse some specific field.
    #[error(
        display = "Not enough bytes to parse field '{}'. Expected {}, \
                   remaining {} at position {}.",
        _0,
        _1,
        _2,
        _3
    )]
    NotEnoughBytes(String, usize, usize, usize),
    #[error(display = "Failed to parse UTF-8 field '{}'. Error: {}", _0, _1)]
    InvalidUtf8(String, Utf8Error),
    #[error(display = "Unknown transport protocol: {}", _0)]
    UnknownProtocol(u8),
}

#[derive(Debug, Error)]
/// Peer discovery errors.
pub enum Error {
    /// Too long data item key.
    #[error(display = "Too long item key. Max length is 255 bytes.")]
    TooLongKey,
    /// Data item limit reached - 255.
    #[error(display = "Data item limit reached - 255.")]
    TooManyDataItems,
    /// Deserialization error.
    #[error(display = "Failed to deserialize DiscoveryMsg from bytes: {}", _0)]
    Deserialize(DeserializeError),
    /// Socket related I/O error.
    #[error(display = "I/O failure: {}", _0)]
    Io(io::Error),
}

impl From<DeserializeError> for Error {
    fn from(e: DeserializeError) -> Self {
        Error::Deserialize(e)
    }
}
