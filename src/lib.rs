use doc_comment::doctest;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus;

use std::fmt;

pub mod buffer;
pub mod hash;
pub mod property;
pub mod random;
pub mod symmetric;

mod helpers;

// Compile and test the README
doctest!("../README.md");

/// Error type
///
/// These errors are a subset of [`NTSTATUS`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).
/// Only the values used by CNG are part of this enum.
#[derive(Clone, Copy, Debug, PartialOrd, PartialEq)]
pub enum Error {
    NotFound,
    InvalidParameter,
    NoMemory,
    BufferTooSmall,
    InvalidHandle,
    NotSupported,
    AuthTagMismatch,
    InvalidBufferSize,

    Unknown(NTSTATUS),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

impl Error {
    fn check(status: NTSTATUS) -> Result<()> {
        match status {
            ntstatus::STATUS_SUCCESS => Ok(()),
            ntstatus::STATUS_NOT_FOUND => Err(Error::NotFound),
            ntstatus::STATUS_INVALID_PARAMETER => Err(Error::InvalidParameter),
            ntstatus::STATUS_NO_MEMORY => Err(Error::NoMemory),
            ntstatus::STATUS_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
            ntstatus::STATUS_INVALID_HANDLE => Err(Error::InvalidHandle),
            ntstatus::STATUS_NOT_SUPPORTED => Err(Error::NotSupported),
            ntstatus::STATUS_AUTH_TAG_MISMATCH => Err(Error::AuthTagMismatch),
            ntstatus::STATUS_INVALID_BUFFER_SIZE => Err(Error::InvalidBufferSize),
            value => Err(Error::Unknown(value)),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
