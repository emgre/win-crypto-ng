#![allow(
    // We're running Clippy across 1.37, stable, beta and nightly, sometimes the
    // older versions don't recognize lints that are warned against in the newer
    // versions
    clippy::unknown_clippy_lints,
    // Requires a nightly-only feature: https://github.com/rust-lang/rust/issues/54883
    clippy::unnested_or_patterns,
)]

use doc_comment::doctest;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus;

use std::fmt;

pub mod asymmetric;
pub mod buffer;
mod handle;
pub mod hash;
pub mod key;
pub mod property;
pub mod random;
pub mod signature;
pub mod symmetric;

pub mod helpers;

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
    InvalidSignature,
    NoMemory,
    BufferTooSmall,
    InvalidHandle,
    NotSupported,
    AuthTagMismatch,
    InvalidBufferSize,
    Unsuccessful,
    RequestOutOfSequence,

    BadData,

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
            ntstatus::STATUS_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
            ntstatus::STATUS_INVALID_HANDLE => Err(Error::InvalidHandle),
            ntstatus::STATUS_INVALID_SIGNATURE => Err(Error::InvalidSignature),
            ntstatus::STATUS_NOT_SUPPORTED => Err(Error::NotSupported),
            ntstatus::STATUS_AUTH_TAG_MISMATCH => Err(Error::AuthTagMismatch),
            ntstatus::STATUS_INVALID_BUFFER_SIZE => Err(Error::InvalidBufferSize),
            ntstatus::STATUS_REQUEST_OUT_OF_SEQUENCE => Err(Error::RequestOutOfSequence),
            ntstatus::STATUS_NO_MEMORY | winapi::shared::winerror::NTE_NO_MEMORY => {
                Err(Error::NoMemory)
            }
            ntstatus::STATUS_DATA_ERROR | winapi::shared::winerror::NTE_BAD_DATA => {
                Err(Error::BadData)
            }
            ntstatus::STATUS_UNSUCCESSFUL => Err(Error::Unsuccessful),
            value => Err(Error::Unknown(value)),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
