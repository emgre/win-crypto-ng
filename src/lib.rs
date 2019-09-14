use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus;

pub mod buffer;
pub mod symmetric;

mod helpers;

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

impl Error {
    fn check(status: NTSTATUS) -> std::result::Result<(), Self> {
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