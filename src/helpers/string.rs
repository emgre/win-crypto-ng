//! Owned Unicode, nul-aware and nul-terminated wide string
//!
//! Provides a lossless conversion for FFI APIs expecting an Unicode
//! nul-terminated string.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use winapi::shared::ntdef::LPCWSTR;

/// C-string terminator.
const NUL: u16 = 0;

/// Owned, wide variant of the `CString` type.
#[derive(Debug, PartialEq)]
pub struct WideCString {
    // Guaranteed to end with NUL
    inner: Vec<u16>,
}

/// Whether the input bytes were not terminated with NUL or one was found but
/// not at the end.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FromBytesWithNulError {
    NotTerminated,
    InteriorNul { index: usize },
}

impl fmt::Display for FromBytesWithNulError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTerminated => f.write_str("not terminated with NUL byte"),
            Self::InteriorNul { index } => f.write_fmt(format_args!(
                "NUL byte found not at the end (index: {})",
                index
            )),
        }
    }
}

impl std::error::Error for FromBytesWithNulError {}

impl WideCString {
    pub fn from_bytes_with_nul(val: Box<[u16]>) -> Result<Self, FromBytesWithNulError> {
        match val.iter().position(|&x| x == NUL) {
            None => Err(FromBytesWithNulError::NotTerminated),
            Some(idx) if idx == val.len() - 1 => Ok(Self { inner: val.into() }),
            Some(index) => Err(FromBytesWithNulError::InteriorNul { index }),
        }
    }

    pub fn as_slice_with_nul(&self) -> &[u16] {
        self.inner.as_slice()
    }

    pub fn as_ptr(&self) -> LPCWSTR {
        self.inner.as_ptr()
    }
}

impl From<&str> for WideCString {
    fn from(value: &str) -> WideCString {
        Self {
            inner: OsStr::new(value)
                .encode_wide()
                .chain(Some(NUL).into_iter())
                .collect(),
        }
    }
}

impl ToString for WideCString {
    fn to_string(&self) -> String {
        let without_nul = &self.inner[..self.inner.len().saturating_sub(1)];

        OsString::from_wide(without_nul)
            .to_string_lossy()
            .as_ref()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_with_nul() {
        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([NUL])),
            Ok(WideCString { inner: vec![NUL] })
        );
        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([97, 110, NUL])),
            Ok(WideCString {
                inner: vec![97, 110, NUL]
            })
        );

        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([])),
            Err(FromBytesWithNulError::NotTerminated)
        );
        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([97, 110])),
            Err(FromBytesWithNulError::NotTerminated)
        );

        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([97, NUL, 110])),
            Err(FromBytesWithNulError::InteriorNul { index: 1 })
        );
        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([NUL, NUL, 110])),
            Err(FromBytesWithNulError::InteriorNul { index: 0 })
        );
        assert_eq!(
            WideCString::from_bytes_with_nul(Box::new([97, NUL, NUL])),
            Err(FromBytesWithNulError::InteriorNul { index: 1 })
        );
    }

    #[test]
    fn string() {
        assert_eq!(
            WideCString::from("abc"),
            WideCString {
                inner: vec![97, 98, 99, NUL]
            }
        );
        assert_eq!(
            WideCString::from("🦀"),
            WideCString {
                inner: vec![0xD83E, 0xDD80, NUL]
            }
        );

        assert_eq!(
            WideCString::from("abc").as_slice_with_nul(),
            &[97, 98, 99, NUL]
        );
        assert_eq!(
            WideCString::from("🦀").as_slice_with_nul(),
            &[0xD83E, 0xDD80, NUL]
        );

        assert_eq!(WideCString::from("abc").to_string().as_str(), "abc");
        assert_eq!(WideCString::from("abc").to_string().len(), 3);
        assert_eq!(WideCString::from("🦀").to_string().as_str(), "🦀");
        assert_eq!(WideCString::from("🦀").to_string().len(), 4);
    }
}
