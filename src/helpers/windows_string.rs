//! Owned Unicode, nul-aware and nul-terminated wide string
//!
//! Provides a lossless conversion for FFI APIs expecting an Unicode
//! nul-terminated string.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use winapi::shared::ntdef::LPCWSTR;

/// C-string terminator.
const NUL: u16 = 0;

/// Owned, wide variant of the `CString` type.
#[derive(Debug, PartialEq)]
pub struct WindowsString {
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

impl WindowsString {
    pub(crate) fn new() -> Self {
        WindowsString { inner: Vec::new() }
    }

    pub fn from_bytes_with_nul(val: Cow<'_, [u16]>) -> Result<Self, FromBytesWithNulError> {
        match val.iter().position(|&x| x == NUL) {
            Some(idx) if idx == val.len() - 1 => Ok(Self {
                inner: val.into_owned(),
            }),
            None => Err(FromBytesWithNulError::NotTerminated),
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

impl ToString for WindowsString {
    fn to_string(&self) -> String {
        let without_nul = &self.inner[..self.inner.len().saturating_sub(1)];

        OsString::from_wide(without_nul)
            .to_string_lossy()
            .as_ref()
            .to_string()
    }
}

impl From<&str> for WindowsString {
    fn from(value: &str) -> WindowsString {
        Self {
            inner: OsStr::new(value)
                .encode_wide()
                .chain(Some(NUL).into_iter())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_with_nul() {
        assert_eq!(
            WindowsString::from_bytes_with_nul([NUL].to_vec().into()),
            Ok(WindowsString { inner: vec![NUL] })
        );
        assert_eq!(
            WindowsString::from_bytes_with_nul([97, 110, NUL][..].into()),
            Ok(WindowsString {
                inner: vec![97, 110, NUL]
            })
        );

        assert_eq!(
            WindowsString::from_bytes_with_nul([].to_vec().into()),
            Err(FromBytesWithNulError::NotTerminated)
        );
        assert_eq!(
            WindowsString::from_bytes_with_nul([97, 110].to_vec().into()),
            Err(FromBytesWithNulError::NotTerminated)
        );

        assert_eq!(
            WindowsString::from_bytes_with_nul([97, NUL, 110].to_vec().into()),
            Err(FromBytesWithNulError::InteriorNul { index: 1 })
        );
        assert_eq!(
            WindowsString::from_bytes_with_nul([NUL, NUL, 110].to_vec().into()),
            Err(FromBytesWithNulError::InteriorNul { index: 0 })
        );
        assert_eq!(
            WindowsString::from_bytes_with_nul([97, NUL, NUL].to_vec().into()),
            Err(FromBytesWithNulError::InteriorNul { index: 1 })
        );
    }

    #[test]
    fn string() {
        assert_eq!(
            WindowsString::from("abc"),
            WindowsString {
                inner: vec![97, 98, 99, NUL]
            }
        );
        assert_eq!(
            WindowsString::from("🦀"),
            WindowsString {
                inner: vec![0xD83E, 0xDD80, NUL]
            }
        );

        assert_eq!(
            WindowsString::from("abc").as_slice_with_nul(),
            &[97, 98, 99, NUL]
        );
        assert_eq!(
            WindowsString::from("🦀").as_slice_with_nul(),
            &[0xD83E, 0xDD80, NUL]
        );

        assert_eq!(WindowsString::from("abc").to_string().as_str(), "abc");
        assert_eq!(WindowsString::from("abc").to_string().len(), 3);
        assert_eq!(WindowsString::from("🦀").to_string().as_str(), "🦀");
        assert_eq!(WindowsString::from("🦀").to_string().len(), 4);
    }
}
