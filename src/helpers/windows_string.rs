//! Owned Unicode, nul-aware and nul-terminated wide string
//!
//! Provides a lossless conversion for FFI APIs expecting an Unicode
//! nul-terminated string.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use winapi::shared::ntdef::LPCWSTR;

pub struct WindowsString {
    inner: Vec<u16>,
}

impl WindowsString {
    pub fn from_str(value: &str) -> Self {
        Self {
            inner: OsStr::new(value)
                .encode_wide()
                .chain(Some(0).into_iter())
                .collect(),
        }
    }

    pub fn from_ptr(ptr: *const u16) -> Self {
        unsafe {
            let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
            Self {
                inner: std::slice::from_raw_parts(ptr, len).to_vec(),
            }
        }
    }

    pub fn as_slice(&self) -> &[u16] {
        self.inner.as_slice()
    }

    pub fn as_ptr(&self) -> LPCWSTR {
        self.inner.as_ptr()
    }
}

impl ToString for WindowsString {
    fn to_string(&self) -> String {
        OsString::from_wide(&self.inner)
            .to_string_lossy()
            .as_ref()
            .to_string()
    }
}
