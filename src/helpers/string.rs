use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use winapi::shared::ntdef::LPCWSTR;

pub struct WideCString {
    // Guaranteed to end with NUL
    inner: Vec<u16>,
}

impl WideCString {
    pub fn from_bytes_with_nul(val: Box<[u16]>) -> Self {
        if let Some(last) = val.iter().last() {
            assert_eq!(last, &0u16);
        }

        Self {
            inner: val.into_vec(),
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
                .chain(Some(0).into_iter())
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
