//! CNG object handles.

use core::ptr;

use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::VOID;

use crate::helpers::WideCString;
use crate::{Error, Result};

pub trait Handle {
    fn as_ptr(&self) -> BCRYPT_HANDLE;
    fn as_mut_ptr(&mut self) -> *mut BCRYPT_HANDLE;
}

/// Algorithm provider handle
pub struct AlgoHandle {
    handle: BCRYPT_ALG_HANDLE,
}

impl AlgoHandle {
    pub fn open(id: &str) -> Result<Self> {
        let mut handle = ptr::null_mut::<VOID>();
        unsafe {
            let id_str = WideCString::from(id);
            Error::check(BCryptOpenAlgorithmProvider(
                &mut handle,
                id_str.as_ptr(),
                ptr::null(),
                0,
            ))
            .map(|_| Self { handle })
        }
    }
}

impl Drop for AlgoHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.handle, 0);
            }
        }
    }
}

impl Handle for AlgoHandle {
    fn as_ptr(&self) -> BCRYPT_ALG_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_ALG_HANDLE {
        &mut self.handle
    }
}

/// Cryptographic key handle
pub struct KeyHandle {
    pub(crate) handle: BCRYPT_KEY_HANDLE,
}

impl KeyHandle {
    pub fn new() -> Self {
        Self {
            handle: ptr::null_mut(),
        }
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptDestroyKey(self.handle);
            }
        }
    }
}

impl Default for KeyHandle {
    fn default() -> Self {
        KeyHandle::new()
    }
}

impl Handle for KeyHandle {
    fn as_ptr(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_KEY_HANDLE {
        &mut self.handle
    }
}
