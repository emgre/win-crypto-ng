use crate::property::Property;
use crate::{Error, Result};
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::{LPCWSTR, PUCHAR, ULONG, VOID};

mod bytes;
pub use bytes::{AsBytes, FromBytes, Pod};
mod windows_string;
pub use windows_string::WindowsString;

pub trait Handle {
    fn as_ptr(&self) -> BCRYPT_HANDLE;
    fn as_mut_ptr(&mut self) -> *mut BCRYPT_HANDLE;

    fn set_property<T: Property>(&self, value: &T::Value) -> Result<()> {
        let property = WindowsString::from(T::IDENTIFIER);
        unsafe {
            Error::check(BCryptSetProperty(
                self.as_ptr(),
                property.as_ptr(),
                value as *const _ as PUCHAR,
                std::mem::size_of_val(value) as ULONG,
                0,
            ))
        }
    }

    fn get_property<T: Property>(&self) -> Result<T::Value>
    where
        T::Value: Sized,
    {
        let property = WindowsString::from(T::IDENTIFIER);
        // Determine how much data we need to allocate for the return value
        let mut size = get_property_size(self.as_ptr(), property.as_ptr())?;
        assert_eq!(
            size as usize,
            std::mem::size_of::<T::Value>(),
            "CNG property needs to allocate extra data in sized get_property variant"
        );

        // We are not expected to allocate extra trailing data, so construct the
        // value and return it inline (especially important for `Copy` types)
        let mut result = MaybeUninit::<T::Value>::uninit();

        unsafe {
            Error::check(BCryptGetProperty(
                self.as_ptr(),
                property.as_ptr(),
                result.as_mut_ptr() as *mut _,
                size,
                &mut size,
                0,
            ))?;
        }
        // SAFETY: Verify that the API call has written the exact amount of
        // bytes, so that we can conclude it's been entirely initialized
        assert_eq!(size as usize, std::mem::size_of::<T::Value>());

        Ok(unsafe { result.assume_init() })
    }

    fn get_property_unsized<T: Property>(&self) -> Result<Box<T::Value>> {
        let property = WindowsString::from(T::IDENTIFIER);

        let mut size = get_property_size(self.as_ptr(), property.as_ptr())?;
        let mut result = vec![0u8; size as usize].into_boxed_slice();

        unsafe {
            Error::check(BCryptGetProperty(
                self.as_ptr(),
                property.as_ptr(),
                result.as_mut_ptr(),
                size,
                &mut size,
                0,
            ))?;
        }
        // SAFETY: Verify that the API call has written the exact amount of
        // bytes, so that we can conclude it's been entirely initialized
        assert_eq!(size as usize, result.len());

        Ok(FromBytes::from_boxed(result))
    }
}

fn get_property_size(handle: BCRYPT_HANDLE, prop: LPCWSTR) -> Result<ULONG> {
    let mut size: ULONG = 0;
    unsafe {
        Error::check(BCryptGetProperty(handle, prop, null_mut(), 0, &mut size, 0))?;
    }
    Ok(size)
}

pub struct AlgoHandle {
    handle: BCRYPT_ALG_HANDLE,
}

impl AlgoHandle {
    pub fn open(id: &str) -> Result<Self> {
        let mut handle = null_mut::<VOID>();
        unsafe {
            let id_str = WindowsString::from(id);
            Error::check(BCryptOpenAlgorithmProvider(
                &mut handle,
                id_str.as_ptr(),
                null(),
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
        Self { handle: null_mut() }
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
