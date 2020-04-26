use crate::{Error, Result};
use std::ffi::{OsStr, OsString};
use std::mem::MaybeUninit;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::{LPCWSTR, PUCHAR, UCHAR, ULONG, VOID};

pub trait Handle {
    fn as_ptr(&self) -> BCRYPT_HANDLE;
    fn as_mut_ptr(&mut self) -> *mut BCRYPT_HANDLE;

    fn set_property<T: ?Sized>(&self, property: &str, value: &T) -> Result<()> {
        let property_str = WindowsString::from_str(property);
        unsafe {
            Error::check(BCryptSetProperty(
                self.as_ptr(),
                property_str.as_ptr(),
                value as *const _ as PUCHAR,
                std::mem::size_of_val(value) as ULONG,
                0,
            ))
        }
    }

    fn get_property<T>(&self, property: &str) -> Result<T> {
        let property_str = WindowsString::from_str(property);
        let mut value = MaybeUninit::<T>::uninit();
        let mut result_len = MaybeUninit::<ULONG>::uninit();
        unsafe {
            Error::check(BCryptGetProperty(
                self.as_ptr(),
                property_str.as_ptr(),
                value.as_mut_ptr() as *mut UCHAR,
                std::mem::size_of::<T>() as ULONG,
                result_len.as_mut_ptr(),
                0,
            ))
            .map(|_| value.assume_init())
        }
    }
}

pub struct AlgoHandle {
    handle: BCRYPT_ALG_HANDLE,
}

impl AlgoHandle {
    pub fn open(id: &str) -> Result<Self> {
        let mut handle = null_mut::<VOID>();
        unsafe {
            let id_str = WindowsString::from_str(id);
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

pub struct WindowsString {
    inner: Vec<u16>,
}

#[allow(dead_code)]
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

/*pub fn list_algorithms() {
    let mut alg_count = MaybeUninit::<ULONG>::uninit();
    let mut alg_list = MaybeUninit::<*mut BCRYPT_ALGORITHM_IDENTIFIER>::uninit();
    unsafe {
        BCryptEnumAlgorithms(
            BCRYPT_HASH_OPERATION,
            alg_count.as_mut_ptr(),
            alg_list.as_mut_ptr(),
            0
        );

        for i in 0..alg_count.assume_init() {
            let name = WindowsString::from_ptr((*alg_list.assume_init().offset(i as isize)).pszName);
            println!("{}", name.to_str());
        }
    }
}*/
