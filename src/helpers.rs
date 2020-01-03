use crate::{Error, Result};
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::{LPCWSTR, PUCHAR, UCHAR, ULONG, VOID};
use std::ffi::{OsStr, OsString};
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};

/// A wrapper type around `T` that also carries an inline dynamically-sized
/// buffer at the end.
///
/// Right now, this type is mostly used to act as a storage for values in `head`
/// (e.g. string buffer data).
///
/// Rust does not support ergonomically wide pointers to custom DSTs as of now,
/// so the runtime length of the buffer must be carried and used separately in
/// order to slice into the tail byte buffer.
#[repr(C)]
pub struct Tailed<T> {
    pub head: T,
    pub tail: [u8],
}

impl<T> Deref for Tailed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.head
    }
}

pub trait Handle {
    fn as_ptr(&self) -> BCRYPT_HANDLE;
    fn as_mut_ptr(&mut self) -> *mut BCRYPT_HANDLE;

    fn set_property<T: ?Sized>(&self, property: &str, value: &T) -> Result<()> {
        let property_str = WindowsString::from_str(property);
        unsafe {
            Error::check(
                BCryptSetProperty(
                    self.as_ptr(),
                    property_str.as_ptr(),
                    value as *const _ as PUCHAR,
                    std::mem::size_of_val(value) as ULONG,
                    0
                )
            )
        }
    }

    fn get_property<T>(&self, property: &str) -> Result<T> {
        let property = &WindowsString::from_str(property);

        let mut value = MaybeUninit::<T>::uninit();
        let (ptr, size) = (value.as_mut_ptr(), std::mem::size_of::<T>());

        unsafe {
            get_property_internal(self.as_ptr(), &property, ptr, size).map(|_| value.assume_init())
        }
    }

    /// Returns a pointer to the resulting dynamically-sized property (allocated
    /// on heap), along with the size of the extra buffer carried alongside `T`.
    fn get_property_unsized<T>(&self, property: &str) -> Result<(Box<Tailed<T>>, usize)> {
        let property = &WindowsString::from_str(property);
        // NOTE: Consider using Box<MaybeUninit<_>> instead of transmuting when
        // https://github.com/rust-lang/rust/issues/63291 is stabilized.
        let boxed_buf = get_property_unsized_raw(self.as_ptr(), property)?;
        let (len, sizeof) = (boxed_buf.len(), std::mem::size_of::<T>());
        // Make sure we allocated enough to at least hold `T` value (w/o tail).
        assert!(len >= sizeof);
        // SAFETY:
        // 1a. We expect the C API to write to the byte buffer a value of type `T`,
        // 1b. `Tailed` is `repr(C)` with first field being type T,
        // 1c. C standard mandates that pointer to the structure points to its
        // initial member (e.g. https://stackoverflow.com/a/11057233),
        // 1d. ...thus the first field is correctly initialized as `T` bytewise.
        // 2a. Second field is a dynamically-sized byte buffer,
        // 2b. which is of the same underlying type as the source buffer,
        // 2c. and `repr(C)` should guarantee the proper offset and alignment as
        //     if were a VLA,
        // 2d. ...thus a valid slice can be constructed with length (also
        //     returned here) supplied at run-time, so the type is valid.
        Ok((unsafe { std::mem::transmute(boxed_buf) }, len - sizeof))
    }
}

fn get_property_unsized_raw(handle: BCRYPT_HANDLE, property: &WindowsString) -> Result<Box<[u8]>> {
    let size = get_property_size(handle, property)?;
    let mut buf = vec![0u8; size].into_boxed_slice();
    let ptr = buf.as_mut_ptr();

    unsafe { get_property_internal(handle, property, ptr, size).map(|_| buf) }
}

fn get_property_size(handle: BCRYPT_HANDLE, property: &WindowsString) -> Result<usize> {
    unsafe { get_property_internal::<()>(handle, property, null_mut(), 0) }
}

unsafe fn get_property_internal<T>(
    handle: BCRYPT_HANDLE,
    property: &WindowsString,
    out: *mut T,
    size: usize,
) -> Result<usize> {
    let mut written = ULONG::default();
    Error::check(BCryptGetProperty(
        handle,
        property.as_ptr(),
        out as *mut UCHAR,
        size as ULONG,
        &mut written,
        0,
    ))
    .map(|_| written as usize)
}

pub struct AlgoHandle {
    handle: BCRYPT_ALG_HANDLE,
}

impl AlgoHandle {
    pub fn open(id: &str) -> Result<Self> {
        let mut handle = null_mut::<VOID>();
        unsafe {
            let id_str = WindowsString::from_str(id);
            Error::check(
                BCryptOpenAlgorithmProvider(
                    &mut handle,
                    id_str.as_ptr(),
                    null(),
                    0)
            ).map(|_| Self { handle })
        }
    }
}

impl Drop for AlgoHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { BCryptCloseAlgorithmProvider(self.handle, 0); }
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

impl WindowsString {
    pub fn from_str(value: &str) -> Self {
        Self { inner: OsStr::new(value).encode_wide().chain(Some(0).into_iter()).collect() }
    }

    pub fn from_ptr(ptr: *const u16) -> Self {
        unsafe {
            let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
            Self { inner: std::slice::from_raw_parts(ptr, len).to_vec() }
        }
    }

    pub fn as_slice(&self) -> &[u16] {
        self.inner.as_slice()
    }

    pub fn as_ptr(&self) -> LPCWSTR {
        self.inner.as_ptr()
    }

    pub fn to_str(&self) -> String {
        OsString::from_wide(&self.inner).to_string_lossy().as_ref().to_string()
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