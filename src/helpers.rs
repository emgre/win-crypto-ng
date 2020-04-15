use crate::property::Property;
use crate::{Error, Result};
use std::ffi::{OsStr, OsString};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::{LPCWSTR, PUCHAR, ULONG, VOID};

pub trait Handle {
    fn as_ptr(&self) -> BCRYPT_HANDLE;
    fn as_mut_ptr(&mut self) -> *mut BCRYPT_HANDLE;

    fn set_property<T: Property>(&self, value: &T::Value) -> Result<()> {
        let property = WindowsString::from_str(T::IDENTIFIER);
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

    fn get_property<T: Property>(&self) -> Result<MaybeUnsized<T::Value>>
    where
        T::Value: Sized,
    {
        let property = WindowsString::from_str(T::IDENTIFIER);
        // Determine how much data we need to allocate for the return value
        let mut size = get_property_size(self.as_ptr(), property.as_ptr())?;

        // We are not expected to allocate extra trailing data, so construct the
        // value and return it inline (especially important for `Copy` types)
        Ok(if size as usize == std::mem::size_of::<T::Value>() {
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

            MaybeUnsized::Inline(unsafe { result.assume_init() })
        } else {
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
            // Assert that we actually wrote as many bytes as we were asked to
            // allocate
            assert_eq!(result.len(), size as usize);

            MaybeUnsized::Unsized(unsafe { TypedBlob::from_box(result) })
        })
    }

    fn get_property_unsized<T: Property>(&self) -> Result<TypedBlob<T::Value>> {
        let property = WindowsString::from_str(T::IDENTIFIER);

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

        Ok(unsafe { TypedBlob::from_box_unsized(result) })
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

/// A typed view into an opaque blob of heap-allocated bytes.
pub struct TypedBlob<T: ?Sized> {
    allocation: Box<[u8]>,
    marker: PhantomData<T>,
}

impl<T: ?Sized> std::fmt::Debug for TypedBlob<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TypedBlob({}, {:?})", std::any::type_name::<T>(), self.allocation)
    }
}

impl<T: ?Sized> Into<Box<[u8]>> for TypedBlob<T> {
    fn into(self) -> Box<[u8]> {
        self.allocation
    }
}

#[allow(dead_code)]
impl<T: ?Sized> TypedBlob<T> {
    pub fn into_inner(self) -> Box<[u8]> {
        self.into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.allocation
    }
}

impl<T: Sized> Deref for TypedBlob<T> {
    type Target = T;

    /// Creates a typed reference to the underlying data structure backed by the
    /// source bytes.
    fn deref(&self) -> &T {
        // SAFETY: The only way to create this struct with sized `T` is via
        // `TypedBlob::from_box`, where:
        // 1. the caller has to prove that the data is of correct format,
        // 2. we check that the resulting reference will be well-aligned, and
        // 3. the allocation is big enough to hold a value of type `T`.
        unsafe { &*(self.allocation.as_ptr() as *const T) }
    }
}

impl<T, U: AsRef<T>> AsRef<T> for TypedBlob<U> {
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

#[allow(dead_code)]
impl<T: Sized> TypedBlob<T> {
    /// Converts an opaque blob of bytes into a typed blob asserting that the
    /// raw bytes correspond in shape to value of type `T`.
    ///
    /// # Panics
    /// This function panicks if the allocation is not big enough to hold a
    /// value of type `T` or if the backing pointee alignment is not compatible
    /// with that of `T`.
    pub unsafe fn from_box(allocation: Box<[u8]>) -> Self {
        assert!(allocation.len() >= std::mem::size_of::<T>());
        // Verify that we can produce a valid reference (which are required to
        // always be well-aligned).
        assert_eq!(allocation.as_ptr() as usize % std::mem::align_of::<T>(), 0);

        TypedBlob {
            allocation,
            marker: PhantomData,
        }
    }
}

impl<T> AsRef<[T]> for TypedBlob<[T]> {
    /// Creates a typed reference to the underlying data structure backed by the
    /// source bytes.
    ///
    /// # Panics
    /// This function panicks if the allocation does not fit exactly a certain
    /// count of `T`-sized values.
    fn as_ref(&self) -> &[T] {
        // SAFETY: The only way to create this struct with *unsized* `T` is via
        // `TypedBlob::from_box_unsized`, where:
        // 1. the caller has to prove that the data is of correct format,
        // 2. we check that the resulting reference will be well-aligned.

        // Ensure that allocation can hold exactly N elements of type T - we
        // disallow any trailing bytes outside of the resulting `[T]` slice.
        assert_eq!(self.allocation.len() % std::mem::size_of::<T>(), 0);

        unsafe {
            std::slice::from_raw_parts(
                self.allocation.as_ptr() as *const T,
                // Account for possibly fewer slice elements, e.g. [u16] will
                // have 2 times fewer elements than [u8] for the same bytes.
                self.allocation.len() * std::mem::size_of::<u8>() / std::mem::size_of::<T>(),
            )
        }
    }
}

#[allow(dead_code)]
impl<T: ?Sized> TypedBlob<T> {
    /// Converts an opaque blob of bytes into a typed blob asserting that the
    /// raw bytes correspond in shape to value of type `T`.
    ///
    /// **NOTE: Only slices are supported at the moment.** To uphold safety
    /// invariants, this type can only be safely dereferenced for slice types,
    /// as long as the allocation size matches the slice layout.
    ///
    /// # Panics
    /// This function panicks if the backing pointee alignment is not compatible
    /// with that of `&T`.
    ///
    /// # Safety
    /// The caller has to guarantee that the type of is of correct layout.
    /// For slices (`[T]`), the memory allocation should contain *exactly* given
    /// N elements of type T.
    pub unsafe fn from_box_unsized(allocation: Box<[u8]>) -> Self {
        // Verify that we can produce a valid reference (which are required to
        // always be well-aligned).
        assert_eq!(allocation.as_ptr() as usize % std::mem::align_of::<&T>(), 0);

        TypedBlob {
            allocation,
            marker: PhantomData,
        }
    }
}

/// Helper struct that contains the data either inline or in a heap allocation.
/// Allows to skip allocation for sufficiently small data or when the size is
/// static.
pub enum MaybeUnsized<T> {
    Inline(T),
    Unsized(TypedBlob<T>),
}

impl<T: Copy> MaybeUnsized<T> {
    pub fn copied(&self) -> T {
        *self.as_ref()
    }
}

impl<T> AsRef<T> for MaybeUnsized<T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Inline(value) => &value,
            Self::Unsized(blob) => &blob,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_blob() {
        #[repr(C)]
        #[derive(Debug)]
        struct Inner {
            first: u16,
            second: u32,
        }

        let bytes = vec![0x1, 0x1, 0xFF, 0xFF, 0x2, 0x2, 0x2, 0x2, 0xDE, 0xDE].into_boxed_slice();
        let typed = unsafe { TypedBlob::<Inner>::from_box(bytes.clone()) };
        assert_eq!(typed.first, 0x0101);
        assert_eq!(typed.second, 0x02020202);
        let typed = unsafe { TypedBlob::<[u8; 10]>::from_box(bytes.clone()) };
        assert_eq!(&*typed, bytes.as_ref());

        let typed = unsafe { TypedBlob::<[u8]>::from_box_unsized(bytes.clone()) };
        assert_eq!(typed.as_ref(), bytes.as_ref());
        let typed = unsafe { TypedBlob::<[u16]>::from_box_unsized(bytes.clone()) };
        assert_eq!(typed.as_ref(), &[0x0101, 0xFFFF, 0x0202, 0x0202, 0xDEDE]);

        assert!(std::panic::catch_unwind(|| {
            // Allocation is too small
            unsafe { TypedBlob::<[[u8; 1000]; 1]>::from_box(bytes.clone()) }
        })
        .is_err());
    }
}
