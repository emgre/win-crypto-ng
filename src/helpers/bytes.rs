//! Byte fiddling utilities.
//!
//! Define [FromBytes] and [AsBytes] traits, which allow for safe data conversion
//! assuming the data meets certain layout-specific restrictions.
//! See documentation for [AsBytes] for more details.
//!
//! These traits are implemented automatically for sized data structures if they
//! implement [Pod] trait.

use core::alloc::Layout;
use core::{mem, ptr, slice};

/// Checks if a pointer can be a valid Rust reference.
pub(crate) fn ptr_ref_cast<T, U>(ptr: *const U) -> *const T {
    assert_ne!(ptr, ptr::null());
    assert_eq!(ptr as usize % mem::align_of::<T>(), 0);
    ptr as *const _
}

/// Attempts to cast the pointer to byte slice to a pointer of a generic slice.
/// Adjusts the length metadata as required.
/// Panics if the pointer is null.
///
/// # Safety
///
pub unsafe fn ptr_slice_cast<T>(ptr: *const [u8]) -> *const [T] {
    assert_ne!(ptr as *const (), ptr::null());
    // SAFETY: [u8] is 1-byte aligned so no need to check that before deref
    let len = (&*ptr).len();

    let new_len = len * mem::size_of::<u8>() / mem::size_of::<T>();

    let slice = slice::from_raw_parts(ptr as *const T, new_len);
    slice as *const _ as *const [T]
}

/// Marker trait for types that can be safely converted to bytes.
///
/// # Safety
/// Implementee MUST be `#[repr(C)]` and:
/// - not contain any pointer types that are dereferenced,
/// - itself or any of its members MUST NOT implement a custom destructor,
/// - be inhabited,
/// - allow any bit pattern
///
/// ## Layout
/// Implementee also needs to be layout-compatible with [u8].
pub unsafe trait AsBytes {
    fn as_bytes(&self) -> &[u8] {
        let len = mem::size_of_val(self);
        // SAFETY: Guaranteed by documented unsafe impl invariants.
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, len) }
    }

    fn into_bytes(self: Box<Self>) -> Box<[u8]> {
        let len = mem::size_of_val(self.as_ref());
        // SAFETY: Guaranteed by documented unsafe impl invariants of `AsBytes`.
        let ptr = Box::into_raw(self);
        unsafe {
            let slice = slice::from_raw_parts_mut(ptr as *mut _ as *mut u8, len);

            Box::from_raw(slice)
        }
    }
}

/// Marker trait for types that can be safely converted to bytes.
pub unsafe trait FromBytes {
    /// Specified the minimum layout requirements for the allocation:
    /// - is at least as big as `min_layout().size()`
    /// - reference/pointer is at least as aligned as `min_layout().align()`
    ///
    /// For DSTs, final size should be exactly the same as the allocation's.
    unsafe fn min_layout() -> std::alloc::Layout;

    fn from_bytes(bytes: &[u8]) -> &Self {
        let min_layout = unsafe { Self::min_layout() };
        // Make sure the allocation meets the expected layout requirements
        assert!(bytes.len() >= min_layout.size(), 0);
        assert_eq!(bytes.as_ptr() as usize % min_layout.align(), 0);

        let old_size = mem::size_of_val(bytes);
        // SAFETY: It's up to the implementer to provide a sound
        // `Self::ptr_cast` implementation.
        let new = unsafe { &*Self::ptr_cast(bytes) };

        let new_size = mem::size_of_val(new);
        // Make sure we don't leak data/forget any information when adjusting
        // the (possibly wide) pointer
        assert_eq!(old_size, new_size);

        new
    }

    fn from_boxed(boxed: Box<[u8]>) -> Box<Self> {
        let min_layout = unsafe { Self::min_layout() };
        // Make sure the allocation meets the expected layout requirements
        assert!(boxed.len() >= min_layout.size(), 0);
        assert_eq!(boxed.as_ptr() as usize % min_layout.align(), 0);

        let old_size = mem::size_of_val(boxed.as_ref());

        let ptr = Box::into_raw(boxed);
        // SAFETY: It's up to the implementer to provide a sound
        // `Self::ptr_cast` implementation.
        let new = unsafe { Box::from_raw(Self::ptr_cast(ptr) as *mut Self) };

        let new_size = mem::size_of_val(new.as_ref());
        // Make sure we don't leak data/forget any information when adjusting
        // the (possibly wide) pointer
        assert_eq!(old_size, new_size);

        new
    }

    #[doc(hidden)]
    unsafe fn ptr_cast(source: *const [u8]) -> *const Self;
}

unsafe impl FromBytes for [u16] {
    unsafe fn min_layout() -> Layout {
        // Allow for empty slices but require correct alignment
        Layout::from_size_align_unchecked(0, mem::align_of::<u16>())
    }
    unsafe fn ptr_cast(source: *const [u8]) -> *const Self {
        ptr_slice_cast(source)
    }
}

unsafe impl FromBytes for [u8] {
    unsafe fn min_layout() -> Layout {
        // Allow for empty slices but require correct alignment
        Layout::from_size_align_unchecked(0, mem::align_of::<u8>())
    }
    unsafe fn ptr_cast(source: *const [u8]) -> *const [u8] {
        source
    }

    fn from_bytes(bytes: &[u8]) -> &Self {
        bytes
    }
    fn from_boxed(boxed: Box<[u8]>) -> Box<Self> {
        boxed
    }
}

/// Marker trait that can be safely converted from and into bytes.
///
/// Automatically implements [AsBytes] and [FromBytes].
/// # Safety
/// See documentation for [AsBytes] for safety invariants that need to be upheld.
pub unsafe trait Pod: Sized {}

unsafe impl<T> AsBytes for T where T: Pod {}
unsafe impl<T> FromBytes for T
where
    T: Pod,
{
    unsafe fn min_layout() -> Layout {
        Layout::new::<Self>()
    }

    unsafe fn ptr_cast(ptr: *const [u8]) -> *const Self {
        ptr_ref_cast(ptr as *const ())
    }
}

use winapi::shared::bcrypt;
unsafe impl Pod for u32 {} // Ignores endianness
unsafe impl Pod for bcrypt::BCRYPT_KEY_LENGTHS_STRUCT {}

unsafe impl Pod for bcrypt::BCRYPT_DH_PARAMETER_HEADER {}
unsafe impl Pod for bcrypt::BCRYPT_DSA_PARAMETER_HEADER {}
unsafe impl Pod for bcrypt::BCRYPT_DSA_PARAMETER_HEADER_V2 {}

unsafe impl Pod for bcrypt::BCRYPT_KEY_BLOB {}
unsafe impl Pod for bcrypt::BCRYPT_DH_KEY_BLOB {}
unsafe impl Pod for bcrypt::BCRYPT_DSA_KEY_BLOB {}
unsafe impl Pod for bcrypt::BCRYPT_DSA_KEY_BLOB_V2 {}
unsafe impl Pod for bcrypt::BCRYPT_ECCKEY_BLOB {}
unsafe impl Pod for bcrypt::BCRYPT_RSAKEY_BLOB {}
