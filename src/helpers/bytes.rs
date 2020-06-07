//! WIP

/// Checks if a pointer can be a valid Rust reference.
fn ptr_ref_cast<T, U>(ptr: *const U) -> *const T {
    assert_ne!(ptr, std::ptr::null());
    assert_eq!(ptr as usize % std::mem::align_of::<T>(), 0);
    ptr as *const _
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

// TODO: Add IntoBytes

// TODO: Add error handling
pub unsafe trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> &Self;
    fn from_boxed(boxed: Box<[u8]>) -> Box<Self>;
}

unsafe impl FromBytes for [u16] {
    fn from_bytes(_bytes: &[u8]) -> &Self {
        unimplemented!()
    }

    fn from_boxed(boxed: Box<[u8]>) -> Box<[u16]> {
        assert_eq!(boxed.len() % std::mem::size_of::<u16>(), 0);
        assert_eq!(boxed.as_ptr() as usize % std::mem::align_of::<u16>(), 0);

        // Account for possibly fewer slice elements, e.g. [u16] will
        // have 2 times fewer elements than [u8] for the same bytes.
        let new_len = boxed.len() * std::mem::size_of::<u8>() / std::mem::size_of::<u16>();
        let ptr = Box::into_raw(boxed);

        #[allow(clippy::cast_ptr_alignment)] // alignment of pointer checked above
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u16, new_len) };

        unsafe { Box::from_raw(slice as *mut Self) }
    }
}

unsafe impl FromBytes for [u8] {
    fn from_bytes(bytes: &[u8]) -> &Self {
        bytes
    }
    fn from_boxed(boxed: Box<[u8]>) -> Box<Self> {
        boxed
    }
}

unsafe impl FromBytes for u32 {
    fn from_bytes(bytes: &[u8]) -> &Self {
        assert!(bytes.len() >= 4);

        let ptr = bytes.as_ptr();
        // NOTE: Assumes native endianness
        unsafe { &*ptr_ref_cast(ptr) }
    }

    fn from_boxed(_boxed: Box<[u8]>) -> Box<Self> {
        unimplemented!()
    }
}

unsafe impl FromBytes for winapi::shared::bcrypt::BCRYPT_KEY_LENGTHS_STRUCT {
    fn from_bytes(bytes: &[u8]) -> &Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());

        unsafe { &*ptr_ref_cast(bytes.as_ptr()) }
    }

    fn from_boxed(_boxed: Box<[u8]>) -> Box<Self> {
        unimplemented!()
    }
}
