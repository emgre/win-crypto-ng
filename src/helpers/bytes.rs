//! WIP

/// Checks if a pointer can be a valid Rust reference.
fn _check_ref_safe<T>(ptr: *const T) -> Result<(), ()> {
    if ptr == std::ptr::null() || ptr as usize % std::mem::align_of::<&T>() != 0 {
        return Err(());
    }

    Ok(())
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

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

        // Account for possibly fewer slice elements, e.g. [u16] will
        // have 2 times fewer elements than [u8] for the same bytes.
        let new_len = boxed.len() * std::mem::size_of::<u8>() / std::mem::size_of::<u16>();
        let ptr = Box::leak(boxed);

        let slice = unsafe { std::slice::from_raw_parts_mut(ptr.as_mut_ptr(), new_len) };

        unsafe { Box::from_raw(slice as *mut [u8] as *mut [()] as *mut Self) }
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

        // TODO: This must be documented wrt endianess etc.
        unsafe { std::mem::transmute(bytes.as_ptr()) }
    }

    fn from_boxed(_boxed: Box<[u8]>) -> Box<Self> {
        unimplemented!()
    }
}

unsafe impl FromBytes for winapi::shared::bcrypt::BCRYPT_KEY_LENGTHS_STRUCT {
    fn from_bytes(bytes: &[u8]) -> &Self {
        // TODO: Check the size etc.
        unsafe { std::mem::transmute(bytes.as_ptr()) }
    }

    fn from_boxed(_boxed: Box<[u8]>) -> Box<Self> {
        unimplemented!()
    }
}
