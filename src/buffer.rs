use zeroize::Zeroize;
use std::fmt::{Debug, Error, Formatter};

/// Secure buffer implementation.
///
/// On creation, the buffer is initialized with zeroes and on destruction,
/// its content is **always** set to `0` before being released.
#[derive(PartialOrd, PartialEq)]
pub struct Buffer {
    inner: Vec<u8>,
}

impl Buffer {
    /// Create a new buffer of the specified size.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::buffer::Buffer;
    /// let buf = Buffer::new(76);
    /// assert_eq!(76, buf.len());
    /// ```
    pub fn new(size: usize) -> Self {
        Buffer { inner: vec![0; size] }
    }

    pub fn from(data: &[u8]) -> Self {
        Buffer { inner: data.to_vec() }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:02X?}", self.inner)
    }
}
