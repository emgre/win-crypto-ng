//! Secure buffer implementation

use std::fmt::{Debug, Error, Formatter};
use std::mem;

/// Secure buffer implementation.
///
/// On creation, the buffer is initialized with zeroes.
/// On destruction, if the `zeroize` feature is enabled, its content is set to
/// `0` before being released.
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
    /// assert_eq!(buf.len(), 76);
    /// ```
    pub fn new(size: usize) -> Self {
        Buffer {
            inner: vec![0; size],
        }
    }

    /// Create a new buffer with its data copied from the slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::buffer::Buffer;
    /// const SOME_DATA: &'static [u8] = &[0x01, 0x02, 0x03, 0x04];
    /// let buf = Buffer::from(SOME_DATA);
    /// assert_eq!(buf.as_slice(), SOME_DATA);
    /// ```
    pub fn from(data: &[u8]) -> Self {
        Buffer {
            inner: data.to_vec(),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
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

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }

    pub fn into_inner(mut self) -> Vec<u8> {
        mem::replace(&mut self.inner, Vec::new())
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut self.inner);
    }
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:02X?}", self.inner)
    }
}
