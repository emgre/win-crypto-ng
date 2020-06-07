//! Cryptographic hash algorithms
//!
//! Cryptographic hash algorithms are mathematicl algorithms that map data of arbitrary size to a
//! fixed size value. There are one-way functions practically infeasible to invert.
//!
//! # Usage
//!
//! The first step is to create an instance of the algorithm needed. All the hash algorithms
//! supported are defined in the [`HashAlgorithmId`] enum.
//!
//! The creation of an algorithm can be relatively time-intensive. Therefore, it is advised to cache
//! and reuse the created algorithms.
//!
//! Once the algorithm is created, an instance of an hash can be created. Using the [`hash`] method,
//! it is possible to hash per block. For example, if the user wants to hash a large file, it can
//! call the [`hash`] multiple times with only a subset of the file, limiting the memory usage.
//! The final result will be exactly the same as if the whole file was loaded and [`hash`] was
//! called once.
//!
//! To get the hash value, the user must call the [`finish`] method. This effectively consumes the
//! hash instance. To start the calculation of a new hash, a new instance must be created from the
//! algorithm.
//!
//! The following example hashes a string with the SHA-256 algorithm:
//! ```
//! use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};
//!
//! const DATA: &'static str = "This is a test.";
//!
//! let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
//! let mut hash = algo.new_hash().unwrap();
//! hash.hash(DATA.as_bytes()).unwrap();
//! let result = hash.finish().unwrap();
//!
//! assert_eq!(result.as_slice(), &[
//!     0xA8, 0xA2, 0xF6, 0xEB, 0xE2, 0x86, 0x69, 0x7C,
//!     0x52, 0x7E, 0xB3, 0x5A, 0x58, 0xB5, 0x53, 0x95,
//!     0x32, 0xE9, 0xB3, 0xAE, 0x3B, 0x64, 0xD4, 0xEB,
//!     0x0A, 0x46, 0xFB, 0x65, 0x7B, 0x41, 0x56, 0x2C,
//! ]);
//! ```
//!
//! [`HashAlgorithmId`]: enum.HashAlgorithmId.html
//! [`hash`]: struct.Hash.html#method.hash
//! [`finish`]: struct.Hash.html#method.finish

use crate::buffer::Buffer;
use crate::helpers::{AlgoHandle, Handle, WindowsString};
use crate::property::{AlgorithmName, HashLength, ObjectLength};
use crate::{Error, Result};
use std::convert::TryFrom;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::{PUCHAR, ULONG};

/// Hashing algorithm identifiers
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
pub enum HashAlgorithmId {
    /// The 160-bit secure hash algorithm.
    ///
    /// Standard: FIPS 180-2, FIPS 198.
    Sha1,
    /// The 256-bit secure hash algorithm.
    ///
    /// Standard: FIPS 180-2, FIPS 198.
    Sha256,
    /// The 384-bit secure hash algorithm.
    ///
    /// Standard: FIPS 180-2, FIPS 198.
    Sha384,
    /// The 512-bit secure hash algorithm.
    ///
    /// Standard: FIPS 180-2, FIPS 198.
    Sha512,
    /// The MD2 hash algorithm.
    ///
    /// Standard: RFC 1319.
    Md2,
    /// The MD4 hash algorithm.
    ///
    /// Standard: RFC 1320.
    Md4,
    /// The MD5 hash algorithm.
    ///
    /// Standard: RFC 1321.
    Md5,
    // The advanced encryption standard (AES) cipher based message authentication code (CMAC) symmetric encryption algorithm.
    //
    // Standard: SP 800-38B.
    //
    // **Windows 8**: Support for this algorithm begins.
    //AesCmac,
    // The advanced encryption standard (AES) Galois message authentication code (GMAC) symmetric encryption algorithm.
    //
    // Standard: SP800-38D.
    //
    // **Windows Vista**: This algorithm is supported beginning with Windows Vista with SP1.
    //AesGmac,
}

impl HashAlgorithmId {
    fn to_str(self) -> &'static str {
        match self {
            Self::Sha1 => BCRYPT_SHA1_ALGORITHM,
            Self::Sha256 => BCRYPT_SHA256_ALGORITHM,
            Self::Sha384 => BCRYPT_SHA384_ALGORITHM,
            Self::Sha512 => BCRYPT_SHA512_ALGORITHM,
            Self::Md2 => BCRYPT_MD2_ALGORITHM,
            Self::Md4 => BCRYPT_MD4_ALGORITHM,
            Self::Md5 => BCRYPT_MD5_ALGORITHM,
            //Self::AesCmac => BCRYPT_AES_CMAC_ALGORITHM,
            //Self::AesGmac => BCRYPT_AES_GMAC_ALGORITHM,
        }
    }
}

impl<'a> TryFrom<&'a str> for HashAlgorithmId {
    type Error = &'a str;

    fn try_from(val: &'a str) -> Result<HashAlgorithmId, Self::Error> {
        match val {
            BCRYPT_SHA1_ALGORITHM => Ok(Self::Sha1),
            BCRYPT_SHA256_ALGORITHM => Ok(Self::Sha256),
            BCRYPT_SHA384_ALGORITHM => Ok(Self::Sha384),
            BCRYPT_SHA512_ALGORITHM => Ok(Self::Sha512),
            BCRYPT_MD2_ALGORITHM => Ok(Self::Md2),
            BCRYPT_MD4_ALGORITHM => Ok(Self::Md4),
            BCRYPT_MD5_ALGORITHM => Ok(Self::Md5),
            val => Err(val),
        }
    }
}

/// Hashing algorithm
pub struct HashAlgorithm {
    handle: AlgoHandle,
}

impl HashAlgorithm {
    /// Open a hash algorithm provider
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};
    /// let algo = HashAlgorithm::open(HashAlgorithmId::Sha256);
    ///
    /// assert!(algo.is_ok());
    /// ```
    pub fn open(id: HashAlgorithmId) -> Result<Self> {
        let handle = AlgoHandle::open(id.to_str())?;

        Ok(Self { handle })
    }

    /// Creates a new hash from the algorithm
    pub fn new_hash(&self) -> Result<Hash> {
        let object_size = self.handle.get_property::<ObjectLength>()?;

        let mut hash_handle = HashHandle::new();
        let mut object = Buffer::new(object_size as usize);
        unsafe {
            Error::check(BCryptCreateHash(
                self.handle.as_ptr(),
                hash_handle.as_mut_ptr(),
                object.as_mut_ptr(),
                object.len() as ULONG,
                null_mut(),
                0,
                0,
            ))
            .map(|_| Hash {
                handle: hash_handle,
                object,
            })
        }
    }
}

struct HashHandle {
    handle: BCRYPT_HASH_HANDLE,
}

impl HashHandle {
    pub fn new() -> Self {
        Self { handle: null_mut() }
    }
}

impl Drop for HashHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptDestroyHash(self.handle);
            }
        }
    }
}

impl Handle for HashHandle {
    fn as_ptr(&self) -> BCRYPT_HASH_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_HASH_HANDLE {
        &mut self.handle
    }
}

/// Hashing operation
pub struct Hash {
    handle: HashHandle,
    /// Backing allocation for the hash object
    object: Buffer,
}

impl Hash {
    /// Perform a one way hash on the data
    ///
    /// This method can be called multiple times. To get the final result, use [`finish`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};
    /// let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
    /// let mut hash = algo.new_hash().unwrap();
    /// hash.hash("Some data".as_bytes()).unwrap();
    /// hash.hash("Some more data".as_bytes()).unwrap();
    /// ```
    ///
    /// [`finish`]: #method.finish
    pub fn hash(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            Error::check(BCryptHashData(
                self.handle.as_ptr(),
                data.as_ptr() as PUCHAR,
                data.len() as ULONG,
                0,
            ))
        }
    }

    /// Get the hash value
    ///
    /// This method consumes the hash operation. To create a new hash, a new instance must be created.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};
    /// let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
    /// let mut hash = algo.new_hash().unwrap();
    /// hash.hash("Some data".as_bytes()).unwrap();
    /// let result = hash.finish().unwrap();
    ///
    /// assert_eq!(result.as_slice(), [
    ///     0x1F, 0xE6, 0x38, 0xB4, 0x78, 0xF8, 0xF0, 0xB2,
    ///     0xC2, 0xAA, 0xB3, 0xDB, 0xFD, 0x3F, 0x05, 0xD6,
    ///     0xDf, 0xE2, 0x19, 0x1C, 0xD7, 0xB4, 0x48, 0x22,
    ///     0x41, 0xFE, 0x58, 0x56, 0x7E, 0x37, 0xAE, 0xF6,
    /// ]);
    /// ```
    pub fn finish(self) -> Result<Buffer> {
        let hash_size = self.hash_size()?;
        let mut result = Buffer::new(hash_size);

        unsafe {
            Error::check(BCryptFinishHash(
                self.handle.as_ptr(),
                result.as_mut_ptr(),
                result.len() as ULONG,
                0,
            ))
            .map(|_| result)
        }
    }

    /// Get the final hash length, in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};
    /// let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
    /// let hash = algo.new_hash().unwrap();
    /// let hash_size = hash.hash_size().unwrap();
    ///
    /// assert_eq!(hash_size, 32);
    /// ```
    pub fn hash_size(&self) -> Result<usize> {
        self.handle
            .get_property::<HashLength>()
            .map(|hash_size| hash_size as usize)
    }

    /// Get the hash algorithm used for this hash object.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};
    /// let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
    /// let hash = algo.new_hash().unwrap();
    ///
    /// assert_eq!(hash.hash_algorithm().unwrap(), HashAlgorithmId::Sha256);
    /// ```
    pub fn hash_algorithm(&self) -> Result<HashAlgorithmId> {
        self.handle
            .get_property_unsized::<AlgorithmName>()
            .map(|name| WindowsString::from_bytes_with_nul(name).to_string())
            .map(|name| {
                HashAlgorithmId::try_from(name.as_str())
                    .expect("Windows CNG API to return a correct algorithm name")
            })
    }
}

impl Clone for Hash {
    fn clone(&self) -> Self {
        // Rely on the fact that the existing buffer was already created with
        // size of `BCRYPT_OBJECT_LENGTH` as required by `BCryptDuplicateHash`.
        let object_size = self.object.len();

        let mut handle = HashHandle::new();
        let mut object = Buffer::new(object_size);

        Error::check(unsafe {
            BCryptDuplicateHash(
                self.handle.as_ptr(),
                handle.as_mut_ptr(),
                object.as_mut_ptr(),
                object.len() as ULONG,
                0,
            )
        })
        .expect("to always be able to duplicate a valid hash object");

        Self { handle, object }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &'static str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn sha1() {
        check_hash(
            HashAlgorithmId::Sha1,
            DATA.as_bytes(),
            &[
                0x2B, 0x44, 0x89, 0x60, 0x6A, 0x23, 0xFB, 0x31, 0xFC, 0xDC, 0x84, 0x9F, 0xA7, 0xE5,
                0x77, 0xBA, 0x90, 0xF6, 0xD3, 0x9A,
            ],
        )
    }

    #[test]
    fn sha256() {
        check_hash(
            HashAlgorithmId::Sha256,
            DATA.as_bytes(),
            &[
                0x0E, 0xA3, 0x7C, 0x24, 0x3F, 0x60, 0x97, 0x4B, 0x0D, 0x54, 0xC6, 0xB2, 0xD7, 0x6C,
                0xEC, 0xE3, 0xF4, 0xC7, 0x42, 0x49, 0x2C, 0xCE, 0x48, 0xEA, 0xF8, 0x1F, 0x35, 0x79,
                0x31, 0xD6, 0xD6, 0x9E,
            ],
        )
    }

    #[test]
    fn sha384() {
        check_hash(
            HashAlgorithmId::Sha384,
            DATA.as_bytes(),
            &[
                0x2A, 0x10, 0x60, 0x89, 0x6A, 0xCB, 0xA9, 0xFA, 0x37, 0x11, 0xBF, 0x10, 0x9E, 0x90,
                0x24, 0xEA, 0x19, 0xF5, 0xFC, 0x33, 0xAF, 0x0F, 0x47, 0x15, 0xC3, 0xE9, 0xD8, 0x63,
                0xB3, 0x24, 0xA5, 0x08, 0x9F, 0xAB, 0x95, 0x36, 0xB2, 0xAC, 0x10, 0xF6, 0xC1, 0xE7,
                0x31, 0x03, 0x09, 0x54, 0x18, 0x41,
            ],
        )
    }

    #[test]
    fn sha512() {
        check_hash(
            HashAlgorithmId::Sha512,
            DATA.as_bytes(),
            &[
                0x39, 0x50, 0xAC, 0xCD, 0xFE, 0xF7, 0x46, 0x20, 0x71, 0x42, 0x78, 0x76, 0x5B, 0xBD,
                0xCE, 0x04, 0xD4, 0x57, 0x90, 0x4B, 0x7C, 0xEA, 0x86, 0x31, 0x39, 0x6C, 0xBA, 0x6D,
                0x8B, 0xCE, 0xFC, 0xE0, 0x30, 0x8F, 0xC4, 0x7C, 0xFB, 0x88, 0x5B, 0xC8, 0x9E, 0xBD,
                0xF4, 0xFF, 0xA6, 0xF9, 0x8F, 0xC8, 0x51, 0x05, 0x54, 0x7C, 0xBD, 0xDF, 0x56, 0x57,
                0xB6, 0xAD, 0xBD, 0xDD, 0xA3, 0x8C, 0xB9, 0xB5,
            ],
        )
    }

    #[test]
    fn md2() {
        check_hash(
            HashAlgorithmId::Md2,
            DATA.as_bytes(),
            &[
                0x08, 0x18, 0x53, 0xA0, 0x5C, 0x1F, 0x58, 0xC6, 0xED, 0x43, 0x46, 0x4C, 0x79, 0x7D,
                0x65, 0x26,
            ],
        )
    }

    #[test]
    fn md4() {
        check_hash(
            HashAlgorithmId::Md4,
            DATA.as_bytes(),
            &[
                0x24, 0x3C, 0xDA, 0xF5, 0x91, 0x4A, 0xE8, 0x70, 0x91, 0xC7, 0x13, 0xB5, 0xFA, 0x9F,
                0xA7, 0x98,
            ],
        )
    }

    #[test]
    fn md5() {
        check_hash(
            HashAlgorithmId::Md5,
            DATA.as_bytes(),
            &[
                0xE8, 0x89, 0xD8, 0x2D, 0xD1, 0x11, 0xD6, 0x31, 0x5D, 0x7B, 0x1E, 0xDC, 0xE2, 0xB1,
                0xB3, 0x0F,
            ],
        )
    }

    fn check_hash(algo_id: HashAlgorithmId, data: &[u8], expected_hash: &[u8]) {
        let algo = HashAlgorithm::open(algo_id).unwrap();
        let mut hash = algo.new_hash().unwrap();
        let hash_size = hash.hash_size().unwrap();
        hash.hash(data).unwrap();
        let result = hash.finish().unwrap();

        assert_eq!(hash_size, expected_hash.len());
        assert_eq!(result.as_slice(), expected_hash);

        check_clone_impl(algo_id);
    }

    fn check_clone_impl(algo_id: HashAlgorithmId) {
        let algo = HashAlgorithm::open(algo_id).unwrap();
        let mut hash1 = algo.new_hash().unwrap();
        hash1.hash(DATA.as_bytes()).unwrap();

        let mut hash2 = hash1.clone();
        assert_ne!(hash1.handle.as_ptr(), hash2.handle.as_ptr());

        const AUX_DATA: &[u8] = &[0xE8, 0x91, 0xD9, 0x12];
        hash1.hash(AUX_DATA).unwrap();
        hash2.hash(AUX_DATA).unwrap();

        let result1 = hash1.finish().unwrap();
        let result2 = hash2.finish().unwrap();
        assert_eq!(result1, result2);
    }
}
