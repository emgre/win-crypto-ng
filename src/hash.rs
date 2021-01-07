//! Cryptographic hash algorithms & MAC functions
//!
//! Cryptographic hash algorithms are mathematical algorithms that map data of arbitrary size to a
//! fixed size value. There are one-way functions practically infeasible to invert.
//!
//! Message authentication code (MAC) is a short piece of information attached
//! to a message confirming its authenticity and data integrity.
//!
//! # Usage
//!
//! The first step is to create an instance of the algorithm needed. All the hash algorithms
//! supported are defined in the [`HashAlgorithmId`] enum. For MACs, see the [`MacAlgorithmId`] enum.
//!
//! The creation of an algorithm can be relatively time-intensive. Therefore, it is advised to cache
//! and reuse the created algorithms.
//!
//! Once the algorithm is created, an instance of an hash can be created. It's worth noting that
//! hash and MAC instances share the underlying [`Hash`] type.
//!
//! Using the [`hash`][`Hash::hash`] method,
//! it is possible to hash per block. For example, if the user wants to hash a large file, it can
//! call the [`hash`][`Hash::hash`] multiple times with only a subset of the file, limiting the memory usage.
//! The final result will be exactly the same as if the whole file was loaded and [`hash`][`Hash::hash`] was
//! called once.
//!
//! To get the hash value, the user must call the [`finish`][`Hash::finish`] method. This effectively consumes the
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
//!```
//! The example below computes a simple MAC value from null input, using the AES-GMAC algorithm:
//! ```
//! use win_crypto_ng::hash::{HashAlgorithm, MacAlgorithmId};
//!
//! const SECRET: &[u8] = &[
//!   0xcf, 0x06, 0x3a, 0x34, 0xd4, 0xa9, 0xa7, 0x6c,
//!   0x2c, 0x86, 0x78, 0x7d, 0x3f, 0x96, 0xdb, 0x71,
//! ];
//! const IV: &[u8] = &[
//!   0x11, 0x3b, 0x97, 0x85, 0x97, 0x18, 0x64, 0xc8,
//!   0x3b, 0x01, 0xc7, 0x87
//! ];
//!
//! let algo = HashAlgorithm::open(MacAlgorithmId::AesGmac).unwrap();
//! let mut mac = algo.new_mac(SECRET, Some(IV)).unwrap();
//! mac.hash(&[]).unwrap();
//! let result = mac.finish().unwrap();
//!
//! assert_eq!(result.as_slice(), &[
//!   0x72, 0xac, 0x84, 0x93, 0xe3, 0xa5, 0x22, 0x8b,
//!   0x5d, 0x13, 0x0a, 0x69, 0xd2, 0x51, 0x0e, 0x42,
//! ]);
//! ```
//!
//! [`HashAlgorithmId`]: enum.HashAlgorithmId.html
//! [`MacAlgorithmId`]: enum.MacAlgorithmId.html
//! [`Hash`]: struct.Hash.html
//! [`Hash::hash]: struct.Hash.html#method.hash
//! [`Hash::finish`]: struct.Hash.html#method.finish

use crate::buffer::Buffer;
use crate::helpers::{AlgoHandle, Handle, WindowsString};
use crate::property::{AlgorithmName, HashLength, InitializationVector, ObjectLength};
use crate::{Error, Result};
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::{PUCHAR, ULONG};

/// Algorithm kind used with hashing facilities.
///
/// This can be either a regular [`HashAlgorithmId`] (hash function)
/// or [`MacAlgorithmId`] (message authentication code).
///
/// [`HashAlgorithmId`]: ./enum.HashAlgorithmId.html
/// [`MacAlgorithmId`]: ./enum.MacAlgorithmId.html
pub trait AlgorithmKind {
    fn to_str(&self) -> &'static str;
}

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
}

impl AlgorithmKind for HashAlgorithmId {
    fn to_str(&self) -> &'static str {
        HashAlgorithmId::to_str(*self)
    }
}

/// MAC (Message authentication code) algorithm identifiers
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
pub enum MacAlgorithmId {
    /// The advanced encryption standard (AES) cipher based message authentication code (CMAC) symmetric encryption algorithm.
    ///
    /// Standard: SP 800-38B.
    ///
    /// **Windows 8**: Support for this algorithm begins.
    AesCmac,
    /// The advanced encryption standard (AES) Galois message authentication code (GMAC) symmetric encryption algorithm.
    ///
    /// Standard: SP800-38D.
    ///
    /// **Windows Vista**: This algorithm is supported beginning with Windows Vista with SP1.
    AesGmac,
}

impl AlgorithmKind for MacAlgorithmId {
    fn to_str(&self) -> &'static str {
        MacAlgorithmId::to_str(*self)
    }
}

impl HashAlgorithmId {
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Sha1 => BCRYPT_SHA1_ALGORITHM,
            Self::Sha256 => BCRYPT_SHA256_ALGORITHM,
            Self::Sha384 => BCRYPT_SHA384_ALGORITHM,
            Self::Sha512 => BCRYPT_SHA512_ALGORITHM,
            Self::Md2 => BCRYPT_MD2_ALGORITHM,
            Self::Md4 => BCRYPT_MD4_ALGORITHM,
            Self::Md5 => BCRYPT_MD5_ALGORITHM,
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

impl MacAlgorithmId {
    fn to_str(self) -> &'static str {
        match self {
            Self::AesCmac => BCRYPT_AES_CMAC_ALGORITHM,
            Self::AesGmac => BCRYPT_AES_GMAC_ALGORITHM,
        }
    }
}

impl<'a> TryFrom<&'a str> for MacAlgorithmId {
    type Error = &'a str;

    fn try_from(val: &'a str) -> std::result::Result<MacAlgorithmId, Self::Error> {
        match val {
            BCRYPT_AES_CMAC_ALGORITHM => Ok(Self::AesCmac),
            BCRYPT_AES_GMAC_ALGORITHM => Ok(Self::AesGmac),
            val => Err(val),
        }
    }
}

/// Hashing algorithm
pub struct HashAlgorithm<Kind: AlgorithmKind> {
    handle: AlgoHandle,
    _kind: PhantomData<Kind>,
}

impl<Kind: AlgorithmKind> HashAlgorithm<Kind> {
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
    pub fn open(id: Kind) -> Result<Self> {
        let handle = AlgoHandle::open(id.to_str())?;

        Ok(Self {
            handle,
            _kind: PhantomData,
        })
    }

    fn create_hash(&self, secret: Option<&[u8]>, iv: Option<&[u8]>) -> Result<Hash> {
        let (sec_ptr, sec_len) = secret
            .map(|x| (x.as_ptr(), x.len()))
            .unwrap_or((std::ptr::null(), 0));
        let object_size = self.handle.get_property::<ObjectLength>()?;

        let mut hash_handle = HashHandle::new();
        let mut object = Buffer::new(object_size as usize);
        unsafe {
            Error::check(BCryptCreateHash(
                self.handle.as_ptr(),
                hash_handle.as_mut_ptr(),
                object.as_mut_ptr(),
                object.len() as ULONG,
                sec_ptr as *mut _,
                sec_len as ULONG,
                0,
            ))?;
        };

        if let Some(iv) = iv {
            hash_handle.set_property::<InitializationVector>(iv)?;
        }

        Ok(Hash {
            handle: hash_handle,
            object,
        })
    }
}

impl HashAlgorithm<HashAlgorithmId> {
    /// Creates a new hash from the algorithm
    pub fn new_hash(&self) -> Result<Hash> {
        self.create_hash(None, None)
    }
}

impl HashAlgorithm<MacAlgorithmId> {
    /// Creates a new Message Authentication Code (MAC), if supported by the
    /// backing algorithm (AES-GMAC/AES-CMAC).
    ///
    /// Passing IV is required for GMAC mode, otherwise don't pass it for OMAC.
    pub fn new_mac(&self, secret: &[u8], iv: Option<&[u8]>) -> Result<Hash> {
        self.create_hash(Some(secret), iv)
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

    pub(crate) fn finish_in_place(self, out: &mut [u8]) -> Result<()> {
        let hash_size = self.hash_size()?;
        assert_eq!(out.len(), hash_size);

        unsafe {
            Error::check(BCryptFinishHash(
                self.handle.as_ptr(),
                out.as_mut_ptr(),
                out.len() as ULONG,
                0,
            ))?;
        }

        Ok(())
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
            .map(|name| {
                WindowsString::from_bytes_with_nul(name.as_ref().into())
                    .expect("API to return 0-terminated wide string")
            })
            .map(|name| {
                HashAlgorithmId::try_from(name.to_string().as_str())
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

#[cfg(feature = "digest")]
pub mod digest_trait {
    use super::{Hash, HashAlgorithm, HashAlgorithmId};
    use digest::generic_array::{typenum, ArrayLength, GenericArray};
    use std::marker::PhantomData;

    /// Helper trait for [`digest::Digest`] implementations.
    pub trait WinDigestAlgo: Clone {
        type BlockSize: ArrayLength<u8>;
        type OutputSize: ArrayLength<u8>;
        fn algo_id() -> HashAlgorithmId;
    }

    /// Helper struct that implements [`digest::Digest`] trait.
    #[derive(Clone)]
    pub struct WinDigest<A> {
        _algo: PhantomData<A>,
        inner: Hash,
    }

    impl<A: WinDigestAlgo> digest::BlockInput for WinDigest<A> {
        type BlockSize = A::BlockSize;
    }

    impl<A: WinDigestAlgo> Default for WinDigest<A> {
        fn default() -> Self {
            let algo = HashAlgorithm::open(A::algo_id()).unwrap();
            Self {
                _algo: PhantomData,
                inner: algo.new_hash().unwrap(),
            }
        }
    }

    impl<A: WinDigestAlgo> digest::Update for WinDigest<A> {
        fn update(&mut self, data: impl AsRef<[u8]>) {
            self.inner.hash(data.as_ref()).unwrap();
        }
    }

    impl<A: WinDigestAlgo> digest::FixedOutput for WinDigest<A> {
        type OutputSize = A::OutputSize;

        fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
            self.inner.finish_in_place(out).unwrap();
        }
        fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
            let mut new = Self::default();
            std::mem::swap(self, &mut new);
            new.inner.finish_in_place(out).unwrap();
        }
    }

    impl<A: WinDigestAlgo> digest::Reset for WinDigest<A> {
        fn reset(&mut self) {
            let mut new = Self::default();
            std::mem::swap(self, &mut new);
        }
    }

    macro_rules! impl_win_digest {
        ($name:ident, $block_size:ty, $output_size:ty, $algo:ident) => {
            #[derive(Clone, Copy)]
            pub struct $name;
            impl WinDigestAlgo for $name {
                type BlockSize = $block_size;
                type OutputSize = $output_size;
                fn algo_id() -> HashAlgorithmId {
                    HashAlgorithmId::$algo
                }
            }
        };
    }

    impl_win_digest!(Md2, typenum::U16, typenum::U16, Md2);
    impl_win_digest!(Md4, typenum::U64, typenum::U16, Md4);
    impl_win_digest!(Md5, typenum::U64, typenum::U16, Md5);

    impl_win_digest!(Sha1, typenum::U64, typenum::U20, Sha1);
    impl_win_digest!(Sha256, typenum::U64, typenum::U32, Sha256);
    impl_win_digest!(Sha384, typenum::U128, typenum::U48, Sha384);
    impl_win_digest!(Sha512, typenum::U128, typenum::U64, Sha512);
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

    trait HexSlice: std::borrow::Borrow<str> {
        fn as_hex(&self) -> Vec<u8> {
            let res: Vec<u8> = self
                .borrow()
                .as_bytes()
                .rchunks(2)
                .map(|slice| std::str::from_utf8(slice).unwrap())
                .map(|chr| u8::from_str_radix(chr, 16).unwrap())
                .rev()
                .collect();
            res
        }
    }
    impl<'a> HexSlice for &'a str {}

    #[test]
    fn cmac() {
        // Test vectors from
        // https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/omac/omac-ad.pdf
        let test_vectors = vec![
            ("2b7e151628aed2a6abf7158809cf4f3c", "", "bb1d6929e95937287fa37d129b756746"),
            ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"),
            ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"),
            ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe")
        ];

        for (key, msg, tag) in test_vectors {
            let (key, msg, tag) = (&key.as_hex(), &msg.as_hex(), &tag.as_hex());
            check_mac(MacAlgorithmId::AesCmac, msg, tag, key);
        }
    }

    #[test]
    fn gmac() {
        // Test select vectors from (PTlen = 0 are effectively GMAC vectors)
        // http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
        let algo = HashAlgorithm::open(MacAlgorithmId::AesGmac).unwrap();

        let key = &"ce8d1103100fa290f953fbb439efdee4".as_hex();
        let iv = &"4874c6f8082366fc7e49b933".as_hex();
        let mut gmac = algo.new_mac(key, Some(iv)).unwrap();
        gmac.hash(&"d69d033c32029789263c689e11ff7e9e8eefc48ddbc4e10eeae1c9edbb44f04e7cc6471501eadda3940ab433d0a8c210".as_hex()).unwrap(); // AAD
        let digest = gmac.finish().unwrap();
        assert_eq!(
            digest.as_slice(),
            &*"a5964b77af0b8aecd844d6adec8b7b1c".as_hex()
        );

        let key = &"4fedd84c9495e7ff81db48d367305d80".as_hex();
        let iv = &"d82bfb016a35b5efa5e3438a".as_hex();
        let mut gmac = algo.new_mac(key, Some(iv)).unwrap();
        gmac.hash(&"0c80e282e64aeac2fba241686a9b33a6bdbac1230442e79fc5c0b6926158b0bf9b8562b570d784e749b69d64ed17f45e".as_hex()).unwrap(); // AAD
        let digest = gmac.finish().unwrap();
        assert_eq!(
            digest.as_slice(),
            &*"aad8933fdce92b9a24c2a9c2cc367291".as_hex()
        );
    }

    fn check_mac(algo_id: MacAlgorithmId, data: &[u8], expected_hash: &[u8], secret: &[u8]) {
        let algo = HashAlgorithm::open(algo_id).unwrap();
        let mut hash = algo.new_mac(secret, None).unwrap();
        let hash_size = hash.hash_size().unwrap();
        hash.hash(data).unwrap();
        let result = hash.finish().unwrap();

        assert_eq!(hash_size, expected_hash.len());
        assert_eq!(result.as_slice(), expected_hash);
    }
}
