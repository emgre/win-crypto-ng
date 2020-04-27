//! Symmetric encryption algorithms
//!
//! Symmetric encryption algorithms uses the same key (the shared-secret) to encrypt and decrypt the
//! data. It is usually more performant and secure to use this type of encryption than using
//! asymmetric encryption algorithms.
//!
//! # Usage
//!
//! The first step is to create an instance of the algorithm needed. All the block ciphers
//! algorithms supported are defined in the [`SymmetricAlgorithmId`] enum. Since they encrypt per
//! block, a chaining mode is also needed. All the supported chaining modes are defined in the
//! [`ChainingMode`] enum.
//!
//! The creation of an algorithm can be relatively time-intensive. Therefore, it is advised to cache
//! and reuse the created algorithms.
//!
//! Once the algorithm is created, multiple keys can be created. Each key is initialized with a
//! secret of a specific size. To check what key sizes are supported, see
//! [`SymmetricAlgorithm.valid_key_sizes`].
//!
//! With the key in hand, it is then possible to encrypt or decrypt data. Padding is always added
//! to fit a whole block. If the data fits exactly in a block, an extra block of padding is added.
//! When encrypting or decrypting, an initialization vector (IV) may be required.
//!
//! The following example encrypts then decrypts a message using AES with CBC chaining mode:
//! ```
//! use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
//!
//! const KEY: &'static str = "0123456789ABCDEF";
//! const IV: &'static str = "asdfqwerasdfqwer";
//! const DATA: &'static str = "This is a test.";
//!
//! let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
//! let key = algo.new_key(KEY.as_bytes()).unwrap();
//! let ciphertext = key.encrypt(Some(IV.as_bytes()), DATA.as_bytes()).unwrap();
//! let plaintext = key.decrypt(Some(IV.as_bytes()), ciphertext.as_slice()).unwrap();
//!
//! assert_eq!(std::str::from_utf8(&plaintext.as_slice()[..DATA.len()]).unwrap(), DATA);
//! ```
//!
//! [`SymmetricAlgorithmId`]: enum.SymmetricAlgorithmId.html
//! [`ChainingMode`]: enum.ChainingMode.html
//! [`SymmetricAlgorithm.valid_key_sizes`]: struct.SymmetricAlgorithm.html#method.valid_key_sizes

use crate::buffer::Buffer;
use crate::helpers::{AlgoHandle, Handle, WindowsString};
use crate::property::{self, BlockLength, KeyLength, KeyLengths, ObjectLength};
use crate::{Error, Result};
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::{PUCHAR, ULONG};

/// Symmetric algorithm identifiers
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
pub enum SymmetricAlgorithmId {
    /// The advanced encryption standard symmetric encryption algorithm.
    ///
    /// Standard: FIPS 197.
    Aes,
    /// The data encryption standard symmetric encryption algorithm.
    ///
    /// Standard: FIPS 46-3, FIPS 81.
    Des,
    /// The extended data encryption standard symmetric encryption algorithm.
    ///
    /// Standard: None.
    DesX,
    /// The RC2 block symmetric encryption algorithm.
    ///
    /// Standard: RFC 2268.
    Rc2,
    // The RC4 symmetric encryption algorithm.
    //
    // Standard: Various.
    //Rc4,
    /// The triple data encryption standard symmetric encryption algorithm.
    ///
    /// Standard: SP800-67, SP800-38A.
    TripleDes,
    /// The 112-bit triple data encryption standard symmetric encryption algorithm.
    ///
    /// Standard: SP800-67, SP800-38A.
    TripleDes112,
    // The advanced encryption standard symmetric encryption algorithm in XTS mode.
    //
    // Standard: SP-800-38E, IEEE Std 1619-2007.
    //
    // **Windows 10**: Support for this algorithm begins.
    //XtsAes,
}

impl SymmetricAlgorithmId {
    fn to_str(self) -> &'static str {
        match self {
            Self::Aes => BCRYPT_AES_ALGORITHM,
            Self::Des => BCRYPT_DES_ALGORITHM,
            Self::DesX => BCRYPT_DESX_ALGORITHM,
            Self::Rc2 => BCRYPT_RC2_ALGORITHM,
            //Self::Rc4 => BCRYPT_RC4_ALGORITHM,
            Self::TripleDes => BCRYPT_3DES_ALGORITHM,
            Self::TripleDes112 => BCRYPT_3DES_112_ALGORITHM,
            //Self::XtsAes => BCRYPT_XTS_AES_ALGORITHM,
        }
    }
}

/// Symmetric algorithm chaining modes
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
pub enum ChainingMode {
    /// Electronic Codebook
    ///
    /// Standard: SP800-38A
    Ecb,
    /// Cipher Block Chaining
    ///
    /// Standard: SP800-38A
    Cbc,
    /// Cipher Feedback
    ///
    /// Standard: SP800-38A
    Cfb,
    // Counter with CBC. Only available on AES algorithm.
    //
    // Standard: SP800-38C
    //
    // **Windows Vista**: This value is supported beginning with Windows Vista with SP1.
    //Ccm,
    // Galois/Counter Mode. Only available on AES algorithm.
    //
    // Standard: SP800-38D
    //
    // **Windows Vista**: This value is supported beginning with Windows Vista with SP1.
    //Gcm,
}

impl ChainingMode {
    fn to_str(self) -> &'static str {
        match self {
            Self::Ecb => BCRYPT_CHAIN_MODE_ECB,
            Self::Cbc => BCRYPT_CHAIN_MODE_CBC,
            Self::Cfb => BCRYPT_CHAIN_MODE_CFB,
            //Self::Ccm => BCRYPT_CHAIN_MODE_CCM,
            //Self::Gcm => BCRYPT_CHAIN_MODE_GCM,
        }
    }
}

/// Symmetric algorithm
pub struct SymmetricAlgorithm {
    handle: AlgoHandle,
    chaining_mode: ChainingMode,
}

impl SymmetricAlgorithm {
    /// Open a symmetric algorithm provider
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc);
    ///
    /// assert!(algo.is_ok());
    /// ```
    pub fn open(id: SymmetricAlgorithmId, chaining_mode: ChainingMode) -> Result<Self> {
        let handle = AlgoHandle::open(id.to_str())?;

        let value = WindowsString::from_str(chaining_mode.to_str());
        handle.set_property::<property::ChainingMode>(value.as_slice())?;

        Ok(Self {
            handle,
            chaining_mode,
        })
    }

    /// Returns the chaining mode of the algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let chaining_mode = algo.chaining_mode();
    ///
    /// assert_eq!(ChainingMode::Cbc, chaining_mode);
    /// ```
    pub fn chaining_mode(&self) -> ChainingMode {
        self.chaining_mode
    }

    /// Returns a list of all the valid key sizes for an algorithm.
    ///
    /// The key sizes are defined in bits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let valid_key_sizes = algo.valid_key_sizes().unwrap();
    ///
    /// assert_eq!([128, 192, 256], valid_key_sizes.as_slice());
    /// ```
    pub fn valid_key_sizes(&self) -> Result<Vec<usize>> {
        let key_sizes = self.handle.get_property::<KeyLengths>()?;
        let key_sizes = key_sizes.as_ref();

        if key_sizes.dwIncrement != 0 {
            Ok(
                (key_sizes.dwMinLength as usize..=key_sizes.dwMaxLength as usize)
                    .step_by(key_sizes.dwIncrement as usize)
                    .collect(),
            )
        } else {
            Ok(vec![key_sizes.dwMinLength as usize])
        }
    }

    /// Creates a new key from the algorithm
    ///
    /// The secret value is the shared-secret between the two parties.
    /// For example, it may be a hash of a password or some other reproducible data.
    /// The size of the secret must fit with one of the valid key sizes (see [`valid_key_sizes`]).
    ///
    /// [`valid_key_sizes`]: #method.valid_key_sizes
    pub fn new_key(&self, secret: &[u8]) -> Result<SymmetricAlgorithmKey> {
        let object_size = self.handle.get_property::<ObjectLength>()?.copied();

        let mut key_handle = KeyHandle::new();
        let mut object = Buffer::new(object_size as usize);
        unsafe {
            Error::check(BCryptGenerateSymmetricKey(
                self.handle.as_ptr(),
                key_handle.as_mut_ptr(),
                object.as_mut_ptr(),
                object.len() as ULONG,
                secret.as_ptr() as PUCHAR,
                secret.len() as ULONG,
                0,
            ))
            .map(|_| SymmetricAlgorithmKey {
                handle: key_handle,
                _object: object,
            })
        }
    }
}

struct KeyHandle {
    handle: BCRYPT_KEY_HANDLE,
}

impl KeyHandle {
    pub fn new() -> Self {
        Self { handle: null_mut() }
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptDestroyKey(self.handle);
            }
        }
    }
}

impl Handle for KeyHandle {
    fn as_ptr(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_KEY_HANDLE {
        &mut self.handle
    }
}

/// Symmetric algorithm key
pub struct SymmetricAlgorithmKey {
    handle: KeyHandle,
    _object: Buffer,
}

impl SymmetricAlgorithmKey {
    /// Returns the key value size in bits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// # let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let key = algo.new_key("0123456789ABCDEF".as_bytes()).unwrap();
    /// let key_size = key.key_size().unwrap();
    ///
    /// assert_eq!(128, key_size);
    /// ```
    pub fn key_size(&self) -> Result<usize> {
        self.handle
            .get_property::<KeyLength>()
            .map(|key_size| key_size.copied() as usize)
    }

    /// Returns the block size in bytes.
    ///
    /// This can be useful to find what size the IV should be.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// # let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let key = algo.new_key("0123456789ABCDEF".as_bytes()).unwrap();
    /// let key_size = key.block_size().unwrap();
    ///
    /// assert_eq!(16, key_size);
    /// ```
    pub fn block_size(&self) -> Result<usize> {
        self.handle
            .get_property::<BlockLength>()
            .map(|block_size| block_size.copied() as usize)
    }

    /// Encrypts data using the symmetric key
    ///
    /// The IV is not needed for [`ChainingMode::Ecb`], so `None` should be used
    /// in this case.
    ///
    /// For chaining modes needing an IV, `None` can be used and a default IV will be used.
    /// This is not documented on Microsoft's website and is therefore not recommended.
    ///
    /// The data is padded with zeroes to a multiple of the block size of the cipher. If
    /// the data length equals the block size of the cipher, one additional block of
    /// padding is appended to the data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// # let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let key = algo.new_key("0123456789ABCDEF".as_bytes()).unwrap();
    /// let iv = "_THIS_IS_THE_IV_".as_bytes();
    /// let plaintext = "THIS_IS_THE_DATA".as_bytes();
    /// let ciphertext = key.encrypt(Some(iv), plaintext).unwrap();
    ///
    /// assert_eq!(ciphertext.as_slice(), [
    ///     0xE4, 0xD9, 0x90, 0x64, 0xA6, 0xA6, 0x5F, 0x7E,
    ///     0x70, 0xDB, 0xF9, 0xDD, 0xE7, 0x0D, 0x6F, 0x6A,
    ///     0x0C, 0xEC, 0xDB, 0xAD, 0x01, 0xB4, 0xB1, 0xDE,
    ///     0xB4, 0x4A, 0xB8, 0xA0, 0xEA, 0x0E, 0x8F, 0x31]);
    /// ```
    pub fn encrypt(&self, iv: Option<&[u8]>, data: &[u8]) -> Result<Buffer> {
        let mut iv_copy = iv.map(|iv| Buffer::from(iv));
        let iv_ptr = iv_copy.as_mut().map_or(null_mut(), |iv| iv.as_mut_ptr());
        let iv_len = iv_copy.as_ref().map_or(0, |iv| iv.len() as ULONG);

        let mut encrypted_len = MaybeUninit::<ULONG>::uninit();
        unsafe {
            Error::check(BCryptEncrypt(
                self.handle.as_ptr(),
                data.as_ptr() as PUCHAR,
                data.len() as ULONG,
                null_mut(),
                iv_ptr,
                iv_len,
                null_mut(),
                0,
                encrypted_len.as_mut_ptr(),
                BCRYPT_BLOCK_PADDING,
            ))?;

            let mut output = Buffer::new(encrypted_len.assume_init() as usize);

            Error::check(BCryptEncrypt(
                self.handle.as_ptr(),
                data.as_ptr() as PUCHAR,
                data.len() as ULONG,
                null_mut(),
                iv_ptr,
                iv_len,
                output.as_mut_ptr(),
                output.len() as ULONG,
                encrypted_len.as_mut_ptr(),
                BCRYPT_BLOCK_PADDING,
            ))
            .map(|_| output)
        }
    }

    /// Decrypts data using the symmetric key
    ///
    /// The IV is not needed for [`ChainingMode::Ecb`], so `None` should be used
    /// in this case.
    ///
    /// For chaining modes needing an IV, `None` can be used and a default IV will be used.
    /// This is not documented on Microsoft's website and is therefore not recommended.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};
    /// # let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let key = algo.new_key("0123456789ABCDEF".as_bytes()).unwrap();
    /// let iv = "_THIS_IS_THE_IV_".as_bytes();
    /// let ciphertext = [
    ///     0xE4, 0xD9, 0x90, 0x64, 0xA6, 0xA6, 0x5F, 0x7E,
    ///     0x70, 0xDB, 0xF9, 0xDD, 0xE7, 0x0D, 0x6F, 0x6A,
    ///     0x0C, 0xEC, 0xDB, 0xAD, 0x01, 0xB4, 0xB1, 0xDE,
    ///     0xB4, 0x4A, 0xB8, 0xA0, 0xEA, 0x0E, 0x8F, 0x31
    /// ];
    /// let plaintext = key.decrypt(Some(iv), &ciphertext).unwrap();
    ///
    /// assert_eq!(&plaintext.as_slice()[..16], "THIS_IS_THE_DATA".as_bytes());
    /// ```
    pub fn decrypt(&self, iv: Option<&[u8]>, data: &[u8]) -> Result<Buffer> {
        let mut iv_copy = iv.map(|iv| Buffer::from(iv));
        let iv_ptr = iv_copy.as_mut().map_or(null_mut(), |iv| iv.as_mut_ptr());
        let iv_len = iv_copy.as_ref().map_or(0, |iv| iv.len() as ULONG);

        let mut plaintext_len = MaybeUninit::<ULONG>::uninit();
        unsafe {
            Error::check(BCryptDecrypt(
                self.handle.as_ptr(),
                data.as_ptr() as PUCHAR,
                data.len() as ULONG,
                null_mut(),
                iv_ptr,
                iv_len,
                null_mut(),
                0,
                plaintext_len.as_mut_ptr(),
                BCRYPT_BLOCK_PADDING,
            ))?;

            let mut output = Buffer::new(plaintext_len.assume_init() as usize);

            Error::check(BCryptDecrypt(
                self.handle.as_ptr(),
                data.as_ptr() as PUCHAR,
                data.len() as ULONG,
                null_mut(),
                iv_ptr,
                iv_len,
                output.as_mut_ptr(),
                output.len() as ULONG,
                plaintext_len.as_mut_ptr(),
                BCRYPT_BLOCK_PADDING,
            ))
            .map(|_| output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &'static str = "0123456789ABCDEF0123456789ABCDEF";
    const IV: &'static str = "0123456789ABCDEF0123456789ABCDEF";
    const DATA: &'static str = "0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn aes() {
        check_common_chaining_modes(SymmetricAlgorithmId::Aes, 16, 16);
        check_common_chaining_modes(SymmetricAlgorithmId::Aes, 24, 16);
        check_common_chaining_modes(SymmetricAlgorithmId::Aes, 32, 16);
    }

    #[test]
    fn des() {
        check_common_chaining_modes(SymmetricAlgorithmId::Des, 8, 8);
    }

    #[test]
    fn des_x() {
        check_common_chaining_modes(SymmetricAlgorithmId::DesX, 24, 8);
    }

    #[test]
    fn rc2() {
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 2, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 3, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 4, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 5, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 6, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 7, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 8, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 9, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 10, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 11, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 12, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 13, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 14, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 15, 8);
        check_common_chaining_modes(SymmetricAlgorithmId::Rc2, 16, 8);
    }

    #[test]
    fn triple_des() {
        check_common_chaining_modes(SymmetricAlgorithmId::TripleDes, 24, 8);
    }

    #[test]
    fn triple_des_112() {
        check_common_chaining_modes(SymmetricAlgorithmId::TripleDes112, 16, 8);
    }

    fn check_common_chaining_modes(
        algo_id: SymmetricAlgorithmId,
        key_size: usize,
        block_size: usize,
    ) {
        check_encryption_decryption(
            algo_id,
            ChainingMode::Ecb,
            &SECRET.as_bytes()[..key_size],
            None,
            &DATA.as_bytes()[..block_size],
            block_size,
        );
        check_encryption_decryption(
            algo_id,
            ChainingMode::Cbc,
            &SECRET.as_bytes()[..key_size],
            Some(&IV.as_bytes()[..block_size]),
            &DATA.as_bytes(),
            block_size,
        );
        check_encryption_decryption(
            algo_id,
            ChainingMode::Cfb,
            &SECRET.as_bytes()[..key_size],
            Some(&IV.as_bytes()[..block_size]),
            &DATA.as_bytes(),
            block_size,
        );
    }

    fn check_encryption_decryption(
        algo_id: SymmetricAlgorithmId,
        chaining_mode: ChainingMode,
        secret: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        expected_block_size: usize,
    ) {
        let algo = SymmetricAlgorithm::open(algo_id, chaining_mode).unwrap();
        let key = algo.new_key(secret).unwrap();
        let ciphertext = key.encrypt(iv, data).unwrap();
        let plaintext = key.decrypt(iv, ciphertext.as_slice()).unwrap();

        assert_eq!(data, &plaintext.as_slice()[..data.len()]);
        assert_eq!(secret.len() * 8, key.key_size().unwrap());
        assert_eq!(expected_block_size, key.block_size().unwrap());
    }
}
