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
//! use win_crypto_ng::symmetric::Padding;
//!
//! const KEY: &'static str = "0123456789ABCDEF";
//! const IV: &'static str = "asdfqwerasdfqwer";
//! const DATA: &'static str = "This is a test.";
//!
//! let iv = IV.as_bytes().to_owned();
//!
//! let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
//! let key = algo.new_key(KEY.as_bytes()).unwrap();
//! let ciphertext = key.encrypt(Some(&mut iv.clone()), DATA.as_bytes(), Some(Padding::Block)).unwrap();
//! let plaintext = key.decrypt(Some(&mut iv.clone()), ciphertext.as_slice(), Some(Padding::Block)).unwrap();
//!
//! assert_eq!(std::str::from_utf8(&plaintext.as_slice()[..DATA.len()]).unwrap(), DATA);
//! ```
//!
//! [`SymmetricAlgorithmId`]: enum.SymmetricAlgorithmId.html
//! [`ChainingMode`]: enum.ChainingMode.html
//! [`SymmetricAlgorithm.valid_key_sizes`]: struct.SymmetricAlgorithm.html#method.valid_key_sizes

use crate::buffer::Buffer;
use crate::helpers::{AlgoHandle, Handle, KeyHandle, WindowsString};
use crate::property::{self, BlockLength, KeyLength, KeyLengths, MessageBlockLength, ObjectLength};
use crate::{Error, Result};
use std::fmt;
use std::marker::PhantomData;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Padding to be used together with symmetric algorithms
pub enum Padding {
    /// Pad the data to the next block size.
    ///
    /// N.B. Data equal in length to the block size will be padded to the *next*
    /// block size.
    Block,
}

/// Marker trait for a symmetric algorithm.
pub trait Algorithm {
    const ID: Option<SymmetricAlgorithmId>;

    fn id(&self) -> SymmetricAlgorithmId;
}

impl Algorithm for SymmetricAlgorithmId {
    const ID: Option<SymmetricAlgorithmId> = None;
    fn id(&self) -> SymmetricAlgorithmId {
        *self
    }
}

/// The advanced encryption standard symmetric encryption algorithm.
///
/// Standard: FIPS 197
pub struct Aes;
impl Algorithm for Aes {
    const ID: Option<SymmetricAlgorithmId> = Some(SymmetricAlgorithmId::Aes);
    fn id(&self) -> SymmetricAlgorithmId {
        SymmetricAlgorithmId::Aes
    }
}
/// The data encryption standard symmetric encryption algorithm.
///
/// Standard: FIPS 46-3, FIPS 81.
pub struct Des;
impl Algorithm for Des {
    const ID: Option<SymmetricAlgorithmId> = Some(SymmetricAlgorithmId::Des);
    fn id(&self) -> SymmetricAlgorithmId {
        SymmetricAlgorithmId::Des
    }
}
/// The extended data encryption standard symmetric encryption algorithm.
///
/// Standard: None.
pub struct DesX;
impl Algorithm for DesX {
    const ID: Option<SymmetricAlgorithmId> = Some(SymmetricAlgorithmId::DesX);
    fn id(&self) -> SymmetricAlgorithmId {
        SymmetricAlgorithmId::DesX
    }
}
/// The RC2 block symmetric encryption algorithm.
///
/// Standard: RFC 2268.
pub struct Rc2;
impl Algorithm for Rc2 {
    const ID: Option<SymmetricAlgorithmId> = Some(SymmetricAlgorithmId::Rc2);
    fn id(&self) -> SymmetricAlgorithmId {
        SymmetricAlgorithmId::Rc2
    }
}
/// The triple data encryption standard symmetric encryption algorithm.
///
/// Standard: SP800-67, SP800-38A.
pub struct TripleDes;
impl Algorithm for TripleDes {
    const ID: Option<SymmetricAlgorithmId> = Some(SymmetricAlgorithmId::TripleDes);
    fn id(&self) -> SymmetricAlgorithmId {
        SymmetricAlgorithmId::TripleDes
    }
}
/// The 112-bit triple data encryption standard symmetric encryption algorithm.
///
/// Standard: SP800-67, SP800-38A.
pub struct TripleDes112;
impl Algorithm for TripleDes112 {
    const ID: Option<SymmetricAlgorithmId> = Some(SymmetricAlgorithmId::TripleDes112);
    fn id(&self) -> SymmetricAlgorithmId {
        SymmetricAlgorithmId::TripleDes112
    }
}

/// Marker trait denoting key size in bits.
pub trait KeyBits {
    /// Value known at compile-time, `None` if only known at run-time.
    const VALUE: Option<usize> = None;
}
/// Key length known at run-time.
pub struct DynamicKeyBits;

impl KeyBits for DynamicKeyBits {
    const VALUE: Option<usize> = None;
}

/// Handle to a symmetric key.
pub struct Key<A: Algorithm, B: KeyBits = DynamicKeyBits> {
    inner: SymmetricAlgorithmKey,
    _algo: PhantomData<A>,
    _bits: PhantomData<B>,
}

impl<A: Algorithm, B: KeyBits> fmt::Debug for Key<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Key<{}> {{ ... }}",
            A::ID.map(|x| x.to_str()).unwrap_or_default()
        )
    }
}

impl<A: Algorithm, B: KeyBits> core::convert::TryFrom<SymmetricAlgorithmKey> for Key<A, B> {
    type Error = SymmetricAlgorithmKey;

    fn try_from(value: SymmetricAlgorithmKey) -> Result<Self, Self::Error> {
        let name = value
            .handle
            .get_property_unsized::<property::AlgorithmName>()
            .expect("Key to always know its algorithm name");
        let name = WindowsString::from_bytes_with_nul(Vec::from(name).into()).unwrap();

        let id = A::ID
            .map(SymmetricAlgorithmId::to_str)
            .map(WindowsString::from)
            .unwrap_or_else(WindowsString::new);

        let key_size = value.key_size().expect("Key to know its length");
        if name == id && B::VALUE.map_or(true, |len| len == key_size) {
            Ok(Self {
                inner: value,
                _algo: PhantomData,
                _bits: PhantomData,
            })
        } else {
            Err(value)
        }
    }
}

impl<A: Algorithm, B: KeyBits> AsRef<SymmetricAlgorithmKey> for Key<A, B> {
    fn as_ref(&self) -> &SymmetricAlgorithmKey {
        &self.inner
    }
}

impl<A: Algorithm, B: KeyBits> Key<A, B> {
    /// Discards type-level information and returns a dynamic key handle.
    pub fn into_erased(self) -> SymmetricAlgorithmKey {
        self.inner
    }
}

impl<A: Algorithm, B: KeyBits> Clone for Key<A, B> {
    fn clone(&self) -> Self {
        let mut handle = KeyHandle::new();
        let mut _object = Vec::with_capacity(self.inner._object.len());

        unsafe {
            Error::check(BCryptDuplicateKey(
                self.inner.handle.as_ptr(),
                handle.as_mut_ptr(),
                _object.as_mut_slice().as_mut_ptr(),
                _object.capacity() as u32,
                0,
            ))
        }
        .expect(
            "CNG to succesfully duplicate a previously successfully created key
            object",
        );

        Self {
            inner: SymmetricAlgorithmKey {
                handle,
                _object: Buffer::from_vec(_object),
            },
            _algo: PhantomData,
            _bits: PhantomData,
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

        let value = WindowsString::from(chaining_mode.to_str());
        handle.set_property::<property::ChainingMode>(value.as_slice_with_nul())?;

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
        let object_size = self.handle.get_property::<ObjectLength>()?;

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
            .map(|key_size| key_size as usize)
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
            .map(|block_size| block_size as usize)
    }

    /// Sets the message block length.
    ///
    /// This can be set on any key handle that has the CFB chaining mode set. By
    /// default, it is set to 1 for 8-bit CFB. Setting it to the block
    /// size in bytes causes full-block CFB to be used. For XTS keys it is used to
    /// set the size, in bytes, of the XTS Data Unit (commonly 512 or 4096).
    ///
    /// See [here](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_MESSAGE_BLOCK_LENGTH)
    /// for more info.
    pub fn set_msg_block_len(&mut self, len: usize) -> Result<()> {
        self.handle
            .set_property::<MessageBlockLength>(&(len as u32))
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
    /// # use win_crypto_ng::symmetric::Padding;
    /// # let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let key = algo.new_key("0123456789ABCDEF".as_bytes()).unwrap();
    /// let mut iv = b"_THIS_IS_THE_IV_".to_vec();
    /// let plaintext = "THIS_IS_THE_DATA".as_bytes();
    /// let ciphertext = key.encrypt(Some(&mut iv), plaintext, Some(Padding::Block)).unwrap();
    ///
    /// assert_eq!(ciphertext.as_slice(), [
    ///     0xE4, 0xD9, 0x90, 0x64, 0xA6, 0xA6, 0x5F, 0x7E,
    ///     0x70, 0xDB, 0xF9, 0xDD, 0xE7, 0x0D, 0x6F, 0x6A,
    ///     0x0C, 0xEC, 0xDB, 0xAD, 0x01, 0xB4, 0xB1, 0xDE,
    ///     0xB4, 0x4A, 0xB8, 0xA0, 0xEA, 0x0E, 0x8F, 0x31]);
    /// ```
    pub fn encrypt(
        &self,
        iv: Option<&mut [u8]>,
        data: &[u8],
        padding: Option<Padding>,
    ) -> Result<Buffer> {
        let (iv_ptr, iv_len) = iv
            .map(|iv| (iv.as_mut_ptr(), iv.len() as ULONG))
            .unwrap_or((null_mut(), 0));

        let flags = match padding {
            Some(Padding::Block) => BCRYPT_BLOCK_PADDING,
            _ => 0,
        };

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
                flags,
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
                flags,
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
    /// # use win_crypto_ng::symmetric::Padding;
    /// # let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    /// let key = algo.new_key("0123456789ABCDEF".as_bytes()).unwrap();
    /// let mut iv = b"_THIS_IS_THE_IV_".to_vec();
    /// let ciphertext = [
    ///     0xE4, 0xD9, 0x90, 0x64, 0xA6, 0xA6, 0x5F, 0x7E,
    ///     0x70, 0xDB, 0xF9, 0xDD, 0xE7, 0x0D, 0x6F, 0x6A,
    ///     0x0C, 0xEC, 0xDB, 0xAD, 0x01, 0xB4, 0xB1, 0xDE,
    ///     0xB4, 0x4A, 0xB8, 0xA0, 0xEA, 0x0E, 0x8F, 0x31
    /// ];
    /// let plaintext = key.decrypt(Some(&mut iv), &ciphertext, Some(Padding::Block)).unwrap();
    ///
    /// assert_eq!(&plaintext.as_slice()[..16], "THIS_IS_THE_DATA".as_bytes());
    /// ```
    pub fn decrypt(
        &self,
        iv: Option<&mut [u8]>,
        data: &[u8],
        padding: Option<Padding>,
    ) -> Result<Buffer> {
        let (iv_ptr, iv_len) = iv
            .map(|iv| (iv.as_mut_ptr(), iv.len() as ULONG))
            .unwrap_or((null_mut(), 0));

        let flags = match padding {
            Some(Padding::Block) => BCRYPT_BLOCK_PADDING,
            _ => 0,
        };

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
                flags,
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
                flags,
            ))
            .map(|_| output)
        }
    }
}

#[cfg(feature = "block-cipher")]
pub use block_cipher;
#[cfg(feature = "block-cipher")]
mod block_cipher_trait {
    use super::*;

    use core::convert::TryFrom;

    use block_cipher::generic_array::{
        typenum::{self},
        ArrayLength,
    };
    use block_cipher::{self, Block, BlockCipher, Key, NewBlockCipher};

    impl<T> KeyBits for T where T: typenum::Unsigned {
        const VALUE: Option<usize> = Some(Self::USIZE);
    }

    impl<B: KeyBits> NewBlockCipher for super::Key<Aes, B>
    where
        B: typenum::Unsigned,
        // Fancy way of allowing only {128, 192, 256}
        B: typenum::IsGreaterOrEqual<typenum::U128, Output = typenum::B1>,
        B: typenum::IsLessOrEqual<typenum::U256, Output = typenum::B1>,
        B: typenum::PartialDiv<typenum::U64>,
        // Help the trait solver see that it's also divisible by 8
        B: typenum::PartialDiv<typenum::U8>,
        <B as typenum::PartialDiv<typenum::U8>>::Output: ArrayLength<u8>,
    {
        /// Key size in bytes with which cipher guaranteed to be initialized.
        type KeySize = <B as typenum::PartialDiv<typenum::U8>>::Output;

        /// Create new block cipher instance from key with fixed size.
        fn new(key: &Key<Self>) -> Self {
            let prov =
                SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Ecb).unwrap();
            let key = prov.new_key(key).unwrap();
            match Self::try_from(key) {
                Ok(value) => value,
                Err(..) => panic!(),
            }
        }
    }

    impl<B: KeyBits> BlockCipher for super::Key<Aes, B> {
        /// Size of the block in bytes
        type BlockSize = typenum::U16;

        /// Number of blocks which can be processed in parallel by
        /// cipher implementation
        type ParBlocks = typenum::U1;

        /// Encrypt block in-place
        fn encrypt_block(&self, block: &mut Block<Self>) {
            // FIXME: We assume here that we use ECB (as initialized via the
            // NewBlockCipher trait)
            // FIXME: Adapt the implementation to use the in-place one
            let buf = self.as_ref().encrypt(None, block.as_slice(), None).unwrap();
            let mut buf = buf.into_inner();
            block[..].copy_from_slice(buf.as_mut_slice());
        }

        /// Decrypt block in-place
        fn decrypt_block(&self, block: &mut Block<Self>) {
            // FIXME: We assume here that we use ECB (as initialized via the
            // NewBlockCipher trait)
            // FIXME: Adapt the implementation to use the in-place one
            let buf = self.as_ref().decrypt(None, block.as_slice(), None).unwrap();
            let mut buf = buf.into_inner();
            block[..].copy_from_slice(buf.as_mut_slice());
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
            Some(IV.as_bytes()[..block_size].to_vec().as_mut()),
            &DATA.as_bytes(),
            block_size,
        );
        check_encryption_decryption(
            algo_id,
            ChainingMode::Cfb,
            &SECRET.as_bytes()[..key_size],
            Some(IV.as_bytes()[..block_size].to_vec().as_mut()),
            &DATA.as_bytes(),
            block_size,
        );
    }

    fn check_encryption_decryption(
        algo_id: SymmetricAlgorithmId,
        chaining_mode: ChainingMode,
        secret: &[u8],
        iv: Option<&mut [u8]>,
        data: &[u8],
        expected_block_size: usize,
    ) {
        let iv_cloned = || iv.as_ref().map(|x| x.to_vec());
        let algo = SymmetricAlgorithm::open(algo_id, chaining_mode).unwrap();
        let key = algo.new_key(secret).unwrap();
        let ciphertext = key
            .encrypt(iv_cloned().as_mut().map(|x| x.as_mut()), data, None)
            .unwrap();
        let plaintext = key
            .decrypt(
                iv_cloned().as_mut().map(|x| x.as_mut()),
                ciphertext.as_slice(),
                None,
            )
            .unwrap();

        assert_eq!(data, &plaintext.as_slice()[..data.len()]);
        assert_eq!(secret.len() * 8, key.key_size().unwrap());
        assert_eq!(expected_block_size, key.block_size().unwrap());
    }

    #[cfg(feature = "block-cipher")]
    fn _assert_aes_keysize_valid() {
        use block_cipher::{generic_array::typenum, NewBlockCipher};
        fn _assert_trait_impl<T: NewBlockCipher>() {}
        _assert_trait_impl::<super::Key<Aes, typenum::U128>>();
        _assert_trait_impl::<super::Key<Aes, typenum::U192>>();
        _assert_trait_impl::<super::Key<Aes, typenum::U256>>();
    }

    #[cfg(feature = "block-cipher")]
    #[test]
    fn cipher_trait() {
        use core::convert::TryFrom;

        let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Ecb).unwrap();
        let key = algo.new_key(SECRET.as_bytes()).unwrap();

        let key = match Key::<Rc2>::try_from(key) {
            Ok(..) => panic!(),
            Err(value) => value,
        };

        let typed = match Key::<Aes>::try_from(key) {
            Ok(value) => value,
            Err(..) => panic!(),
        };

        use block_cipher::{generic_array::GenericArray, BlockCipher};
        let mut data = DATA.as_bytes()[..16].to_owned();
        typed.encrypt_block(GenericArray::from_mut_slice(data.as_mut()));
        typed.decrypt_block(GenericArray::from_mut_slice(data.as_mut()));
    }

    #[cfg(feature = "block-cipher")]
    #[test]
    fn marker_bits() {
        use block_cipher::generic_array::typenum;
        use core::convert::TryFrom;

        let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Ecb).unwrap();

        let key = algo.new_key(b"123456789012345678901234").unwrap();
        if let Ok(..) = Key::<Aes, typenum::U128>::try_from(key) {
            panic!();
        }
        let key = algo.new_key(b"123456789012345678901234").unwrap();
        if let Ok(..) = Key::<Aes, typenum::U256>::try_from(key) {
            panic!();
        }
        let key = algo.new_key(b"123456789012345678901234").unwrap();
        if let Err(..) = Key::<Aes, typenum::U192>::try_from(key) {
            panic!();
        }
        // Test 256 bit keys
        let key = algo.new_key(b"12345678901234567890123456789012").unwrap();
        if let Ok(..) = Key::<Aes, typenum::U128>::try_from(key) {
            panic!();
        }
        let key = algo.new_key(b"12345678901234567890123456789012").unwrap();
        if let Ok(..) = Key::<Aes, typenum::U192>::try_from(key) {
            panic!();
        }
        let key = algo.new_key(b"12345678901234567890123456789012").unwrap();
        if let Err(..) = Key::<Aes, typenum::U256>::try_from(key) {
            panic!();
        }
    }
}
