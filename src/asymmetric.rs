//! Asymmetric encryption algorithms

use crate::helpers::{AlgoHandle, Handle, TypedBlob, WindowsString};
use crate::key::KeyHandle;
use crate::{Error, Result};
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

/// Asymmetric algorithm identifiers
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
pub enum AsymmetricAlgorithmId {
    /// The Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: PKCS #3
    Dh,
    /// The digital signature algorithm.
    ///
    /// Standard: FIPS 186-2
    ///
    /// **Windows 8**: Beginning with Windows 8, this algorithm supports
    /// FIPS 186-3. Keys less than or equal to 1024 bits adhere to FIPS 186-2
    /// and keys greater than 1024 to FIPS 186-3.
    Dsa,
    /// The 256-bit prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A
    EcdhP256,
    /// The 384-bit prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A
    EcdhP384,
    /// The 521-bit prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A
    EcdhP521,
    /// The 256-bit prime elliptic curve digital signature algorithm (FIPS 186-2).
    ///
    /// Standard: FIPS 186-2, X9.62
    EcdsaP256,
    /// The 384-bit prime elliptic curve digital signature algorithm (FIPS 186-2).
    ///
    /// Standard: FIPS 186-2, X9.62
    EcdsaP384,
    /// The 521-bit prime elliptic curve digital signature algorithm (FIPS 186-2).
    ///
    /// Standard: FIPS 186-2, X9.62
    EcdsaP521,
    /// The RSA public key algorithm.
    ///
    /// Standard: PKCS #1 v1.5 and v2.0.
    Rsa,
}

impl AsymmetricAlgorithmId {
    fn to_str(&self) -> &str {
        match self {
            Self::Dh => BCRYPT_DH_ALGORITHM,
            Self::Dsa => BCRYPT_DSA_ALGORITHM,
            Self::EcdhP256 => BCRYPT_ECDH_P256_ALGORITHM,
            Self::EcdhP384 => BCRYPT_ECDH_P384_ALGORITHM,
            Self::EcdhP521 => BCRYPT_ECDH_P521_ALGORITHM,
            Self::EcdsaP256 => BCRYPT_ECDSA_P256_ALGORITHM,
            Self::EcdsaP384 => BCRYPT_ECDSA_P384_ALGORITHM,
            Self::EcdsaP521 => BCRYPT_ECDSA_P521_ALGORITHM,
            Self::Rsa => BCRYPT_RSA_ALGORITHM,
        }
    }
}

/// Asymmetric algorithm
pub struct AsymmetricAlgorithm {
    handle: AlgoHandle,
}

impl AsymmetricAlgorithm {
    /// Open an asymmetric algorithm provider
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa);
    ///
    /// assert!(algo.is_ok());
    /// ```
    pub fn open(id: AsymmetricAlgorithmId) -> Result<Self> {
        let handle = AlgoHandle::open(id.to_str())?;

        Ok(Self { handle })
    }
}

pub struct KeyPair(KeyHandle);
pub struct KeyPairBuilder<'a> {
    _provider: &'a AsymmetricAlgorithm,
    handle: BCRYPT_KEY_HANDLE,
}

impl KeyPair {
    pub fn generate(provider: &AsymmetricAlgorithm, length: u32) -> Result<KeyPairBuilder> {
        let mut handle: BCRYPT_KEY_HANDLE = null_mut();

        crate::Error::check(unsafe {
            BCryptGenerateKeyPair(provider.handle.as_ptr(), &mut handle, length as ULONG, 0)
        })?;

        Ok(KeyPairBuilder {
            _provider: provider,
            handle,
        })
    }

    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, KeyPair};
    ///
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Dsa).unwrap();
    /// let pair = KeyPair::generate(&algo, 1024).expect("key to be generated").finalize();
    ///
    /// let blob = pair.export().unwrap();
    /// eprintln!("{:?}", blob.as_ref().dwMagic);
    /// assert_eq!(blob.as_ref().dwMagic, winapi::shared::bcrypt::BCRYPT_DSA_PUBLIC_MAGIC);
    /// ```
    pub fn export(&self) -> Result<TypedBlob<BCRYPT_DSA_KEY_BLOB>> {
        // TODO: Handle generically different key types
        let property = WindowsString::from_str(BCRYPT_DSA_PUBLIC_BLOB);

        let mut bytes: ULONG = 0;
        unsafe {
            Error::check(BCryptExportKey(
                self.0.as_ptr(),
                null_mut(),
                property.as_ptr(),
                null_mut(),
                0,
                &mut bytes,
                0,
            ))?;
        }
        let mut blob = vec![0u8; bytes as usize].into_boxed_slice();

        unsafe {
            Error::check(BCryptExportKey(
                self.0.as_ptr(),
                null_mut(),
                property.as_ptr(),
                blob.as_mut_ptr(),
                bytes,
                &mut bytes,
                0,
            ))?;
        }

        Ok(unsafe { TypedBlob::<BCRYPT_DSA_KEY_BLOB>::from_box(blob) })
    }
}

impl KeyPairBuilder<'_> {
    /// # Examples
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, KeyPair};
    ///
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
    /// let pair = KeyPair::generate(&algo, 1024).expect("key to be generated").finalize();
    /// assert!(KeyPair::generate(&algo, 1023).is_err(), "key length is invalid");
    /// ```
    pub fn finalize(self) -> KeyPair {
        Error::check(unsafe { BCryptFinalizeKeyPair(self.handle, 0) })
            .map(|_| {
                KeyPair(KeyHandle {
                    handle: self.handle,
                })
            })
            .expect("internal library error")
    }
}
