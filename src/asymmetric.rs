//! Asymmetric algorithms
//!
//! Asymmetric algorithms (also known as public-key algorithms) use pairs of
//! keys: *public key*, which can be known by others, and *private key*, which
//! is known only to the owner. The most common usages include encryption and
//! digital signing.
//!
//! > **NOTE**: This is currently a stub and should be expanded.

use crate::helpers::{AlgoHandle, Handle, TypedBlob, WindowsString};
use crate::key::{BlobType, KeyHandle};
use crate::property::AlgorithmName;
use crate::{Error, Result};
use std::convert::TryFrom;
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

impl<'a> TryFrom<&'a str> for AsymmetricAlgorithmId {
    type Error = &'a str;

    fn try_from(val: &'a str) -> std::result::Result<AsymmetricAlgorithmId, Self::Error> {
        match val {
            BCRYPT_DH_ALGORITHM => Ok(Self::Dh),
            BCRYPT_DSA_ALGORITHM => Ok(Self::Dsa),
            BCRYPT_ECDH_P256_ALGORITHM => Ok(Self::EcdhP256),
            BCRYPT_ECDH_P384_ALGORITHM => Ok(Self::EcdhP384),
            BCRYPT_ECDH_P521_ALGORITHM => Ok(Self::EcdhP521),
            BCRYPT_ECDSA_P256_ALGORITHM => Ok(Self::EcdsaP256),
            BCRYPT_ECDSA_P384_ALGORITHM => Ok(Self::EcdsaP384),
            BCRYPT_ECDSA_P521_ALGORITHM => Ok(Self::EcdsaP521),
            BCRYPT_RSA_ALGORITHM => Ok(Self::Rsa),
            val => Err(val),
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

    ///
    /// # Examples
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
    /// assert_eq!(algo.id(), Ok(AsymmetricAlgorithmId::Rsa));
    /// ```
    pub fn id(&self) -> Result<AsymmetricAlgorithmId> {
        let name = self.handle.get_property_unsized::<AlgorithmName>()?;
        let name = WindowsString::from_ptr(name.as_ref().as_ptr());

        AsymmetricAlgorithmId::try_from(&*name.to_string()).map_err(|_| crate::Error::InvalidHandle)
    }
}

use std::marker::PhantomData;

macro_rules! algo_struct {
    (pub struct $ident: ident, $algo: expr) => {
        pub struct $ident {}
        impl Algo for $ident { const ID: AsymmetricAlgorithmId = $algo; }
    };
}
pub trait Algo {
    const ID: AsymmetricAlgorithmId;
}
algo_struct!(pub struct Dh, AsymmetricAlgorithmId::Dh);
algo_struct!(pub struct Dsa, AsymmetricAlgorithmId::Dsa);
algo_struct!(pub struct Ecdh256, AsymmetricAlgorithmId::EcdhP256);
algo_struct!(pub struct Ecdh384, AsymmetricAlgorithmId::EcdhP384);
algo_struct!(pub struct Ecdh521, AsymmetricAlgorithmId::EcdhP521);
algo_struct!(pub struct Ecdsa256, AsymmetricAlgorithmId::EcdsaP256);
algo_struct!(pub struct Ecdsa384, AsymmetricAlgorithmId::EcdsaP384);
algo_struct!(pub struct Ecdsa521, AsymmetricAlgorithmId::EcdsaP521);
algo_struct!(pub struct Rsa, AsymmetricAlgorithmId::Rsa);

pub trait Parts {}
pub struct Private {}
impl Parts for Private {}
pub struct Public {}
impl Parts for Public {}

pub struct AsymmetricKey<A: Algo,  P: Parts = Public>(KeyHandle, PhantomData<A>, PhantomData<P>);

impl<A: Algo, P: Parts> From<KeyHandle> for AsymmetricKey<A, P> {
    fn from(handle: KeyHandle) -> Self {
        Self(handle, PhantomData, PhantomData)
    }
}

impl<A: Algo, P: Parts> From<KeyPair> for AsymmetricKey<A, P> {
    fn from(handle: KeyPair) -> Self {
        Self(handle.0, PhantomData, PhantomData)
    }
}

impl<A: Algo, P: Parts> From<AsymmetricKey<A, P>> for KeyPair {
    fn from(handle: AsymmetricKey<A, P>) -> Self {
        KeyPair(handle.0)
    }
}

use crate::key::{RsaFullPrivate, RsaPublic};

impl AsymmetricKey<Rsa, Private> {
    pub fn generate(length: u32) -> Result<Self> {
        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
        let pair = KeyPair::generate(&provider, length)?.finalize();

        Ok(Self::from(pair.0))
    }

    pub fn export_public(&self) -> Result<TypedBlob<RsaPublic>> {
        Ok(KeyPair::export(self.0.handle, BlobType::RsaPublic)?
            .try_into::<RsaPublic>()
            .expect("Guaranteed"))
    }

    /// Attempts to export the key to a given blob type.
    /// # Example
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, KeyPair};
    /// # use win_crypto_ng::asymmetric::{Algo, Rsa, Private, AsymmetricKey};
    /// # use win_crypto_ng::key::{BlobType, RsaPublic, RsaPrivate};
    /// # use win_crypto_ng::key::{RsaKeyBlobFullPrivate, RsaKeyBlobPublic};
    ///
    /// let pair = AsymmetricKey::<Rsa, Private>::generate(1024).expect("key to be generated");
    /// let blob = pair.export_public().unwrap();
    /// dbg!(blob.as_bytes());
    ///
    /// let public = blob;
    /// let pub_exp = public.pub_exp();
    /// let modulus = public.modulus();
    ///
    /// let private = pair.export_full().unwrap();
    /// assert_eq!(pub_exp, private.pub_exp());
    /// assert_eq!(modulus, private.modulus());
    /// ```
    pub fn export_full(&self) -> Result<TypedBlob<RsaFullPrivate>> {
        Ok(KeyPair::export(self.0.handle, BlobType::RsaFullPrivate)?
            .try_into::<RsaFullPrivate>()
            .expect("Guaranteed"))
    }
}

pub struct KeyPair(KeyHandle);
impl KeyPair {
    pub fn as_raw_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.0.handle
    }
}

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


    pub fn export(handle: BCRYPT_KEY_HANDLE, kind: BlobType) -> Result<TypedBlob<BCRYPT_KEY_BLOB>> {
        let property = WindowsString::from_str(kind.as_value());

        let mut bytes: ULONG = 0;
        unsafe {
            Error::check(BCryptExportKey(
                handle,
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
                handle,
                null_mut(),
                property.as_ptr(),
                blob.as_mut_ptr(),
                bytes,
                &mut bytes,
                0,
            ))?;
        }

        Ok(unsafe { TypedBlob::from_box(blob) })
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
