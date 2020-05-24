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
use crate::Result;
use std::convert::TryFrom;
use std::marker::PhantomData;
use winapi::shared::bcrypt::*;

use builder::KeyPair;

pub mod builder;

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
    pub fn to_str(&self) -> &str {
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

    pub fn key_bits(&self) -> Option<u32> {
        match self {
            AsymmetricAlgorithmId::EcdhP256 => Some(256),
            AsymmetricAlgorithmId::EcdhP384 => Some(384),
            AsymmetricAlgorithmId::EcdhP521 => Some(521),
            AsymmetricAlgorithmId::EcdsaP256 => Some(256),
            AsymmetricAlgorithmId::EcdsaP384 => Some(384),
            AsymmetricAlgorithmId::EcdsaP521 => Some(521),
            _ => None,
        }
    }

    pub fn is_key_bits_supported(&self, key_bits: u32) -> bool {
        match (self, key_bits, key_bits % 64) {
            | (AsymmetricAlgorithmId::Dh, 512..=4096, 0)
            | (AsymmetricAlgorithmId::Rsa, 512..=16384, 0)
            // Prior to Windows 8, only values <= 1024 are supported,
            // after that it's <= 3072.
            // TODO: Check version using winapi::um::winbase::VerifyVersionInfoW
            | (AsymmetricAlgorithmId::Dsa, 512..=3072, ..)
            | (AsymmetricAlgorithmId::EcdhP256, 256, ..)
            | (AsymmetricAlgorithmId::EcdhP384, 384, ..)
            | (AsymmetricAlgorithmId::EcdhP521, 521, ..)
            | (AsymmetricAlgorithmId::EcdsaP256, 256, ..)
            | (AsymmetricAlgorithmId::EcdsaP384, 384, ..)
            | (AsymmetricAlgorithmId::EcdsaP521, 521, ..) => true,
            _ => false,
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

/// Marker trait for an asymmetric algorithm.
pub trait Algorithm {
    fn id(&self) -> AsymmetricAlgorithmId;
}

macro_rules! algo_struct {
    (pub struct $ident: ident, $algo: expr) => {
        pub struct $ident;
        impl Algorithm for $ident {
            #[inline(always)]
            fn id(&self) -> AsymmetricAlgorithmId {
                $algo
            }
        }
    };
}

algo_struct!(pub struct Dh, AsymmetricAlgorithmId::Dh);
algo_struct!(pub struct Dsa, AsymmetricAlgorithmId::Dsa);
algo_struct!(pub struct EcdhP256, AsymmetricAlgorithmId::EcdhP256);
algo_struct!(pub struct EcdhP384, AsymmetricAlgorithmId::EcdhP384);
algo_struct!(pub struct EcdhP521, AsymmetricAlgorithmId::EcdhP521);
algo_struct!(pub struct EcdsaP256, AsymmetricAlgorithmId::EcdsaP256);
algo_struct!(pub struct EcdsaP384, AsymmetricAlgorithmId::EcdsaP384);
algo_struct!(pub struct EcdsaP521, AsymmetricAlgorithmId::EcdsaP521);
algo_struct!(pub struct Rsa, AsymmetricAlgorithmId::Rsa);

pub trait Parts {}
pub struct Private {}
impl Parts for Private {}
pub struct Public {}
impl Parts for Public {}

impl Algorithm for AsymmetricAlgorithmId {
    fn id(&self) -> AsymmetricAlgorithmId {
        *self
    }
}

pub struct AsymmetricKey<A: Algorithm = AsymmetricAlgorithmId, P: Parts = Public>(
    KeyHandle,
    A,
    PhantomData<P>,
);

impl AsymmetricKey {
    pub fn id(&self) -> AsymmetricAlgorithmId {
        Algorithm::id(&self.1)
    }
}

impl<A: Algorithm, P: Parts> AsymmetricKey<A, P> {
    pub fn into_handle(self) -> KeyHandle {
        self.0
    }
}

impl<A: Algorithm, P: Parts> From<(KeyHandle, A)> for AsymmetricKey<A, P> {
    fn from(handle: (KeyHandle, A)) -> Self {
        Self(handle.0, handle.1, PhantomData)
    }
}

use crate::key::{RsaFullPrivate, RsaPublic};

impl AsymmetricKey<Rsa, Private> {
    ///
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// # use win_crypto_ng::asymmetric::{Algorithm, Rsa, Private, AsymmetricKey};
    /// # use win_crypto_ng::key::{BlobType, RsaPublic, RsaPrivate};
    /// # use win_crypto_ng::key::{RsaKeyBlobFullPrivate, RsaKeyPublicView};
    ///
    /// let pair = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();
    /// let blob = pair.export_full().unwrap();
    /// let (modulus, prime1) = (blob.modulus().to_owned(), blob.prime1().to_owned());
    ///
    /// let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
    /// let imported = AsymmetricKey::<Rsa, Private>::import(&provider, blob).unwrap();
    /// let imported_blob = imported.export_full().unwrap();
    /// assert_eq!(modulus, imported_blob.modulus());
    /// assert_eq!(prime1, imported_blob.prime1());
    /// ```
    pub fn import(
        provider: &AsymmetricAlgorithm,
        blob: TypedBlob<crate::key::RsaFullPrivate>,
    ) -> Result<Self> {
        if provider.id()? != AsymmetricAlgorithmId::Rsa {
            return Err(crate::Error::InvalidParameter);
        };

        KeyPair::import(provider, blob.into(), true).map(|pair| Self::from((pair.0, Rsa)))
    }

    pub fn export_public(&self) -> Result<TypedBlob<RsaPublic>> {
        Ok(KeyPair::export(self.0.handle, BlobType::RsaPublic)?
            .try_into::<RsaPublic>()
            .expect("Guaranteed"))
    }

    /// Attempts to export the key to a given blob type.
    /// # Example
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// # use win_crypto_ng::asymmetric::{Algorithm, Rsa, Private, AsymmetricKey};
    /// # use win_crypto_ng::key::{BlobType, RsaPublic, RsaPrivate};
    /// # use win_crypto_ng::key::{RsaKeyBlobFullPrivate, RsaKeyPublicView};
    ///
    /// let pair = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();
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

trait Import<A: Algorithm, P: Parts> {
    type Blob: Into<TypedBlob<BCRYPT_KEY_BLOB>>;
    fn import(
        algo: A,
        provider: &AsymmetricAlgorithm,
        blob: Self::Blob,
    ) -> Result<AsymmetricKey<A, P>> {
        if provider.id()? != algo.id() {
            return Err(crate::Error::InvalidParameter);
        };

        KeyPair::import(provider, blob.into(), true)
            .map(|pair| AsymmetricKey::<A, P>::from((pair.0, algo)))
    }
}

macro_rules! import_blobs {
    ($(($algorithm: ident, $parts: ident, $blob: ty)),*$(,)?) => {
        $(
        impl Import<$algorithm, $parts> for AsymmetricKey<$algorithm, $parts> {
            type Blob = $blob;
        }
        )*
    };
}

use crate::key::*;

enum DsaPublicBlob {
    V1(TypedBlob<DsaPublic>),
    V2(TypedBlob<DsaPublicV2>),
}

impl Into<TypedBlob<BCRYPT_KEY_BLOB>> for DsaPublicBlob {
    fn into(self) -> TypedBlob<BCRYPT_KEY_BLOB> {
        match self {
            DsaPublicBlob::V1(v1) => v1.into(),
            DsaPublicBlob::V2(v2) => v2.into(),
        }
    }
}

enum DsaPrivateBlob {
    V1(TypedBlob<DsaPrivate>),
    V2(TypedBlob<DsaPrivateV2>),
}

impl Into<TypedBlob<BCRYPT_KEY_BLOB>> for DsaPrivateBlob {
    fn into(self) -> TypedBlob<BCRYPT_KEY_BLOB> {
        match self {
            DsaPrivateBlob::V1(v1) => v1.into(),
            DsaPrivateBlob::V2(v2) => v2.into(),
        }
    }
}

import_blobs!(
    (Dh, Public, TypedBlob<DhPublic>),
    (Dh, Private, TypedBlob<DhPrivate>),
    (Dsa, Public, DsaPublicBlob),
    (Dsa, Private, DsaPrivateBlob),
    (EcdhP256, Public, TypedBlob<EcdhP256Public>),
    (EcdhP256, Private, TypedBlob<EcdhP256Private>),
    (EcdhP384, Public, TypedBlob<EcdhP384Public>),
    (EcdhP384, Private, TypedBlob<EcdhP384Private>),
    (EcdhP521, Public, TypedBlob<EcdhP521Public>),
    (EcdhP521, Private, TypedBlob<EcdhP521Private>),
    (EcdsaP256, Public, TypedBlob<EcdsaP256Public>),
    (EcdsaP256, Private, TypedBlob<EcdsaP256Private>),
    (EcdsaP384, Public, TypedBlob<EcdsaP384Public>),
    (EcdsaP384, Private, TypedBlob<EcdsaP384Private>),
    (EcdsaP521, Public, TypedBlob<EcdsaP521Public>),
    (EcdsaP521, Private, TypedBlob<EcdsaP521Private>),
    (Rsa, Public, TypedBlob<RsaPublic>),
    (Rsa, Private, TypedBlob<RsaPrivate>),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import() {
        let generated = AsymmetricKey::builder(Rsa).key_bits(1024).build();
        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();

        // let blob =
        // let imported = AsymmetricKey::import(&provider, blob: TypedBlob<crate::key::RsaPrivate>)
        panic!();
    }
}
