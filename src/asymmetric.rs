//! Asymmetric algorithms
//!
//! Asymmetric algorithms (also known as public-key algorithms) use pairs of
//! keys: *public key*, which can be known by others, and *private key*, which
//! is known only to the owner. The most common usages include encryption and
//! digital signing.
//!
//! > **NOTE**: This is currently a stub and should be expanded.

use crate::handle::{AlgoHandle, KeyHandle};
use crate::helpers::blob::{Blob, BlobLayout};
use crate::helpers::WideCString;
use crate::key::{BlobType, ErasedKeyBlob};
use crate::property::{Access, AlgorithmName, EccCurveName};
use crate::Result;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::marker::PhantomData;
use winapi::shared::bcrypt::*;

use builder::KeyPair;
use ecc::{Curve, NamedCurve};
use ecc::{Curve25519, NistP256, NistP384, NistP521};

pub mod builder;
pub mod ecc;

/// Asymmetric algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// Generic prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A, FIPS 186-2 (Curves P-{256, 384, 521}).
    Ecdh(NamedCurve),
    /// Generic prime elliptic curve digital signature algorithm.
    ///
    /// Standard: ANSI X9.62, FIPS 186-2 (Curves P-{256, 384, 521}).
    Ecdsa(NamedCurve),
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
            Self::Ecdh(NamedCurve::NistP256) => BCRYPT_ECDH_P256_ALGORITHM,
            Self::Ecdh(NamedCurve::NistP384) => BCRYPT_ECDH_P384_ALGORITHM,
            Self::Ecdh(NamedCurve::NistP521) => BCRYPT_ECDH_P521_ALGORITHM,
            Self::Ecdh(..) => BCRYPT_ECDH_ALGORITHM,
            Self::Ecdsa(NamedCurve::NistP256) => BCRYPT_ECDSA_P256_ALGORITHM,
            Self::Ecdsa(NamedCurve::NistP384) => BCRYPT_ECDSA_P384_ALGORITHM,
            Self::Ecdsa(NamedCurve::NistP521) => BCRYPT_ECDSA_P521_ALGORITHM,
            Self::Ecdsa(..) => BCRYPT_ECDSA_ALGORITHM,
            Self::Rsa => BCRYPT_RSA_ALGORITHM,
        }
    }

    pub fn key_bits(&self) -> Option<u32> {
        match self {
            Self::Ecdh(curve) | Self::Ecdsa(curve) => Some(curve.key_bits()),
            _ => None,
        }
    }

    pub fn is_key_bits_supported(&self, key_bits: u32) -> bool {
        match (self, key_bits) {
            | (Self::Dh, 512..=4096)
            | (Self::Rsa, 512..=16384)
            // Prior to Windows 8, only values <= 1024 are supported,
            // after that it's <= 3072.
            // TODO: Check version using winapi::um::winbase::VerifyVersionInfoW
            | (Self::Dsa, 512..=3072) if key_bits % 64 == 0 => true,
            | (Self::Ecdh(curve), bits)
            | (Self::Ecdsa(curve), bits) if curve.key_bits() == bits => true,
            _ => false,
        }
    }
}

impl<'a> TryFrom<&'a str> for AsymmetricAlgorithmId {
    type Error = &'a str;

    fn try_from(val: &'a str) -> Result<AsymmetricAlgorithmId, Self::Error> {
        match val {
            BCRYPT_DH_ALGORITHM => Ok(Self::Dh),
            BCRYPT_DSA_ALGORITHM => Ok(Self::Dsa),
            BCRYPT_ECDH_P256_ALGORITHM => Ok(Self::Ecdh(NamedCurve::NistP256)),
            BCRYPT_ECDH_P384_ALGORITHM => Ok(Self::Ecdh(NamedCurve::NistP384)),
            BCRYPT_ECDH_P521_ALGORITHM => Ok(Self::Ecdh(NamedCurve::NistP521)),
            BCRYPT_ECDSA_P256_ALGORITHM => Ok(Self::Ecdsa(NamedCurve::NistP256)),
            BCRYPT_ECDSA_P384_ALGORITHM => Ok(Self::Ecdsa(NamedCurve::NistP384)),
            BCRYPT_ECDSA_P521_ALGORITHM => Ok(Self::Ecdsa(NamedCurve::NistP521)),
            BCRYPT_RSA_ALGORITHM => Ok(Self::Rsa),
            // TODO: Make curves optional in {Ecdh, Ecdsa}?
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

        // The provider for elliptic algorithms using NIST P-{256,384,521}
        // curves is separate from the generic one and does not support setting
        // properties
        match id {
            AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP256)
            | AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP384)
            | AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP521)
            | AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP256)
            | AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP384)
            | AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP521) => {}
            AsymmetricAlgorithmId::Ecdh(curve) | AsymmetricAlgorithmId::Ecdsa(curve) => {
                let property = WideCString::from(curve.as_str());

                handle.set_property::<EccCurveName>(property.as_slice_with_nul())?;
            }
            _ => {}
        }

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
        let name = self
            .handle
            .get_property_unsized::<AlgorithmName>()
            .map(|name| WideCString::from_bytes_with_nul(name).to_string())?;

        AsymmetricAlgorithmId::try_from(name.as_str()).map_err(|_| crate::Error::InvalidHandle)
    }
}

pub struct Ecdsa<C: Curve>(C);
impl<C: Curve> Algorithm for Ecdsa<C> {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Ecdsa(self.0.as_curve())
    }
}

pub struct Ecdh<C: Curve>(C);
impl<C: Curve> Algorithm for Ecdh<C> {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Ecdh(self.0.as_curve())
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

impl<A: Algorithm, P: Parts> AsymmetricKey<A, P> {
    pub fn id(&self) -> AsymmetricAlgorithmId {
        Algorithm::id(&self.1)
    }

    pub fn into_handle(self) -> KeyHandle {
        self.0
    }
}

impl<A: Algorithm> AsymmetricKey<A, Private> {
    pub fn as_public(&self) -> &AsymmetricKey<A, Public> {
        // NOTE: This assumes that Private is always a key pair
        unsafe { &*(self as *const _ as *const AsymmetricKey<A, Public>) }
    }
}

impl<A: Algorithm, P: Parts> From<(KeyHandle, A)> for AsymmetricKey<A, P> {
    fn from(handle: (KeyHandle, A)) -> Self {
        Self(handle.0, handle.1, PhantomData)
    }
}

impl AsymmetricKey<Rsa, Private> {
    /// Attempts to export the key to a given blob type.
    /// # Example
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// # use win_crypto_ng::asymmetric::{Algorithm, Rsa, Private, AsymmetricKey};
    /// # use win_crypto_ng::asymmetric::Export;
    ///
    /// let pair = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();
    /// let blob = pair.as_public().export().unwrap();
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
    pub fn export_full(&self) -> Result<Box<Blob<RsaKeyFullPrivateBlob>>> {
        Ok(KeyPair::export(self.0.handle, BlobType::RsaFullPrivate)?
            .try_into()
            .map_err(|_| crate::Error::BadData)?)
    }
}

pub trait Import<'a, A: Algorithm, P: Parts> {
    type Blob: AsRef<Blob<ErasedKeyBlob>> + 'a;
    fn import(
        algo: A,
        provider: &AsymmetricAlgorithm,
        blob: Self::Blob,
    ) -> Result<AsymmetricKey<A, P>> {
        if provider.id()? != algo.id() {
            return Err(crate::Error::InvalidParameter);
        };

        KeyPair::import(provider, blob.as_ref(), true)
            .map(|pair| AsymmetricKey::<A, P>::from((pair.0, algo)))
    }
}

macro_rules! import_blobs {
    ($(($algorithm: ty, $parts: ident, $blob: ty)),*$(,)?) => {
        $(
        impl<'a> Import<'a, $algorithm, $parts> for AsymmetricKey<$algorithm, $parts> {
            type Blob = $blob;
        }
        )*
    };
}

import_blobs!(
    (AsymmetricAlgorithmId, Public, &'a Blob<ErasedKeyBlob>),
    (AsymmetricAlgorithmId, Private, &'a Blob<ErasedKeyBlob>),
    (Dh, Public, &'a Blob<DhKeyPublicBlob>),
    (Dh, Private, &'a Blob<DhKeyPrivateBlob>),
    (Dsa, Public, DsaPublicBlob),
    (Dsa, Private, DsaPrivateBlob),
    (Ecdh<NistP256>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdh<NistP256>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Ecdh<NistP384>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdh<NistP384>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Ecdh<NistP521>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdh<NistP521>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Ecdh<Curve25519>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdh<Curve25519>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Ecdsa<NistP256>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdsa<NistP256>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Ecdsa<NistP384>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdsa<NistP384>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Ecdsa<NistP521>, Public, &'a Blob<EccKeyPublicBlob>),
    (Ecdsa<NistP521>, Private, &'a Blob<EccKeyPrivateBlob>),
    (Rsa, Public, &'a Blob<RsaKeyPublicBlob>),
    (Rsa, Private, &'a Blob<RsaKeyPrivateBlob>),
);

/// Attempts to export the key to a given blob type.
///
/// # Example
/// ```
/// use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
/// use win_crypto_ng::asymmetric::{Algorithm, Rsa, Private, AsymmetricKey};
/// use win_crypto_ng::asymmetric::Export;
///
/// let pair = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();
/// let blob = pair.as_public().export().unwrap();
/// dbg!(blob.as_bytes());
///
/// let public = blob;
/// let pub_exp = public.pub_exp();
/// let modulus = public.modulus();
///
/// let private = pair.export().unwrap();
/// assert_eq!(pub_exp, private.pub_exp());
/// assert_eq!(modulus, private.modulus());
/// ```
pub trait Export<A: Algorithm, P: Parts>: Borrow<AsymmetricKey<A, P>> {
    type Blob: KeyBlob + BlobLayout;

    #[doc(hidden)]
    fn blob_type(&self) -> BlobType;

    fn export(&self) -> Result<Box<Blob<Self::Blob>>> {
        let key = self.borrow();
        let blob_type = self.blob_type();

        let blob = KeyPair::export(key.0.handle, blob_type)?;
        Ok(blob.try_into().map_err(|_| crate::Error::BadData)?)
    }
}

macro_rules! export_blobs {
    ($type: ty, $parts: ty, $blob: ty, $blob_type: expr) => {
        impl<'a> Export<$type, $parts> for AsymmetricKey<$type, $parts> {
            type Blob = $blob;

            fn blob_type(&self) -> BlobType {
                $blob_type
            }
        }
    };
}

export_blobs!(
    AsymmetricAlgorithmId,
    Public,
    ErasedKeyBlob,
    BlobType::PublicKey
);
export_blobs!(
    AsymmetricAlgorithmId,
    Private,
    ErasedKeyBlob,
    BlobType::PrivateKey
);
export_blobs!(Dh, Public, DhKeyPublicBlob, BlobType::DhPublic);
export_blobs!(Dh, Private, DhKeyPrivateBlob, BlobType::DhPrivate);
export_blobs!(Dsa, Public, DsaKeyPublicBlob, BlobType::DsaPublic);
export_blobs!(Dsa, Private, DsaKeyPrivateBlob, BlobType::DsaPrivate);
export_blobs!(
    Ecdh<NistP256>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdh<NistP256>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(
    Ecdh<NistP384>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdh<NistP384>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(
    Ecdh<NistP521>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdh<NistP521>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(
    Ecdsa<NistP256>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdsa<NistP256>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(
    Ecdsa<NistP384>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdsa<NistP384>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(
    Ecdsa<NistP521>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdsa<NistP521>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(
    Ecdh<Curve25519>,
    Public,
    EccKeyPublicBlob,
    BlobType::EccPublic
);
export_blobs!(
    Ecdh<Curve25519>,
    Private,
    EccKeyPrivateBlob,
    BlobType::EccPrivate
);
export_blobs!(Rsa, Public, RsaKeyPublicBlob, BlobType::RsaPublic);
export_blobs!(Rsa, Private, RsaKeyPrivateBlob, BlobType::RsaPrivate);

use crate::key::*;

pub enum DsaPublicBlob {
    V1(Box<Blob<DsaKeyPublicBlob>>),
    V2(Box<Blob<DsaKeyPublicV2Blob>>),
}

impl<'a> AsRef<Blob<ErasedKeyBlob>> for DsaPublicBlob {
    fn as_ref(&self) -> &Blob<ErasedKeyBlob> {
        match self {
            DsaPublicBlob::V1(v1) => v1.as_erased(),
            DsaPublicBlob::V2(v2) => v2.as_erased(),
        }
    }
}

pub enum DsaPrivateBlob {
    V1(Box<Blob<DsaKeyPrivateBlob>>),
    V2(Box<Blob<DsaKeyPrivateV2Blob>>),
}

impl<'a> AsRef<Blob<ErasedKeyBlob>> for DsaPrivateBlob {
    fn as_ref(&self) -> &Blob<ErasedKeyBlob> {
        match self {
            DsaPrivateBlob::V1(v1) => v1.as_erased(),
            DsaPrivateBlob::V2(v2) => v2.as_erased(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_export() -> Result<()> {
        let dynamic = AsymmetricKey::builder(AsymmetricAlgorithmId::Rsa)
            .key_bits(1024)
            .build()?;
        let blob = dynamic.export()?;
        let blob = blob.try_into().unwrap_or_else(|_| panic!());

        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
        let imported = AsymmetricKey::<_, Private>::import(Rsa, &provider, &blob)?;
        let imported_blob = imported.export()?;

        assert_eq!(blob.modulus(), imported_blob.modulus());
        assert_eq!(blob.pub_exp(), imported_blob.pub_exp());
        assert_eq!(blob.prime1(), imported_blob.prime1());

        let key = AsymmetricKey::builder(Ecdsa(NistP521)).build()?;
        let blob = key.export().unwrap();
        dbg!(blob.x().len());
        dbg!(blob.y().len());
        dbg!(blob.d().len());

        let key = AsymmetricKey::builder(Ecdh(Curve25519)).build()?;
        let blob = key.export()?;
        dbg!(blob.x().len());
        dbg!(blob.y().len());
        dbg!(blob.d().len());
        Ok(())
    }
}
