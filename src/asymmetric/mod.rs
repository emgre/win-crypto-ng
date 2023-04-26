//! Asymmetric algorithms
//!
//! Asymmetric algorithms (also known as public-key algorithms) use pairs of
//! keys: *public key*, which can be known by others, and *private key*, which
//! is known only to the owner. The most common usages include encryption and
//! digital signing.

use crate::helpers::WindowsString;
use crate::helpers::{AlgoHandle, Handle, KeyHandle};
use crate::helpers::{Blob, BlobLayout};
use crate::key_blob::{BlobType, ErasedKeyBlob, *};
use crate::property::{AlgorithmName, EccCurveName};
use crate::Result;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;

use builder::KeyPair;
use ecc::{Curve, NamedCurve};
use ecc::{Curve25519, NistP256, NistP384, NistP521};

pub mod agreement;
pub mod builder;
pub mod ecc;
pub mod signature;

/// Asymmetric algorithm identifiers.
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

    pub fn key_bits(self) -> Option<u32> {
        match self {
            Self::Ecdh(curve) | Self::Ecdsa(curve) => Some(curve.key_bits()),
            _ => None,
        }
    }

    pub fn is_key_bits_supported(self, key_bits: u32) -> bool {
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

/// Asymmetric algorithm provider.
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
                let property = WindowsString::from(curve.to_str());

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
        self.handle
            .get_property_unsized::<AlgorithmName>()
            .map(|name| {
                WindowsString::from_bytes_with_nul(name.as_ref().into())
                    .expect("API to return 0-terminated wide string")
            })
            .and_then(|name| {
                AsymmetricAlgorithmId::try_from(name.to_string().as_str())
                    .map_err(|_| crate::Error::InvalidHandle)
            })
    }
}

/// Marker trait for an asymmetric algorithm.
pub trait Algorithm {
    fn id(&self) -> AsymmetricAlgorithmId;
}

/// Marker type representing the ECDSA (Elliptic Curve Digital Signature Algorithm).
pub struct Ecdsa<C: Curve>(pub C);
impl<C: Curve> Algorithm for Ecdsa<C> {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Ecdsa(self.0.as_curve())
    }
}

/// Marker type representing the ECDH (Elliptic Curve Diffie-Hellman) algorithm.
pub struct Ecdh<C: Curve>(pub C);
impl<C: Curve> Algorithm for Ecdh<C> {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Ecdh(self.0.as_curve())
    }
}

/// Marker type representing the DH (Diffie-Hellman) algorithm.
pub struct Dh;
impl Algorithm for Dh {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Dh
    }
}

/// Marker type representing the DSA (Digital Signature Algorithm).
pub struct Dsa;
impl Algorithm for Dsa {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Dsa
    }
}

/// Marker type representing the RSA (Rivest-Shamir-Adleman) algorithm.
pub struct Rsa;
impl Algorithm for Rsa {
    #[inline(always)]
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Rsa
    }
}

/// Marker trait used to denote whether a key holds public or private parts.
pub trait Parts {}
/// Marker type used to denote private key parts.
pub struct Private {}
impl Parts for Private {}
/// Marker type used to denote public key parts.
pub struct Public {}
impl Parts for Public {}

impl Algorithm for AsymmetricAlgorithmId {
    fn id(&self) -> AsymmetricAlgorithmId {
        *self
    }
}

/// Asymmetric key handle.
///
/// Can be specified as that of which type is known at run-time (erased) or
/// with a concrete algorithm parameter.
///
/// ## Type-safety
/// At the time of writing, all of the relevant crypto operations are
/// implemented for only keys whose algorithm is statically known. This means
/// that the keys using the dynamic `AsymmetricAlgorithmId` need to be
/// re-imported in order to statically verify the algorithm used.
///
/// ```
/// use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey};
/// use win_crypto_ng::asymmetric::{Rsa, Private, Import, Export};
///
/// let dynamic: AsymmetricKey<AsymmetricAlgorithmId, Private> =
///     AsymmetricKey::builder(AsymmetricAlgorithmId::Rsa).key_bits(512).build().unwrap();
/// let dynamic_blob = dynamic.export().unwrap();
///
/// let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
/// let rsa_blob = dynamic_blob.try_into().unwrap_or_else(|_| panic!());
/// let rsa_key = AsymmetricKey::<Rsa, Private>::import(Rsa, &provider, &rsa_blob).unwrap();
/// // Can now additional impls for `AsymmetricKey<Rsa, Private>`, e.g.
/// // rsa_key.decrypt(..);
/// ```
///
/// ## Generation
/// ```
/// use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey};
/// use win_crypto_ng::asymmetric::{Rsa, Private};
///
/// // Handle to an asymmetric key whose algorithm ID is known at run-time
/// let handle: AsymmetricKey<AsymmetricAlgorithmId, Private> =
///     AsymmetricKey::builder(AsymmetricAlgorithmId::Rsa).key_bits(512).build().unwrap();
///
/// // Handle to an asymmetric key whose algorithm is known to be RSA
/// let handle: AsymmetricKey<Rsa, Private> =
///     AsymmetricKey::builder(Rsa).key_bits(512).build().unwrap();
/// ```
pub struct AsymmetricKey<A: Algorithm = AsymmetricAlgorithmId, P: Parts = Public>(
    KeyHandle,
    A,
    PhantomData<P>,
);

impl<A: Algorithm, P: Parts> AsymmetricKey<A, P> {
    /// Returns the asymmetric algorithm ID known at run-time.
    pub fn id(&self) -> AsymmetricAlgorithmId {
        Algorithm::id(&self.1)
    }
}

impl<A: Algorithm> AsymmetricKey<A, Private> {
    /// Views the key pair as having only public key parts.
    pub fn as_public(&self) -> &AsymmetricKey<A, Public> {
        // NOTE: This assumes that Private is always a key pair
        unsafe { &*(self as *const _ as *const AsymmetricKey<A, Public>) }
    }
}

impl AsymmetricKey<Rsa, Private> {
    /// Export the RSA key to "full" raw data format. Additionally includes
    /// coefficient and (private) exponents.
    pub fn export_full(&self) -> Result<Box<Blob<RsaKeyFullPrivateBlob>>> {
        KeyPair::export(self.0.handle, BlobType::RsaFullPrivate)?
            .try_into()
            .map_err(|_| crate::Error::BadData)
    }
}

/// Import asymmetric key using the raw key data format.
pub trait Import<'a, A: Algorithm, P: Parts> {
    type Blob: AsRef<Blob<ErasedKeyBlob>> + 'a;
    fn import(
        algo: A,
        provider: &AsymmetricAlgorithm,
        blob: Self::Blob,
    ) -> Result<AsymmetricKey<A, P>> {
        KeyPair::import(provider, blob.as_ref(), true)
            .map(|pair| AsymmetricKey(pair.0, algo, PhantomData))
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

// TODO: Come up with an ergonomic high-level API for key importing from parts
impl AsymmetricKey<Rsa, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &RsaKeyPrivatePayload,
    ) -> Result<Self> {
        let key_bits = parts.modulus.len() * 8;
        if key_bits % 64 != 0 || !(512..=16384).contains(&key_bits) {
            return Err(crate::Error::InvalidParameter);
        }

        let header = BCRYPT_RSAKEY_BLOB {
            BitLength: key_bits as u32,
            Magic: BCRYPT_RSAPRIVATE_MAGIC,
            cbModulus: parts.modulus.len() as u32,
            cbPublicExp: parts.pub_exp.len() as u32,
            cbPrime1: parts.prime1.len() as u32,
            cbPrime2: parts.prime2.len() as u32,
        };
        let blob = Blob::<RsaKeyPrivateBlob>::clone_from_parts(&header, parts);

        <Self as Import<_, _>>::import(Rsa, provider, &blob)
    }
}

impl AsymmetricKey<Rsa, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &RsaKeyPublicPayload,
    ) -> Result<Self> {
        let key_bits = parts.modulus.len() * 8;
        if key_bits % 64 != 0 || !(512..=16384).contains(&key_bits) {
            return Err(crate::Error::InvalidParameter);
        }

        let header = BCRYPT_RSAKEY_BLOB {
            BitLength: key_bits as u32,
            Magic: BCRYPT_RSAPUBLIC_MAGIC,
            cbModulus: parts.modulus.len() as u32,
            cbPublicExp: parts.pub_exp.len() as u32,
            cbPrime1: 0,
            cbPrime2: 0,
        };
        let blob = Blob::<RsaKeyPublicBlob>::clone_from_parts(&header, parts);

        <Self as Import<_, _>>::import(Rsa, provider, &blob)
    }
}

impl AsymmetricKey<Ecdsa<NistP256>, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPrivatePayload,
    ) -> Result<Self> {
        let key_len = NistP256.key_bits() / 8;
        if [parts.x, parts.y, parts.d]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdsa(NistP256), provider, &blob)
    }
}

impl AsymmetricKey<Ecdsa<NistP256>, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPublicPayload,
    ) -> Result<Self> {
        let key_len = NistP256.key_bits() / 8;
        if [parts.x, parts.y]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdsa(NistP256), provider, &blob)
    }
}

impl AsymmetricKey<Ecdsa<NistP384>, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPrivatePayload,
    ) -> Result<Self> {
        let key_len = NistP384.key_bits() / 8;
        if [parts.x, parts.y, parts.d]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdsa(NistP384), provider, &blob)
    }
}

impl AsymmetricKey<Ecdsa<NistP384>, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPublicPayload,
    ) -> Result<Self> {
        let key_len = NistP384.key_bits() / 8;
        if [parts.x, parts.y]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdsa(NistP384), provider, &blob)
    }
}

impl AsymmetricKey<Ecdsa<NistP521>, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPrivatePayload,
    ) -> Result<Self> {
        let key_len = (NistP521.key_bits() + 7) / 8;
        if [parts.x, parts.y, parts.d]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDSA_PRIVATE_P521_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdsa(NistP521), provider, &blob)
    }
}

impl AsymmetricKey<Ecdsa<NistP521>, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPublicPayload,
    ) -> Result<Self> {
        let key_len = (NistP521.key_bits() + 7) / 8;
        if [parts.x, parts.y]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdsa(NistP521), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<Curve25519>, Private> {
    pub fn import_from_parts(provider: &AsymmetricAlgorithm, private: &[u8]) -> Result<Self> {
        let key_len = (Curve25519.key_bits() + 7) / 8;
        if private.len() != key_len as usize {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC,
                cbKey: key_len,
            },
            &EccKeyPrivatePayload {
                x: &[0u8; 32],
                y: &[0u8; 32],
                d: private,
            },
        );

        <Self as Import<_, _>>::import(Ecdh(Curve25519), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<Curve25519>, Public> {
    pub fn import_from_parts(provider: &AsymmetricAlgorithm, public: &[u8]) -> Result<Self> {
        let key_len = (Curve25519.key_bits() + 7) / 8;
        if public.len() != key_len as usize {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
                cbKey: key_len,
            },
            &EccKeyPublicPayload {
                x: public,
                y: &[0u8; 32],
            },
        );

        <Self as Import<_, _>>::import(Ecdh(Curve25519), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<NistP256>, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPrivatePayload,
    ) -> Result<Self> {
        let key_len = NistP256.key_bits() / 8;
        if [parts.x, parts.y, parts.d]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PRIVATE_P256_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdh(NistP256), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<NistP256>, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPublicPayload,
    ) -> Result<Self> {
        let key_len = NistP256.key_bits() / 8;
        if [parts.x, parts.y]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_P256_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdh(NistP256), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<NistP384>, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPrivatePayload,
    ) -> Result<Self> {
        let key_len = NistP384.key_bits() / 8;
        if [parts.x, parts.y, parts.d]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PRIVATE_P384_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdh(NistP384), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<NistP384>, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPublicPayload,
    ) -> Result<Self> {
        let key_len = NistP384.key_bits() / 8;
        if [parts.x, parts.y]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_P384_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdh(NistP384), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<NistP521>, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPrivatePayload,
    ) -> Result<Self> {
        let key_len = (NistP521.key_bits() + 7) / 8;
        if [parts.x, parts.y, parts.d]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPrivateBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PRIVATE_P521_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdh(NistP521), provider, &blob)
    }
}

impl AsymmetricKey<Ecdh<NistP521>, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &EccKeyPublicPayload,
    ) -> Result<Self> {
        let key_len = (NistP521.key_bits() + 7) / 8;
        if [parts.x, parts.y]
            .iter()
            .any(|v| v.len() != key_len as usize)
        {
            return Err(crate::Error::InvalidParameter);
        }

        let blob = Blob::<EccKeyPublicBlob>::clone_from_parts(
            &BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_P521_MAGIC,
                cbKey: key_len,
            },
            parts,
        );

        <Self as Import<_, _>>::import(Ecdh(NistP521), provider, &blob)
    }
}

/// Export asymmetric key to the raw key data format.
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
        blob.try_into().map_err(|_| crate::Error::BadData)
    }
}

macro_rules! export_blobs {
    ($(($type: ty, $parts: ty, $blob: ty, $blob_type: expr)),*$(,)?) => {
        $(
        impl<'a> Export<$type, $parts> for AsymmetricKey<$type, $parts> {
            type Blob = $blob;

            fn blob_type(&self) -> BlobType {
                $blob_type
            }
        }
        )*
    };
}

#[rustfmt::skip]
export_blobs!(
    (AsymmetricAlgorithmId, Public, ErasedKeyBlob, BlobType::PublicKey),
    (AsymmetricAlgorithmId, Private, ErasedKeyBlob, BlobType::PrivateKey),
    (Dh, Public, DhKeyPublicBlob, BlobType::DhPublic),
    (Dh, Private, DhKeyPrivateBlob, BlobType::DhPrivate),
    (Dsa, Public, DsaKeyPublicBlob, BlobType::DsaPublic),
    (Dsa, Private, DsaKeyPrivateBlob, BlobType::DsaPrivate),
    (Ecdh<NistP256>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdh<NistP256>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Ecdh<NistP384>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdh<NistP384>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Ecdh<NistP521>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdh<NistP521>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Ecdsa<NistP256>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdsa<NistP256>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Ecdsa<NistP384>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdsa<NistP384>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Ecdsa<NistP521>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdsa<NistP521>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Ecdh<Curve25519>, Public, EccKeyPublicBlob, BlobType::EccPublic),
    (Ecdh<Curve25519>, Private, EccKeyPrivateBlob, BlobType::EccPrivate),
    (Rsa, Public, RsaKeyPublicBlob, BlobType::RsaPublic),
    (Rsa, Private, RsaKeyPrivateBlob, BlobType::RsaPrivate),
);

/// Raw public DSA key data blob.
pub enum DsaPublicBlob {
    /// Used with keys having ≤ 1024 bit length.
    V1(Box<Blob<DsaKeyPublicBlob>>),
    /// Used with keys having > 1024 bit length.
    V2(Box<Blob<DsaKeyPublicV2Blob>>),
}

impl AsRef<Blob<ErasedKeyBlob>> for DsaPublicBlob {
    fn as_ref(&self) -> &Blob<ErasedKeyBlob> {
        match self {
            DsaPublicBlob::V1(v1) => v1.as_erased(),
            DsaPublicBlob::V2(v2) => v2.as_erased(),
        }
    }
}

/// Raw private DSA key data blob.
///
/// For keys of ≤ 1024 bit length, use the `V1` variant. Otherwise, use `V2`.
pub enum DsaPrivateBlob {
    V1(Box<Blob<DsaKeyPrivateBlob>>),
    V2(Box<Blob<DsaKeyPrivateV2Blob>>),
}

impl AsRef<Blob<ErasedKeyBlob>> for DsaPrivateBlob {
    fn as_ref(&self) -> &Blob<ErasedKeyBlob> {
        match self {
            DsaPrivateBlob::V1(v1) => v1.as_erased(),
            DsaPrivateBlob::V2(v2) => v2.as_erased(),
        }
    }
}

/// OAEP (Optimal Asymmetric Encryption Padding) data.
#[derive(Clone, Debug)]
pub struct OaepPadding {
    pub algorithm: crate::hash::HashAlgorithmId,
    pub label: Vec<u8>,
}

/// Supported encryption padding schemes.
#[derive(Clone, Debug)]
pub enum EncryptionPadding {
    /// OAEP (Optimal Asymmetric Encryption Padding) scheme.
    Oaep(OaepPadding),
    /// PKCS #1 padding scheme.
    Pkcs1,
}

struct OaepPaddingInfo<'a> {
    _borrowed: &'a OaepPadding,
    // Lifetime marker for borrowed hash algorithm identifier string
    // FIXME: Just use &'static [u16] for alg ID once winapi 0.4 is released
    value: BCRYPT_OAEP_PADDING_INFO,
}

impl OaepPadding {
    fn to_ffi_args(&self, out: &mut WindowsString) -> OaepPaddingInfo {
        *out = WindowsString::from(self.algorithm.to_str());
        OaepPaddingInfo {
            _borrowed: self,
            value: BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: out.as_ptr(),
                pbLabel: self.label.as_ptr() as *mut _,
                cbLabel: self.label.len() as u32,
            },
        }
    }
}

impl EncryptionPadding {
    fn to_ffi_args<'a>(&'a self, out: &'a mut WindowsString) -> (Option<OaepPaddingInfo<'a>>, u32) {
        match self {
            Self::Oaep(oaep_padding) => (Some(oaep_padding.to_ffi_args(out)), BCRYPT_PAD_OAEP),
            Self::Pkcs1 => (None, BCRYPT_PAD_PKCS1),
        }
    }
}

impl<P: Parts> AsymmetricKey<Rsa, P> {
    /// Encrypt a message using the RSA key.
    pub fn encrypt(&self, padding: Option<EncryptionPadding>, data: &[u8]) -> Result<Box<[u8]>> {
        let mut out = WindowsString::new();
        let padding = padding.as_ref().map(|x| x.to_ffi_args(&mut out));

        let (pad_info, flags) = padding.as_ref().unwrap_or(&(None, 0));
        let pad_info = pad_info
            .as_ref()
            .map(|pad| &pad.value as *const BCRYPT_OAEP_PADDING_INFO as *mut _);

        let mut encrypted_len = 0;
        unsafe {
            crate::Error::check(BCryptEncrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                null_mut(),
                0,
                &mut encrypted_len,
                *flags,
            ))?;

            let mut output = vec![0u8; encrypted_len as usize];

            crate::Error::check(BCryptEncrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut encrypted_len,
                *flags,
            ))
            .map(|_| output.into_boxed_slice())
        }
    }
}

impl AsymmetricKey<Rsa, Private> {
    /// Decrypt a message using the RSA key.
    pub fn decrypt(&self, padding: Option<EncryptionPadding>, data: &[u8]) -> Result<Box<[u8]>> {
        let mut out = WindowsString::new();
        let padding = padding.as_ref().map(|x| x.to_ffi_args(&mut out));

        let (pad_info, flags) = padding.as_ref().unwrap_or(&(None, 0));
        let pad_info = pad_info
            .as_ref()
            .map(|pad| &pad.value as *const BCRYPT_OAEP_PADDING_INFO as *mut _);

        let mut encrypted_len = 0;
        unsafe {
            crate::Error::check(BCryptDecrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                null_mut(),
                0,
                &mut encrypted_len,
                *flags,
            ))?;

            let mut output = vec![0u8; encrypted_len as usize];

            crate::Error::check(BCryptDecrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut encrypted_len,
                *flags,
            ))
            .map(|_| output.into_boxed_slice())
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

        AsymmetricKey::<Rsa, Private>::import_from_parts(
            &provider,
            &RsaKeyPrivatePayload {
                pub_exp: blob.pub_exp(),
                modulus: blob.modulus(),
                prime1: blob.prime1(),
                prime2: blob.prime2(),
            },
        )?;

        let key = AsymmetricKey::builder(Ecdsa(NistP521)).build()?;
        let blob = key.export()?;
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

    #[test]
    fn encrypt_decrypt() {
        let key = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();

        let plaintext = b"This is an important message.";

        let ciphertext = key.encrypt(None, &*plaintext);
        // Can't encrypt incomplete blocks without any padding
        assert!(ciphertext.is_err());

        let padding = Some(EncryptionPadding::Pkcs1);
        let ciphertext = key.encrypt(padding.clone(), &*plaintext).unwrap();
        assert_eq!(ciphertext.len(), 1024 / 8);
        let decoded = key.decrypt(padding, ciphertext.as_ref()).unwrap();
        assert_eq!(plaintext, decoded.as_ref());

        let padding = Some(EncryptionPadding::Oaep(OaepPadding {
            algorithm: crate::hash::HashAlgorithmId::Sha256,
            label: Vec::from(b"some data" as &[_]),
        }));
        let ciphertext = key.encrypt(padding.clone(), &*plaintext).unwrap();
        assert_eq!(ciphertext.len(), 1024 / 8);
        let decoded = key.decrypt(padding.clone(), ciphertext.as_ref()).unwrap();
        assert_eq!(plaintext, decoded.as_ref());

        // Check if private key can decrypt what's been encrypted with public one
        let blob = key.as_public().export().unwrap();
        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
        let public_key = AsymmetricKey::<Rsa, Public>::import(Rsa, &provider, &blob).unwrap();

        let padding = Some(EncryptionPadding::Pkcs1);
        let ciphertext = public_key.encrypt(padding.clone(), &*plaintext).unwrap();
        assert_eq!(ciphertext.len(), 1024 / 8);
        let decoded = key.decrypt(padding, ciphertext.as_ref()).unwrap();
        assert_eq!(plaintext, decoded.as_ref());
    }

    #[test]
    fn send() {
        use crate::helpers::assert_send;
        assert_send::<AsymmetricAlgorithm>();
        assert_send::<AsymmetricKey>();
        assert_send::<AsymmetricKey<Rsa, Private>>();
        assert_send::<AsymmetricKey<Ecdh<Curve25519>, Private>>();
    }
}
