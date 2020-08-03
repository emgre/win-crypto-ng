//! Asymmetric algorithms
//!
//! Asymmetric algorithms (also known as public-key algorithms) use pairs of
//! keys: *public key*, which can be known by others, and *private key*, which
//! is known only to the owner. The most common usages include encryption and
//! digital signing.

use crate::handle::{AlgoHandle, Handle, KeyHandle};
use crate::helpers::blob::{Blob, BlobLayout};
use crate::helpers::WideCString;
use crate::key::{BlobType, ErasedKeyBlob};
use crate::{Error, Result};
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

use ecc::NamedCurve;

pub mod dh;
//pub mod dsa;
//pub mod dynamic;
pub mod ecc;
//pub mod ecdh;
//pub mod ecdsa;
pub mod rsa;

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

/// Asymmetric algorithm provider instance
pub trait Algorithm: Sized {
    fn id(&self) -> AsymmetricAlgorithmId;
    fn open(&self) -> Result<AsymmetricAlgorithm<Self>>;
}

pub struct AsymmetricAlgorithm<A: Algorithm> {
    handle: AlgoHandle,
    algorithm: A,
}

impl<A: Algorithm> AsymmetricAlgorithm<A> {
    fn new(handle: AlgoHandle, algorithm: A) -> AsymmetricAlgorithm<A> {
        Self {
            handle,
            algorithm,
        }
    }
}

pub trait Parts {}
pub struct Private {}
impl Parts for Private {}
pub struct Public {}
impl Parts for Public {}

pub struct AsymmetricKey<A: Algorithm, P: Parts = Public> {
    handle: KeyHandle,
    _algorithm: PhantomData<A>,
    _part: PhantomData<P>,
}

impl<A: Algorithm, P: Parts> AsymmetricKey<A, P> {
    fn new(handle: KeyHandle) -> Self {
        Self{
            handle,
            _algorithm: PhantomData,
            _part: PhantomData,
        }
    }

    pub fn into_handle(self) -> KeyHandle {
        self.handle
    }
}

impl<A: Algorithm> AsymmetricKey<A, Private> {
    pub fn as_public(&self) -> &AsymmetricKey<A, Public> {
        // NOTE: This assumes that Private is always a key pair
        unsafe { &*(self as *const _ as *const AsymmetricKey<A, Public>) }
    }
}

pub trait Import<'a, A: Algorithm, P: Parts> {
    type Blob: AsRef<Blob<ErasedKeyBlob>> + 'a;

    fn import(
        algo: &AsymmetricAlgorithm<A>,
        blob: Self::Blob,
    ) -> Result<AsymmetricKey<A, P>> {
        KeyPair::import(algo, blob.as_ref(), true)
            .map(|pair| AsymmetricKey::new(pair.0))
    }
}

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

        let blob = KeyPair::export(key.handle.handle, blob_type)?;
        Ok(blob.try_into().map_err(|_| crate::Error::BadData)?)
    }
}

impl<A: Algorithm> AsymmetricKey<A, Private> {
    pub fn builder(algorithm: A) -> Builder<A> {
        Builder { algorithm }
    }
}

/// Main builder type used to generate asymmetric key pairs.
pub struct Builder<A: Algorithm> {
    algorithm: A,
}

impl<A: Algorithm + NotNeedsKeySize> Builder<A> {
    pub fn build(self) -> Result<AsymmetricKey<A, Private>> {
        BuilderWithParams {
            key_bits: self.algorithm.id().key_bits().unwrap_or(0),
            algorithm: self.algorithm,
            params: (),
        }
        .build()
    }
}

impl<A: Algorithm + NeedsKeySize> Builder<A> {
    pub fn key_bits(self, key_bits: u32) -> BuilderWithKeyBits<A> {
        BuilderWithKeyBits {
            algorithm: self.algorithm,
            key_bits,
            key_constraint: PhantomData,
        }
    }
}

/// Marker trait for key constraint such as key size.
pub trait KeyConstraint {}
/// No constraint for keys. Used by default.
pub struct NoConstraint {}
impl KeyConstraint for NoConstraint {}
/// Key size in bits has to be in the [512, 1024] range.
pub struct KeyBitsGte512Lte1024 {}
impl KeyConstraint for KeyBitsGte512Lte1024 {}
/// Key size in bits has to be in the (1024, 3072] range.
pub struct KeyBitsGt1024Lte3072 {}
impl KeyConstraint for KeyBitsGt1024Lte3072 {}

/// Builder type with key length provided in bits.
pub struct BuilderWithKeyBits<A: Algorithm, C: KeyConstraint = NoConstraint> {
    algorithm: A,
    key_bits: u32,
    key_constraint: PhantomData<C>,
}

/// Marker trait implemented for algorithms that do not require explicitly
/// providing key size in bits (and, by extension, other parameters).
pub trait NotNeedsKeySize: Algorithm {}

/// Marker trait implemented for algorithms that require explicitly providing
/// key size in bits to be generated.
pub trait NeedsKeySize: Algorithm {}

fn set_property(handle: BCRYPT_HANDLE, property: &str, value: &[u8]) -> Result<()> {
    let property = WideCString::from(property);
    unsafe {
        Error::check(BCryptSetProperty(
            handle,
            property.as_ptr(),
            value as *const _ as _,
            value.len() as u32,
            0,
        ))?;
    }
    Ok(())
}

pub trait BuilderParams {
    fn set_param(&self, _handle: BCRYPT_HANDLE, _key_bits: u32) -> Result<()> {
        Ok(())
    }
}

impl BuilderParams for () {}

pub struct BuilderWithParams<A: Algorithm, Params: BuilderParams = ()> {
    algorithm: A,
    key_bits: u32,
    params: Params,
}

impl<A: Algorithm, P: BuilderParams> BuilderWithParams<A, P> {
    pub fn build(self) -> Result<AsymmetricKey<A, Private>> {
        let provider = self.algorithm.open()?;
        let pair = KeyPair::generate(&provider, self.key_bits)?;
        self.params.set_param(pair.handle, self.key_bits)?;

        pair.finalize()
            .map(|pair| AsymmetricKey::new(pair.0))
    }
}

/// Type-erased version of [`AsymmetricKey`]
pub(crate) struct KeyPair(pub(crate) KeyHandle);

struct KeyPairBuilder {
    handle: BCRYPT_KEY_HANDLE,
}

impl KeyPair {
    fn generate<A: Algorithm>(algo: &AsymmetricAlgorithm<A>, length: u32) -> Result<KeyPairBuilder> {
        let mut handle: BCRYPT_KEY_HANDLE = null_mut();

        crate::Error::check(unsafe {
            BCryptGenerateKeyPair(algo.handle.as_ptr(), &mut handle, length as ULONG, 0)
        })?;

        Ok(KeyPairBuilder {
            handle,
        })
    }

    pub fn import<A: Algorithm>(
        algo: &AsymmetricAlgorithm<A>,
        key_data: &Blob<ErasedKeyBlob>,
        no_validate_public: bool,
    ) -> Result<Self> {
        let blob_type = key_data.blob_type().ok_or(Error::InvalidParameter)?;
        let property = WideCString::from(blob_type.as_value());

        let mut handle = KeyHandle::default();
        Error::check(unsafe {
            BCryptImportKeyPair(
                algo.handle.as_ptr(),
                null_mut(),
                property.as_ptr(),
                handle.as_mut_ptr(),
                key_data.as_bytes().as_ptr() as *mut _,
                key_data.as_bytes().len() as u32,
                if no_validate_public {
                    BCRYPT_NO_KEY_VALIDATION
                } else {
                    0
                },
            )
        })
        .map(|_| KeyPair(handle))
    }

    pub fn export(handle: BCRYPT_KEY_HANDLE, kind: BlobType) -> Result<Box<Blob<ErasedKeyBlob>>> {
        let property = WideCString::from(kind.as_value());

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
        eprintln!("Asked to allocate {} bytes", bytes);

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

        Ok(Blob::<ErasedKeyBlob>::from_boxed(blob))
    }
}

impl KeyPairBuilder {
    fn finalize(self) -> Result<KeyPair> {
        Error::check(unsafe { BCryptFinalizeKeyPair(self.handle, 0) }).map(|_| {
            KeyPair(KeyHandle {
                handle: self.handle,
            })
        })
    }
}

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
    use super::rsa::Rsa;

    /*#[test]
    fn import_export() -> Result<()> {
        let dynamic = AsymmetricKey::builder(AsymmetricAlgorithmId::Rsa)
            .key_bits(1024)
            .build()?;
        let blob = dynamic.export()?;
        let blob = blob.try_into().unwrap_or_else(|_| panic!());

        let algo = Rsa::open()?;
        let imported = AsymmetricKey::<_, Private>::import(&algo, &blob)?;
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
    }*/
}
