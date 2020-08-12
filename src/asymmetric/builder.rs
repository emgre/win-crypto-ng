//! Type-safe asymmetric key generation.
//!
//! # Example
//! ```
//! use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey};
//! use win_crypto_ng::asymmetric::{ecc::NistP384, Ecdh, Rsa};
//!
//! // Handle to an asymmetric key whose algorithm ID is known at run-time
//! let handle: AsymmetricKey<AsymmetricAlgorithmId, _> =
//!     AsymmetricKey::builder(AsymmetricAlgorithmId::Rsa).key_bits(512).build().unwrap();
//!
//! // Handle to an asymmetric key whose algorithm is known to be RSA
//! let handle: AsymmetricKey<Rsa, _> =
//!     AsymmetricKey::builder(Rsa).key_bits(512).build().unwrap();
//!
//! let handle = AsymmetricKey::builder(Ecdh(NistP384)).build().unwrap();
//! ```

use crate::helpers::{Blob, Pod, WindowsString};
use crate::helpers::{Handle, KeyHandle};
use crate::key_blob::{BlobType, ErasedKeyBlob};
use crate::{Error, Result};
use std::marker::PhantomData;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

use super::ecc::Curve;
use super::{Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, Private};
use super::{Dh, Dsa, Ecdh, Ecdsa, Rsa};

impl AsymmetricKey {
    /// Create a type-safe builder capable of generating asymmetric keys.
    pub fn builder<B: Algorithm>(algorithm: B) -> Builder<B> {
        Builder { algorithm }
    }
}

/// Main builder type used to generate asymmetric key pairs.
pub struct Builder<A: Algorithm> {
    algorithm: A,
}

impl<A: Algorithm + NotNeedsKeySize> Builder<A> {
    /// Generate the final key.
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
    /// Supply bits of the key to be generated.
    pub fn key_bits(self, key_bits: u32) -> BuilderWithKeyBits<A> {
        BuilderWithKeyBits {
            algorithm: self.algorithm,
            key_bits,
            key_constraint: PhantomData,
        }
    }
}

impl Builder<Dsa> {
    /// Supply bits of the key to be generated.
    ///
    /// Returns `Ok(..)` if the value in the range of `512..=1024`, otherwise
    /// returns `(Error::InvalidParameter`.
    pub fn key_bits_in_512_1024(
        self,
        key_bits: u32,
    ) -> Result<BuilderWithKeyBits<Dsa, KeyBitsGte512Lte1024>> {
        match key_bits {
            512..=1024 => {}
            _ => return Err(Error::InvalidParameter),
        }

        Ok(BuilderWithKeyBits {
            algorithm: self.algorithm,
            key_bits,
            key_constraint: PhantomData,
        })
    }

    /// Supply bits of the key to be generated.
    ///
    /// Returns `Ok(..)` if the value in the range of `1024..=3072`, otherwise
    /// returns `(Error::InvalidParameter`.
    pub fn key_bits_in_1024_3072(
        self,
        key_bits: u32,
    ) -> Result<BuilderWithKeyBits<Dsa, KeyBitsGt1024Lte3072>> {
        match key_bits {
            1024..=3072 => {}
            _ => return Err(Error::InvalidParameter),
        }

        Ok(BuilderWithKeyBits {
            algorithm: self.algorithm,
            key_bits,
            key_constraint: PhantomData,
        })
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
impl NotNeedsKeySize for AsymmetricAlgorithmId {}
impl<C: Curve> NotNeedsKeySize for Ecdh<C> {}
impl<C: Curve> NotNeedsKeySize for Ecdsa<C> {}
/// Marker trait implemented for algorithms that require explicitly providing
/// key size in bits to be generated.
pub trait NeedsKeySize: Algorithm {}
impl NeedsKeySize for AsymmetricAlgorithmId {}
impl NeedsKeySize for Dh {}
impl NeedsKeySize for Dsa {}
impl NeedsKeySize for Rsa {}

impl BuilderWithKeyBits<AsymmetricAlgorithmId> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    pub fn with_params(
        self,
        params: BuilderOptions,
    ) -> BuilderWithParams<AsymmetricAlgorithmId, BuilderOptions> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dh> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    pub fn with_params(self, params: DhParams) -> BuilderWithParams<Dh, DhParams> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl<C: super::Curve> BuilderWithKeyBits<Ecdh<C>> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    ///
    /// Is a no-op.
    pub fn with_params(self, params: ()) -> BuilderWithParams<Ecdh<C>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl<C: super::Curve> BuilderWithKeyBits<Ecdsa<C>> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    ///
    /// Is a no-op.
    pub fn with_params(self, params: ()) -> BuilderWithParams<Ecdsa<C>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    pub fn with_params(self, params: DsaParams) -> BuilderWithParams<Dsa, DsaParams> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa, KeyBitsGte512Lte1024> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    pub fn with_params(self, params: DsaParamsV1) -> BuilderWithParams<Dsa, DsaParamsV1> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa, KeyBitsGt1024Lte3072> {
    /// Supply additional algorithm-specific parameters to generate a key with.
    pub fn with_params(self, params: DsaParamsV2) -> BuilderWithParams<Dsa, DsaParamsV2> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

/// Algorithm-specific parameters to generate a key with.
pub enum BuilderOptions {
    /// Parameters to be used with the DH algorithm. Specifies `modulus` and `generator` params.
    Dh(DhParams),
    Dsa(DsaParams),
}

fn set_property(handle: BCRYPT_HANDLE, property: &str, value: &[u8]) -> Result<()> {
    let property = WindowsString::from(property);
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

/// Marker type for additional algorithm-specific parameters.
///
/// The trait is sealed as it's only meant to be implemented by the types in
/// this crate.
pub trait BuilderParams: private::Sealed {
    #[doc(hidden)]
    fn set_param(&self, _handle: BCRYPT_HANDLE, _key_bits: u32) -> Result<()> {
        Ok(())
    }
}
impl BuilderParams for () {}
impl BuilderParams for BuilderOptions {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        let (property, blob) = match self {
            BuilderOptions::Dsa(params) => (BCRYPT_DSA_PARAMETERS, params.to_blob_bytes(key_bits)),
            BuilderOptions::Dh(params) => {
                (BCRYPT_DH_PARAMETERS, params.to_blob(key_bits).into_bytes())
            }
        };

        set_property(handle, property, &blob)
    }
}

impl BuilderParams for DhParams {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(
            handle,
            BCRYPT_DH_PARAMETERS,
            self.to_blob(key_bits).as_ref().as_bytes(),
        )
    }
}

impl BuilderParams for DsaParams {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(handle, BCRYPT_DSA_PARAMETERS, &self.to_blob_bytes(key_bits))
    }
}

impl BuilderParams for DsaParamsV1 {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(
            handle,
            BCRYPT_DSA_PARAMETERS,
            self.to_blob(key_bits).as_bytes(),
        )
    }
}
impl BuilderParams for DsaParamsV2 {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(
            handle,
            BCRYPT_DSA_PARAMETERS,
            self.to_blob(key_bits).as_bytes(),
        )
    }
}

/// Builder type with provided both key length and algorithm-specific parameters.
pub struct BuilderWithParams<A: Algorithm, Params: BuilderParams = ()> {
    algorithm: A,
    key_bits: u32,
    params: Params,
}

impl<A: Algorithm, P: BuilderParams> BuilderWithParams<A, P> {
    /// Generate the final key.
    pub fn build(self) -> Result<AsymmetricKey<A, Private>> {
        let id = self.algorithm.id();

        let provider = AsymmetricAlgorithm::open(id)?;
        let pair = KeyPair::generate(&provider, self.key_bits)?;
        self.params.set_param(pair.handle, self.key_bits)?;

        pair.finalize()
            .map(|pair| AsymmetricKey(pair.0, self.algorithm, PhantomData))
    }
}

/// Algorithm-specific DH parameters.
#[derive(Debug)]
pub struct DhParams {
    /// DH group modulus.
    pub modulus: Vec<u8>,
    /// DH group generator.
    pub generator: Vec<u8>,
}

/// Algorithm-specific DH parameters.
pub enum DsaParams {
    /// Used with key of size in the `512..=1024` range.
    V1(DsaParamsV1),
    /// Used with key of size in the `1024..=3072` range.
    V2(DsaParamsV2),
}

/// Algorithm-specific DSA parameters. Applies to keys with lesser or equal than
/// 1024 bit length.
pub struct DsaParamsV1 {
    /// The number of iterations performed to generate the prime number `q` from the `seed`.
    pub count: u32,
    /// The seed value, in big-endian format, used to generate q.
    pub seed: [u8; 20],
    /// The 160-bit prime factor, in big-endian format.
    pub q: [u8; 20],
    /// DSA prime number, in big-endian format.
    pub prime: Vec<u8>,
    /// DSA generator number, in big-endian format.
    pub generator: Vec<u8>,
}

impl DsaParams {
    fn to_blob_bytes(&self, key_bits: u32) -> Box<[u8]> {
        match self {
            DsaParams::V1(params) => params.to_blob(key_bits).into_bytes(),
            DsaParams::V2(params) => params.to_blob(key_bits).into_bytes(),
        }
    }
}

/// Specifies the Federal Information Processing Standard (FIPS) to apply when
/// used in conjuction with a DSA key of greater than 1024 bit length.
#[repr(C)]
#[derive(Copy, Clone)]
pub enum FipsVersion {
    Fips186V2,
    Fips186V3,
}

/// Specifies the hashing algorithm to use in the DSA key context.
#[repr(C)]
#[derive(Copy, Clone)]
pub enum DsaHashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Algorithm-specific DSA parameters. Applies to keys with greater than 1024
/// bit length.
pub struct DsaParamsV2 {
    /// The number of iterations performed to generate the prime number q from
    /// the seed. For more information, see NIST standard FIPS186-3.
    pub count: u32,
    /// Specifies the hashing algorithm to use.
    pub hash: DsaHashAlgorithm,
    /// Specifies the Federal Information Processing Standard (FIPS) to apply.
    pub standard: FipsVersion,
    /// Length of the seed used to generate the prime number q.
    pub seed_len: u32,
    /// Size of the prime number q. Currently, if the key is less than 128
    /// bits, q is 20 bytes long. If the key exceeds 256 bits, q is 32 bytes
    /// long.
    pub group_size: u32,
    /// DSA prime number, in big-endian format.
    pub prime: Vec<u8>,
    /// DSA generator number, in big-endian format.
    pub generator: Vec<u8>,
}

impl DsaParamsV1 {
    fn to_blob(&self, key_bits: u32) -> Box<Blob<DsaParameter>> {
        let key_bytes = key_bits as usize / 8;
        let header_len = std::mem::size_of::<BCRYPT_DSA_PARAMETER_HEADER>();
        let length = header_len + key_bytes + key_bytes;

        Blob::<DsaParameter>::clone_from_parts(
            &BCRYPT_DSA_PARAMETER_HEADER {
                cbLength: length as u32,
                dwMagic: BCRYPT_DSA_PARAMETERS_MAGIC,
                cbKeyLength: key_bytes as u32,
                Count: self.count.to_be_bytes(),
                Seed: self.seed,
                q: self.q,
            },
            &DsaParameterViewTail {
                generator: &self.generator,
                prime: &self.prime,
            },
        )
    }
}

impl DsaParamsV2 {
    fn to_blob(&self, key_bits: u32) -> Box<Blob<DsaParameterV2>> {
        let key_bytes = key_bits as usize / 8;
        let header_len = std::mem::size_of::<BCRYPT_DSA_PARAMETER_HEADER_V2>();
        let length = header_len + key_bytes + key_bytes;

        Blob::<DsaParameterV2>::clone_from_parts(
            &BCRYPT_DSA_PARAMETER_HEADER_V2 {
                cbLength: length as u32,
                dwMagic: BCRYPT_DSA_PARAMETERS_MAGIC_V2,
                cbKeyLength: key_bytes as u32,
                Count: self.count.to_be_bytes(),
                cbSeedLength: self.seed_len,
                hashAlgorithm: self.hash as u32,
                standardVersion: self.standard as u32,
                cbGroupSize: self.group_size,
            },
            // TODO: Verify that prime and generator are last (docs are empty on layout...)
            &DsaParameterV2ViewTail {
                generator: &self.generator,
                prime: &self.prime,
            },
        )
    }
}

impl DhParams {
    fn to_blob(&self, key_bits: u32) -> Box<Blob<DhParameter>> {
        let key_bytes = key_bits as usize / 8;
        let header_len = std::mem::size_of::<BCRYPT_DH_PARAMETER_HEADER>();
        let length = header_len + key_bytes + key_bytes;

        Blob::<DhParameter>::clone_from_parts(
            &BCRYPT_DH_PARAMETER_HEADER {
                cbLength: length as u32,
                dwMagic: BCRYPT_DH_PARAMETERS_MAGIC,
                cbKeyLength: key_bytes as u32,
            },
            &DhParameterViewTail {
                generator: &self.generator,
                modulus: &self.modulus,
            },
        )
    }
}

impl BuilderWithKeyBits<AsymmetricAlgorithmId> {
    /// Generate the final key.
    pub fn build(self) -> Result<AsymmetricKey<AsymmetricAlgorithmId, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

impl BuilderWithKeyBits<Rsa> {
    /// Generate the final key.
    pub fn build(self) -> Result<AsymmetricKey<Rsa, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

impl BuilderWithKeyBits<Dsa> {
    /// Generate the final key.
    pub fn build(self) -> Result<AsymmetricKey<Dsa, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

/// Type-erased version of [`AsymmetricKey`]
pub(crate) struct KeyPair(pub(crate) KeyHandle);

struct KeyPairBuilder<'a> {
    _provider: &'a AsymmetricAlgorithm,
    handle: BCRYPT_KEY_HANDLE,
}

impl KeyPair {
    fn generate(provider: &AsymmetricAlgorithm, length: u32) -> Result<KeyPairBuilder> {
        let mut handle: BCRYPT_KEY_HANDLE = null_mut();

        crate::Error::check(unsafe {
            BCryptGenerateKeyPair(provider.handle.as_ptr(), &mut handle, length as ULONG, 0)
        })?;

        Ok(KeyPairBuilder {
            _provider: provider,
            handle,
        })
    }

    pub fn import(
        provider: &AsymmetricAlgorithm,
        key_data: &Blob<ErasedKeyBlob>,
        no_validate_public: bool,
    ) -> Result<Self> {
        let blob_type = key_data.blob_type().ok_or(Error::InvalidParameter)?;
        let property = WindowsString::from(blob_type.as_value());

        let mut handle = KeyHandle::default();
        Error::check(unsafe {
            BCryptImportKeyPair(
                provider.handle.as_ptr(),
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
        let property = WindowsString::from(kind.as_value());

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

impl KeyPairBuilder<'_> {
    fn finalize(self) -> Result<KeyPair> {
        Error::check(unsafe { BCryptFinalizeKeyPair(self.handle, 0) }).map(|_| {
            KeyPair(KeyHandle {
                handle: self.handle,
            })
        })
    }
}

use crate::blob;

unsafe impl Pod for BCRYPT_DSA_PARAMETER_HEADER {}
blob! {
    /// Dynamic struct layout for [`BCRYPT_DSA_PARAMETER_HEADER`].
    ///
    /// [`BCRYPT_DSA_PARAMETER_HEADER`]: https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_parameter_header
    enum DsaParameter {},
    header: BCRYPT_DSA_PARAMETER_HEADER,
    /// Dynamically-sized part of the [`DsaParameter`] blob.
    ///
    /// All the fields are stored as a big-endian multiprecision integer.
    ///
    /// [`DsaParameter`]: enum.DsaParameter.html
    view: struct ref DsaParameterViewTail {
        prime[cbKeyLength],
        generator[cbKeyLength],
    }
}

unsafe impl Pod for BCRYPT_DSA_PARAMETER_HEADER_V2 {}
blob! {
    /// Dynamic struct layout for [`BCRYPT_DSA_PARAMETER_HEADER_V2`].
    ///
    /// [`BCRYPT_DSA_PARAMETER_HEADER_V2`]: https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_parameter_header_v2
    enum DsaParameterV2 {},
    header: BCRYPT_DSA_PARAMETER_HEADER_V2,
    /// Dynamically-sized part of the [`DsaParameterV2`] blob.
    ///
    /// All the fields are stored as a big-endian multiprecision integer.
    ///
    /// [`DsaParameterV2`]: enum.DsaParameterV2.html
    view: struct ref DsaParameterV2ViewTail {
        prime[cbKeyLength],
        generator[cbKeyLength],
    }
}

unsafe impl Pod for BCRYPT_DH_PARAMETER_HEADER {}
blob! {
    /// Dynamic struct layout for [`BCRYPT_DH_PARAMETER_HEADER`].
    ///
    /// [`BCRYPT_DH_PARAMETER_HEADER`]: https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_parameter_header
    enum DhParameter {},
    header: BCRYPT_DH_PARAMETER_HEADER,
    /// Dynamically-sized part of the [`DhParameter`] blob.
    ///
    /// All the fields are stored as a big-endian multiprecision integer.
    ///
    /// [`DhParameter`]: enum.DhParameter.html
    view: struct ref DhParameterViewTail {
        modulus[cbKeyLength],
        generator[cbKeyLength],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    const OAKLEY_GROUP_1_P: [u8; 96] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f,
        0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,
        0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,
        0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22,
        0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95,
        0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
        0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51,
        0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
        0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];

    #[rustfmt::skip]
    const OAKLEY_GROUP_1_G: [u8; 96] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    ];

    #[test]
    fn builds() -> Result<()> {
        use crate::asymmetric::ecc::{NistP384, NistP521};

        let id = AsymmetricAlgorithmId::Rsa;
        assert!(AsymmetricKey::builder(id).key_bits(512).build().is_ok());
        assert!(AsymmetricKey::builder(id).key_bits(1024).build().is_ok());
        assert!(AsymmetricKey::builder(id).key_bits(1080).build().is_ok());
        assert!(AsymmetricKey::builder(id).key_bits(1081).build().is_err());

        assert!(AsymmetricKey::builder(Rsa).key_bits(1024).build().is_ok());
        assert!(AsymmetricKey::builder(Dsa).key_bits(1024).build().is_ok());
        assert!(AsymmetricKey::builder(Ecdsa(NistP521)).build().is_ok());
        assert!(AsymmetricKey::builder(Ecdh(NistP384)).build().is_ok());

        let (generator, modulus) = (OAKLEY_GROUP_1_G.to_vec(), OAKLEY_GROUP_1_P.to_vec());
        AsymmetricKey::builder(Dh)
            .key_bits(768)
            .with_params(DhParams { generator, modulus })
            .build()?;
        // TODO: Add an example with `DsaParams`

        Ok(())
    }
}

mod private {
    // https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
    pub trait Sealed {}
    impl<T> Sealed for T {}
}
