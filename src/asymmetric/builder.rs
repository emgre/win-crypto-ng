//! Type-safe builders to generate various asymmetric keys.

use crate::handle::{Handle, KeyHandle};
use crate::helpers::{Blob, WideCString};
use crate::key::BlobType;
use crate::key::ErasedKeyBlob;
use crate::{Error, Result};
use std::marker::PhantomData;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

use super::ecc::Curve;
use super::{Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, Private};
use super::{Dh, Dsa, Ecdh, Ecdsa, Rsa};

impl AsymmetricKey {
    pub fn builder<B: Algorithm>(algorithm: B) -> Builder<B> {
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

impl Builder<Dsa> {
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

    pub fn key_bits_in_1024_3072(
        self,
        key_bits: u32,
    ) -> Result<BuilderWithKeyBits<Dsa, KeyBitsGte1024Lte3072>> {
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
/// Key size in bits has to be in the [512, 1024] range.
pub struct KeyBitsGte1024Lte3072 {}
impl KeyConstraint for KeyBitsGte1024Lte3072 {}

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
    pub fn with_params(self, params: DhParams) -> BuilderWithParams<Dh, DhParams> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl<C: super::Curve> BuilderWithKeyBits<Ecdh<C>> {
    pub fn with_params(self, params: ()) -> BuilderWithParams<Ecdh<C>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl<C: super::Curve> BuilderWithKeyBits<Ecdsa<C>> {
    pub fn with_params(self, params: ()) -> BuilderWithParams<Ecdsa<C>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa> {
    pub fn with_params(self, params: DsaParams) -> BuilderWithParams<Dsa, DsaParams> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa, KeyBitsGte512Lte1024> {
    pub fn with_params(self, params: DsaParamsV1) -> BuilderWithParams<Dsa, DsaParamsV1> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa, KeyBitsGte1024Lte3072> {
    pub fn with_params(self, params: DsaParamsV2) -> BuilderWithParams<Dsa, DsaParamsV2> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

pub enum BuilderOptions {
    Dh(DhParams),
    Dsa(DsaParams),
}

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
impl BuilderParams for BuilderOptions {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        let (property, blob) = match self {
            BuilderOptions::Dsa(params) => (BCRYPT_DSA_PARAMETERS, params.to_blob(key_bits)),
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
        set_property(handle, BCRYPT_DSA_PARAMETERS, &self.to_blob(key_bits))
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

pub struct BuilderWithParams<A: Algorithm, Params: BuilderParams = ()> {
    algorithm: A,
    key_bits: u32,
    params: Params,
}

impl<A: Algorithm, P: BuilderParams> BuilderWithParams<A, P> {
    pub fn build(self) -> Result<AsymmetricKey<A, Private>> {
        let id = self.algorithm.id();

        let provider = AsymmetricAlgorithm::open(id)?;
        let pair = KeyPair::generate(&provider, self.key_bits)?;
        self.params.set_param(pair.handle, self.key_bits)?;

        pair.finalize()
            .map(|pair| AsymmetricKey(pair.0, self.algorithm, PhantomData))
    }
}

///
#[derive(Debug)]
pub struct DhParams {
    modulus: Vec<u8>,
    generator: Vec<u8>,
}

pub enum DsaParams {
    V1(DsaParamsV1),
    V2(DsaParamsV2),
}

pub struct DsaParamsV1 {
    count: u32,
    seed: [u8; 20], // big-endian
    q: [u8; 20],    // big-endian
    prime: Vec<u8>,
    generator: Vec<u8>,
}

impl DsaParams {
    fn to_blob(&self, key_bits: u32) -> Box<[u8]> {
        match self {
            DsaParams::V1(params) => params.to_blob(key_bits).into_bytes(),
            DsaParams::V2(params) => params.to_blob(key_bits).into_bytes(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum FipsVersion {
    Fips186V2,
    Fips186V3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum DsaHashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct DsaParamsV2 {
    count: u32,
    hash: DsaHashAlgorithm,
    standard: FipsVersion,
    seed_len: u32,
    group_size: u32,
    prime: Vec<u8>,
    generator: Vec<u8>,
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
        let property = WideCString::from(blob_type.as_value());

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

blob! {
    enum DsaParameter {},
    header: BCRYPT_DSA_PARAMETER_HEADER,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_parameter_header
    view: struct ref DsaParameterViewTail {
        prime[cbKeyLength],
        generator[cbKeyLength],
    }
}

blob! {
    enum DsaParameterV2 {},
    header: BCRYPT_DSA_PARAMETER_HEADER_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_parameter_header
    view: struct ref DsaParameterV2ViewTail {
        prime[cbKeyLength],
        generator[cbKeyLength],
    }
}

blob! {
    enum DhParameter {},
    header: BCRYPT_DH_PARAMETER_HEADER,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_parameter_header
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
