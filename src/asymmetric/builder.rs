//! Type-safe builders to generate various asymmetric keys.

use crate::handle::{Handle};
use crate::helpers::{Blob, Pod, WideCString};
use crate::{Error, Result};
use super::KeyPair;
use std::marker::PhantomData;
use winapi::shared::bcrypt::*;

use super::ecc::Curve;
use super::{Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, DynamicAsymmetricAlgorithm, Private};

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
        let id = self.algorithm.id();

        let provider = AsymmetricAlgorithm::open(id)?;
        let pair = KeyPair::generate(&provider, self.key_bits)?;
        self.params.set_param(pair.handle, self.key_bits)?;

        pair.finalize()
            .map(|pair| AsymmetricKey::new(pair.0))
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
