//! Cryptographic key handle

use crate::helpers::{Handle, TypedBlob};
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

/// Cryptographic key handle used in (a)symmetric algorithms
pub struct KeyHandle {
    pub(crate) handle: BCRYPT_KEY_HANDLE,
}

impl KeyHandle {
    pub fn new() -> Self {
        Self { handle: null_mut() }
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptDestroyKey(self.handle);
            }
        }
    }
}

impl Default for KeyHandle {
    fn default() -> Self {
        KeyHandle::new()
    }
}

impl Handle for KeyHandle {
    fn as_ptr(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_KEY_HANDLE {
        &mut self.handle
    }
}

/// Type of a key blob.
pub enum BlobType {
    AesWrapKey,
    DhPrivate,
    DhPublic,
    DsaPublic,
    DsaPrivate,
    EccPrivate,
    EccPublic,
    KeyData,
    OpaqueKey,
    PublicKey,
    PrivateKey,
    RsaFullPrivate,
    RsaPrivate,
    RsaPublic,
    LegacyDhPrivate,
    LegacyDhPublic,
    LegacyDsaPrivate,
    LegacyDsaPublic,
    LegacyDsaV2Private,
    LegacyRsaPrivate,
    LegacyRsaPublic,
}

impl BlobType {
    pub fn as_value(&self) -> &'static str {
        match self {
            BlobType::AesWrapKey => BCRYPT_AES_WRAP_KEY_BLOB,
            BlobType::DhPrivate => BCRYPT_DH_PRIVATE_BLOB,
            BlobType::DhPublic => BCRYPT_DH_PUBLIC_BLOB,
            BlobType::DsaPublic => BCRYPT_DSA_PUBLIC_BLOB,
            BlobType::DsaPrivate => BCRYPT_DSA_PRIVATE_BLOB,
            BlobType::EccPrivate => BCRYPT_ECCPRIVATE_BLOB,
            BlobType::EccPublic => BCRYPT_ECCPUBLIC_BLOB,
            BlobType::KeyData => BCRYPT_KEY_DATA_BLOB,
            BlobType::OpaqueKey => BCRYPT_OPAQUE_KEY_BLOB,
            BlobType::PublicKey => BCRYPT_PUBLIC_KEY_BLOB,
            BlobType::PrivateKey => BCRYPT_PRIVATE_KEY_BLOB,
            BlobType::RsaFullPrivate => BCRYPT_RSAFULLPRIVATE_BLOB,
            BlobType::RsaPrivate => BCRYPT_RSAPRIVATE_BLOB,
            BlobType::RsaPublic => BCRYPT_RSAPUBLIC_BLOB,
            BlobType::LegacyDhPrivate => LEGACY_DH_PRIVATE_BLOB,
            BlobType::LegacyDhPublic => LEGACY_DH_PUBLIC_BLOB,
            BlobType::LegacyDsaPrivate => LEGACY_DSA_PRIVATE_BLOB,
            BlobType::LegacyDsaPublic => LEGACY_DSA_PUBLIC_BLOB,
            BlobType::LegacyDsaV2Private => LEGACY_DSA_V2_PRIVATE_BLOB,
            BlobType::LegacyRsaPrivate => LEGACY_RSAPRIVATE_BLOB,
            BlobType::LegacyRsaPublic => LEGACY_RSAPUBLIC_BLOB,
        }
    }
}

pub trait KeyBlob {
    const MAGIC: ULONG;
    type Value;
}

pub enum DhPrivate {}
impl KeyBlob for DhPrivate {
    const MAGIC: ULONG = BCRYPT_DH_PRIVATE_MAGIC;
    type Value = BCRYPT_DH_KEY_BLOB;
}

pub enum DsaPublic {}
impl KeyBlob for DsaPublic {
    const MAGIC: ULONG = BCRYPT_DSA_PUBLIC_MAGIC;
    type Value = BCRYPT_DSA_KEY_BLOB;
}

pub enum DsaPrivate {}
impl KeyBlob for DsaPrivate {
    const MAGIC: ULONG = BCRYPT_DSA_PRIVATE_MAGIC;
    type Value = BCRYPT_DSA_KEY_BLOB;
}

pub enum DsaPublicV2 {}
impl KeyBlob for DsaPublicV2 {
    const MAGIC: ULONG = BCRYPT_DSA_PUBLIC_MAGIC_V2;
    type Value = BCRYPT_DSA_KEY_BLOB_V2;
}

pub enum DsaPrivateV2 {}
impl KeyBlob for DsaPrivateV2 {
    const MAGIC: ULONG = BCRYPT_DSA_PRIVATE_MAGIC_V2;
    type Value = BCRYPT_DSA_KEY_BLOB_V2;
}

pub enum EcdhP256Private {}
impl KeyBlob for EcdhP256Private {
    const MAGIC: ULONG = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdhP256Public {}
impl KeyBlob for EcdhP256Public {
    const MAGIC: ULONG = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdhP384Private {}
impl KeyBlob for EcdhP384Private {
    const MAGIC: ULONG = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdhP384Public {}
impl KeyBlob for EcdhP384Public {
    const MAGIC: ULONG = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdhP521Private {}
impl KeyBlob for EcdhP521Private {
    const MAGIC: ULONG = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdhP521Public {}
impl KeyBlob for EcdhP521Public {
    const MAGIC: ULONG = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdsaP256Private {}
impl KeyBlob for EcdsaP256Private {
    const MAGIC: ULONG = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdsaP256Public {}
impl KeyBlob for EcdsaP256Public {
    const MAGIC: ULONG = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdsaP384Private {}
impl KeyBlob for EcdsaP384Private {
    const MAGIC: ULONG = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdsaP384Public {}
impl KeyBlob for EcdsaP384Public {
    const MAGIC: ULONG = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdsaP521Private {}
impl KeyBlob for EcdsaP521Private {
    const MAGIC: ULONG = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum EcdsaP521Public {}
impl KeyBlob for EcdsaP521Public {
    const MAGIC: ULONG = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
    type Value = BCRYPT_ECCKEY_BLOB;
}

pub enum RsaFullPrivate {}
impl KeyBlob for RsaFullPrivate {
    const MAGIC: ULONG = BCRYPT_RSAFULLPRIVATE_MAGIC;
    type Value = BCRYPT_RSAKEY_BLOB;
}

pub enum RsaPrivate {}
impl KeyBlob for RsaPrivate {
    const MAGIC: ULONG = BCRYPT_RSAPRIVATE_MAGIC;
    type Value = BCRYPT_RSAKEY_BLOB;
}

pub enum RsaPublic {}
impl KeyBlob for RsaPublic {
    const MAGIC: ULONG = BCRYPT_RSAPUBLIC_MAGIC;
    type Value = BCRYPT_RSAKEY_BLOB;
}

impl TypedBlob<BCRYPT_KEY_BLOB> {
    pub fn try_into<T: KeyBlob>(self) -> Result<TypedBlob<T::Value>, Self> {
        if self.Magic == T::MAGIC {
            Ok(unsafe { TypedBlob::from_box(self.into_inner()) })
        } else {
            Err(self)
        }
    }
}
