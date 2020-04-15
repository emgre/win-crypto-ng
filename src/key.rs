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

/// Marker trait for values containing CNG key blob types.
pub trait KeyBlob {
    const MAGIC: ULONG;
    type Value;
}

macro_rules! newtype_key_blob {
    ($name: ident, $magic: expr, $value: ty) => {
        #[repr(transparent)]
        pub struct $name($value);
        impl AsRef<$value> for $name {
            fn as_ref(&self) -> &$value {
                &self.0
            }
        }
        impl KeyBlob for $name {
            const MAGIC: ULONG = $magic;
            type Value = $value;
        }
    };
}

newtype_key_blob!(DhPrivate, BCRYPT_DH_PRIVATE_MAGIC, BCRYPT_DH_KEY_BLOB);
newtype_key_blob!(DhPublic, BCRYPT_DH_PUBLIC_MAGIC, BCRYPT_DH_KEY_BLOB);
newtype_key_blob!(DsaPublic, BCRYPT_DSA_PUBLIC_MAGIC, BCRYPT_DSA_KEY_BLOB);
newtype_key_blob!(DsaPrivate, BCRYPT_DSA_PRIVATE_MAGIC, BCRYPT_DSA_KEY_BLOB);
newtype_key_blob!(DsaPublicV2, BCRYPT_DSA_PUBLIC_MAGIC_V2, BCRYPT_DSA_KEY_BLOB_V2);
newtype_key_blob!(DsaPrivateV2, BCRYPT_DSA_PRIVATE_MAGIC_V2, BCRYPT_DSA_KEY_BLOB_V2);
newtype_key_blob!(RsaFullPrivate, BCRYPT_RSAFULLPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB);
newtype_key_blob!(RsaPrivate, BCRYPT_RSAPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB);
newtype_key_blob!(RsaPublic, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSAKEY_BLOB);
newtype_key_blob!(EcdhP256Public, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdhP256Private, BCRYPT_ECDH_PRIVATE_P256_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdhP384Public, BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdhP384Private, BCRYPT_ECDH_PRIVATE_P384_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdhP521Public, BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdhP521Private, BCRYPT_ECDH_PRIVATE_P521_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdsaP256Public, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdsaP256Private, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdsaP384Public, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdsaP384Private, BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdsaP521Public, BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECCKEY_BLOB);
newtype_key_blob!(EcdsaP521Private, BCRYPT_ECDSA_PRIVATE_P521_MAGIC, BCRYPT_ECCKEY_BLOB);

impl TypedBlob<BCRYPT_KEY_BLOB> {
    pub fn try_into<T: KeyBlob>(self) -> Result<TypedBlob<T>, Self> {
        if self.Magic == T::MAGIC {
            Ok(unsafe { TypedBlob::from_box(self.into_inner()) })
        } else {
            Err(self)
        }
    }
}
