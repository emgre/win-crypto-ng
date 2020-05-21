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

impl RsaKeyBlobPublic for TypedBlob<RsaPublic> {}
impl RsaKeyBlobPrivate for TypedBlob<RsaPrivate> {}
impl RsaKeyBlobFullPrivate for TypedBlob<RsaFullPrivate> {}
impl DsaKeyBlobPublic for TypedBlob<DsaPublic> {}
impl DsaKeyBlobPrivate for TypedBlob<DsaPrivate> {}
impl DsaKeyBlobPublicV2 for TypedBlob<DsaPublicV2> {}
impl DsaKeyBlobPrivateV2 for TypedBlob<DsaPrivateV2> {}
impl DhKeyBlobPublic for TypedBlob<DhPublic> {}
impl DhKeyBlobPrivate for TypedBlob<DhPrivate> {}
impl EccKeyBlobPublic for TypedBlob<EcdhP256Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhP256Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdhP384Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhP384Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdhP521Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhP521Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdsaP256Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdsaP256Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdsaP384Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdsaP384Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdsaP521Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdsaP521Private> {}

trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<T: ?Sized> AsBytes for TypedBlob<T> {
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Defines a trait for accessing dynamic fields (byte slices) for structs that
/// have a header of a known size which also defines the rest of the struct
/// layout.
/// Assumes a contiguous byte buffer.
macro_rules! dyn_struct {
    (
        $(#[$outer:meta])*
        trait $ident: ident {
            $header: ty,
            $(
                $(#[$meta:meta])*
                $field: ident [$($len: tt)*],
            )*
        }
    ) => {
        $(#[$outer])*
        trait $ident: AsBytes + AsRef<$header> {
            dyn_struct! { ;
                $(
                    $(#[$meta])*
                    $field [$($len)*],
                )*
            }
        }
    };
    // Expand fields. Recursively expand each field, pushing the processed field
    //  identifier to a queue which is later used to calculate field offset for
    // subsequent fields
    (
        $($prev: ident,)* ;
        $(#[$curr_meta:meta])*
        $curr: ident [$($curr_len: tt)*],
        $(
            $(#[$field_meta:meta])*
            $field: ident [$($field_len: tt)*],
        )*
    ) => {
        $(#[$curr_meta])*
        #[inline(always)]
        fn $curr(&self) -> &[u8] {
            let this = self.as_ref();

            let offset = std::mem::size_of_val(this)
                $(+ self.$prev().len())*;

            let size: usize = dyn_struct! { this, $($curr_len)* };

            &self.as_bytes()[offset..offset + size]
        }
        // Once expanded, push the processed ident and recursively expand other
        // fields
        dyn_struct! { $($prev,)* $curr, ;
            $(
                $(#[$field_meta])*
                $field [$($field_len)*],
            )*
        }
    };

    ($($prev: ident,)* ; ) => {};
    // Accept either header member values or arbitrary expressions (e.g. numeric
    // constants)
    ($this: expr, $ident: ident) => { $this.$ident as usize };
    ($this: expr, $expr: expr) => { $expr };

}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    trait RsaKeyBlobPublic {
        BCRYPT_RSAKEY_BLOB,
        pub_exp[cbPublicExp],
        modulus[cbModulus],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    trait RsaKeyBlobPrivate {
        BCRYPT_RSAKEY_BLOB,
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    trait RsaKeyBlobFullPrivate {
        BCRYPT_RSAKEY_BLOB,
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
        exponent1[cbPrime1],
        exponent2[cbPrime2],
        coeff[cbPrime1],
        priv_exp[cbModulus],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    #[allow(non_snake_case)]
    trait DhKeyBlobPublic {
        BCRYPT_DH_KEY_BLOB,
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    #[allow(non_snake_case)]
    trait DhKeyBlobPrivate {
        BCRYPT_DH_KEY_BLOB,
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    trait DsaKeyBlobPublic {
        BCRYPT_DSA_KEY_BLOB,
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    trait DsaKeyBlobPrivate {
        BCRYPT_DSA_KEY_BLOB,
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    trait DsaKeyBlobPublicV2 {
        BCRYPT_DSA_KEY_BLOB_V2,
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    trait DsaKeyBlobPrivateV2 {
        BCRYPT_DSA_KEY_BLOB_V2,
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    trait EccKeyBlobPublic {
        BCRYPT_ECCKEY_BLOB,
        x[cbKey],
        y[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    trait EccKeyBlobPrivate {
        BCRYPT_ECCKEY_BLOB,
        x[cbKey],
        y[cbKey],
        d[cbKey],
    }
}
