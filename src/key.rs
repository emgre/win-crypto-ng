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

impl TypedBlob<DhPublic> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { DhKeyBlobPublic::Modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { DhKeyBlobPublic::Generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { DhKeyBlobPublic::Public(self) }
}

impl TypedBlob<DhPrivate> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { DhKeyBlobPrivate::Modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { DhKeyBlobPrivate::Generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { DhKeyBlobPrivate::Public(self) }
    /// PrivateExponent value as big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] { DhKeyBlobPrivate::PrivateExponent(self) }
}

impl TypedBlob<DsaPublic> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { DsaKeyBlobPublic::Modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { DsaKeyBlobPublic::Generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { DsaKeyBlobPublic::Public(self) }
}

impl TypedBlob<DsaPrivate> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { DsaKeyBlobPrivate::Modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { DsaKeyBlobPrivate::Generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { DsaKeyBlobPrivate::Public(self) }
    /// PrivateExponent value as big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] { DsaKeyBlobPrivate::PrivateExponent(self) }
}

impl TypedBlob<DsaPublicV2> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { DsaKeyBlobPublicV2::Modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { DsaKeyBlobPublicV2::Generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { DsaKeyBlobPublicV2::Public(self) }
}

impl TypedBlob<DsaPrivateV2> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { DsaKeyBlobPrivateV2::Modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { DsaKeyBlobPrivateV2::Generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { DsaKeyBlobPrivateV2::Public(self) }
    /// PrivateExponent value as big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] { DsaKeyBlobPrivateV2::PrivateExponent(self) }
}

macro_rules! ecc_forward_impls {
    ($public: ident, $private: ident) => {
        impl TypedBlob<$public> {
            /// `x` coordinate as big-endian multiprecision integer.
            pub fn x(&self) -> &[u8] { EccKeyBlobPublic::X(self) }
            /// `y` coordinate as big-endian multiprecision integer.
            pub fn y(&self) -> &[u8] { EccKeyBlobPublic::Y(self) }
        }
        impl TypedBlob<$private> {
            /// `x` coordinate as big-endian multiprecision integer.
            pub fn x(&self) -> &[u8] { EccKeyBlobPrivate::X(self) }
            /// `y` coordinate as big-endian multiprecision integer.
            pub fn y(&self) -> &[u8] { EccKeyBlobPrivate::Y(self) }
            /// `d` coordinate as big-endian multiprecision integer.
            pub fn d(&self) -> &[u8] { EccKeyBlobPrivate::d(self) }
        }
        impl EccKeyBlobPublic for TypedBlob<$public> {}
        impl EccKeyBlobPrivate for TypedBlob<$private> {}
    };
}

ecc_forward_impls!(EcdhP256Public, EcdhP256Private);
ecc_forward_impls!(EcdhP384Public, EcdhP384Private);
ecc_forward_impls!(EcdhP521Public, EcdhP521Private);
ecc_forward_impls!(EcdsaP256Public, EcdsaP256Private);
ecc_forward_impls!(EcdsaP384Public, EcdsaP384Private);
ecc_forward_impls!(EcdsaP521Public, EcdsaP521Private);

impl RsaKeyBlobPublic for TypedBlob<RsaPublic> {}
impl RsaKeyBlobPrivate for TypedBlob<RsaPrivate> {}
impl RsaKeyBlobFullPrivate for TypedBlob<RsaFullPrivate> {}
impl DsaKeyBlobPublic for TypedBlob<DsaPublic> {}
impl DsaKeyBlobPrivate for TypedBlob<DsaPrivate> {}
impl DsaKeyBlobPublicV2 for TypedBlob<DsaPublicV2> {}
impl DsaKeyBlobPrivateV2 for TypedBlob<DsaPrivateV2> {}
impl DhKeyBlobPublic for TypedBlob<DhPublic> {}
impl DhKeyBlobPrivate for TypedBlob<DhPrivate> {}

impl TypedBlob<RsaPublic> {
    /// Returns a big-endian multiprecision integer representing the public exponent.
    pub fn pub_exp(&self) -> &[u8] {
        RsaKeyBlobPublic::PublicExponent(self)
    }
    /// Returns a big-endian multiprecision integer representing the modulus.
    pub fn modulus(&self) -> &[u8] {
        RsaKeyBlobPublic::Modulus(self)
    }
}

impl TypedBlob<RsaPrivate> {
        /// Public exponent as a big-endian multiprecision integer.
        pub fn pub_exp(&self) -> &[u8] {
            RsaKeyBlobPrivate::PublicExponent(self)
        }
        /// Modulus as a big-endian multiprecision integer.
        pub fn modulus(&self) -> &[u8] {
            RsaKeyBlobPrivate::Modulus(self)
        }
        /// First prime as a big-endian multiprecision integer.
        pub fn prime_first(&self) -> &[u8] {
            RsaKeyBlobPrivate::Prime1(self)
        }
        /// Second prime as a big-endian multiprecision integer.
        pub fn prime_second(&self) -> &[u8] {
            RsaKeyBlobPrivate::Prime2(self)
        }
}

impl TypedBlob<RsaFullPrivate> {
    /// Public exponent as a big-endian multiprecision integer.
    pub fn pub_exp(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::PublicExponent(self)
    }
    /// Modulus as a big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::Modulus(self)
    }
    /// First prime as a big-endian multiprecision integer.
    pub fn prime_first(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::Prime1(self)
    }
    /// Second prime as a big-endian multiprecision integer.
    pub fn prime_second(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::Prime2(self)
    }
    /// First exponent as a big-endian multiprecision integer.
    pub fn exp_first(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::Exponent1(self)
    }
    /// Second exponent as a big-endian multiprecision integer.
    pub fn exp_second(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::Exponent2(self)
    }
    /// Coefficient as a big-endian multiprecision integer.
    pub fn coeff(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::Coefficient(self)
    }
    /// Private exponent as a big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] {
        RsaKeyBlobFullPrivate::PrivateExponent(self)
    }
}

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
                $field: ident [$len: ident],
            )*
        }
    ) => {
        $(#[$outer])*
        trait $ident: AsBytes + AsRef<$header> {
            dyn_struct! { ;
                $(
                    $(#[$meta])*
                    $field [$len],
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
        $curr: ident [$curr_len: ident],
        $(
            $(#[$field_meta:meta])*
            $field: ident [$field_len: ident],
        )*
    ) => {
        $(#[$curr_meta])*
        #[inline(always)]
        fn $curr(&self) -> &[u8] {
            let this = self.as_ref();

            let offset = std::mem::size_of_val(this)
                $(+ self.$prev().len())*;

            &self.as_bytes()[offset..offset + (this.$curr_len as usize)]
        }
        // Once expanded, push the processed ident and recursively expand other
        // fields
        dyn_struct! { $($prev,)* $curr, ;
            $(
                $(#[$field_meta])*
                $field [$field_len],
            )*
        }
    };

    ($($prev: ident,)* ; ) => {}
}


dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[allow(non_snake_case)]
    trait RsaKeyBlobPublic {
        BCRYPT_RSAKEY_BLOB,
        PublicExponent[cbPublicExp],
        Modulus[cbModulus],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[allow(non_snake_case)]
    trait RsaKeyBlobPrivate {
        BCRYPT_RSAKEY_BLOB,
        PublicExponent[cbPublicExp],
        Modulus[cbModulus],
        Prime1[cbPrime1],
        Prime2[cbPrime2],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[allow(non_snake_case)]
    trait RsaKeyBlobFullPrivate {
        BCRYPT_RSAKEY_BLOB,
        PublicExponent[cbPublicExp],
        Modulus[cbModulus],
        Prime1[cbPrime1],
        Prime2[cbPrime2],
        Exponent1[cbPrime1],
        Exponent2[cbPrime2],
        Coefficient[cbPrime1],
        PrivateExponent[cbModulus],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    #[allow(non_snake_case)]
    trait DhKeyBlobPublic {
        BCRYPT_DH_KEY_BLOB,
        Modulus[cbKey],
        Generator[cbKey],
        Public[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    #[allow(non_snake_case)]
    trait DhKeyBlobPrivate {
        BCRYPT_DH_KEY_BLOB,
        Modulus[cbKey],
        Generator[cbKey],
        Public[cbKey],
        PrivateExponent[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    #[allow(non_snake_case)]
    trait DsaKeyBlobPublic {
        BCRYPT_DSA_KEY_BLOB,
        Modulus[cbKey],
        Generator[cbKey],
        Public[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    #[allow(non_snake_case)]
    trait DsaKeyBlobPrivate {
        BCRYPT_DSA_KEY_BLOB,
        Modulus[cbKey],
        Generator[cbKey],
        Public[cbKey],
        // TODO: This is exactly 20 bytes long
        PrivateExponent[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    #[allow(non_snake_case)]
    trait DsaKeyBlobPublicV2 {
        BCRYPT_DSA_KEY_BLOB_V2,
        Modulus[cbKey],
        Generator[cbKey],
        Public[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    #[allow(non_snake_case)]
    trait DsaKeyBlobPrivateV2 {
        BCRYPT_DSA_KEY_BLOB_V2,
        Modulus[cbKey],
        Generator[cbKey],
        Public[cbKey],
        // TODO: This is exactly 20 bytes long
        PrivateExponent[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    #[allow(non_snake_case)]
    trait EccKeyBlobPublic {
        BCRYPT_ECCKEY_BLOB,
        X[cbKey],
        Y[cbKey],
    }
}

dyn_struct! {
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    #[allow(non_snake_case)]
    trait EccKeyBlobPrivate {
        BCRYPT_ECCKEY_BLOB,
        X[cbKey],
        Y[cbKey],
        d[cbKey],
    }
}
