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
    pub fn modulus(&self) -> &[u8] { <Self as DhKeyBlob>::modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { <Self as DhKeyBlob>::generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { <Self as DhKeyBlob>::public(self) }
}

impl TypedBlob<DhPrivate> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { <Self as DhKeyBlob>::modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { <Self as DhKeyBlob>::generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { <Self as DhKeyBlob>::public(self) }
    /// PrivateExponent value as big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] { <Self as DhKeyBlob>::priv_exp(self) }
}

impl TypedBlob<DsaPublic> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { <Self as DsaKeyBlob>::modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { <Self as DsaKeyBlob>::generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { <Self as DsaKeyBlob>::public(self) }
}

impl TypedBlob<DsaPrivate> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { <Self as DsaKeyBlob>::modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { <Self as DsaKeyBlob>::generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { <Self as DsaKeyBlob>::public(self) }
    /// PrivateExponent value as big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] { <Self as DsaKeyBlob>::priv_exp(self) }
}

impl TypedBlob<DsaPublicV2> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { <Self as DsaKeyBlobV2>::modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { <Self as DsaKeyBlobV2>::generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { <Self as DsaKeyBlobV2>::public(self) }
}

impl TypedBlob<DsaPrivateV2> {
    /// Modulus as big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] { <Self as DsaKeyBlobV2>::modulus(self) }
    /// Generator coordinate as big-endian multiprecision integer.
    pub fn generator(&self) -> &[u8] { <Self as DsaKeyBlobV2>::generator(self) }
    /// Public value as big-endian multiprecision integer.
    pub fn public(&self) -> &[u8] { <Self as DsaKeyBlobV2>::public(self) }
    /// PrivateExponent value as big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] { <Self as DsaKeyBlobV2>::priv_exp(self) }
}

macro_rules! ecc_forward_impls {
    ($name: ident, public) => {
        impl TypedBlob<$name> {
            /// `x` coordinate as big-endian multiprecision integer.
            pub fn x(&self) -> &[u8] { <Self as EccKeyBlob>::x(self) }
            /// `y` coordinate as big-endian multiprecision integer.
            pub fn y(&self) -> &[u8] { <Self as EccKeyBlob>::y(self) }
        }
    };
    ($name: ident, private) => {
        ecc_forward_impls!($name, public);
        impl TypedBlob<$name> {
            /// `d` coordinate as big-endian multiprecision integer.
            pub fn d(&self) -> &[u8] { <Self as EccKeyBlob>::d(self) }
        }
    };
    ($public: ident, $private: ident) => {
        ecc_forward_impls!($public, public);
        ecc_forward_impls!($private, private);
    };
}

ecc_forward_impls!(EcdhP256Public, EcdhP256Private);
ecc_forward_impls!(EcdhP384Public, EcdhP384Private);
ecc_forward_impls!(EcdhP521Public, EcdhP521Private);
ecc_forward_impls!(EcdsaP256Public, EcdsaP256Private);
ecc_forward_impls!(EcdsaP384Public, EcdsaP384Private);
ecc_forward_impls!(EcdsaP521Public, EcdsaP521Private);

impl TypedBlob<RsaPublic> {
    /// Returns a big-endian multiprecision integer representing the public exponent.
    pub fn pub_exp(&self) -> &[u8] {
        <Self as RsaKeyBlob>::pub_exp(self)
    }
    /// Returns a big-endian multiprecision integer representing the modulus.
    pub fn modulus(&self) -> &[u8] {
        <Self as RsaKeyBlob>::modulus(self)
    }
}

impl TypedBlob<RsaPrivate> {
        /// Public exponent as a big-endian multiprecision integer.
        pub fn pub_exp(&self) -> &[u8] {
            <Self as RsaKeyBlob>::pub_exp(self)
        }
        /// Modulus as a big-endian multiprecision integer.
        pub fn modulus(&self) -> &[u8] {
            <Self as RsaKeyBlob>::modulus(self)
        }
        /// First prime as a big-endian multiprecision integer.
        pub fn prime_first(&self) -> &[u8] {
            <Self as RsaKeyBlob>::prime_first(self)
        }
        /// Second prime as a big-endian multiprecision integer.
        pub fn prime_second(&self) -> &[u8] {
            <Self as RsaKeyBlob>::prime_second(self)
        }
}

impl TypedBlob<RsaFullPrivate> {
    /// Public exponent as a big-endian multiprecision integer.
    pub fn pub_exp(&self) -> &[u8] {
        <Self as RsaKeyBlob>::pub_exp(self)
    }
    /// Modulus as a big-endian multiprecision integer.
    pub fn modulus(&self) -> &[u8] {
        <Self as RsaKeyBlob>::modulus(self)
    }
    /// First prime as a big-endian multiprecision integer.
    pub fn prime_first(&self) -> &[u8] {
        <Self as RsaKeyBlob>::prime_first(self)
    }
    /// Second prime as a big-endian multiprecision integer.
    pub fn prime_second(&self) -> &[u8] {
        <Self as RsaKeyBlob>::prime_second(self)
    }
    /// First exponent as a big-endian multiprecision integer.
    pub fn exp_first(&self) -> &[u8] {
        <Self as RsaKeyBlob>::exp_first(self)
    }
    /// Second exponent as a big-endian multiprecision integer.
    pub fn exp_second(&self) -> &[u8] {
        <Self as RsaKeyBlob>::exp_second(self)
    }
    /// Coefficient as a big-endian multiprecision integer.
    pub fn coeff(&self) -> &[u8] {
        <Self as RsaKeyBlob>::coeff(self)
    }
    /// Private exponent as a big-endian multiprecision integer.
    pub fn priv_exp(&self) -> &[u8] {
        <Self as RsaKeyBlob>::priv_exp(self)
    }
}

pub(super) trait AsBytes {
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
    ($(#[$outer:meta])* $ident: ident, $header: ty, $($fields: ident [$($len: ident)+]),* $(,),*) => {
        $(#[$outer])*
        trait $ident: AsBytes + AsRef<$header> {
            dyn_struct! { ; $($($fields [$len]),*),* }

        }
    };
    // Expand fields
    ($($prev: ident,)* ; $curr: ident [$len: ident], $($fields: ident [$($len2: ident)+]),*) => {
        #[inline(always)]
        fn $curr(&self) -> &[u8] {
            let this = self.as_ref();

            let offset = std::mem::size_of_val(this)
                $(+ self.$prev().len())*;

            &self.as_bytes()[offset..offset + (this.$len as usize)]
        }

        dyn_struct! { $($prev,)* $curr, ; $( $($fields [$len2],)+ ),* }
    };

    ($($prev: ident,)* ; ) => {}
}

// TODO: Extract that to a macro for dynamic structs
pub(super) trait DhKeyBlob {
    /// Modulus as big-endian multiprecision integer.
    fn modulus(&self) -> &[u8];
    /// Generator coordinate as big-endian multiprecision integer.
    fn generator(&self) -> &[u8];
    /// Public value as big-endian multiprecision integer.
    fn public(&self) -> &[u8];
    /// PrivateExponent value as big-endian multiprecision integer.
    fn priv_exp(&self) -> &[u8];
}

impl<T> DhKeyBlob for T where T: AsBytes + AsRef<BCRYPT_DH_KEY_BLOB> {
    fn modulus(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DH_KEY_BLOB>();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn generator(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DH_KEY_BLOB>()
            + self.modulus().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn public(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DH_KEY_BLOB>()
        + self.modulus().len()
        + self.generator().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn priv_exp(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB>()
            + self.modulus().len()
            + self.generator().len()
            + self.public().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
}

// TODO: Extract that to a macro for dynamic structs
pub(super) trait DsaKeyBlob {
    /// Modulus as big-endian multiprecision integer.
    fn modulus(&self) -> &[u8];
    /// Generator coordinate as big-endian multiprecision integer.
    fn generator(&self) -> &[u8];
    /// Public value as big-endian multiprecision integer.
    fn public(&self) -> &[u8];
    /// PrivateExponent value as big-endian multiprecision integer.
    fn priv_exp(&self) -> &[u8];
}

impl<T> DsaKeyBlob for T where T: AsBytes + AsRef<BCRYPT_DSA_KEY_BLOB> {
    fn modulus(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB>();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn generator(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB>()
            + self.modulus().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn public(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB>()
        + self.modulus().len()
        + self.generator().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn priv_exp(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB>()
            + self.modulus().len()
            + self.generator().len()
            + self.public().len();

        &self.as_bytes()[offset..offset + 20]
    }
}

// TODO: Extract that to a macro for dynamic structs
pub(super) trait DsaKeyBlobV2 {
    /// Modulus as big-endian multiprecision integer.
    fn modulus(&self) -> &[u8];
    /// Generator coordinate as big-endian multiprecision integer.
    fn generator(&self) -> &[u8];
    /// Public value as big-endian multiprecision integer.
    fn public(&self) -> &[u8];
    /// PrivateExponent value as big-endian multiprecision integer.
    fn priv_exp(&self) -> &[u8];
}

impl<T> DsaKeyBlobV2 for T where T: AsBytes + AsRef<BCRYPT_DSA_KEY_BLOB_V2> {
    fn modulus(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB_V2>();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn generator(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB_V2>()
            + self.modulus().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn public(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB_V2>()
        + self.modulus().len()
        + self.generator().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    fn priv_exp(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_DSA_KEY_BLOB_V2>()
            + self.modulus().len()
            + self.generator().len()
            + self.public().len();

        &self.as_bytes()[offset..offset + 20]
    }
}

// TODO: Extract that to a macro for dynamic structs
pub(super) trait EccKeyBlob {
    /// `x` coordinate as big-endian multiprecision integer.
    fn x(&self) -> &[u8];
    /// `y` coordinate as big-endian multiprecision integer.
    fn y(&self) -> &[u8];
    /// `d` value as big-endian multiprecision integer.
    fn d(&self) -> &[u8];
}

impl<T> EccKeyBlob for T where T: AsBytes + AsRef<BCRYPT_ECCKEY_BLOB> {
    fn x(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    /// `y` coordinate as big-endian multiprecision integer.
    fn y(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>()
            + self.x().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
    /// `d` value as big-endian multiprecision integer.
    fn d(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>()
            + self.x().len()
            + self.y().len();
            &self.as_bytes()[offset..offset + (self.as_ref().cbKey as usize)]
    }
}

// TODO: Extract that to a macro for dynamic structs
pub(super) trait RsaKeyBlob {
    /// Public exponent as a big-endian multiprecision integer.
    fn pub_exp(&self) -> &[u8];
    /// Modulus as a big-endian multiprecision integer.
    fn modulus(&self) -> &[u8];
    fn prime_first(&self) -> &[u8];
    fn prime_second(&self) -> &[u8];
    fn exp_first(&self) -> &[u8];
    fn exp_second(&self) -> &[u8];
    fn coeff(&self) -> &[u8];
    fn priv_exp(&self) -> &[u8];
}

impl<T> RsaKeyBlob for T where T: AsBytes + AsRef<BCRYPT_RSAKEY_BLOB> {
    fn pub_exp(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();

        &self.as_bytes()[offset..offset + (self.as_ref().cbPublicExp as usize)]
    }

    fn modulus(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbModulus as usize)]
    }

    fn prime_first(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len()
            + self.modulus().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbPrime1 as usize)]
    }

    fn prime_second(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len()
            + self.modulus().len()
            + self.prime_first().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbPrime2 as usize)]
    }

    fn exp_first(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len()
            + self.modulus().len()
            + self.prime_first().len()
            + self.prime_second().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbPrime1 as usize)]
    }

    fn exp_second(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len()
            + self.modulus().len()
            + self.prime_first().len()
            + self.prime_second().len()
            + self.exp_first().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbPrime2 as usize)]
    }

    fn coeff(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len()
            + self.modulus().len()
            + self.prime_first().len()
            + self.prime_second().len()
            + self.exp_first().len()
            + self.exp_second().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbPrime1 as usize)]
    }

    fn priv_exp(&self) -> &[u8] {
        let offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + self.pub_exp().len()
            + self.modulus().len()
            + self.prime_first().len()
            + self.prime_second().len()
            + self.exp_first().len()
            + self.exp_second().len()
            + self.coeff().len();

        &self.as_bytes()[offset..offset + (self.as_ref().cbModulus as usize)]
    }
}
