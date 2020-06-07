//! Cryptographic key handle

use crate::blob;
use crate::helpers::blob::{Blob, BlobLayout};
use crate::helpers::Handle;
use std::convert::TryFrom;
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

impl<'a> TryFrom<&'a str> for BlobType {
    type Error = &'a str;

    fn try_from(val: &'a str) -> Result<BlobType, Self::Error> {
        match val {
            BCRYPT_AES_WRAP_KEY_BLOB => Ok(BlobType::AesWrapKey),
            BCRYPT_DH_PRIVATE_BLOB => Ok(BlobType::DhPrivate),
            BCRYPT_DH_PUBLIC_BLOB => Ok(BlobType::DhPublic),
            BCRYPT_DSA_PUBLIC_BLOB => Ok(BlobType::DsaPublic),
            BCRYPT_DSA_PRIVATE_BLOB => Ok(BlobType::DsaPrivate),
            BCRYPT_ECCPRIVATE_BLOB => Ok(BlobType::EccPrivate),
            BCRYPT_ECCPUBLIC_BLOB => Ok(BlobType::EccPublic),
            BCRYPT_KEY_DATA_BLOB => Ok(BlobType::KeyData),
            BCRYPT_OPAQUE_KEY_BLOB => Ok(BlobType::OpaqueKey),
            BCRYPT_PUBLIC_KEY_BLOB => Ok(BlobType::PublicKey),
            BCRYPT_PRIVATE_KEY_BLOB => Ok(BlobType::PrivateKey),
            BCRYPT_RSAFULLPRIVATE_BLOB => Ok(BlobType::RsaFullPrivate),
            BCRYPT_RSAPRIVATE_BLOB => Ok(BlobType::RsaPrivate),
            BCRYPT_RSAPUBLIC_BLOB => Ok(BlobType::RsaPublic),
            LEGACY_DH_PRIVATE_BLOB => Ok(BlobType::LegacyDhPrivate),
            LEGACY_DH_PUBLIC_BLOB => Ok(BlobType::LegacyDhPublic),
            LEGACY_DSA_PRIVATE_BLOB => Ok(BlobType::LegacyDsaPrivate),
            LEGACY_DSA_PUBLIC_BLOB => Ok(BlobType::LegacyDsaPublic),
            LEGACY_DSA_V2_PRIVATE_BLOB => Ok(BlobType::LegacyDsaV2Private),
            LEGACY_RSAPRIVATE_BLOB => Ok(BlobType::LegacyRsaPrivate),
            LEGACY_RSAPUBLIC_BLOB => Ok(BlobType::LegacyRsaPublic),
            val => Err(val),
        }
    }
}

/// Marker trait for values containing CNG key blob types.
pub unsafe trait KeyBlob: Sized {
    // TODO: Require : BlobLayout + Self::Header: AsRef<BCRYPT_KEY_BLOB>
    // This can be used to cheaply get the magic and to get rid of `unsafe`
    // trait and make the as_erased call actually safe
    const VALID_MAGIC: &'static [ULONG];

    fn is_magic_valid(magic: ULONG) -> bool {
        let accepts_all = Self::VALID_MAGIC == [];
        accepts_all || Self::VALID_MAGIC.iter().any(|&x| x == magic)
    }
}

impl<T> AsRef<Blob<ErasedKeyBlob>> for Blob<T>
where
    T: BlobLayout + KeyBlob,
{
    fn as_ref(&self) -> &Blob<ErasedKeyBlob> {
        self.as_erased()
    }
}

impl<T> Blob<T>
where
    T: BlobLayout + KeyBlob,
{
    pub fn magic(&self) -> ULONG {
        self.as_erased().header().Magic
    }

    pub fn blob_type(&self) -> Option<BlobType> {
        magic_to_blob_type(self.magic())
    }

    pub fn as_erased(&self) -> &Blob<ErasedKeyBlob> {
        // SAFETY: The `KeyBlob` trait is only implemented for types that also
        // implement BlobLayout and whose header extends the basic
        // BCRYPT_KEY_BLOB, which Blob<ErasedKeyBlob> wraps
        unsafe { self.ref_cast() }
    }

    // NOTE: TryInto can't be implemented due to blanket generic TryFrom impl,
    // i.e. U = T provides a blanket Into<T> for T impl.
    pub fn try_into<U>(self: Box<Self>) -> Result<Box<Blob<U>>, Box<Self>>
    where
        U: BlobLayout + KeyBlob,
    {
        if !U::is_magic_valid(self.magic()) {
            return Err(self);
        }

        Ok(Blob::<U>::from_boxed(self.into_bytes()))
    }
}

macro_rules! key_blobs {
    ($($name: ident, $blob: expr, magic: $([$($val: ident),*])?),*) => {
        fn magic_to_blob_type(magic: ULONG) -> Option<BlobType> {
            match magic {
                $(
                    $($(| $val)* => Some($blob),)?
                )*
                _ => None
            }
        }

        $(
            unsafe impl KeyBlob for $name {
                const VALID_MAGIC: &'static [ULONG] = &[$($($val),*)?];
            }

        )*
    };
}

key_blobs! {
    ErasedKeyBlob, BlobType::PublicKey, magic:,
    DhKeyPublicBlob, BlobType::DhPublic, magic: [BCRYPT_DH_PUBLIC_MAGIC],
    DhKeyPrivateBlob, BlobType::DhPrivate, magic: [BCRYPT_DH_PRIVATE_MAGIC],
    DsaKeyPublicBlob, BlobType::DsaPublic, magic: [BCRYPT_DSA_PUBLIC_MAGIC],
    DsaKeyPrivateBlob, BlobType::DsaPrivate, magic: [BCRYPT_DSA_PRIVATE_MAGIC],
    DsaKeyPublicV2Blob, BlobType::DsaPublic, magic: [BCRYPT_DSA_PUBLIC_MAGIC_V2],
    DsaKeyPrivateV2Blob, BlobType::DsaPrivate, magic: [BCRYPT_DSA_PRIVATE_MAGIC_V2],
    EccKeyPublicBlob, BlobType::EccPublic, magic: [
        BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, BCRYPT_ECDH_PUBLIC_P256_MAGIC,
        BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PUBLIC_P521_MAGIC,
        BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PUBLIC_P521_MAGIC
    ],
    EccKeyPrivateBlob, BlobType::EccPrivate, magic: [
        BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, BCRYPT_ECDH_PRIVATE_P256_MAGIC,
        BCRYPT_ECDH_PRIVATE_P384_MAGIC, BCRYPT_ECDH_PRIVATE_P521_MAGIC,
        BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC, BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
        BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECDSA_PRIVATE_P521_MAGIC
    ],
    RsaKeyPublicBlob, BlobType::RsaPublic, magic: [BCRYPT_RSAPUBLIC_MAGIC],
    RsaKeyPrivateBlob, BlobType::RsaPrivate, magic: [BCRYPT_RSAPRIVATE_MAGIC],
    RsaKeyFullPrivateBlob, BlobType::RsaFullPrivate, magic: [BCRYPT_RSAFULLPRIVATE_MAGIC]
}

blob! {
    enum ErasedKeyBlob {},
    header: BCRYPT_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    view: struct ref ErasedKeyBlobView {
        phantom[0],
    }
}

blob! {
    enum RsaKeyPublicBlob {},
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    view: struct ref RsaKeyPublicViewTail {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
    }
}

blob! {
    #[derive(Debug)]
    enum RsaKeyPrivateBlob {},
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[derive(Debug)]
    view: struct ref RsaKeyBlobPrivateTail {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
    }
}

blob! {
    enum RsaKeyFullPrivateBlob {},
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    view: struct ref RsaKeyBlobFullPrivateTail {
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

blob! {
    enum DhKeyPublicBlob {},
    header: BCRYPT_DH_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    view: struct ref DhKeyBlobPublicTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

blob! {
    enum DhKeyPrivateBlob {},
    header: BCRYPT_DH_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    view: struct ref DhKeyBlobPrivateTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[cbKey],
    }
}

blob! {
    enum DsaKeyPublicBlob {},
    header: BCRYPT_DSA_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    view: struct ref DsaKeyBlobPublicTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

blob! {
    enum DsaKeyPrivateBlob {},
    header: BCRYPT_DSA_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    view: struct ref DsaKeyBlobPrivateTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

blob! {
    enum DsaKeyPublicV2Blob {},
    header: BCRYPT_DSA_KEY_BLOB_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    view: struct ref DsaKeyBlobPublicV2Tail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

blob! {
    enum DsaKeyPrivateV2Blob {},
    header: BCRYPT_DSA_KEY_BLOB_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    view: struct ref DsaKeyBlobPrivateV2Tail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

blob! {
    enum EccKeyPublicBlob {},
    header: BCRYPT_ECCKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    view: struct ref EccKeyBlobPublicTail {
        x[cbKey],
        y[cbKey],
    }
}

blob! {
    enum EccKeyPrivateBlob {},
    header: BCRYPT_ECCKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    view: struct ref EccKeyBlobPrivateTail {
        x[cbKey],
        y[cbKey],
        d[cbKey],
    }
}
