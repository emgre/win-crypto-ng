use super::{
    Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey,
    Export, Import, KeyPair, Private, Public,
};
use super::builder::{BuilderWithKeyBits, NeedsKeySize, BuilderWithParams};
use crate::buffer::Buffer;
use crate::handle::AlgoHandle;
use crate::helpers::{Blob, WideCString};
use crate::key::{BlobType, RsaKeyFullPrivateBlob, RsaKeyPrivateBlob, RsaKeyPublicBlob};
use crate::Result;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;
use std::mem::MaybeUninit;

/// RSA (Rivest-Shamir-Adleman) public key algorithm
///
/// **Standard**: PKCS #1 v1.5 and v2.0
pub struct Rsa;

impl Rsa {
    /// Open the algorithm provider for RSA
    pub fn open() -> Result<AsymmetricAlgorithm<Self>> {
        let handle = AlgoHandle::open(AsymmetricAlgorithmId::Rsa.to_str())?;
        Ok(AsymmetricAlgorithm::new(handle, Self))
    }
}

impl Algorithm for Rsa {
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Rsa
    }
}

// Import/Export

impl AsymmetricKey<Rsa, Private> {
    /// Export the full private key
    ///
    /// # Example
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// # use win_crypto_ng::asymmetric::{Algorithm, Private, AsymmetricKey};
    /// # use win_crypto_ng::asymmetric::rsa::Rsa;
    /// # use win_crypto_ng::asymmetric::Export;
    ///
    /// let algo = Rsa::open().unwrap();
    /// let pair = algo.builder().key_bits(1024).build().unwrap();
    /// let public = pair.as_public().export().unwrap();
    ///
    /// let pub_exp = public.pub_exp();
    /// let modulus = public.modulus();
    ///
    /// let private = pair.export_full().unwrap();
    /// assert_eq!(pub_exp, private.pub_exp());
    /// assert_eq!(modulus, private.modulus());
    /// ```
    pub fn export_full(&self) -> Result<Box<Blob<RsaKeyFullPrivateBlob>>> {
        Ok(
            KeyPair::export(self.0.handle, BlobType::RsaFullPrivate)?
                .try_into()
                .map_err(|_| crate::Error::BadData)?,
        )
    }
}

impl<'a> Import<'a, Rsa, Public> for AsymmetricKey<Rsa, Public> {
    type Blob = &'a Blob<RsaKeyPublicBlob>;
}

impl<'a> Import<'a, Rsa, Private> for AsymmetricKey<Rsa, Private> {
    type Blob = &'a Blob<RsaKeyPrivateBlob>;
}

/*
impl AsymmetricKey<Rsa, Private> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &RsaKeyPrivatePayload,
    ) -> Result<Self> {
        let key_bits = parts.modulus.len() * 8;
        if key_bits % 64 != 0 || key_bits < 512 || key_bits > 16384 {
            return Err(crate::Error::InvalidParameter);
        }

        let header = BCRYPT_RSAKEY_BLOB {
            BitLength: key_bits as u32,
            Magic: BCRYPT_RSAPRIVATE_MAGIC,
            cbModulus: parts.modulus.len() as u32,
            cbPublicExp: parts.pub_exp.len() as u32,
            cbPrime1: parts.prime1.len() as u32,
            cbPrime2: parts.prime2.len() as u32,
        };
        let blob = Blob::<RsaKeyPrivateBlob>::clone_from_parts(&header, parts);

        <Self as Import<_, _>>::import(Rsa, provider, &blob)
    }
}

impl AsymmetricKey<Rsa, Public> {
    pub fn import_from_parts(
        provider: &AsymmetricAlgorithm,
        parts: &RsaKeyPublicPayload,
    ) -> Result<Self> {
        let key_bits = parts.modulus.len() * 8;
        if key_bits % 64 != 0 || key_bits < 512 || key_bits > 16384 {
            return Err(crate::Error::InvalidParameter);
        }

        let header = BCRYPT_RSAKEY_BLOB {
            BitLength: key_bits as u32,
            Magic: BCRYPT_RSAPUBLIC_MAGIC,
            cbModulus: parts.modulus.len() as u32,
            cbPublicExp: parts.pub_exp.len() as u32,
            cbPrime1: 0,
            cbPrime2: 0,
        };
        let blob = Blob::<RsaKeyPublicBlob>::clone_from_parts(&header, parts);

        <Self as Import<_, _>>::import(Rsa, provider, &blob)
    }
}
*/

impl Export<Rsa, Public> for AsymmetricKey<Rsa, Public> {
    type Blob = RsaKeyPublicBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::RsaPublic
    }
}

impl Export<Rsa, Private> for AsymmetricKey<Rsa, Private> {
    type Blob = RsaKeyPrivateBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::RsaPrivate
    }
}

// Builder

impl NeedsKeySize for Rsa {}

impl BuilderWithKeyBits<'_, Rsa> {
    pub fn build(self) -> Result<AsymmetricKey<Rsa, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

// Encryption/decryption

#[derive(Clone, Debug)]
pub struct OaepPadding {
    algorithm: crate::hash::HashAlgorithmId,
    label: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum EncryptionPadding {
    Oaep(OaepPadding),
    Pkcs1,
}

struct OaepPaddingInfo<'a> {
    _borrowed: &'a OaepPadding,
    value: BCRYPT_OAEP_PADDING_INFO,
}

impl OaepPadding {
    fn to_ffi_args<'a>(&self, out: &'a mut WideCString) -> OaepPaddingInfo {
        *out = WideCString::from(self.algorithm.as_str());
        OaepPaddingInfo {
            _borrowed: self,
            value: BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: out.as_ptr(),
                pbLabel: self.label.as_ptr() as *mut _,
                cbLabel: self.label.len() as u32,
            },
        }
    }
}

impl EncryptionPadding {
    fn to_ffi_args<'a>(&'a self, out: &'a mut WideCString) -> (Option<OaepPaddingInfo<'a>>, u32) {
        match self {
            Self::Oaep(oaep_padding) => (Some(oaep_padding.to_ffi_args(out)), BCRYPT_PAD_OAEP),
            Self::Pkcs1 => (None, BCRYPT_PAD_PKCS1),
        }
    }
}

impl AsymmetricKey<Rsa, Private> {
    /// Encrypt data using RSA
    ///
    /// # Example
    /// ```
    /// # use win_crypto_ng::asymmetric::rsa::{Rsa, EncryptionPadding};
    /// const DATA: &[u8] = "this is a test".as_bytes();
    ///
    /// let algo = Rsa::open().unwrap();
    /// let pair = algo.builder().key_bits(1024).build().unwrap();
    /// let encrypted = pair.encrypt(DATA, Some(EncryptionPadding::Pkcs1)).unwrap();
    /// dbg!(encrypted);
    /// ```
    pub fn encrypt(&self, data: &[u8], padding: Option<EncryptionPadding>) -> Result<Buffer> {
        use crate::handle::Handle;
        use std::ptr::null_mut;

        let mut out = WideCString::new();
        let padding = padding.as_ref().map(|x| x.to_ffi_args(&mut out));

        let (pad_info, flags) = padding.as_ref().unwrap_or(&(None, 0));
        let pad_info = pad_info
            .as_ref()
            .map(|pad| &pad.value as *const BCRYPT_OAEP_PADDING_INFO as *mut _);

        let mut encrypted_len = MaybeUninit::<ULONG>::uninit();
        unsafe {
            crate::Error::check(BCryptEncrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                null_mut(),
                0,
                encrypted_len.as_mut_ptr(),
                *flags,
            ))?;

            let mut output = Buffer::new(encrypted_len.assume_init() as usize);

            crate::Error::check(BCryptEncrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                encrypted_len.as_mut_ptr(),
                *flags,
            ))
            .map(|_| output)
        }
    }

    pub fn decrypt(&self, data: &[u8], padding: Option<EncryptionPadding>) -> Result<Buffer> {
        use crate::handle::Handle;
        use std::ptr::null_mut;

        let mut out = WideCString::new();
        let padding = padding.as_ref().map(|x| x.to_ffi_args(&mut out));

        let (pad_info, flags) = padding.as_ref().unwrap_or(&(None, 0));
        let pad_info = pad_info
            .as_ref()
            .map(|pad| &pad.value as *const BCRYPT_OAEP_PADDING_INFO as *mut _);

        let mut plaintext_len = MaybeUninit::<ULONG>::uninit();
        unsafe {
            crate::Error::check(BCryptDecrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                null_mut(),
                0,
                plaintext_len.as_mut_ptr(),
                *flags,
            ))?;

            let mut output = Buffer::new(plaintext_len.assume_init() as usize);

            crate::Error::check(BCryptDecrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                plaintext_len.as_mut_ptr(),
                *flags,
            ))
            .map(|_| output)
        }
    }
}

impl AsymmetricKey<Rsa, Public> {
    pub fn encrypt(&self, data: &[u8], padding: Option<EncryptionPadding>) -> Result<Buffer> {
        use crate::handle::Handle;
        use std::ptr::null_mut;

        let mut out = WideCString::new();
        let padding = padding.as_ref().map(|x| x.to_ffi_args(&mut out));

        let (pad_info, flags) = padding.as_ref().unwrap_or(&(None, 0));
        let pad_info = pad_info
            .as_ref()
            .map(|pad| &pad.value as *const BCRYPT_OAEP_PADDING_INFO as *mut _);

        let mut encrypted_len = MaybeUninit::<ULONG>::uninit();
        unsafe {
            crate::Error::check(BCryptEncrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                null_mut(),
                0,
                encrypted_len.as_mut_ptr(),
                *flags,
            ))?;

            let mut output = Buffer::new(encrypted_len.assume_init() as usize);

            crate::Error::check(BCryptEncrypt(
                self.0.as_ptr(),
                data.as_ptr() as _,
                data.len() as _,
                pad_info.unwrap_or_else(null_mut),
                null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                encrypted_len.as_mut_ptr(),
                *flags,
            ))
            .map(|_| output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    const DATA: &str = "0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn import_export() -> Result<()> {
        let algo = Rsa::open()?;
        let generated_key = algo.builder()
            .key_bits(1024)
            .build()?;
        let blob = generated_key.export()?;

        let algo = Rsa::open()?;
        let imported = AsymmetricKey::<_, Private>::import(&algo, &blob)?;
        let imported_blob = imported.export()?;

        assert_eq!(blob.modulus(), imported_blob.modulus());
        assert_eq!(blob.pub_exp(), imported_blob.pub_exp());
        assert_eq!(blob.prime1(), imported_blob.prime1());

        Ok(())
    }

    #[test]
    fn encrypt_decrypt() {
        let algo = Rsa::open().unwrap();
        let pair = algo.builder().key_bits(1024).build().unwrap();

        let ciphertext = pair
            .encrypt(DATA.as_bytes(), Some(EncryptionPadding::Pkcs1))
            .unwrap();

        let plaintext = pair
            .decrypt(ciphertext.as_slice(), Some(EncryptionPadding::Pkcs1))
            .unwrap();

        assert_ne!(ciphertext.as_slice(), DATA.as_bytes());
        assert_eq!(plaintext.as_slice(), DATA.as_bytes());
    }
}
