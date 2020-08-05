//! Digital signature facilities.
//!
//! A scheme to verify the authenticity of digital messages or documents using
//! asymmetric cryptography.

use crate::asymmetric::ecc::{NistP256, NistP384, NistP521};
use crate::asymmetric::{AsymmetricKey, Dsa, Ecdsa, Private, Public, Rsa};
use crate::hash::HashAlgorithmId;
use crate::helpers::WindowsString;
use crate::helpers::{Handle, KeyHandle};
use crate::{Error, Result};
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;

pub trait Signer {
    fn sign(&self, input: &[u8], padding: Option<SignaturePadding>) -> Result<Box<[u8]>>;
}

pub trait Verifier {
    fn verify(
        &self,
        hash: &[u8],
        signature: &[u8],
        padding: Option<SignaturePadding>,
    ) -> Result<()>;
}

macro_rules! impl_sign_verify {
    ($type: ty) => {
        impl Signer for $type {
            fn sign(&self, input: &[u8], padding: Option<SignaturePadding>) -> Result<Box<[u8]>> {
                sign_hash(&self.0, padding, input)
            }
        }
        impl_verify!($type);
    };
}
macro_rules! impl_verify {
    ($type: ty) => {
        impl Verifier for $type {
            fn verify(
                &self,
                hash: &[u8],
                signature: &[u8],
                padding: Option<SignaturePadding>,
            ) -> Result<()> {
                verify_signature(&self.0, padding, hash, signature)
            }
        }
    };
}

impl_sign_verify!(AsymmetricKey<Rsa, Private>);
impl_verify!(AsymmetricKey<Rsa, Public>);
impl_sign_verify!(AsymmetricKey<Dsa, Private>);
impl_verify!(AsymmetricKey<Dsa, Public>);
impl_sign_verify!(AsymmetricKey<Ecdsa<NistP256>, Private>);
impl_verify!(AsymmetricKey<Ecdsa<NistP256>, Public>);
impl_sign_verify!(AsymmetricKey<Ecdsa<NistP384>, Private>);
impl_verify!(AsymmetricKey<Ecdsa<NistP384>, Public>);
impl_sign_verify!(AsymmetricKey<Ecdsa<NistP521>, Private>);
impl_verify!(AsymmetricKey<Ecdsa<NistP521>, Public>);

/// Padding scheme to be used when creating/verifying a hash signature.
#[derive(Clone, Copy)]
pub enum SignaturePadding {
    /// Use the PKCS #1 padding scheme.
    Pkcs1(Pkcs1Padding),
    /// Use the Probabilistic Signature Scheme (PSS) padding scheme.
    Pss(PssPadding),
}

impl SignaturePadding {
    pub fn pkcs1(algorithm: HashAlgorithmId) -> SignaturePadding {
        SignaturePadding::Pkcs1(Pkcs1Padding { algorithm })
    }
    pub fn pss(algorithm: HashAlgorithmId, salt: u32) -> SignaturePadding {
        SignaturePadding::Pss(PssPadding { algorithm, salt })
    }
}

/// PKCS #1 padding scheme.
/// # More
/// https://docs.microsoft.com/pl-pl/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_pkcs1_padding_info
#[derive(Clone, Copy)]
pub struct Pkcs1Padding {
    /// Hashing algorithm to be used to create the padding.
    pub algorithm: HashAlgorithmId,
}

/// Probabilistic Signature Scheme (PSS) padding scheme.
#[derive(Clone, Copy)]
pub struct PssPadding {
    /// Hashing algorithm to be used to create the padding.
    pub algorithm: HashAlgorithmId,
    /// The size, in bytes, of the random salt to use for the padding.
    pub salt: u32,
}

#[repr(C)]
union PaddingInfo<'a> {
    pkcs: BCRYPT_PKCS1_PADDING_INFO,
    pss: BCRYPT_PSS_PADDING_INFO,
    // Lifetime marker for borrowed hash algorithm identifier string
    // FIXME: Just use &'static [u16] for alg ID once winapi 0.4 is released
    marker: std::marker::PhantomData<&'a ()>,
}

impl SignaturePadding {
    fn to_ffi_args<'a>(&self, out: &'a mut WindowsString) -> (PaddingInfo<'a>, u32) {
        match self {
            SignaturePadding::Pkcs1(Pkcs1Padding { algorithm }) => {
                *out = WindowsString::from(algorithm.to_str());
                (
                    PaddingInfo {
                        pkcs: BCRYPT_PKCS1_PADDING_INFO {
                            pszAlgId: out.as_ptr(),
                        },
                    },
                    BCRYPT_PAD_PKCS1,
                )
            }
            SignaturePadding::Pss(PssPadding { algorithm, salt }) => {
                *out = WindowsString::from(algorithm.to_str());
                (
                    PaddingInfo {
                        pss: BCRYPT_PSS_PADDING_INFO {
                            pszAlgId: out.as_ptr(),
                            cbSalt: *salt,
                        },
                    },
                    BCRYPT_PAD_PSS,
                )
            }
        }
    }
}

fn sign_hash(
    key: &KeyHandle,
    padding: Option<SignaturePadding>,
    input: &[u8],
) -> Result<Box<[u8]>> {
    let mut hash_alg_id = WindowsString::new();
    let padding = padding.map(|x| x.to_ffi_args(&mut hash_alg_id));
    let padding_info = padding
        .as_ref()
        .map(|(padding, _)| padding as *const _ as *mut _);
    let padding_info = padding_info.unwrap_or_else(null_mut);
    let flags = padding.as_ref().map(|(_, flags)| *flags).unwrap_or(0);

    let mut result = 0;

    Error::check(unsafe {
        BCryptSignHash(
            key.handle,
            padding_info,
            input.as_ptr() as *mut _,
            input.len() as u32,
            null_mut(),
            0,
            &mut result,
            flags,
        )
    })?;
    let mut output = vec![0u8; result as usize].into_boxed_slice();

    Error::check(unsafe {
        BCryptSignHash(
            key.handle,
            padding_info,
            input.as_ptr() as *mut _,
            input.len() as u32,
            output.as_mut_ptr(),
            output.len() as u32,
            &mut result,
            flags,
        )
    })?;
    assert_eq!(output.len(), result as usize);

    Ok(output)
}

fn verify_signature(
    key: &KeyHandle,
    padding: Option<SignaturePadding>,
    hash: &[u8],
    signature: &[u8],
) -> Result<()> {
    let mut hash_alg_id = WindowsString::new();
    let padding = padding.map(|x| x.to_ffi_args(&mut hash_alg_id));
    let padding_info = padding
        .as_ref()
        .map(|(padding, _)| padding as *const _ as *mut _);
    let padding_info = padding_info.unwrap_or_else(null_mut);
    let flags = padding.as_ref().map(|(_, flags)| *flags).unwrap_or(0);

    Error::check(unsafe {
        BCryptVerifySignature(
            key.as_ptr(),
            padding_info,
            hash.as_ptr() as *mut _,
            hash.len() as u32,
            signature.as_ptr() as *mut _,
            signature.len() as u32,
            flags,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_sign_verify() {
        use super::SignaturePadding;
        use crate::hash::HashAlgorithmId::*;

        let key = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();

        let digest: Vec<u8> = (0..32).collect();
        let padding = SignaturePadding::pkcs1(Sha256);
        let signature = key
            .sign(&*digest, Some(padding))
            .expect("Signing to succeed");
        key.verify(&digest, &signature, Some(padding))
            .expect("Signature to be valid");

        key.verify(&[0xDE, 0xAD], &signature, Some(padding))
            .expect_err("Bad digest");
        key.verify(&digest, &[0xDE, 0xAD], Some(padding))
            .expect_err("Bad signature");
        let padding_sha1 = SignaturePadding::pkcs1(Sha1);
        let padding_pss = SignaturePadding::pss(Sha256, 64);
        key.verify(&digest, &signature, Some(padding_sha1))
            .expect_err("Bad padding");
        key.verify(&digest, &signature, Some(padding_pss))
            .expect_err("Bad padding");

        let key = AsymmetricKey::builder(Ecdsa(NistP256)).build().unwrap();
        let signature = key.sign(&*digest, None).expect("Signing to succeed");
        key.verify(&digest, &signature, None)
            .expect("Signature to be valid");
        key.verify(&[0xDE, 0xAD], &signature, None)
            .expect_err("Bad digest");
        key.verify(&digest, &[0xDE, 0xAD], None)
            .expect_err("Bad signature");
    }
}
