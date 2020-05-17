//! Digital signature
//!
//! A scheme to verify the authenticity of digital messages or documents using
//! asymmetric cryptography.

use crate::hash::HashAlgorithmId;
use crate::helpers::{Handle, WindowsString};
use crate::key::KeyHandle;
use crate::{Error, Result};
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;

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
                *out = WindowsString::from_str(algorithm.to_str());
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
                *out = WindowsString::from_str(algorithm.to_str());
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

pub fn sign_hash(key: &KeyHandle, padding: SignaturePadding, input: &[u8]) -> Result<Box<[u8]>> {
    let mut hash_alg_id = WindowsString::new();
    let (padding_info, flags) = padding.to_ffi_args(&mut hash_alg_id);
    let mut result = 0;

    Error::check(unsafe {
        BCryptSignHash(
            key.handle,
            &padding_info as *const _ as *mut _,
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
            &padding_info as *const _ as *mut _,
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

pub fn verify_signature(
    key: &KeyHandle,
    padding: SignaturePadding,
    hash: &[u8],
    signature: &[u8],
) -> Result<()> {
    let mut hash_alg_id = WindowsString::new();
    let (padding_info, flags) = padding.to_ffi_args(&mut hash_alg_id);

    Error::check(unsafe {
        BCryptVerifySignature(
            key.as_ptr(),
            &padding_info as *const _ as *mut _,
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
        use crate::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use crate::hash::HashAlgorithmId::*;
        use winapi::shared::bcrypt::*;

        let provider =
            AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).expect("To open provider");
        // TODO: Replace when key generation API will be wrapped
        let mut key_handle = KeyHandle::new();
        crate::Error::check(unsafe {
            BCryptGenerateKeyPair(provider.handle.as_ptr(), key_handle.as_mut_ptr(), 1024, 0)
        })
        .unwrap();
        crate::Error::check(unsafe { BCryptFinalizeKeyPair(key_handle.as_ptr(), 0) }).unwrap();

        let digest: Vec<u8> = (0..32).collect();
        let padding = SignaturePadding::pkcs1(Sha256);
        let signature =
            super::sign_hash(&key_handle, padding, &*digest).expect("Signing to succeed");
        verify_signature(&key_handle, padding, &digest, &signature).expect("Signature to be valid");

        verify_signature(&key_handle, padding, &[0xDE, 0xAD], &signature).expect_err("Bad digest");
        verify_signature(&key_handle, padding, &digest, &[0xDE, 0xAD]).expect_err("Bad signature");
        let padding_sha1 = SignaturePadding::pkcs1(Sha1);
        let padding_pss = SignaturePadding::pss(Sha256, 64);
        verify_signature(&key_handle, padding_sha1, &digest, &signature).expect_err("Bad padding");
        verify_signature(&key_handle, padding_pss, &digest, &signature).expect_err("Bad padding");
    }
}
