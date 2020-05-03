use crate::buffer::Buffer;
use crate::hash::HashAlgorithmId;
use crate::helpers::{Handle, KeyHandle, WindowsString};
use crate::property::KeyLength;
use crate::{Error, Result};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::{PUCHAR, ULONG};
use winapi::shared::ntdef::VOID;

pub mod dh;
pub mod rsa;

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum PaddingOption {
    PKCS1(HashAlgorithmId),
    PSS(HashAlgorithmId, u32),
}

impl PaddingOption {
    fn to_flag(self) -> ULONG {
        match self {
            Self::PKCS1(_) => BCRYPT_PAD_PKCS1,
            Self::PSS(_, _) => BCRYPT_PAD_PSS,
        }
    }

    fn to_struct(self) -> Box<dyn std::any::Any> {
        match self {
            Self::PKCS1(id) => Box::new(BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId: WindowsString::from_str(id.to_str()).as_ptr(),
            }),
            Self::PSS(id, salt_len) => Box::new(BCRYPT_PSS_PADDING_INFO {
                pszAlgId: WindowsString::from_str(id.to_str()).as_ptr(),
                cbSalt: salt_len,
            }),
        }
    }
}

pub struct KeyPair<T: KeyPairType> {
    handle: KeyHandle,
    _phantom: PhantomData<T>,
}

impl<T: KeyPairType> KeyPair<T> {
    fn new(handle: KeyHandle) -> Self {
        Self {
            handle,
            _phantom: PhantomData,
        }
    }

    pub fn key_size(&self) -> Result<usize> {
        self.handle
            .get_property::<KeyLength>()
            .map(|key_size| key_size.copied() as usize)
    }

    pub fn sign(&self, data: &[u8], padding_opt: PaddingOption) -> Result<Buffer> {
        let padding_info = padding_opt.to_struct();
        let padding_info_raw = Box::into_raw(padding_info);
        let result = {
            let mut signature_len = MaybeUninit::<ULONG>::uninit();
            unsafe {
                Error::check(BCryptSignHash(
                    self.handle.as_ptr(),
                    padding_info_raw as *mut VOID,
                    data.as_ptr() as PUCHAR,
                    data.len() as ULONG,
                    null_mut(),
                    0,
                    signature_len.as_mut_ptr(),
                    padding_opt.to_flag(),
                ))?;

                let mut output = Buffer::new(signature_len.assume_init() as usize);

                Error::check(BCryptSignHash(
                    self.handle.as_ptr(),
                    padding_info_raw as *mut VOID,
                    data.as_ptr() as PUCHAR,
                    data.len() as ULONG,
                    output.as_mut_ptr(),
                    output.len() as ULONG,
                    signature_len.as_mut_ptr(),
                    padding_opt.to_flag(),
                ))
                .map(|_| output)
            }
        };
        unsafe {
            Box::from_raw(padding_info_raw);
        }
        result
    }

    pub fn verify(&self, data: &[u8], signature: &[u8], padding_opt: PaddingOption) -> Result<()> {
        let padding_info = padding_opt.to_struct();
        let padding_info_raw = Box::into_raw(padding_info);
        let result = {
            unsafe {
                Error::check(BCryptVerifySignature(
                    self.handle.as_ptr(),
                    padding_info_raw as *mut VOID,
                    data.as_ptr() as PUCHAR,
                    data.len() as ULONG,
                    signature.as_ptr() as PUCHAR,
                    signature.len() as ULONG,
                    padding_opt.to_flag(),
                ))
            }
        };
        unsafe {
            Box::from_raw(padding_info_raw);
        }
        result
    }
}

pub trait KeyPairType {
    type PublicKeyType: PublicKey;
    type PrivateKeyType: PrivateKey;
}

pub trait PublicKey {}

pub trait PrivateKey {}
