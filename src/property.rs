//! Named properties support for CNG objects.

use crate::handle::Handle;
use crate::helpers::{FromBytes, WideCString};
use crate::{Error, Result};
use core::mem::{self, MaybeUninit};
use core::ptr;
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{LPCWSTR, PUCHAR, ULONG, WCHAR};

impl<T: Handle> Access for T {}

/// Supports setting and getting named properties for CNG objects.
pub trait Access: Handle {
    fn set_property<T: Property>(&self, value: &T::Value) -> Result<()> {
        let property = WideCString::from(T::IDENTIFIER);
        unsafe {
            Error::check(BCryptSetProperty(
                self.as_ptr(),
                property.as_ptr(),
                value as *const _ as PUCHAR,
                mem::size_of_val(value) as ULONG,
                0,
            ))
        }
    }

    fn get_property<T: Property>(&self) -> Result<T::Value>
    where
        T::Value: Sized,
    {
        let property = WideCString::from(T::IDENTIFIER);
        let mut size = mem::size_of::<T::Value>() as u32;

        // We are not expected to allocate extra trailing data, so construct the
        // value and return it inline (especially important for `Copy` types)
        let mut result = MaybeUninit::<T::Value>::uninit();

        unsafe {
            Error::check(BCryptGetProperty(
                self.as_ptr(),
                property.as_ptr(),
                result.as_mut_ptr() as *mut _,
                size,
                &mut size,
                0,
            ))?;
        }
        // SAFETY: Verify that the API call has written the exact amount of
        // bytes, so that we can conclude it's been entirely initialized
        assert_eq!(size as usize, mem::size_of::<T::Value>());

        Ok(unsafe { result.assume_init() })
    }

    fn get_property_unsized<T: Property>(&self) -> Result<Box<T::Value>> {
        let property = WideCString::from(T::IDENTIFIER);

        let mut size = get_property_size(self.as_ptr(), property.as_ptr())?;
        let mut result = vec![0u8; size as usize].into_boxed_slice();

        unsafe {
            Error::check(BCryptGetProperty(
                self.as_ptr(),
                property.as_ptr(),
                result.as_mut_ptr(),
                size,
                &mut size,
                0,
            ))?;
        }
        // SAFETY: Verify that the API call has written the exact amount of
        // bytes, so that we can conclude it's been entirely initialized
        assert_eq!(size as usize, result.len());

        Ok(FromBytes::from_boxed(result))
    }
}

fn get_property_size(handle: BCRYPT_HANDLE, prop: LPCWSTR) -> Result<ULONG> {
    let mut size: ULONG = 0;
    unsafe {
        Error::check(BCryptGetProperty(
            handle,
            prop,
            ptr::null_mut(),
            0,
            &mut size,
            0,
        ))?;
    }
    Ok(size)
}

// Marker trait for any type that can be used as the CNG property.
pub trait Property {
    const IDENTIFIER: &'static str;
    type Value: FromBytes + ?Sized;
}

/// [**BCRYPT_ALGORITHM_NAME**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_ALGORITHM_NAME)
///
/// `L"AlgorithmName"`
///
/// A null-terminated Unicode string that contains the name of the algorithm.
pub enum AlgorithmName {}
impl Property for AlgorithmName {
    const IDENTIFIER: &'static str = BCRYPT_ALGORITHM_NAME;
    type Value = [WCHAR];
}

/// [**BCRYPT_BLOCK_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_BLOCK_LENGTH)
///
/// `L"BlockLength"`
///
/// The size, in bytes, of a cipher block for the algorithm. This property only
/// applies to block cipher algorithms. This data type is a **DWORD**.
pub enum BlockLength {}
impl Property for BlockLength {
    const IDENTIFIER: &'static str = BCRYPT_BLOCK_LENGTH;
    type Value = DWORD;
}

/// [**BCRYPT_CHAINING_MODE**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_CHAINING_MODE)
///
/// `L"ChainingMode"`
///
/// A pointer to a null-terminated Unicode string that represents the chaining
/// mode of the encryption algorithm. This property can be set on an algorithm
/// handle or a key handle to one of the following values.
///
/// | Identifier            | Value              |  Description                                                                                                                                         |
/// |-----------------------|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
/// | BCRYPT_CHAIN_MODE_CBC | L"ChainingModeCBC" | Sets the algorithm's chaining mode to cipher block chaining.                                                                                         |
/// | BCRYPT_CHAIN_MODE_CCM | L"ChainingModeCCM" | Sets the algorithm's chaining mode to counter with CBC-MAC mode (CCM).Windows Vista:  This value is supported beginning with Windows Vista with SP1. |
/// | BCRYPT_CHAIN_MODE_CFB | L"ChainingModeCFB" | Sets the algorithm's chaining mode to cipher feedback.                                                                                               |
/// | BCRYPT_CHAIN_MODE_ECB | L"ChainingModeECB" | Sets the algorithm's chaining mode to electronic codebook.                                                                                           |
/// | BCRYPT_CHAIN_MODE_GCM | L"ChainingModeGCM" | Sets the algorithm's chaining mode to Galois/counter mode (GCM).Windows Vista:  This value is supported beginning with Windows Vista with SP1.       |
/// | BCRYPT_CHAIN_MODE_NA  | L"ChainingModeN/A" | The algorithm does not support chaining.                                                                                                             |
pub enum ChainingMode {}
impl Property for ChainingMode {
    const IDENTIFIER: &'static str = BCRYPT_CHAINING_MODE;
    type Value = [WCHAR];
}

pub enum EccCurveName {}
impl Property for EccCurveName {
    const IDENTIFIER: &'static str = BCRYPT_ECC_CURVE_NAME;
    type Value = [WCHAR];
}

/// [**BCRYPT_HASH_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_HASH_LENGTH)
///
/// `L"HashDigestLength"`
///
/// The size, in bytes, of the hash value of a hash provider. This data type is
/// a **DWORD**.
pub enum HashLength {}
impl Property for HashLength {
    const IDENTIFIER: &'static str = BCRYPT_HASH_LENGTH;
    type Value = DWORD;
}

/// [**BCRYPT_KEY_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_KEY_LENGTH)
///
/// `L"KeyLength"`
///
/// The size, in bits, of the key value of a symmetric key provider. This data
/// type is a **DWORD**.
pub enum KeyLength {}
impl Property for KeyLength {
    const IDENTIFIER: &'static str = BCRYPT_KEY_LENGTH;
    type Value = DWORD;
}

/// [**BCRYPT_KEY_LENGTHS**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_KEY_LENGTHS)
///
/// `L"KeyLengths"`
///
/// The key lengths that are supported by the algorithm. This property is a
/// [BCRYPT_KEY_LENGTHS_STRUCT] structure. This property only applies to
/// algorithms.
///
/// [BCRYPT_KEY_LENGTHS_STRUCT]: https://docs.microsoft.com/windows/desktop/api/Bcrypt/ns-bcrypt-bcrypt_key_lengths_struct
pub enum KeyLengths {}
impl Property for KeyLengths {
    const IDENTIFIER: &'static str = BCRYPT_KEY_LENGTHS;
    type Value = BCRYPT_KEY_LENGTHS_STRUCT;
}

/// [**BCRYPT_OBJECT_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_OBJECT_LENGTH)
///
/// `L"ObjectLength"`
///
/// The size, in bytes, of the subobject of a provider. This data type is a
/// **DWORD**. Currently, the hash and symmetric cipher algorithm providers use
/// caller-allocated buffers to store their subobjects. For example, the hash
/// provider requires you to allocate memory for the hash object obtained with
/// the [BCryptCreateHash](https://docs.microsoft.com/windows/desktop/api/Bcrypt/nf-bcrypt-bcryptcreatehash)
/// function. This property provides the buffer size for a provider's object so
/// you can allocate memory for the object created by the provider.
pub enum ObjectLength {}
impl Property for ObjectLength {
    const IDENTIFIER: &'static str = BCRYPT_OBJECT_LENGTH;
    type Value = DWORD;
}

pub enum DsaParameters {}
impl Property for DsaParameters {
    const IDENTIFIER: &'static str = BCRYPT_DSA_PARAMETERS;
    type Value = [u8];
}

pub enum DhParameters {}
impl Property for DhParameters {
    const IDENTIFIER: &'static str = BCRYPT_DH_PARAMETERS;
    type Value = [u8];
}
