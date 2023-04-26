//! Named properties support for CNG objects.

use crate::helpers::{FromBytes, Pod};

use winapi::shared::bcrypt;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::WCHAR;

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
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_ALGORITHM_NAME;
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
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_BLOCK_LENGTH;
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
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_CHAINING_MODE;
    type Value = [WCHAR];
}

/// [**BCRYPT_ECC_CURVE_NAME**](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves)
///
/// `L"ECCCurveName"`
///
/// A pointer to a null-terminated Unicode string that represents a named curve.
/// This property can be set to specify which named curve should be used
/// together with the *BCRYPT_ECDSA_ALGORITHM* or *BCRYPT_ECDH_ALGORITHM*.
///
/// See [CNG Named Elliptic Curves] or invoke the `certutil -displayEccCurve`
/// command locally for the list of supported named curves.
///
/// [CNG Named Elliptic Curves]: https://docs.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves
pub enum EccCurveName {}
impl Property for EccCurveName {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_ECC_CURVE_NAME;
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
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_HASH_LENGTH;
    type Value = DWORD;
}

/// [**BCRYPT_INITIALIZATION_VECTOR**](https://docs.microsoft.com/pl-pl/windows/win32/seccng/cng-property-identifiers#BCRYPT_INITIALIZATION_VECTOR)
///
/// L"IV"
///
/// Contains the initialization vector (IV) for a key. This property only applies to keys.
pub enum InitializationVector {}
impl Property for InitializationVector {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_INITIALIZATION_VECTOR;
    type Value = [u8];
}

/// [**BCRYPT_KEY_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_KEY_LENGTH)
///
/// `L"KeyLength"`
///
/// The size, in bits, of the key value of a symmetric key provider. This data
/// type is a **DWORD**.
pub enum KeyLength {}
impl Property for KeyLength {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_KEY_LENGTH;
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
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_KEY_LENGTHS;
    type Value = bcrypt::BCRYPT_KEY_LENGTHS_STRUCT;
}

unsafe impl Pod for bcrypt::BCRYPT_KEY_LENGTHS_STRUCT {}

/// [**BCRYPT_MESSAGE_BLOCK_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_MESSAGE_BLOCK_LENGTH)
///
/// `L"MessageBlockLength"`
///
/// This can be set on any key handle that has the CFB chaining mode set. By
/// default, this property is set to 1 for 8-bit CFB. Setting it to the block
/// size in bytes causes full-block CFB to be used. For XTS keys it is used to
/// set the size, in bytes, of the XTS Data Unit (commonly 512 or 4096).
pub enum MessageBlockLength {}
impl Property for MessageBlockLength {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_MESSAGE_BLOCK_LENGTH;
    type Value = DWORD;
}

/// [**BCRYPT_OBJECT_LENGTH**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_OBJECT_LENGTH)
///
/// `L"ObjectLength"`
///
/// The size, in bytes, of the subobject of a provider. This data type is a
/// **DWORD**. Currently, the hash and symmetric cipher algorithm providers use
/// caller-allocated buffers to store their subobjects. For example, the hash
/// provider requires you to allocate memory for the hash object obtained with
/// the [`BCryptCreateHash`] function. This property provides the buffer size for a
/// provider's object so you can allocate memory for the object created by the
/// provider.
///
/// [`BCryptCreateHash`]: <https://docs.microsoft.com/windows/desktop/api/Bcrypt/nf-bcrypt-bcryptcreatehash>
pub enum ObjectLength {}
impl Property for ObjectLength {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_OBJECT_LENGTH;
    type Value = DWORD;
}

/// [**BCRYPT_DSA_PARAMETERS**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_DSA_PARAMETERS)
///
/// `L"DSAParameters"`
///
/// Specifies parameters to use with a DSA key. This property is a
/// `BCRYPT_DSA_PARAMETER_HEADER` or a `BCRYPT_DSA_PARAMETER_HEADER_V2` structure.
/// This property can only be set and must be set for the key before the key is
/// completed.
///
/// Windows 8: Beginning with Windows 8, this property can be
/// a `BCRYPT_DSA_PARAMETER_HEADER_V2` structure. Use this structure if the key
/// size exceeds 1024 bits and is less than or equal to 3072 bits. If the key
/// size is greater than or equal to 512 but less than or equal to 1024 bits,
/// use the `BCRYPT_DSA_PARAMETER_HEADER` structure.
pub enum DsaParameters {}
impl Property for DsaParameters {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_DSA_PARAMETERS;
    // FIXME: Can we somehow use unsized unions?... We need to dynamically pass
    // or receive V1/V2 structs.
    type Value = [u8];
}

/// [**BCRYPT_DH_PARAMETERS**](https://docs.microsoft.com/windows/win32/seccng/cng-property-identifiers#BCRYPT_DH_PARAMETERS)
///
/// `L"DHParameters"`
///
/// Specifies parameters to use with a Diffie-Hellman key. This data type is a
/// pointer to a `BCRYPT_DH_PARAMETER_HEADER` structure. This property can only be
/// set and must be set for the key before the key is completed.
pub enum DhParameters {}
impl Property for DhParameters {
    const IDENTIFIER: &'static str = bcrypt::BCRYPT_DH_PARAMETERS;
    // TODO: Replace with appropriate blob type
    type Value = [u8];
}
