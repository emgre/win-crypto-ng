//! Asymmetric algorithms
//! 
//! Asymmetric algorithms (also known as public-key algorithms) use pairs of
//! keys: *public key*, which can be known by others, and *private key*, which
//! is known only to the owner. The most common usages include encryption and
//! digital signing.
//! 
//! > **NOTE**: This is currently a stub and should be expanded.

use crate::helpers::{AlgoHandle, Handle, WindowsString};
use crate::property::AlgorithmName;
use crate::Result;
use std::convert::TryFrom;
use winapi::shared::bcrypt::*;

/// Asymmetric algorithm identifiers
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
pub enum AsymmetricAlgorithmId {
    /// The Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: PKCS #3
    Dh,
    /// The digital signature algorithm.
    ///
    /// Standard: FIPS 186-2
    ///
    /// **Windows 8**: Beginning with Windows 8, this algorithm supports
    /// FIPS 186-3. Keys less than or equal to 1024 bits adhere to FIPS 186-2
    /// and keys greater than 1024 to FIPS 186-3.
    Dsa,
    /// The 256-bit prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A
    EcdhP256,
    /// The 384-bit prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A
    EcdhP384,
    /// The 521-bit prime elliptic curve Diffie-Hellman key exchange algorithm.
    ///
    /// Standard: SP800-56A
    EcdhP521,
    /// The 256-bit prime elliptic curve digital signature algorithm (FIPS 186-2).
    ///
    /// Standard: FIPS 186-2, X9.62
    EcdsaP256,
    /// The 384-bit prime elliptic curve digital signature algorithm (FIPS 186-2).
    ///
    /// Standard: FIPS 186-2, X9.62
    EcdsaP384,
    /// The 521-bit prime elliptic curve digital signature algorithm (FIPS 186-2).
    ///
    /// Standard: FIPS 186-2, X9.62
    EcdsaP521,
    /// The RSA public key algorithm.
    ///
    /// Standard: PKCS #1 v1.5 and v2.0.
    Rsa,
}

impl AsymmetricAlgorithmId {
    fn to_str(&self) -> &str {
        match self {
            Self::Dh => BCRYPT_DH_ALGORITHM,
            Self::Dsa => BCRYPT_DSA_ALGORITHM,
            Self::EcdhP256 => BCRYPT_ECDH_P256_ALGORITHM,
            Self::EcdhP384 => BCRYPT_ECDH_P384_ALGORITHM,
            Self::EcdhP521 => BCRYPT_ECDH_P521_ALGORITHM,
            Self::EcdsaP256 => BCRYPT_ECDSA_P256_ALGORITHM,
            Self::EcdsaP384 => BCRYPT_ECDSA_P384_ALGORITHM,
            Self::EcdsaP521 => BCRYPT_ECDSA_P521_ALGORITHM,
            Self::Rsa => BCRYPT_RSA_ALGORITHM,
        }
    }
}

impl<'a> TryFrom<&'a str> for AsymmetricAlgorithmId {
    type Error = &'a str;

    fn try_from(val: &'a str) -> std::result::Result<AsymmetricAlgorithmId, Self::Error> {
        match val {
            BCRYPT_DH_ALGORITHM => Ok(Self::Dh),
            BCRYPT_DSA_ALGORITHM => Ok(Self::Dsa),
            BCRYPT_ECDH_P256_ALGORITHM => Ok(Self::EcdhP256),
            BCRYPT_ECDH_P384_ALGORITHM => Ok(Self::EcdhP384),
            BCRYPT_ECDH_P521_ALGORITHM => Ok(Self::EcdhP521),
            BCRYPT_ECDSA_P256_ALGORITHM => Ok(Self::EcdsaP256),
            BCRYPT_ECDSA_P384_ALGORITHM => Ok(Self::EcdsaP384),
            BCRYPT_ECDSA_P521_ALGORITHM => Ok(Self::EcdsaP521),
            BCRYPT_RSA_ALGORITHM => Ok(Self::Rsa),
            val => Err(val),
        }
    }
}

/// Asymmetric algorithm
pub struct AsymmetricAlgorithm {
    handle: AlgoHandle,
}

impl AsymmetricAlgorithm {
    /// Open an asymmetric algorithm provider
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa);
    ///
    /// assert!(algo.is_ok());
    /// ```
    pub fn open(id: AsymmetricAlgorithmId) -> Result<Self> {
        let handle = AlgoHandle::open(id.to_str())?;

        Ok(Self { handle })
    }

    ///
    /// # Examples
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
    /// assert_eq!(algo.id(), Ok(AsymmetricAlgorithmId::Rsa));
    /// ```
    pub fn id(&self) -> Result<AsymmetricAlgorithmId> {
        let name = self.handle.get_property_unsized::<AlgorithmName>()?;
        let name = WindowsString::from_ptr(name.as_ref().as_ptr());

        AsymmetricAlgorithmId::try_from(&*name.to_string())
            .map_err(|_| crate::Error::InvalidHandle)
    }
}
