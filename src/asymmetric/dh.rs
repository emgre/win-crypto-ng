use crate::asymmetric::{KeyPair, KeyPairType, PrivateKey, PublicKey};
use crate::helpers::{AlgoHandle, Handle, KeyHandle};
use crate::{Error, Result};
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::ULONG;

/// The Diffie-Hellman key exchange algorithm.
///
/// Standard: PKCS #3
pub struct DhAlgorithm {
    handle: AlgoHandle,
}

impl DhAlgorithm {
    pub fn open() -> Result<Self> {
        let handle = AlgoHandle::open(BCRYPT_DH_ALGORITHM)?;

        Ok(Self { handle })
    }

    pub fn generate_key_pair(&self, _params: &Parameters, length: u32) -> Result<DhKeyPair> {
        let mut key_handle = KeyHandle::new();

        Error::check(unsafe {
            BCryptGenerateKeyPair(
                self.handle.as_ptr(),
                key_handle.as_mut_ptr(),
                length as ULONG,
                0,
            )
        })?;

        // TODO: set BCRYPT_DH_PARAMETERS property

        Error::check(unsafe { BCryptFinalizeKeyPair(key_handle.as_ptr(), 0) })?;

        Ok(DhKeyPair::new(key_handle))
    }
}

pub type DhKeyPair = KeyPair<DhKeyPairType>;

pub struct DhKeyPairType;

impl KeyPairType for DhKeyPairType {
    type PublicKeyType = DhPublicKey;
    type PrivateKeyType = DhPrivateKey;
}

/// Represents BCRYPT_DH_PARAMETERS
pub struct Parameters {}

pub struct DhPublicKey {}

impl PublicKey for DhPublicKey {}

pub struct DhPrivateKey {}

impl PrivateKey for DhPrivateKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_pair() {
        let algo = DhAlgorithm::open().unwrap();
        let key_pair = algo.generate_key_pair(&Parameters {}, 2048).unwrap();
        assert_eq!(2048, key_pair.key_size().unwrap());
    }
}
