use crate::asymmetric::{KeyPair, KeyPairType, PrivateKey, PublicKey};
use crate::helpers::{AlgoHandle, Handle, KeyHandle};
use crate::{Error, Result};
use winapi::shared::bcrypt::*;
use winapi::shared::minwindef::ULONG;

/// The Diffie-Hellman key exchange algorithm.
///
/// Standard: PKCS #3
pub struct RsaAlgorithm {
    handle: AlgoHandle,
}

impl RsaAlgorithm {
    pub fn open() -> Result<Self> {
        let handle = AlgoHandle::open(BCRYPT_RSA_ALGORITHM)?;

        Ok(Self { handle })
    }

    pub fn generate_key_pair(&self, length: u32) -> Result<RsaKeyPair> {
        let mut key_handle = KeyHandle::new();

        Error::check(unsafe {
            BCryptGenerateKeyPair(
                self.handle.as_ptr(),
                key_handle.as_mut_ptr(),
                length as ULONG,
                0,
            )
        })?;

        Error::check(unsafe { BCryptFinalizeKeyPair(key_handle.as_ptr(), 0) })?;

        Ok(RsaKeyPair::new(key_handle))
    }
}

pub type RsaKeyPair = KeyPair<RsaKeyPairType>;

pub struct RsaKeyPairType;

impl KeyPairType for RsaKeyPairType {
    type PublicKeyType = RsaPublicKey;
    type PrivateKeyType = RsaPrivateKey;
}

pub struct RsaPublicKey {}

impl PublicKey for RsaPublicKey {}

pub struct RsaPrivateKey {}

impl PrivateKey for RsaPrivateKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::PaddingOption;
    use crate::buffer::Buffer;
    use crate::hash::{HashAlgorithm, HashAlgorithmId};
    use crate::Result;

    fn create_hash(hash_algo: HashAlgorithmId, data: &[u8]) -> Result<Buffer> {
        let algo = HashAlgorithm::open(hash_algo)?;
        let mut hash = algo.new_hash()?;
        hash.hash(data)?;
        hash.finish()
    }

    #[test]
    fn generate_key_pair() {
        let algo = RsaAlgorithm::open().unwrap();
        let key_pair = algo.generate_key_pair(2048).unwrap();
        assert_eq!(2048, key_pair.key_size().unwrap());
    }

    #[test]
    fn sign_and_verify() {
        let hash_algo = HashAlgorithmId::Sha256;
        let hash = create_hash(hash_algo, &"Hello world!".as_bytes()).unwrap();

        let algo = RsaAlgorithm::open().unwrap();
        let key_pair = algo.generate_key_pair(2048).unwrap();
        assert_eq!(2048, key_pair.key_size().unwrap());

        let padding_opt = PaddingOption::Pkcs1(hash_algo);
        let signature = key_pair.sign(hash.as_slice(), padding_opt).unwrap();
        assert!(key_pair
            .verify(hash.as_slice(), signature.as_slice(), padding_opt)
            .is_ok());
    }
}
