//! Cryptographically secure random number generation
//!
//! # Usage
//!
//! To generate cryptographically secure random numbers, start by opening a
//! [`RandomNumberGenerator`]. This can be done either via the [`open`] method
//! where you specify the random algorithm to use or with the [`system_preferred`]
//! method, where the system default is used. Then, to fill a buffer with random
//! numbers, call the [`gen_random`] method.
//!
//! ```
//! use win_crypto_ng::random::{RandomAlgorithmId, RandomNumberGenerator};
//!
//! let mut buffer = [0u8; 32];
//! let rng = RandomNumberGenerator::open(RandomAlgorithmId::Rng).unwrap();
//! rng.gen_random(&mut buffer).unwrap();
//!
//! assert_ne!(&buffer, &[0u8; 32]);
//! ```
//!
//! [`RandomNumberGenerator`]: struct.RandomNumberGenerator.html
//! [`open`]: struct.RandomNumberGenerator.html#method.open
//! [`system_preferred`]: struct.RandomNumberGenerator.html#method.system_preferred
//! [`gen_random`]: struct.RandomNumberGenerator.html#method.gen_random

use crate::handle::{AlgoHandle, Handle};
use crate::Error;
use core::convert::TryFrom;
use core::fmt;
use core::ptr;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

/// Random number generation algorithms identifiers
#[derive(Clone, Copy, PartialOrd, PartialEq)]
pub enum RandomAlgorithmId {
    /// The random-number generator algorithm.
    ///
    /// Standard: FIPS 186-2, FIPS 140-2, NIST SP 800-90
    ///
    /// Beginning with Windows Vista with SP1 and Windows Server 2008, the
    /// random number generator is based on the AES counter mode specified in
    /// the NIST SP 800-90 standard.
    ///
    /// **Windows Vista**: The random number generator is based on the hash-based
    /// random number generator specified in the FIPS 186-2 standard.
    ///
    /// **Windows 8**: Beginning with Windows 8, the RNG algorithm supports
    /// FIPS 186-3. Keys less than or equal to 1024 bits adhere to FIPS 186-2
    /// and keys greater than 1024 to FIPS 186-3.
    Rng,
    /// The dual elliptic curve random-number generator algorithm.
    ///
    /// Standard: SP800-90.
    ///
    /// **Windows 8**: Beginning with Windows 8, the EC RNG algorithm supports
    /// FIPS 186-3. Keys less than or equal to 1024 bits adhere to FIPS 186-2
    /// and keys greater than 1024 to FIPS 186-3.
    ///
    /// **Windows 10**: Beginning with Windows 10, the dual elliptic curve random
    /// number generator algorithm has been removed. Existing uses of this
    /// algorithm will continue to work; however, the random number generator is
    /// based on the AES counter mode specified in the NIST SP 800-90 standard.
    /// New code should use [`Rng`](#variant.Rng), and it is recommended that
    /// existing code be changed to use [`Rng`](#variant.Rng).
    DualECRng,
    /// The random-number generator algorithm suitable for DSA (Digital
    /// Signature RandomAlgorithmId).
    ///
    /// Standard: FIPS 186-2.
    ///
    /// **Windows 8**: Support for FIPS 186-3 begins.
    Fips186DsaRng,
}

impl<'a> TryFrom<&'a str> for RandomAlgorithmId {
    type Error = &'a str;

    fn try_from(value: &'a str) -> Result<RandomAlgorithmId, Self::Error> {
        match value {
            BCRYPT_RNG_ALGORITHM => Ok(RandomAlgorithmId::Rng),
            BCRYPT_RNG_DUAL_EC_ALGORITHM => Ok(RandomAlgorithmId::DualECRng),
            BCRYPT_RNG_FIPS186_DSA_ALGORITHM => Ok(RandomAlgorithmId::Fips186DsaRng),
            _ => Err(value),
        }
    }
}

impl Into<&'static str> for RandomAlgorithmId {
    fn into(self) -> &'static str {
        match self {
            RandomAlgorithmId::Rng => BCRYPT_RNG_ALGORITHM,
            RandomAlgorithmId::DualECRng => BCRYPT_RNG_DUAL_EC_ALGORITHM,
            RandomAlgorithmId::Fips186DsaRng => BCRYPT_RNG_FIPS186_DSA_ALGORITHM,
        }
    }
}

impl fmt::Display for RandomAlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(*self))
    }
}

/// Random number generator
///
/// Main type that is capable of generating random
/// numbers.
pub struct RandomNumberGenerator {
    handle: RandomAlgoHandle,
}

impl RandomNumberGenerator {
    /// Open a random number generator using the provided algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::random::{RandomAlgorithmId, RandomNumberGenerator};
    /// let rng = RandomNumberGenerator::open(RandomAlgorithmId::Rng);
    ///
    /// assert!(rng.is_ok());
    /// ```
    pub fn open(id: RandomAlgorithmId) -> crate::Result<RandomNumberGenerator> {
        let handle = RandomAlgoHandle::open(id)?;
        Ok(Self { handle })
    }

    /// Open a random number generator using the system preferred algorithm.
    ///
    /// **Windows Vista**: This is not supported.
    pub fn system_preferred() -> RandomNumberGenerator {
        let handle = RandomAlgoHandle::SystemPreferred;
        Self { handle }
    }

    /// Fills a buffer with random bytes.
    ///
    /// Use a random number for the entropy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::random::{RandomAlgorithmId, RandomNumberGenerator};
    /// let mut buffer = [0u8; 32];
    /// let rng = RandomNumberGenerator::system_preferred();
    /// rng.gen_random(&mut buffer).unwrap();
    ///
    /// assert_ne!(&buffer, &[0u8; 32]);
    /// ```
    pub fn gen_random(&self, buffer: &mut [u8]) -> crate::Result<()> {
        self.gen_random_with_opts(buffer, self.handle.flags())
    }

    /// Fills a buffer with random bytes.
    ///
    /// This function will use the number in the buffer as additional
    /// entropy for the random number.
    ///
    /// **Windows 8 and later**: This does the exact same thing as
    /// [`gen_random`](#method.gen_random).
    ///
    /// # Examples
    ///
    /// ```
    /// # use win_crypto_ng::random::{RandomAlgorithmId, RandomNumberGenerator};
    /// let mut buffer = [0u8; 32];
    /// let rng = RandomNumberGenerator::system_preferred();
    /// rng.gen_random_with_entropy_in_buffer(&mut buffer).unwrap();
    ///
    /// assert_ne!(&buffer, &[0u8; 32]);
    /// ```
    pub fn gen_random_with_entropy_in_buffer(&self, buffer: &mut [u8]) -> crate::Result<()> {
        self.gen_random_with_opts(
            buffer,
            self.handle.flags() | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER,
        )
    }

    fn gen_random_with_opts(&self, buffer: &mut [u8], opts: ULONG) -> crate::Result<()> {
        let handle = self.handle.handle();

        Error::check(unsafe {
            BCryptGenRandom(handle, buffer.as_mut_ptr(), buffer.len() as ULONG, opts)
        })
    }
}

/// Wrapper around `AlgoHandle` that can only specify RNG algorithms.
enum RandomAlgoHandle {
    /// System-preferred algorithm provider.
    SystemPreferred,
    /// An already opened provider for a specified algorithm.
    Specified(AlgoHandle),
}

impl RandomAlgoHandle {
    fn open(id: RandomAlgorithmId) -> crate::Result<Self> {
        Ok(Self::Specified(AlgoHandle::open(id.into())?))
    }

    fn handle(&self) -> BCRYPT_ALG_HANDLE {
        match self {
            Self::SystemPreferred => ptr::null_mut(),
            Self::Specified(handle) => handle.as_ptr(),
        }
    }

    fn flags(&self) -> ULONG {
        match self {
            Self::SystemPreferred => BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            Self::Specified(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rng(rng: RandomNumberGenerator) {
        let empty = vec![0; 32];

        let mut buf = empty.clone();
        rng.gen_random(&mut buf).expect("RNG to succeed");
        assert_ne!(&buf, &empty);

        let mut buf2 = buf.clone();
        rng.gen_random_with_entropy_in_buffer(&mut buf2)
            .expect("RNG to succeeed");
        assert_ne!(&buf2, &empty);
        assert_ne!(&buf2, &buf);
    }

    #[test]
    fn system_preferred() {
        let rng = RandomNumberGenerator::system_preferred();
        test_rng(rng);
    }

    #[test]
    fn rng() {
        let rng = RandomNumberGenerator::open(RandomAlgorithmId::Rng).unwrap();
        test_rng(rng);
    }

    #[test]
    fn dualecrng() {
        let rng = RandomNumberGenerator::open(RandomAlgorithmId::DualECRng).unwrap();
        test_rng(rng);
    }

    #[test]
    fn fips186dsarng() {
        let rng = RandomNumberGenerator::open(RandomAlgorithmId::Fips186DsaRng).unwrap();
        test_rng(rng);
    }
}
