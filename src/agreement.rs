//! Functionality related to secret agreement and key derivation.

use crate::asymmetric::{ecc::Curve, AsymmetricKey, Ecdh, Private, Public};
use crate::handle::{Handle, SecretHandle};
use crate::{Error, Result};

use std::ptr::null_mut;

use winapi::shared::bcrypt::*;

pub fn secret_agreement<C: Curve>(
    private: &AsymmetricKey<Ecdh<C>, Private>,
    public: &AsymmetricKey<Ecdh<C>, Public>,
) -> Result<SecretHandle> {
    let mut handle: BCRYPT_SECRET_HANDLE = null_mut();
    Ok(unsafe {
        Error::check(BCryptSecretAgreement(
            private.0.as_ptr(),
            public.0.as_ptr(),
            &mut handle,
            0,
        ))
        .map(|_| SecretHandle { handle })?
    })
}

impl crate::handle::SecretHandle {
    pub fn derive_raw(&self) -> Result<Box<[u8]>> {
        // NOTE: Only supported on Windows 10
        let id = crate::helpers::WideCString::from(BCRYPT_KDF_RAW_SECRET);

        let mut bytes = 0;
        unsafe {
            Error::check(BCryptDeriveKey(
                self.handle,
                id.as_ptr(),
                null_mut(),
                null_mut(),
                0,
                &mut bytes,
                0,
            ))?;

            let mut output = vec![0u8; bytes as usize];

            Error::check(BCryptDeriveKey(
                self.handle,
                id.as_ptr(),
                null_mut(),
                output.as_mut_ptr(),
                bytes,
                &mut bytes,
                0,
            ))?;
            assert_eq!(bytes as usize, output.len());

            Ok(output.into_boxed_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret() {
        use crate::asymmetric::ecc::NistP256;
        let alice = AsymmetricKey::builder(Ecdh(NistP256)).build().unwrap();
        let bob = AsymmetricKey::builder(Ecdh(NistP256)).build().unwrap();

        let _ = secret_agreement(&alice, &bob.as_public()).unwrap();
    }

    #[test]
    fn derive_raw_secret() {
        use crate::asymmetric::ecc::NistP256;
        let alice = AsymmetricKey::builder(Ecdh(NistP256)).build().unwrap();
        let bob = AsymmetricKey::builder(Ecdh(NistP256)).build().unwrap();

        let secret = secret_agreement(&alice, &bob.as_public()).unwrap();
        let _ = secret.derive_raw().unwrap();
    }
}
