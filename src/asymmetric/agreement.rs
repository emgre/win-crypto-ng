//! Functionality related to secret agreement and key derivation.

use crate::asymmetric::{ecc::Curve, AsymmetricKey, Ecdh, Private, Public};
use crate::helpers::Handle;
use crate::{Error, Result};

use core::ptr::null_mut;

use winapi::shared::bcrypt::*;

/// Creates a secret agreement value from a private and a public key.
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

/// Handle representing a secret agreement value. Used for key derivation.
pub struct SecretHandle {
    handle: BCRYPT_SECRET_HANDLE,
}

unsafe impl Send for SecretHandle {}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptDestroySecret(self.handle);
            }
        }
    }
}

impl Handle for SecretHandle {
    fn as_ptr(&self) -> BCRYPT_SECRET_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_SECRET_HANDLE {
        &mut self.handle
    }
}

impl SecretHandle {
    /// Returns the little-endian representation of the raw secret without any modification.
    ///
    /// > **NOTE**: Supported only on Windows 10.
    pub fn derive_raw(&self) -> Result<Box<[u8]>> {
        // NOTE: Only supported on Windows 10
        let id = crate::helpers::WindowsString::from(BCRYPT_KDF_RAW_SECRET);

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
