use super::{
    Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, BuilderWithKeyBits,
    BuilderWithParams, Export, Import, KeyPair, NeedsKeySize, Private, Public,
};
use crate::handle::AlgoHandle;
use crate::helpers::Blob;
use crate::key::{BlobType, RsaKeyFullPrivateBlob, RsaKeyPrivateBlob, RsaKeyPublicBlob};
use crate::Result;

pub struct Rsa;

impl Algorithm for Rsa {
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Rsa
    }

    fn open(&self) -> Result<AsymmetricAlgorithm<Self>> {
        let handle = AlgoHandle::open(AsymmetricAlgorithmId::Rsa.to_str())?;
        Ok(AsymmetricAlgorithm::new(handle, Self))
    }
}

impl AsymmetricKey<Rsa, Private> {
    /// Attempts to export the key to a given blob type.
    /// # Example
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// # use win_crypto_ng::asymmetric::{Algorithm, Rsa, Private, AsymmetricKey};
    /// # use win_crypto_ng::asymmetric::Export;
    ///
    /// let pair = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();
    /// let blob = pair.as_public().export().unwrap();
    /// dbg!(blob.as_bytes());
    ///
    /// let public = blob;
    /// let pub_exp = public.pub_exp();
    /// let modulus = public.modulus();
    ///
    /// let private = pair.export_full().unwrap();
    /// assert_eq!(pub_exp, private.pub_exp());
    /// assert_eq!(modulus, private.modulus());
    /// ```
    pub fn export_full(&self) -> Result<Box<Blob<RsaKeyFullPrivateBlob>>> {
        Ok(
            KeyPair::export(self.handle.handle, BlobType::RsaFullPrivate)?
                .try_into()
                .map_err(|_| crate::Error::BadData)?,
        )
    }
}

impl<'a> Import<'a, Rsa, Public> for AsymmetricKey<Rsa, Public> {
    type Blob = &'a Blob<RsaKeyPublicBlob>;
}

impl<'a> Import<'a, Rsa, Private> for AsymmetricKey<Rsa, Private> {
    type Blob = &'a Blob<RsaKeyPrivateBlob>;
}

impl Export<Rsa, Public> for AsymmetricKey<Rsa, Public> {
    type Blob = RsaKeyPublicBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::RsaPublic
    }
}

impl Export<Rsa, Private> for AsymmetricKey<Rsa, Private> {
    type Blob = RsaKeyPrivateBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::RsaPrivate
    }
}

impl NeedsKeySize for Rsa {}

impl BuilderWithKeyBits<Rsa> {
    pub fn build(self) -> Result<AsymmetricKey<Rsa, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    #[test]
    fn import_export() -> Result<()> {
        let generated_key = AsymmetricKey::builder(Rsa)
            .key_bits(1024)
            .build()?;
        let blob = generated_key.export()?;

        let algo = Rsa.open()?;
        let imported = AsymmetricKey::<_, Private>::import(&algo, &blob)?;
        let imported_blob = imported.export()?;

        assert_eq!(blob.modulus(), imported_blob.modulus());
        assert_eq!(blob.pub_exp(), imported_blob.pub_exp());
        assert_eq!(blob.prime1(), imported_blob.prime1());

        Ok(())
    }
}
