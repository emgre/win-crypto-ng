use crate::Result;
use crate::handle::AlgoHandle;
use crate::helpers::Blob;
use crate::key::{BlobType, DhKeyPublicBlob, DhKeyPrivateBlob};
use super::{Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, Export, Import, Public, Private, NeedsKeySize, BuilderWithKeyBits, BuilderWithParams, BuilderParams};
use winapi::shared::bcrypt::*;

pub struct Dh;

impl Dh {
    pub fn open() -> Result<AsymmetricAlgorithm<Self>> {
        let handle = AlgoHandle::open(AsymmetricAlgorithmId::Dh.to_str())?;
        Ok(AsymmetricAlgorithm::new(handle, Self))
    }
}

impl Algorithm for Dh {
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Dh
    }
}

impl<'a> Import<'a, Dh, Public> for AsymmetricKey<Dh, Public> {
    type Blob = &'a Blob<DhKeyPublicBlob>;
}

impl<'a> Import<'a, Dh, Private> for AsymmetricKey<Dh, Private> {
    type Blob = &'a Blob<DhKeyPrivateBlob>;
}

impl Export<Dh, Public> for AsymmetricKey<Dh, Public> {
    type Blob = DhKeyPublicBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::DhPublic
    }
}

impl Export<Dh, Private> for AsymmetricKey<Dh, Private> {
    type Blob = DhKeyPrivateBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::DhPrivate
    }
}

impl NeedsKeySize for Dh {}

impl BuilderWithKeyBits<Dh> {
    pub fn with_params(self, params: DhParams) -> BuilderWithParams<Dh, DhParams> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderParams for DhParams {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(
            handle,
            BCRYPT_DH_PARAMETERS,
            self.to_blob(key_bits).as_ref().as_bytes(),
        )
    }
}

#[derive(Debug)]
pub struct DhParams {
    modulus: Vec<u8>,
    generator: Vec<u8>,
}

impl DhParams {
    fn to_blob(&self, key_bits: u32) -> Box<Blob<DhParameter>> {
        let key_bytes = key_bits as usize / 8;
        let header_len = std::mem::size_of::<BCRYPT_DH_PARAMETER_HEADER>();
        let length = header_len + key_bytes + key_bytes;

        Blob::<DhParameter>::clone_from_parts(
            &BCRYPT_DH_PARAMETER_HEADER {
                cbLength: length as u32,
                dwMagic: BCRYPT_DH_PARAMETERS_MAGIC,
                cbKeyLength: key_bytes as u32,
            },
            &DhParameterViewTail {
                generator: &self.generator,
                modulus: &self.modulus,
            },
        )
    }
}

unsafe impl Pod for BCRYPT_DH_PARAMETER_HEADER {}
blob! {
    enum DsaParameter {},
    header: BCRYPT_DSA_PARAMETER_HEADER,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_parameter_header
    view: struct ref DsaParameterViewTail {
        prime[cbKeyLength],
        generator[cbKeyLength],
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
