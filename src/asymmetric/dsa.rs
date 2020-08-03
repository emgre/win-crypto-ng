use crate::Result;
use crate::handle::AlgoHandle;
use crate::helpers::Blob;
use crate::key::{BlobType, DsaKeyPublicBlob, DsaKeyPrivateBlob};
use super::{Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, Export, Import, Public, Private};

pub struct Dsa;

impl Dsa {
    pub fn open() -> Result<AsymmetricAlgorithm<Self>> {
        let handle = AlgoHandle::open(AsymmetricAlgorithmId::Dsa.to_str())?;
        Ok(AsymmetricAlgorithm::new(handle, Self))
    }
}

impl Algorithm for Dsa {
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Dsa
    }
}

impl<'a> Import<'a, Dsa, Public> for AsymmetricKey<Dsa, Public> {
    type Blob = &'a Blob<DsaKeyPublicBlob>;
}

impl<'a> Import<'a, Dsa, Private> for AsymmetricKey<Dsa, Private> {
    type Blob = &'a Blob<DsaKeyPrivateBlob>;
}

impl Export<Dsa, Public> for AsymmetricKey<Dsa, Public> {
    type Blob = DsaKeyPublicBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::DsaPublic
    }
}

impl Export<Dsa, Private> for AsymmetricKey<Dsa, Private> {
    type Blob = DsaKeyPrivateBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::DsaPrivate
    }
}

impl Builder<Dsa> {
    pub fn key_bits_in_512_1024(
        self,
        key_bits: u32,
    ) -> Result<BuilderWithKeyBits<Dsa, KeyBitsGte512Lte1024>> {
        match key_bits {
            512..=1024 => {}
            _ => return Err(Error::InvalidParameter),
        }

        Ok(BuilderWithKeyBits {
            algorithm: self.algorithm,
            key_bits,
            key_constraint: PhantomData,
        })
    }

    pub fn key_bits_in_1024_3072(
        self,
        key_bits: u32,
    ) -> Result<BuilderWithKeyBits<Dsa, KeyBitsGt1024Lte3072>> {
        match key_bits {
            1024..=3072 => {}
            _ => return Err(Error::InvalidParameter),
        }

        Ok(BuilderWithKeyBits {
            algorithm: self.algorithm,
            key_bits,
            key_constraint: PhantomData,
        })
    }
}

impl NeedsKeySize for Dsa {}

impl BuilderWithKeyBits<Dsa> {
    pub fn with_params(self, params: DsaParams) -> BuilderWithParams<Dsa, DsaParams> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa, KeyBitsGte512Lte1024> {
    pub fn with_params(self, params: DsaParamsV1) -> BuilderWithParams<Dsa, DsaParamsV1> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderWithKeyBits<Dsa, KeyBitsGt1024Lte3072> {
    pub fn with_params(self, params: DsaParamsV2) -> BuilderWithParams<Dsa, DsaParamsV2> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}

impl BuilderParams for DsaParams {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(handle, BCRYPT_DSA_PARAMETERS, &self.to_blob(key_bits))
    }
}

impl BuilderParams for DsaParamsV1 {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(
            handle,
            BCRYPT_DSA_PARAMETERS,
            self.to_blob(key_bits).as_bytes(),
        )
    }
}
impl BuilderParams for DsaParamsV2 {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        set_property(
            handle,
            BCRYPT_DSA_PARAMETERS,
            self.to_blob(key_bits).as_bytes(),
        )
    }
}

impl BuilderWithKeyBits<Dsa> {
    pub fn build(self) -> Result<AsymmetricKey<Dsa, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

pub enum DsaParams {
    V1(DsaParamsV1),
    V2(DsaParamsV2),
}

pub struct DsaParamsV1 {
    count: u32,
    seed: [u8; 20], // big-endian
    q: [u8; 20],    // big-endian
    prime: Vec<u8>,
    generator: Vec<u8>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum FipsVersion {
    Fips186V2,
    Fips186V3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum DsaHashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct DsaParamsV2 {
    count: u32,
    hash: DsaHashAlgorithm,
    standard: FipsVersion,
    seed_len: u32,
    group_size: u32,
    prime: Vec<u8>,
    generator: Vec<u8>,
}

impl DsaParams {
    fn to_blob(&self, key_bits: u32) -> Box<[u8]> {
        match self {
            DsaParams::V1(params) => params.to_blob(key_bits).into_bytes(),
            DsaParams::V2(params) => params.to_blob(key_bits).into_bytes(),
        }
    }
}

impl DsaParamsV1 {
    fn to_blob(&self, key_bits: u32) -> Box<Blob<DsaParameter>> {
        let key_bytes = key_bits as usize / 8;
        let header_len = std::mem::size_of::<BCRYPT_DSA_PARAMETER_HEADER>();
        let length = header_len + key_bytes + key_bytes;

        Blob::<DsaParameter>::clone_from_parts(
            &BCRYPT_DSA_PARAMETER_HEADER {
                cbLength: length as u32,
                dwMagic: BCRYPT_DSA_PARAMETERS_MAGIC,
                cbKeyLength: key_bytes as u32,
                Count: self.count.to_be_bytes(),
                Seed: self.seed,
                q: self.q,
            },
            &DsaParameterViewTail {
                generator: &self.generator,
                prime: &self.prime,
            },
        )
    }
}

impl DsaParamsV2 {
    fn to_blob(&self, key_bits: u32) -> Box<Blob<DsaParameterV2>> {
        let key_bytes = key_bits as usize / 8;
        let header_len = std::mem::size_of::<BCRYPT_DSA_PARAMETER_HEADER_V2>();
        let length = header_len + key_bytes + key_bytes;

        Blob::<DsaParameterV2>::clone_from_parts(
            &BCRYPT_DSA_PARAMETER_HEADER_V2 {
                cbLength: length as u32,
                dwMagic: BCRYPT_DSA_PARAMETERS_MAGIC_V2,
                cbKeyLength: key_bytes as u32,
                Count: self.count.to_be_bytes(),
                cbSeedLength: self.seed_len,
                hashAlgorithm: self.hash as u32,
                standardVersion: self.standard as u32,
                cbGroupSize: self.group_size,
            },
            // TODO: Verify that prime and generator are last (docs are empty on layout...)
            &DsaParameterV2ViewTail {
                generator: &self.generator,
                prime: &self.prime,
            },
        )
    }
}

unsafe impl Pod for BCRYPT_DSA_PARAMETER_HEADER_V2 {}
blob! {
    enum DsaParameterV2 {},
    header: BCRYPT_DSA_PARAMETER_HEADER_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_parameter_header
    view: struct ref DsaParameterV2ViewTail {
        prime[cbKeyLength],
        generator[cbKeyLength],
    }
}

unsafe impl Pod for BCRYPT_DSA_PARAMETER_HEADER {}
blob! {
    enum DhParameter {},
    header: BCRYPT_DH_PARAMETER_HEADER,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_parameter_header
    view: struct ref DhParameterViewTail {
        modulus[cbKeyLength],
        generator[cbKeyLength],
    }
}
