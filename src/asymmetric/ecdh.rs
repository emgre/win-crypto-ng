use crate::Result;
use crate::handle::AlgoHandle;
use crate::helpers::Blob;
use crate::key::{BlobType, EccKeyPublicBlob, EccKeyPrivateBlob};
use super::{Algorithm, AsymmetricAlgorithm, AsymmetricAlgorithmId, AsymmetricKey, Export, Import, Public, Private};
use super::ecc::Curve;
use crate::helpers::WideCString;
use crate::property::{Access, EccCurveName};
use std::marker::PhantomData;

pub struct Ecdh<C: Curve>(PhantomData<C>);

impl<C: Curve> Ecdh<C> {
    pub fn open() -> Result<AsymmetricAlgorithm<Self>> {
        let curve = C::as_curve();
        let handle = AlgoHandle::open(AsymmetricAlgorithmId::Ecdh(curve).to_str())?;

        let property = WideCString::from(curve.as_str());
        handle.set_property::<EccCurveName>(property.as_slice_with_nul())?;

        Ok(AsymmetricAlgorithm::new(handle, Self(PhantomData)))
    }
}

impl<C: Curve> Algorithm for Ecdh<C> {
    fn id(&self) -> AsymmetricAlgorithmId {
        AsymmetricAlgorithmId::Ecdh(C::as_curve())
    }
}

impl<'a, C: Curve> Import<'a, Ecdh<C>, Public> for AsymmetricKey<Ecdh<C>, Public> {
    type Blob = &'a Blob<EccKeyPublicBlob>;
}

impl<'a, C: Curve> Import<'a, Ecdh<C>, Private> for AsymmetricKey<Ecdh<C>, Private> {
    type Blob = &'a Blob<EccKeyPrivateBlob>;
}

impl<C: Curve> Export<Ecdh<C>, Public> for AsymmetricKey<Ecdh<C>, Public> {
    type Blob = EccKeyPublicBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::EccPublic
    }
}

impl<C: Curve> Export<Ecdh<C>, Private> for AsymmetricKey<Ecdh<C>, Private> {
    type Blob = EccKeyPrivateBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::EccPrivate
    }
}

impl<C: Curve> NotNeedsKeySize for Ecdh<C> {}

impl<C: Curve> BuilderWithKeyBits<Ecdh<C>> {
    pub fn with_params(self, params: ()) -> BuilderWithParams<Ecdh<C>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }
}
