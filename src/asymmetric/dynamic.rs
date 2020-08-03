/// Dynamic asymmetric algorithm
pub struct DynamicAsymmetricAlgorithm(AsymmetricAlgorithmId);

impl DynamicAsymmetricAlgorithm {
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
    pub fn open(id: AsymmetricAlgorithmId) -> Result<AsymmetricAlgorithm<Self>> {
        let handle = match id {
            AsymmetricAlgorithmId::Dh => dh::Dh::open()?.handle,
            AsymmetricAlgorithmId::Dsa => dsa::Dsa::open()?.handle,
            AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP256) => ecdh::Ecdh::<ecc::NistP256>::open()?.handle,
            AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP384) => ecdh::Ecdh::<ecc::NistP384>::open()?.handle,
            AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP521) => ecdh::Ecdh::<ecc::NistP521>::open()?.handle,
            AsymmetricAlgorithmId::Ecdh(NamedCurve::Curve25519) => ecdh::Ecdh::<ecc::Curve25519>::open()?.handle,
            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP256) => ecdsa::Ecdsa::<ecc::NistP256>::open()?.handle,
            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP384) => ecdsa::Ecdsa::<ecc::NistP384>::open()?.handle,
            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP521) => ecdsa::Ecdsa::<ecc::NistP521>::open()?.handle,
            AsymmetricAlgorithmId::Ecdsa(NamedCurve::Curve25519) => ecdsa::Ecdsa::<ecc::Curve25519>::open()?.handle,
            AsymmetricAlgorithmId::Rsa => rsa::Rsa::open()?.handle,
        };

        Ok(AsymmetricAlgorithm::new(handle, Self(id)))
    }

    /*///
    /// # Examples
    /// ```
    /// # use win_crypto_ng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
    /// let algo = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa).unwrap();
    /// assert_eq!(algo.id(), Ok(AsymmetricAlgorithmId::Rsa));
    /// ```
    pub fn id(&self) -> Result<AsymmetricAlgorithmId> {
        let name = self
            .handle
            .get_property_unsized::<AlgorithmName>()
            .map(|name| WideCString::from_bytes_with_nul(name).unwrap().to_string())?;

        AsymmetricAlgorithmId::try_from(name.as_str()).map_err(|_| crate::Error::InvalidHandle)
    }*/
}

impl Algorithm for DynamicAsymmetricAlgorithm {
    fn id(&self) -> AsymmetricAlgorithmId {
        self.0
        /*let name = handle
            .get_property_unsized::<AlgorithmName>()
            .map(|name| WideCString::from_bytes_with_nul(name).unwrap().to_string())?;

        AsymmetricAlgorithmId::try_from(name.as_str()).map_err(|_| crate::Error::InvalidHandle)*/
    }
}

impl<'a> Import<'a, DynamicAsymmetricAlgorithm, Public> for AsymmetricKey<DynamicAsymmetricAlgorithm, Public> {
    type Blob = &'a Blob<ErasedKeyBlob>;
}

impl<'a> Import<'a, DynamicAsymmetricAlgorithm, Private> for AsymmetricKey<DynamicAsymmetricAlgorithm, Private> {
    type Blob = &'a Blob<ErasedKeyBlob>;
}

impl<'a> Export<DynamicAsymmetricAlgorithm, Public> for AsymmetricKey<DynamicAsymmetricAlgorithm, Public> {
    type Blob = ErasedKeyBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::PublicKey
    }
}

impl<'a> Export<DynamicAsymmetricAlgorithm, Private> for AsymmetricKey<DynamicAsymmetricAlgorithm, Private> {
    type Blob = ErasedKeyBlob;

    fn blob_type(&self) -> BlobType {
        BlobType::PrivateKey
    }
}

impl NotNeedsKeySize for DynamicAsymmetricAlgorithm {}
impl NeedsKeySize for DynamicAsymmetricAlgorithm {}

impl BuilderWithKeyBits<DynamicAsymmetricAlgorithm> {
    pub fn with_params(
        self,
        params: BuilderOptions,
    ) -> BuilderWithParams<AsymmetricAlgorithmId, BuilderOptions> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params,
        }
    }

    pub fn build(self) -> Result<AsymmetricKey<DynamicAsymmetricAlgorithm, Private>> {
        BuilderWithParams {
            algorithm: self.algorithm,
            key_bits: self.key_bits,
            params: (),
        }
        .build()
    }
}

impl BuilderParams for BuilderOptions {
    fn set_param(&self, handle: BCRYPT_HANDLE, key_bits: u32) -> Result<()> {
        let (property, blob) = match self {
            BuilderOptions::Dsa(params) => (BCRYPT_DSA_PARAMETERS, params.to_blob(key_bits)),
            BuilderOptions::Dh(params) => {
                (BCRYPT_DH_PARAMETERS, params.to_blob(key_bits).into_bytes())
            }
        };

        set_property(handle, property, &blob)
    }
}
