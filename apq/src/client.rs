//! MLS client plumbing for the combiner: cipher-suite configs, the client builder, and the
//! `CombinerClient` that holds the agent identity and the classical (+ optional PQ) MLS clients.

use mls_rs::{
    client::Client,
    client_builder::{self, BaseConfig, WithCryptoProvider, WithIdentityProvider},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuiteProvider, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

#[cfg(feature = "cryptokit")]
use mls_rs_crypto_cryptokit::CryptoKitMlKemProvider;

use crate::{CombinerError, Result};

/// ML-KEM-768 cipher suite value (0xFDEA, FIPS 203) in the MLS private-use range.
#[cfg(feature = "cryptokit")]
const ML_KEM_768: u16 = 0xFDEA;

pub type OurConfig =
    WithIdentityProvider<BasicIdentityProvider, WithCryptoProvider<RustCryptoProvider, BaseConfig>>;
pub type MlsClient = Client<OurConfig>;

#[cfg(feature = "cryptokit")]
pub type PqConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<CryptoKitMlKemProvider, BaseConfig>,
>;
#[cfg(feature = "cryptokit")]
pub type PqMlsClient = Client<PqConfig>;

/// Holds an agent signing key and the MLS client(s) that manage its key packages and groups.
/// The signing key's public component is the agent's ClientId (a Basic Credential).
pub struct CombinerClient {
    client_id: Vec<u8>,
    classical: MlsClient,
    #[cfg(feature = "cryptokit")]
    pq: PqMlsClient,
}

impl CombinerClient {
    /// Build a `CombinerClient` from an existing agent signing key.
    pub fn new(signing_key: Vec<u8>) -> Result<Self> {
        let crypto = RustCryptoProvider::new();
        let suite = mls_rs::CipherSuite::CURVE25519_CHACHA;
        let cs = crypto
            .cipher_suite_provider(suite)
            .ok_or(CombinerError::Mls)?;

        let secret_key = mls_rs::crypto::SignatureSecretKey::new(signing_key.clone());
        let public_key = cs
            .signature_key_derive_public(&secret_key)
            .map_err(|_| CombinerError::Mls)?;

        let client_id = public_key.as_ref().to_vec();
        let classical = build_client(secret_key, public_key.clone(), suite);

        #[cfg(feature = "cryptokit")]
        let pq = build_pq_client(
            mls_rs::crypto::SignatureSecretKey::new(signing_key),
            public_key,
            mls_rs::CipherSuite::from(ML_KEM_768),
        );

        Ok(Self {
            client_id,
            classical,
            #[cfg(feature = "cryptokit")]
            pq,
        })
    }

    /// The agent's ClientId bytes (public signing key).
    pub fn client_id(&self) -> &[u8] {
        &self.client_id
    }

    pub fn classical(&self) -> &MlsClient {
        &self.classical
    }

    #[cfg(feature = "cryptokit")]
    pub fn pq(&self) -> &PqMlsClient {
        &self.pq
    }

    /// Generate a fresh classical (0x0003) KeyPackage, MLS-encoded for publication.
    pub fn generate_classical_key_package(&self) -> Result<Vec<u8>> {
        let msg = self
            .classical
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
            .map_err(|_| CombinerError::Mls)?;
        msg.to_bytes().map_err(|_| CombinerError::Mls)
    }

    /// Generate a fresh ML-KEM-768 (0xFDEA) KeyPackage, MLS-encoded for publication.
    #[cfg(feature = "cryptokit")]
    pub fn generate_pq_key_package(&self) -> Result<Vec<u8>> {
        let msg = self
            .pq
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
            .map_err(|_| CombinerError::Mls)?;
        msg.to_bytes().map_err(|_| CombinerError::Mls)
    }
}

fn build_client(
    secret_key: mls_rs::crypto::SignatureSecretKey,
    public_key: mls_rs::crypto::SignaturePublicKey,
    suite: mls_rs::CipherSuite,
) -> MlsClient {
    let credential = BasicCredential::new(public_key.as_ref().to_vec());
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(RustCryptoProvider::new())
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}

#[cfg(feature = "cryptokit")]
fn build_pq_client(
    secret_key: mls_rs::crypto::SignatureSecretKey,
    public_key: mls_rs::crypto::SignaturePublicKey,
    suite: mls_rs::CipherSuite,
) -> PqMlsClient {
    let credential = BasicCredential::new(public_key.as_ref().to_vec());
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(CryptoKitMlKemProvider)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}
