//! MLS client plumbing for the combiner: cipher-suite configs, the client builder, and the
//! `CombinerClient` that holds the agent identity and the classical (+ optional PQ) MLS clients.

use mls_rs::{
    client::Client,
    client_builder::{
        self, BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    },
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuiteProvider, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

#[cfg(feature = "cryptokit")]
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

use zeroize::Zeroizing;

use crate::group::{MlsGroup, PqMlsGroup};
use crate::storage::PersistableGroupStorage;
use crate::{CombinerError, Result};

/// ML-KEM-768 cipher suite value (0xFDEA, FIPS 203) in the MLS private-use range.
#[cfg(feature = "cryptokit")]
const ML_KEM_768: u16 = 0xFDEA;

pub type OurConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithGroupStateStorage<
        PersistableGroupStorage,
        WithCryptoProvider<RustCryptoProvider, BaseConfig>,
    >,
>;
pub type MlsClient = Client<OurConfig>;

#[cfg(feature = "cryptokit")]
pub type PqConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithGroupStateStorage<
        PersistableGroupStorage,
        WithCryptoProvider<AwsLcCryptoProvider, BaseConfig>,
    >,
>;
#[cfg(feature = "cryptokit")]
pub type PqMlsClient = Client<PqConfig>;

/// Holds an agent signing key and the MLS client(s) that manage its key packages and groups.
/// The signing key's public component is the agent's ClientId (a Basic Credential).
pub struct CombinerClient {
    client_id: Vec<u8>,
    classical: MlsClient,
    classical_storage: PersistableGroupStorage,
    #[cfg(feature = "cryptokit")]
    pq: PqMlsClient,
    #[cfg(feature = "cryptokit")]
    pq_storage: PersistableGroupStorage,
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
        let classical_storage = PersistableGroupStorage::new();
        let classical = build_client(
            secret_key,
            public_key.clone(),
            suite,
            classical_storage.clone(),
        );

        #[cfg(feature = "cryptokit")]
        let pq_storage = PersistableGroupStorage::new();
        #[cfg(feature = "cryptokit")]
        let pq = build_pq_client(
            mls_rs::crypto::SignatureSecretKey::new(signing_key),
            public_key,
            mls_rs::CipherSuite::from(ML_KEM_768),
            pq_storage.clone(),
        );

        Ok(Self {
            client_id,
            classical,
            classical_storage,
            #[cfg(feature = "cryptokit")]
            pq,
            #[cfg(feature = "cryptokit")]
            pq_storage,
        })
    }

    /// Serialise this client's group-state storage for archival. Returns the classical store and,
    /// under `cryptokit`, the separate PQ store (without it the PQ half lives in the classical
    /// store, so the second element is `None`). Call after the session has flushed its groups via
    /// `write_to_storage`.
    pub fn export_storage(&self) -> (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>) {
        #[cfg(feature = "cryptokit")]
        {
            (
                self.classical_storage.to_bytes(),
                Some(self.pq_storage.to_bytes()),
            )
        }
        #[cfg(not(feature = "cryptokit"))]
        {
            (self.classical_storage.to_bytes(), None)
        }
    }

    /// Repopulate this client's group-state storage from bytes produced by [`Self::export_storage`].
    pub fn restore_storage(&self, classical: &[u8], pq: Option<&[u8]>) -> Result<()> {
        self.classical_storage.restore_from_bytes(classical)?;
        #[cfg(feature = "cryptokit")]
        if let Some(pq) = pq {
            self.pq_storage.restore_from_bytes(pq)?;
        }
        #[cfg(not(feature = "cryptokit"))]
        let _ = pq;
        Ok(())
    }

    /// Reload a classical group previously written to this client's storage.
    pub fn load_classical_group(&self, group_id: &[u8]) -> Result<MlsGroup> {
        self.classical
            .load_group(group_id)
            .map_err(|_| CombinerError::Mls)
    }

    /// Reload a PQ group previously written to this client's storage. Without `cryptokit` the PQ
    /// half is a classical group held in the classical client.
    pub fn load_pq_group(&self, group_id: &[u8]) -> Result<PqMlsGroup> {
        #[cfg(feature = "cryptokit")]
        {
            self.pq.load_group(group_id).map_err(|_| CombinerError::Mls)
        }
        #[cfg(not(feature = "cryptokit"))]
        {
            self.classical
                .load_group(group_id)
                .map_err(|_| CombinerError::Mls)
        }
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
    storage: PersistableGroupStorage,
) -> MlsClient {
    let credential = BasicCredential::new(public_key.as_ref().to_vec());
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(RustCryptoProvider::new())
        .group_state_storage(storage)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}

#[cfg(feature = "cryptokit")]
fn build_pq_client(
    secret_key: mls_rs::crypto::SignatureSecretKey,
    public_key: mls_rs::crypto::SignaturePublicKey,
    suite: mls_rs::CipherSuite,
    storage: PersistableGroupStorage,
) -> PqMlsClient {
    let credential = BasicCredential::new(public_key.as_ref().to_vec());
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(AwsLcCryptoProvider::new())
        .group_state_storage(storage)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}
