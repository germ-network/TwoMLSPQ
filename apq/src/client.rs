//! MLS client plumbing for the combiner: cipher-suite configs, the client builder, and the
//! `CombinerClient` that holds the agent identity and the classical (+ optional PQ) MLS
//! clients. The key-package storage type `S` is a parameter — exactly as mls-rs's own
//! `Client<C>` is generic over its config — so the concrete store (e.g. the capture/serve
//! store used to build invitations) is chosen by the caller (`two-mls-pq`), keeping `apq`
//! store-agnostic.

use mls_rs::{
    client::Client,
    client_builder::{self, BaseConfig, WithCryptoProvider, WithIdentityProvider, WithKeyPackageRepo},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuiteProvider, CryptoProvider, ExtensionList, KeyPackageStorage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

#[cfg(feature = "cryptokit")]
use mls_rs_crypto_cryptokit::CryptoKitMlKemProvider;
use zeroize::Zeroizing;

use crate::{CombinerError, Result};

/// ML-KEM-768 cipher suite value (0xFDEA, FIPS 203) in the MLS private-use range.
#[cfg(feature = "cryptokit")]
const ML_KEM_768: u16 = 0xFDEA;

pub type OurConfig<S> = WithKeyPackageRepo<
    S,
    WithIdentityProvider<BasicIdentityProvider, WithCryptoProvider<RustCryptoProvider, BaseConfig>>,
>;
pub type MlsClient<S> = Client<OurConfig<S>>;

#[cfg(feature = "cryptokit")]
pub type PqConfig<S> = WithKeyPackageRepo<
    S,
    WithIdentityProvider<
        BasicIdentityProvider,
        WithCryptoProvider<CryptoKitMlKemProvider, BaseConfig>,
    >,
>;
#[cfg(feature = "cryptokit")]
pub type PqMlsClient<S> = Client<PqConfig<S>>;

/// Holds an agent identity (ClientId) and the MLS client(s) that manage its key packages
/// and groups, parameterised by the key-package storage `S`. The ClientId is opaque,
/// caller-supplied bytes carried as the Basic Credential. Each MLS half owns its *own*
/// signing key (classical and PQ are independent); the keys are retained here so the signing
/// identity can be archived and restored. The signing keys' public components are NOT the
/// ClientId.
pub struct CombinerClient<S: KeyPackageStorage + Clone> {
    client_id: Vec<u8>,
    classical_signing_key: Zeroizing<Vec<u8>>,
    classical: MlsClient<S>,
    classical_kp_store: S,
    #[cfg(feature = "cryptokit")]
    pq_signing_key: Zeroizing<Vec<u8>>,
    #[cfg(feature = "cryptokit")]
    pq: PqMlsClient<S>,
    #[cfg(feature = "cryptokit")]
    pq_kp_store: S,
}

impl<S: KeyPackageStorage + Clone> CombinerClient<S> {
    /// Build a `CombinerClient` for the given ClientId with a fresh, independent signing key
    /// per half and empty (default) key-package stores. `client_id` is opaque identity bytes
    /// (the Basic Credential), independent of the generated signing keys.
    pub fn new(client_id: Vec<u8>) -> Result<Self>
    where
        S: Default,
    {
        let crypto = RustCryptoProvider::new();
        let suite = mls_rs::CipherSuite::CURVE25519_CHACHA;
        let cs = crypto
            .cipher_suite_provider(suite)
            .ok_or(CombinerError::Mls)?;

        let (classical_sk, classical_pk) =
            cs.signature_key_generate().map_err(|_| CombinerError::Mls)?;
        let classical_signing_key = Zeroizing::new(classical_sk.as_bytes().to_vec());
        let classical_kp_store = S::default();
        let classical = build_client(
            client_id.clone(),
            classical_sk,
            classical_pk,
            suite,
            classical_kp_store.clone(),
        );

        #[cfg(feature = "cryptokit")]
        let (pq_signing_key, pq, pq_kp_store) = {
            let (pq_sk, pq_pk) = cs.signature_key_generate().map_err(|_| CombinerError::Mls)?;
            let bytes = Zeroizing::new(pq_sk.as_bytes().to_vec());
            let store = S::default();
            let client = build_pq_client(
                client_id.clone(),
                pq_sk,
                pq_pk,
                mls_rs::CipherSuite::from(ML_KEM_768),
                store.clone(),
            );
            (bytes, client, store)
        };

        Ok(Self {
            client_id,
            classical_signing_key,
            classical,
            classical_kp_store,
            #[cfg(feature = "cryptokit")]
            pq_signing_key,
            #[cfg(feature = "cryptokit")]
            pq,
            #[cfg(feature = "cryptokit")]
            pq_kp_store,
        })
    }

    /// Restore a `CombinerClient` from an archived signing identity (ClientId + each half's
    /// signing key), installing the caller-provided key-package store(s). Pass empty stores
    /// for a bare identity restore, or stores preloaded with this identity's key package(s)
    /// to make a receiving (invitation) client whose join can find them. Public keys are
    /// re-derived from the signing keys.
    pub fn from_key_packages(
        client_id: Vec<u8>,
        classical_signing_key: Zeroizing<Vec<u8>>,
        classical_kp_store: S,
        #[cfg(feature = "cryptokit")] pq_signing_key: Zeroizing<Vec<u8>>,
        #[cfg(feature = "cryptokit")] pq_kp_store: S,
    ) -> Result<Self> {
        let crypto = RustCryptoProvider::new();
        let suite = mls_rs::CipherSuite::CURVE25519_CHACHA;
        let cs = crypto
            .cipher_suite_provider(suite)
            .ok_or(CombinerError::Mls)?;

        let classical_sk = mls_rs::crypto::SignatureSecretKey::new(classical_signing_key.to_vec());
        let classical_pk = cs
            .signature_key_derive_public(&classical_sk)
            .map_err(|_| CombinerError::Mls)?;
        let classical = build_client(
            client_id.clone(),
            classical_sk,
            classical_pk,
            suite,
            classical_kp_store.clone(),
        );

        #[cfg(feature = "cryptokit")]
        let pq = {
            let pq_sk = mls_rs::crypto::SignatureSecretKey::new(pq_signing_key.to_vec());
            let pq_pk = cs
                .signature_key_derive_public(&pq_sk)
                .map_err(|_| CombinerError::Mls)?;
            build_pq_client(
                client_id.clone(),
                pq_sk,
                pq_pk,
                mls_rs::CipherSuite::from(ML_KEM_768),
                pq_kp_store.clone(),
            )
        };

        Ok(Self {
            client_id,
            classical_signing_key,
            classical,
            classical_kp_store,
            #[cfg(feature = "cryptokit")]
            pq_signing_key,
            #[cfg(feature = "cryptokit")]
            pq,
            #[cfg(feature = "cryptokit")]
            pq_kp_store,
        })
    }

    /// The agent's ClientId bytes (opaque Basic Credential identity).
    pub fn client_id(&self) -> &[u8] {
        &self.client_id
    }

    /// The classical half's signing key bytes — part of the archivable signing identity.
    pub fn classical_signing_key(&self) -> &[u8] {
        self.classical_signing_key.as_slice()
    }

    /// The PQ half's signing key bytes — part of the archivable signing identity.
    #[cfg(feature = "cryptokit")]
    pub fn pq_signing_key(&self) -> &[u8] {
        self.pq_signing_key.as_slice()
    }

    pub fn classical(&self) -> &MlsClient<S> {
        &self.classical
    }

    #[cfg(feature = "cryptokit")]
    pub fn pq(&self) -> &PqMlsClient<S> {
        &self.pq
    }

    /// The classical half's key-package store handle (for capture/inspection by the caller).
    pub fn classical_kp_store(&self) -> &S {
        &self.classical_kp_store
    }

    /// The PQ half's key-package store handle.
    #[cfg(feature = "cryptokit")]
    pub fn pq_kp_store(&self) -> &S {
        &self.pq_kp_store
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

fn build_client<S: KeyPackageStorage + Clone>(
    client_id: Vec<u8>,
    secret_key: mls_rs::crypto::SignatureSecretKey,
    public_key: mls_rs::crypto::SignaturePublicKey,
    suite: mls_rs::CipherSuite,
    key_package_store: S,
) -> MlsClient<S> {
    let credential = BasicCredential::new(client_id);
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(RustCryptoProvider::new())
        .identity_provider(BasicIdentityProvider::new())
        .key_package_repo(key_package_store)
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}

#[cfg(feature = "cryptokit")]
fn build_pq_client<S: KeyPackageStorage + Clone>(
    client_id: Vec<u8>,
    secret_key: mls_rs::crypto::SignatureSecretKey,
    public_key: mls_rs::crypto::SignaturePublicKey,
    suite: mls_rs::CipherSuite,
    key_package_store: S,
) -> PqMlsClient<S> {
    let credential = BasicCredential::new(client_id);
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(CryptoKitMlKemProvider)
        .identity_provider(BasicIdentityProvider::new())
        .key_package_repo(key_package_store)
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}
