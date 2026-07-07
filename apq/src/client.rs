//! MLS client plumbing for the combiner: cipher-suite configs, the client builder, and the
//! `CombinerClient` that holds the agent identity and the two MLS clients. The key-package
//! storage type `S` is a parameter — exactly as mls-rs's own `Client<C>` is generic over its
//! config — and so are the crypto providers: `C` backs the classical half, `P` the PQ half.
//! The concrete store and providers are chosen by the caller (`two-mls-pq`), keeping `apq`
//! store- and provider-agnostic.

use mls_rs::{
    client::Client,
    client_builder::{
        self, BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
        WithKeyPackageRepo,
    },
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, CryptoProvider, ExtensionList, KeyPackageStorage,
};
use zeroize::Zeroizing;

use crate::storage::PersistableGroupStorage;
use crate::{CombinerError, Result};

/// ML-KEM-768 cipher suite value (0xFDEA, FIPS 203) in the MLS private-use range. Every PQ
/// provider must implement the suite under this exact value (CryptoKit and aws-lc agree).
const ML_KEM_768: u16 = 0xFDEA;

/// The classical half's cipher suite.
const CLASSICAL_SUITE: CipherSuite = CipherSuite::CURVE25519_CHACHA;

/// Which APQ variant the PQ half runs (draft-ietf-mls-combiner). The mode selects the PQ
/// group's cipher suite, and with it the PQ half's signature scheme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApqMode {
    /// APQ confidentiality-only: ML-KEM-768 for the PQ group with classical (Ed25519)
    /// signing keys in both groups.
    ///
    /// The draft's confidentiality + authentication variant (PQ signing keys for the PQ
    /// group) is anticipated but not implemented: it needs a cipher suite composing
    /// ML-KEM-768 with a PQ signature scheme in the providers. Adding it is a new variant
    /// here plus a suite mapping below — no API break.
    #[default]
    ConfidentialityOnly,
}

impl ApqMode {
    /// The PQ half's MLS cipher suite for this mode.
    pub fn pq_cipher_suite(self) -> CipherSuite {
        match self {
            ApqMode::ConfidentialityOnly => CipherSuite::new(ML_KEM_768),
        }
    }
}

/// The injected crypto providers and APQ mode for a [`CombinerClient`]: `classical` backs
/// the classical half (must supply `CURVE25519_CHACHA`), `pq` backs the PQ half (must
/// supply the mode's PQ suite). One concrete provider type may serve both roles (aws-lc
/// does); Apple splits them (`CryptoKitProvider` / `CryptoKitMlKemProvider`).
#[derive(Clone, Debug, Default)]
pub struct CryptoConfig<C, P> {
    pub classical: C,
    pub pq: P,
    pub mode: ApqMode,
}

// Group state lives in a `PersistableGroupStorage` (same shared-map in-memory semantics as
// mls-rs's default provider) so a group's record can be exported per group for session
// archival, and so the caller can hold a handle to it: clones share one map, letting
// session code inspect which prior epochs are still retained (the storage's retention
// trim) — e.g. to expire per-epoch rendezvous addresses in lockstep with that window.
pub type OurConfig<S, C> = WithGroupStateStorage<
    PersistableGroupStorage,
    WithKeyPackageRepo<
        S,
        WithIdentityProvider<BasicIdentityProvider, WithCryptoProvider<C, BaseConfig>>,
    >,
>;
pub type MlsClient<S, C> = Client<OurConfig<S, C>>;

/// The PQ half's config is the same shape as the classical one — only the provider (and
/// the suite it is asked for) differs.
pub type PqConfig<S, P> = OurConfig<S, P>;
pub type PqMlsClient<S, P> = Client<PqConfig<S, P>>;

/// Holds an agent identity (ClientId) and the two MLS clients that manage its key packages
/// and groups, parameterised by the key-package storage `S` and the crypto providers
/// (`C` classical, `P` PQ). The ClientId is opaque, caller-supplied bytes carried as the
/// Basic Credential. Each MLS half owns its *own* signing key (classical and PQ are
/// independent); the keys are retained here so the signing identity can be archived and
/// restored. The signing keys' public components are NOT the ClientId.
pub struct CombinerClient<S, C, P>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    client_id: Vec<u8>,
    classical_signing_key: Zeroizing<Vec<u8>>,
    classical: MlsClient<S, C>,
    classical_kp_store: S,
    /// The injected classical group-state storage; shares its map with the clone
    /// handed to the client builder, so it reflects the storage's epoch retention.
    classical_group_storage: PersistableGroupStorage,
    pq_signing_key: Zeroizing<Vec<u8>>,
    /// The PQ signing key's public half, kept from construction so the rekey
    /// credential handoff never re-derives it.
    pq_signing_public: mls_rs::crypto::SignaturePublicKey,
    pq: PqMlsClient<S, P>,
    pq_kp_store: S,
    pq_group_storage: PersistableGroupStorage,
}

impl<S, C, P> CombinerClient<S, C, P>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    /// Build a `CombinerClient` for the given ClientId with a fresh, independent signing key
    /// per half and empty (default) key-package stores. `client_id` is opaque identity bytes
    /// (the Basic Credential), independent of the generated signing keys.
    ///
    /// Fails with [`CombinerError::UnsupportedCipherSuite`] if `crypto.classical` cannot
    /// supply the classical suite or `crypto.pq` cannot supply the mode's PQ suite.
    pub fn new(client_id: Vec<u8>, crypto: CryptoConfig<C, P>) -> Result<Self>
    where
        S: Default,
    {
        let classical_cs = crypto
            .classical
            .cipher_suite_provider(CLASSICAL_SUITE)
            .ok_or(CombinerError::UnsupportedCipherSuite)?;
        let pq_suite = crypto.mode.pq_cipher_suite();
        let pq_cs = crypto
            .pq
            .cipher_suite_provider(pq_suite)
            .ok_or(CombinerError::UnsupportedCipherSuite)?;

        let (classical_sk, classical_pk) = classical_cs
            .signature_key_generate()
            .map_err(|_| CombinerError::Mls)?;
        let classical_signing_key = Zeroizing::new(classical_sk.as_bytes().to_vec());
        let classical_kp_store = S::default();
        let classical_group_storage = PersistableGroupStorage::new();
        let classical = build_client(
            crypto.classical,
            client_id.clone(),
            classical_sk,
            classical_pk,
            CLASSICAL_SUITE,
            classical_kp_store.clone(),
            classical_group_storage.clone(),
        );

        // The PQ half's signing key comes from the PQ suite's own provider: under
        // ConfidentialityOnly this is Ed25519 (same scheme as the classical half, but an
        // independent key); under a future conf+auth mode it becomes a PQ scheme with no
        // change here.
        let (pq_sk, pq_pk) = pq_cs
            .signature_key_generate()
            .map_err(|_| CombinerError::Mls)?;
        let pq_signing_key = Zeroizing::new(pq_sk.as_bytes().to_vec());
        let pq_signing_public = pq_pk.clone();
        let pq_kp_store = S::default();
        let pq_group_storage = PersistableGroupStorage::new();
        let pq = build_client(
            crypto.pq,
            client_id.clone(),
            pq_sk,
            pq_pk,
            pq_suite,
            pq_kp_store.clone(),
            pq_group_storage.clone(),
        );

        Ok(Self {
            client_id,
            classical_signing_key,
            classical,
            classical_kp_store,
            classical_group_storage,
            pq_signing_key,
            pq_signing_public,
            pq,
            pq_kp_store,
            pq_group_storage,
        })
    }

    /// Restore a `CombinerClient` from an archived signing identity (ClientId + each half's
    /// signing key), installing the caller-provided key-package store(s). Pass empty stores
    /// for a bare identity restore, or stores preloaded with this identity's key package(s)
    /// to make a receiving (invitation) client whose join can find them. Public keys are
    /// re-derived from the signing keys — each half through its own suite's provider.
    pub fn from_key_packages(
        client_id: Vec<u8>,
        classical_signing_key: Zeroizing<Vec<u8>>,
        classical_kp_store: S,
        pq_signing_key: Zeroizing<Vec<u8>>,
        pq_kp_store: S,
        crypto: CryptoConfig<C, P>,
    ) -> Result<Self> {
        let classical_cs = crypto
            .classical
            .cipher_suite_provider(CLASSICAL_SUITE)
            .ok_or(CombinerError::UnsupportedCipherSuite)?;
        let pq_suite = crypto.mode.pq_cipher_suite();
        let pq_cs = crypto
            .pq
            .cipher_suite_provider(pq_suite)
            .ok_or(CombinerError::UnsupportedCipherSuite)?;

        let classical_sk = mls_rs::crypto::SignatureSecretKey::new(classical_signing_key.to_vec());
        let classical_pk = classical_cs
            .signature_key_derive_public(&classical_sk)
            .map_err(|_| CombinerError::Mls)?;
        let classical_group_storage = PersistableGroupStorage::new();
        let classical = build_client(
            crypto.classical,
            client_id.clone(),
            classical_sk,
            classical_pk,
            CLASSICAL_SUITE,
            classical_kp_store.clone(),
            classical_group_storage.clone(),
        );

        let pq_sk = mls_rs::crypto::SignatureSecretKey::new(pq_signing_key.to_vec());
        let pq_pk = pq_cs
            .signature_key_derive_public(&pq_sk)
            .map_err(|_| CombinerError::Mls)?;
        let pq_signing_public = pq_pk.clone();
        let pq_group_storage = PersistableGroupStorage::new();
        let pq = build_client(
            crypto.pq,
            client_id.clone(),
            pq_sk,
            pq_pk,
            pq_suite,
            pq_kp_store.clone(),
            pq_group_storage.clone(),
        );

        Ok(Self {
            client_id,
            classical_signing_key,
            classical,
            classical_kp_store,
            classical_group_storage,
            pq_signing_key,
            pq_signing_public,
            pq,
            pq_kp_store,
            pq_group_storage,
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
    pub fn pq_signing_key(&self) -> &[u8] {
        self.pq_signing_key.as_slice()
    }

    /// The PQ half's signature keypair (secret from storage, public kept from
    /// construction). Used to hand a PQ group's leaf to this agent during an A.5
    /// rekey credential rotation.
    pub fn pq_signature_keypair(
        &self,
    ) -> (
        mls_rs::crypto::SignatureSecretKey,
        mls_rs::crypto::SignaturePublicKey,
    ) {
        (
            mls_rs::crypto::SignatureSecretKey::new(self.pq_signing_key.to_vec()),
            self.pq_signing_public.clone(),
        )
    }

    pub fn classical(&self) -> &MlsClient<S, C> {
        &self.classical
    }

    pub fn pq(&self) -> &PqMlsClient<S, P> {
        &self.pq
    }

    /// The classical half's key-package store handle (for capture/inspection by the caller).
    pub fn classical_kp_store(&self) -> &S {
        &self.classical_kp_store
    }

    /// The PQ half's key-package store handle.
    pub fn pq_kp_store(&self) -> &S {
        &self.pq_kp_store
    }

    /// The classical half's group-state storage handle. Groups created or joined by this
    /// client's classical half write their state here; per-group archival reads it back out.
    /// Clones share one map with the storage inside the classical client, so probing
    /// `epoch(group_id, e)` here reflects exactly which prior epochs are still retained
    /// after the storage's retention trim (applied on each `Group::write_to_storage`).
    pub fn classical_group_storage(&self) -> &PersistableGroupStorage {
        &self.classical_group_storage
    }

    /// The PQ half's group-state storage handle.
    pub fn pq_group_storage(&self) -> &PersistableGroupStorage {
        &self.pq_group_storage
    }

    /// Generate a fresh classical (0x0003) KeyPackage, MLS-encoded for publication.
    pub fn generate_classical_key_package(&self) -> Result<Vec<u8>> {
        let msg = self
            .classical
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
            .map_err(|_| CombinerError::Mls)?;
        msg.to_bytes().map_err(|_| CombinerError::Mls)
    }

    /// Generate a fresh PQ (mode suite, e.g. ML-KEM-768/0xFDEA) KeyPackage, MLS-encoded for
    /// publication.
    pub fn generate_pq_key_package(&self) -> Result<Vec<u8>> {
        let msg = self
            .pq
            .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
            .map_err(|_| CombinerError::Mls)?;
        msg.to_bytes().map_err(|_| CombinerError::Mls)
    }
}

fn build_client<S: KeyPackageStorage + Clone, C: CryptoProvider + Clone>(
    provider: C,
    client_id: Vec<u8>,
    secret_key: mls_rs::crypto::SignatureSecretKey,
    public_key: mls_rs::crypto::SignaturePublicKey,
    suite: CipherSuite,
    key_package_store: S,
    group_storage: PersistableGroupStorage,
) -> MlsClient<S, C> {
    let credential = BasicCredential::new(client_id);
    let signing_identity = SigningIdentity::new(credential.into_credential(), public_key);
    client_builder::ClientBuilder::new()
        .crypto_provider(provider)
        .identity_provider(BasicIdentityProvider::new())
        .key_package_repo(key_package_store)
        .group_state_storage(group_storage)
        .signing_identity(signing_identity, secret_key, suite)
        .build()
}
