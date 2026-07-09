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

/// ML-KEM-768 cipher suite value (0xFDEA, FIPS 203) in the MLS private-use range. This is the
/// wire value TwoMLSPQ pins for the PQ half; every PQ provider must implement the suite under
/// it (CryptoKit and aws-lc agree). A construction-time assert checks it still equals
/// mls-rs-core's `CipherSuite::ML_KEM_768`, so a fork renumber cannot silently diverge.
const ML_KEM_768: u16 = 0xFDEA;

/// Whether a recognized suite's KEM and signature scheme are post-quantum. MLS cipher suites
/// are monolithic (RFC 9420 §17.1): one id fixes KEM + AEAD + hash + signature together, so
/// these axes are read off the suite id — mls-rs exposes no per-suite signature accessor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SuiteClass {
    kem_pq: bool,
    sig_pq: bool,
}

/// Classify a suite TwoMLSPQ recognizes, or `None` for an unassigned value. This is the single
/// place suites are recognized; extend it (adding PQ values from the private-use range) to
/// support more combinations.
fn class(suite: CipherSuite) -> Option<SuiteClass> {
    match u16::from(suite) {
        // RFC 9420 §17.1 base cipher suites (0x0001–0x0007): every one is a classical DHKEM with
        // a classical signature scheme (Ed25519 / P-256 / Ed448 / P-521 / P-384).
        0x0001..=0x0007 => Some(SuiteClass {
            kem_pq: false,
            sig_pq: false,
        }),
        // MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519 (private-use range): post-quantum KEM,
        // classical Ed25519 signature.
        ML_KEM_768 => Some(SuiteClass {
            kem_pq: true,
            sig_pq: false,
        }),
        // Unassigned / unrecognized.
        _ => None,
    }
}

/// The concrete pair of MLS cipher suites a session runs — its classical half and PQ half.
/// This is the source of truth; the APQ *mode* is derived from it via [`ApqCipherSuite::mode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApqCipherSuite {
    pub classical: CipherSuite,
    pub pq: CipherSuite,
}

impl Default for ApqCipherSuite {
    /// The shipped confidentiality-only pair: Curve25519/ChaCha classical + ML-KEM-768 PQ,
    /// both Ed25519-signed.
    fn default() -> Self {
        Self {
            classical: CipherSuite::CURVE25519_CHACHA,
            pq: CipherSuite::new(ML_KEM_768),
        }
    }
}

impl ApqCipherSuite {
    pub const fn new(classical: CipherSuite, pq: CipherSuite) -> Self {
        Self { classical, pq }
    }

    /// Derive the APQ mode from the suite pair, or report why the pair is not a valid APQ
    /// combination. Rules: both halves recognized; the classical half a classical KEM and the
    /// PQ half an ML-KEM KEM; both halves sharing one signature family (the combiner carries a
    /// single identity across both). A classical signature yields
    /// [`ApqMode::ConfidentialityOnly`]; a PQ signature would be confidentiality+authentication,
    /// which has no `ApqMode` variant yet (a PQ-signature suite must be added to `class` first),
    /// so it currently reports [`CombinerError::CipherSuiteMismatch`].
    pub fn mode(self) -> Result<ApqMode> {
        let classical = class(self.classical).ok_or(CombinerError::CipherSuiteMismatch)?;
        let pq = class(self.pq).ok_or(CombinerError::CipherSuiteMismatch)?;
        if classical.kem_pq || !pq.kem_pq || classical.sig_pq != pq.sig_pq {
            return Err(CombinerError::CipherSuiteMismatch);
        }
        if classical.sig_pq {
            return Err(CombinerError::CipherSuiteMismatch);
        }
        Ok(ApqMode::ConfidentialityOnly)
    }

    /// `Ok(())` iff the pair is a valid, recognized APQ combination.
    pub fn validate(self) -> Result<()> {
        self.mode().map(|_| ())
    }

    /// Persist as classical-then-pq big-endian u16s.
    pub fn to_wire(self) -> [u8; 4] {
        let c = u16::from(self.classical).to_be_bytes();
        let p = u16::from(self.pq).to_be_bytes();
        [c[0], c[1], p[0], p[1]]
    }

    /// Inverse of [`to_wire`](Self::to_wire). The result still needs [`validate`](Self::validate).
    pub fn from_wire(bytes: [u8; 4]) -> Self {
        Self {
            classical: CipherSuite::new(u16::from_be_bytes([bytes[0], bytes[1]])),
            pq: CipherSuite::new(u16::from_be_bytes([bytes[2], bytes[3]])),
        }
    }
}

/// Which APQ variant the PQ half runs (draft-ietf-mls-combiner). This is *derived* from the
/// concrete [`ApqCipherSuite`] (see [`ApqCipherSuite::mode`]), never the authority for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApqMode {
    /// APQ confidentiality-only: ML-KEM-768 for the PQ group with classical (Ed25519) signing
    /// keys in both halves — post-quantum confidentiality, classical authentication.
    ///
    /// The draft's confidentiality + authentication variant (a PQ signature scheme) is
    /// anticipated but not implemented. Because MLS suites are monolithic and no PQ-signature
    /// suite has an IANA assignment, adding it means a hardcoded private-range suite value (as
    /// ML-KEM-768 uses 0xFDEA), a new entry in `class`, and a new variant here.
    #[default]
    ConfidentialityOnly,
}

/// An archived signing identity for [`CombinerClient::from_key_packages`]: the ClientId
/// plus each half's signing key and key-package store. Named fields on purpose — the
/// former five-positional-argument form let the two signing keys (or the two stores,
/// both same-typed) be transposed without a type error.
pub struct ArchivedIdentity<S> {
    /// Opaque identity bytes (the Basic Credential).
    pub client_id: Vec<u8>,
    pub classical_signing_key: Zeroizing<Vec<u8>>,
    /// Pass an empty store for a bare identity restore, or one preloaded with this
    /// identity's key package(s) to make a receiving (invitation) client.
    pub classical_kp_store: S,
    pub pq_signing_key: Zeroizing<Vec<u8>>,
    pub pq_kp_store: S,
}

/// The injected crypto providers and cipher-suite pair for a [`CombinerClient`]: `classical`
/// backs the classical half, `pq` backs the PQ half, and `suite` is the concrete
/// [`ApqCipherSuite`] they must support (the APQ mode is derived from it). One concrete
/// provider type may serve both roles (aws-lc does); Apple splits them (`CryptoKitProvider` /
/// `CryptoKitMlKemProvider`).
#[derive(Clone, Debug, Default)]
pub struct CryptoConfig<C, P> {
    pub classical: C,
    pub pq: P,
    pub suite: ApqCipherSuite,
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
    /// The cipher-suite pair this client's two halves were built for — the fixed, stored
    /// property a session is locked to. The APQ mode is derived from it.
    suite: ApqCipherSuite,
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
        let suite = crypto.suite;
        // The suite pair is the source of truth: it must be a coherent APQ combination (derive
        // a known mode) before anything is built. Also assert our pinned PQ wire value still
        // equals mls-rs-core's named constant, so a fork renumber (or the ML_KEM_768_X25519 =
        // 65100 sibling) can't silently diverge.
        suite.validate()?;
        if CipherSuite::new(ML_KEM_768) != CipherSuite::ML_KEM_768 {
            return Err(CombinerError::UnsupportedCipherSuite);
        }
        let classical_cs = crypto
            .classical
            .cipher_suite_provider(suite.classical)
            .ok_or(CombinerError::UnsupportedCipherSuite)?;
        let pq_cs = crypto
            .pq
            .cipher_suite_provider(suite.pq)
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
            suite.classical,
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
            suite.pq,
            pq_kp_store.clone(),
            pq_group_storage.clone(),
        );

        Ok(Self {
            client_id,
            suite,
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

    /// Restore a `CombinerClient` from an [`ArchivedIdentity`] (ClientId + each half's
    /// signing key and key-package store). Public keys are re-derived from the signing
    /// keys — each half through its own suite's provider.
    pub fn from_key_packages(
        identity: ArchivedIdentity<S>,
        crypto: CryptoConfig<C, P>,
    ) -> Result<Self> {
        let ArchivedIdentity {
            client_id,
            classical_signing_key,
            classical_kp_store,
            pq_signing_key,
            pq_kp_store,
        } = identity;
        let suite = crypto.suite;
        suite.validate()?;
        if CipherSuite::new(ML_KEM_768) != CipherSuite::ML_KEM_768 {
            return Err(CombinerError::UnsupportedCipherSuite);
        }
        let classical_cs = crypto
            .classical
            .cipher_suite_provider(suite.classical)
            .ok_or(CombinerError::UnsupportedCipherSuite)?;
        let pq_cs = crypto
            .pq
            .cipher_suite_provider(suite.pq)
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
            suite.classical,
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
            suite.pq,
            pq_kp_store.clone(),
            pq_group_storage.clone(),
        );

        Ok(Self {
            client_id,
            suite,
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

    /// The cipher-suite pair this client runs (classical + PQ).
    pub fn cipher_suite(&self) -> ApqCipherSuite {
        self.suite
    }

    /// The APQ mode, derived from the suite pair. Infallible here: construction already
    /// validated the pair, so the derivation cannot fail.
    pub fn mode(&self) -> ApqMode {
        self.suite.mode().unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::{class, ApqCipherSuite, ApqMode, SuiteClass, ML_KEM_768};
    use mls_rs::CipherSuite;

    #[test]
    fn default_pair_derives_confidentiality_only() {
        assert_eq!(
            ApqCipherSuite::default().mode().unwrap(),
            ApqMode::ConfidentialityOnly
        );
    }

    #[test]
    fn classifier_covers_rfc_suites_and_ml_kem() {
        // Every RFC 9420 §17.1 base suite (0x0001–0x0007) is recognized as classical.
        for v in 0x0001u16..=0x0007 {
            assert_eq!(
                class(CipherSuite::new(v)),
                Some(SuiteClass {
                    kem_pq: false,
                    sig_pq: false
                }),
                "suite 0x{v:04X} should classify as classical"
            );
        }
        // ML-KEM-768 is the one post-quantum KEM.
        assert_eq!(
            class(CipherSuite::new(ML_KEM_768)),
            Some(SuiteClass {
                kem_pq: true,
                sig_pq: false
            })
        );
        // Unassigned values are unrecognized (just past the RFC range, and an unused private value).
        assert!(class(CipherSuite::new(0x0008)).is_none());
        assert!(class(CipherSuite::new(0xFFFF)).is_none());
    }

    #[test]
    fn mode_rejects_incoherent_pairs() {
        let classical = CipherSuite::CURVE25519_CHACHA;
        let pq = CipherSuite::new(ML_KEM_768);
        let unknown = CipherSuite::new(0x0008); // just past the RFC 9420 §17.1 range
                                                // Swapped: PQ suite in the classical slot, classical in the PQ slot.
        assert!(ApqCipherSuite::new(pq, classical).mode().is_err());
        // Both classical: the PQ slot is not a PQ KEM.
        assert!(ApqCipherSuite::new(classical, classical).mode().is_err());
        // Both PQ: the classical slot must be a classical KEM.
        assert!(ApqCipherSuite::new(pq, pq).mode().is_err());
        // An unrecognized suite in either slot.
        assert!(ApqCipherSuite::new(classical, unknown).mode().is_err());
        assert!(ApqCipherSuite::new(unknown, pq).mode().is_err());
    }

    #[test]
    fn drift_guard_pinned_pq_value_equals_core_constant() {
        // The construction-time guard relies on this: our pinned wire value must still be what
        // mls-rs-core names ML-KEM-768. If a fork renumber breaks it, this fails loudly.
        assert_eq!(CipherSuite::new(ML_KEM_768), CipherSuite::ML_KEM_768);
    }

    #[test]
    fn wire_round_trips() {
        let suite = ApqCipherSuite::default();
        assert_eq!(ApqCipherSuite::from_wire(suite.to_wire()), suite);
    }
}
