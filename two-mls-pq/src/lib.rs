uniffi::setup_scaffolding!();

mod invitation;
mod key_package_store;
pub mod key_packages;
mod providers;
mod psk;
pub mod session;
#[cfg(test)]
#[macro_use]
mod test_macros;
#[cfg(test)]
mod demo;
#[cfg(test)]
mod test_utils;

pub use session::TwoMlsPqSession;

use std::sync::Arc;

#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Record-shape contract stamp. Uniffi's load-time checks cover *function*
/// signatures but NOT `uniffi::Record` field layouts or error-enum variants: a
/// Record can change shape with every checksum unchanged, and a mismatched
/// binding + binary pair then mis-reads FFI buffers at the first call touching
/// the changed type (runtime trap mid-flow) instead of failing at startup.
///
/// RULE: bump this on ANY shape change to a `#[derive(uniffi::Record)]` struct
/// or the error enum in this crate. The vendored Swift binding's consumer
/// (AbstractTwoMLS) asserts the value at first construction, so a stale
/// binding/binary pairing fails fast with an actionable message.
// v2 (2026-07-07): TwoMlsPqDigest removed — digests are raw 32-byte SHA-256 values
// (`Vec<u8>` fields on PrepareEncryptResult / QueuedRemoteProposal and in the
// queue_proposal / proposal_context signatures).
// v3 (2026-07-07): TwoMlsPqError gained `UnsupportedCipherSuite` (an injected crypto
// provider cannot supply a required cipher suite; surfaces at client construction).
// v4 (2026-07-09): TwoMlsPqError gained `InvitationSpent` (a single-use invitation's key
// package has already been consumed; `generate_invitation` also gained a `last_resort` flag,
// but that function-signature change is caught by uniffi's own load-time checksum).
const BINDING_CONTRACT_VERSION: u64 = 4;

/// See `BINDING_CONTRACT_VERSION`. Exported so the Swift layer can verify the
/// binding it was generated with matches the binary it loaded.
#[uniffi::export]
pub fn binding_contract_version() -> u64 {
    BINDING_CONTRACT_VERSION
}

/// ATProto DID-scoped client identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClientId {
    pub bytes: Vec<u8>,
}

/// The APQ epoch pair for the send group: the PQ side-band epoch and the classical
/// (traditional) message epoch. Zeros until the corresponding group exists.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ApqEpochs {
    pub pq_epoch: u64,
    pub classical_epoch: u64,
}

/// MLS group identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsGroupId {
    pub bytes: Vec<u8>,
}

/// Paired MLS group identifiers for the classical and PQ halves of one Combiner direction.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CombinerGroupId {
    pub classical: MlsGroupId,
    pub pq: MlsGroupId,
}

/// Session identifier derived from both parties' client IDs at init time.
/// Both sides can derive the same ID independently, preventing identity
/// confusion when both parties initiate simultaneously.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SessionId {
    pub bytes: Vec<u8>,
}

/// Transport rendezvous channel identifier.
/// Derived per epoch via `exportSecret(label="rendezvous", context="TwoMLS", len=32)`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RendezvousId {
    pub bytes: Vec<u8>,
}

// Digests cross this FFI as raw 32-byte values: SHA-256 over the stated object. That is
// this library's OWN wire convention (matching the classical backend's values, so both
// stacks bind the same bytes); the app layer wraps them in whatever typed-digest
// encoding it uses. No app-layer type tags or enum values appear on this surface.

/// Returned by `prepare_to_encrypt`. `proposal_hash` is the SHA-256 of the staged
/// outbound object (the Upd(self) proposal message, or the rotation commit); `encrypt`
/// also binds it into the app message's authenticated data, and the receiver reports
/// the same value as `QueuedRemoteProposal.digest`. `did_commit` is false when stuck in
/// a prior epoch (no pending remote proposal to commit).
#[derive(Debug, uniffi::Record)]
pub struct PrepareEncryptResult {
    pub proposal_hash: Vec<u8>,
    pub committed_remote_client_id: Option<ClientId>,
    pub did_commit: bool,
}

/// Returned by `encrypt`. `epochs` is the send group's APQ pair at send time —
/// the PQ side-band epoch (0 while that half is deferred) and the classical
/// message epoch the ciphertext was produced in.
#[derive(Debug, uniffi::Record)]
pub struct EncryptResult {
    pub cipher_text: Vec<u8>,
    pub sender: ClientId,
    pub recipient: ClientId,
    pub epochs: ApqEpochs,
}

/// Returned by `process_incoming`. Fields are `None` when not applicable to
/// the message type (e.g. `application_message` is absent for proposals/commits).
#[derive(Debug, uniffi::Record)]
pub struct DecryptResult {
    pub application_message: Option<MlsSenderMessage>,
    pub proposal: Option<QueuedRemoteProposal>,
    pub remote_commit: Option<CommitResult>,
}

/// Decrypted application message with its verified sender identity.
#[derive(Debug, uniffi::Record)]
pub struct MlsSenderMessage {
    pub app_message_data: Vec<u8>,
    pub sender_client_id: ClientId,
    pub epoch: u64,
}

/// A remote proposal queued for app-layer acceptance. `sender` sent the
/// proposal; `proposing` is the client being proposed (differs when a client
/// proposes its own rotation). `digest` is the SHA-256 of the proposal message
/// (equal to the sender's `PrepareEncryptResult.proposal_hash`); `context` is
/// the SHA-256 of the receive group's group id, used for ordering against the
/// app-level sequence number.
#[derive(Debug, Clone, uniffi::Record)]
pub struct QueuedRemoteProposal {
    pub digest: Vec<u8>,
    pub sender: ClientId,
    pub proposing: ClientId,
    pub context: Vec<u8>,
}

/// Result of processing a remote commit. `new_sender` is `None` in
/// steady-state commits where only the recipient rotated.
#[derive(Debug, uniffi::Record)]
pub struct CommitResult {
    pub new_sender: Option<ClientId>,
    pub new_recipient: ClientId,
}

/// Credential state for one send direction. `Pending` means a rotation commit
/// was sent but the opposing side has not yet committed their half.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PrincipalState {
    Sync { client_id: ClientId },
    Pending { old: ClientId, new: ClientId },
}

impl PrincipalState {
    /// The current active client ID: the live identity for `Sync`, the pre-rotation one for `Pending`.
    pub fn client_id(&self) -> ClientId {
        match self {
            Self::Sync { client_id } | Self::Pending { old: client_id, .. } => client_id.clone(),
        }
    }
}

/// Opaque serialised session state. Restore via `TwoMlsPqSession.fromArchive(_:)`.
#[derive(Debug, uniffi::Record)]
pub struct Archive {
    pub bytes: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct EpochRendezvous {
    pub epoch: u64,
    pub rendezvous_id: RendezvousId,
}

/// Combiner group IDs and per-epoch rendezvous channels the transport should
/// listen on. Returned by `should_listen_on`.
#[derive(Debug, uniffi::Record)]
pub struct ListenChannels {
    pub send_group: CombinerGroupId,
    pub rendezvous_by_epoch: Vec<EpochRendezvous>,
}

/// MLS cipher suite identified by its IANA-registered u16 value (RFC 9420 §17.1).
/// Private-range values (0xF000–0xFFFF) are used for suites pending IANA assignment.
#[derive(Debug, uniffi::Object)]
pub struct MlsCipherSuite {
    value: u16,
}

impl MlsCipherSuite {
    // RFC 9420 §17.1
    pub const DHKEM_X25519_AES128: u16 = 0x0001;
    pub const DHKEM_P256_AES128: u16 = 0x0002;
    pub const DHKEM_X25519_CHACHA: u16 = 0x0003;
    pub const DHKEM_X448_AES256: u16 = 0x0004;
    pub const DHKEM_P521_AES256: u16 = 0x0005;
    pub const DHKEM_X448_CHACHA: u16 = 0x0006;
    pub const DHKEM_P384_AES256: u16 = 0x0007;
    // Private range (0xF000–0xFFFF) — pending IANA assignment
    /// MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519 (0xFDEA, FIPS 203).
    /// Private-range value; not assigned by draft-ietf-mls-pq-ciphersuites.
    pub const ML_KEM_768: u16 = 0xFDEA;
}

#[uniffi::export]
impl MlsCipherSuite {
    /// Construct from a raw IANA cipher suite value.
    #[uniffi::constructor]
    pub fn new(value: u16) -> Arc<Self> {
        Arc::new(Self { value })
    }

    /// MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519 (0xFDEA, FIPS 203)
    #[uniffi::constructor]
    pub fn ml_kem_768() -> Arc<Self> {
        Arc::new(Self {
            value: Self::ML_KEM_768,
        })
    }

    /// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)
    #[uniffi::constructor]
    pub fn x25519_aes128() -> Arc<Self> {
        Arc::new(Self {
            value: Self::DHKEM_X25519_AES128,
        })
    }

    /// MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (0x0003)
    #[uniffi::constructor]
    pub fn x25519_chacha() -> Arc<Self> {
        Arc::new(Self {
            value: Self::DHKEM_X25519_CHACHA,
        })
    }

    /// The raw IANA-registered (or private-range) u16 value.
    pub fn value(&self) -> u16 {
        self.value
    }

    /// True if this suite is handled by TwoMLS as the PQ component of a session.
    /// Use `is_combiner_classical` to identify the classical half of a Combiner pair
    /// before routing — do not route a Combiner classical KP to mls-rs-uniffi-ios.
    pub fn is_supported(&self) -> bool {
        self.value == Self::ML_KEM_768
    }

    /// True if this suite is the classical component of a Combiner pair (0x0003).
    /// When a key package with this suite is paired with an ML-KEM-768 key package,
    /// both belong to TwoMLS as a `CombinerKeyPackage` — do not route the classical
    /// half to mls-rs-uniffi-ios independently.
    pub fn is_combiner_classical(&self) -> bool {
        self.value == Self::DHKEM_X25519_CHACHA
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TwoMlsPqError {
    #[error("MLS group error")]
    Mls,
    #[error("invalid key package")]
    InvalidKeyPackage,
    #[error("missing welcome")]
    MissingWelcome,
    #[error("PSK binding failure")]
    PskBinding,
    #[error("combiner key package carries no post-quantum cipher suite")]
    PqNotAvailable,
    #[error("session not established")]
    SessionNotEstablished,
    #[error("session not ready for encryption")]
    SessionNotReady,
    #[error("proposal rejected by app layer")]
    ProposalRejected,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("archive corrupt or incompatible")]
    ArchiveInvalid,
    #[error("welcome already consumed for this remote")]
    DuplicateWelcome,
    /// A single-use (not last-resort) invitation whose key package has already been consumed
    /// by an accepted session. Distinct from `DuplicateWelcome` (a per-remote replay guard):
    /// a spent invitation rejects *every* further `receive`, from any remote. The app should
    /// discard it. A last-resort invitation never reports this.
    #[error("single-use invitation key package already consumed")]
    InvitationSpent,
    /// The build's crypto provider cannot supply a required cipher suite — a build or
    /// provider-configuration bug caught at client construction (see
    /// `two-mls-pq/src/providers.rs`), never a runtime condition of a healthy binary.
    #[error("crypto provider does not support the required cipher suite")]
    UnsupportedCipherSuite,
}

/// SHA-256 over `bytes` — the single hashing primitive behind every digest this
/// crate emits (proposal digests, ordering contexts, session ids; the same function
/// the cipher suite's `hash` resolves to). One implementation, so the "both sides
/// derive the same value" invariants cannot split across call sites.
pub(crate) fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}

/// Derive the session identifier for a pair of clients.
/// Both sides compute the same value from the same inputs regardless of who
/// initiated, allowing CommProtocol to deduplicate concurrent session initiations.
#[uniffi::export]
pub fn derive_session_id(my_id: ClientId, their_id: ClientId) -> Result<SessionId> {
    let (first, second) = if my_id.bytes <= their_id.bytes {
        (my_id.bytes, their_id.bytes)
    } else {
        (their_id.bytes, my_id.bytes)
    };

    let mut input = first;
    input.extend_from_slice(&second);

    Ok(SessionId {
        bytes: sha256(&input),
    })
}

impl From<mls_rs::error::MlsError> for TwoMlsPqError {
    fn from(_: mls_rs::error::MlsError) -> Self {
        TwoMlsPqError::Mls
    }
}

impl From<apq::CombinerError> for TwoMlsPqError {
    fn from(e: apq::CombinerError) -> Self {
        match e {
            apq::CombinerError::Mls => TwoMlsPqError::Mls,
            apq::CombinerError::InvalidKeyPackage => TwoMlsPqError::InvalidKeyPackage,
            apq::CombinerError::MissingWelcome => TwoMlsPqError::MissingWelcome,
            apq::CombinerError::DecryptionFailed => TwoMlsPqError::DecryptionFailed,
            apq::CombinerError::ArchiveInvalid => TwoMlsPqError::ArchiveInvalid,
            apq::CombinerError::UnsupportedCipherSuite => TwoMlsPqError::UnsupportedCipherSuite,
        }
    }
}

pub type Result<T> = std::result::Result<T, TwoMlsPqError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn client_id(bytes: &[u8]) -> ClientId {
        ClientId {
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn test_derive_session_id_is_symmetric() -> Result<()> {
        let alice = client_id(b"alice");
        let bob = client_id(b"bob");
        assert_eq!(
            derive_session_id(alice.clone(), bob.clone())?.bytes,
            derive_session_id(bob, alice)?.bytes
        );
        Ok(())
    }

    #[test]
    fn test_derive_session_id_differs_for_different_pairs() -> Result<()> {
        let alice = client_id(b"alice");
        let bob = client_id(b"bob");
        let carol = client_id(b"carol");
        assert_ne!(
            derive_session_id(alice.clone(), bob)?.bytes,
            derive_session_id(alice, carol)?.bytes
        );
        Ok(())
    }
}
