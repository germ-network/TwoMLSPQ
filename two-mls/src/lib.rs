uniffi::setup_scaffolding!();

pub mod key_packages;
pub mod psk;
pub mod session;

pub use session::TwoMlsSession;

#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// ATProto DID-scoped client identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClientId {
    pub bytes: Vec<u8>,
}

/// MLS group identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsGroupId {
    pub bytes: Vec<u8>,
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

/// Content-typed hash digest. Used by the app layer to identify and accept
/// MLS proposals before signalling back to the encryption layer.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TwoMlsDigest {
    pub hash_type: u8,
    pub digest: Vec<u8>,
}

/// Returned by `prepare_to_encrypt`. The app layer must bind `proposal_hash`
/// into its plaintext before calling `encrypt`. `did_commit` is false when
/// stuck in a prior epoch (no pending remote proposal to commit).
#[derive(Debug, uniffi::Record)]
pub struct PrepareEncryptResult {
    pub proposal_hash: TwoMlsDigest,
    pub commited_remote_client_id: Option<ClientId>,
    pub did_commit: bool,
}

/// Returned by `encrypt`.
#[derive(Debug, uniffi::Record)]
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub sender: ClientId,
    pub recipient: ClientId,
    pub epoch: u64,
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
    pub sender: ClientId,
    pub message: Vec<u8>,
}

/// A remote proposal queued for app-layer acceptance. `sender` sent the
/// proposal; `proposing` is the client being proposed (differs when a client
/// proposes its own rotation). `context` is the receive group's group-ID hash,
/// used for ordering against the app-level sequence number.
#[derive(Debug, Clone, uniffi::Record)]
pub struct QueuedRemoteProposal {
    pub digest: TwoMlsDigest,
    pub sender: ClientId,
    pub proposing: ClientId,
    pub context: TwoMlsDigest,
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
pub enum AgentState {
    Sync { client_id: ClientId },
    Pending { old: ClientId, new: ClientId },
}

/// Opaque serialised session state. Restore via `TwoMlsSession.fromArchive(_:)`.
#[derive(Debug, uniffi::Record)]
pub struct Archive {
    pub bytes: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct EpochRendezvous {
    pub epoch: u64,
    pub rendezvous_id: RendezvousId,
}

/// Send-group ID and per-epoch rendezvous channels the transport should listen
/// on. Returned by `should_listen_on`.
#[derive(Debug, uniffi::Record)]
pub struct ListenChannels {
    pub send_group_id: MlsGroupId,
    pub rendezvous_by_epoch: Vec<EpochRendezvous>,
}

/// Whether a party has published a PQ-capable KeyPackage in their ATProto PDS.
/// Detected by finding a `com.germnetwork.keypackage` record using the X-Wing
/// ciphersuite (`MLS_128_XWING_AES128GCM_SHA256_Ed25519`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PqCapability {
    /// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420 ciphersuite 0x0001)
    Classical,
    /// `MLS_128_XWING_AES128GCM_SHA256_Ed25519` — X25519 + ML-KEM-768 hybrid
    /// (draft-mahy-mls-xwing-00)
    XWing,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TwoMlsError {
    #[error("MLS group error")]
    Mls,
    #[error("invalid key package")]
    InvalidKeyPackage,
    #[error("missing welcome")]
    MissingWelcome,
    #[error("PSK binding failure")]
    PskBinding,
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
}

impl From<mls_rs::error::MlsError> for TwoMlsError {
    fn from(_: mls_rs::error::MlsError) -> Self {
        TwoMlsError::Mls
    }
}

pub type Result<T> = std::result::Result<T, TwoMlsError>;
