uniffi::setup_scaffolding!();

pub mod key_packages;
pub mod psk;
pub mod session;

pub use session::TwoMlsSession;

use std::sync::Arc;

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
    pub cipher_text: Vec<u8>,
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
    pub app_message_data: Vec<u8>,
    pub sender_client_id: ClientId,
    pub epoch: u64,
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
    /// MLS_128_XWING_AES128GCM_SHA256_Ed25519 (draft-mahy-mls-xwing-00)
    pub const XWING_AES128: u16 = 0xFE4C;
}

#[uniffi::export]
impl MlsCipherSuite {
    /// Construct from a raw IANA cipher suite value.
    #[uniffi::constructor]
    pub fn new(value: u16) -> Arc<Self> {
        Arc::new(Self { value })
    }

    /// MLS_128_XWING_AES128GCM_SHA256_Ed25519 (0xFE4C, draft-mahy-mls-xwing-00)
    #[uniffi::constructor]
    pub fn xwing() -> Arc<Self> {
        Arc::new(Self {
            value: Self::XWING_AES128,
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

    /// True if this library handles the suite natively.
    /// Classical suites return false — callers should route to the legacy library.
    /// Designed to extend to future pure-PQ suites without API changes.
    pub fn is_supported(&self) -> bool {
        self.value == Self::XWING_AES128
    }
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
