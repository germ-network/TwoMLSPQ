//! The APQ Combiner crate: the `{classical, pq}` group pair and its construction.
//!
//! This is the "separate APQ from TwoMLS" boundary. Everything here is the combiner
//! construction (draft-ietf-mls-combiner + our deviation): the two MLS groups, the
//! **APQ-PSK** (PQ → classical, intra-party), establishment, and the APQ welcome framing.
//! The two-mls layer (`two-mls-pq`) owns session orchestration, the cross-party
//! TwoMLS-PSK, the wire tags, and the UniFFI surface, and drives this layer through
//! `CombinerGroup` / `CombinerClient`.
//!
//! This crate is deliberately UniFFI-free: it takes MLS clients and key-package bytes as
//! primitives, and reports failures as `CombinerError` (the two-mls layer maps these onto
//! its FFI error enum).
//!
//! It is also crypto-provider agnostic: no concrete provider is compiled in. The consumer
//! injects a classical and a PQ `CryptoProvider` (see [`CryptoConfig`]) — e.g. CryptoKit on
//! Apple targets, aws-lc elsewhere — and both are required: APQ always has a PQ half. A
//! provider that cannot supply a required cipher suite (the PQ suite is chosen by
//! [`ApqMode`]) fails at client construction with
//! [`CombinerError::UnsupportedCipherSuite`].

pub mod archive;
pub mod authentication;
mod client;
pub mod component;
mod group;
pub mod pq_ratchet;
pub mod rules;
pub mod storage;

pub use client::{
    ApqCipherSuite, ApqMode, ArchivedIdentity, CombinerClient, CryptoConfig, MlsClient, OurConfig,
    PqConfig, PqMlsClient,
};

pub use group::{
    create_bound_classical_send_group, create_bound_combiner_send_group,
    create_combiner_send_group, create_group_with_member, decode_apq_welcome, encode_apq_welcome,
    ensure_two_party, export_and_register_psk, export_psk, forget_psk, forget_psk_stores,
    join_combiner_group, join_combiner_group_from_halves, join_group_from_welcome,
    load_combiner_group, register_psk, register_psk_stores, sender_client_id, CombinerGroup,
    CombinerGroupState, GroupCreation, MlsGroup, PqMlsGroup, APQ_TAG,
};

/// Failure categories for the combiner layer. The two-mls layer maps these onto its
/// UniFFI error enum (`TwoMlsPqError`) one-to-one.
#[derive(Debug, thiserror::Error)]
pub enum CombinerError {
    #[error("MLS group error")]
    Mls,
    #[error("invalid key package")]
    InvalidKeyPackage,
    #[error("missing welcome")]
    MissingWelcome,
    #[error("decryption failed")]
    DecryptionFailed,
    /// A persistence blob (session archive or group-state snapshot) is structurally invalid:
    /// wrong version, truncation, trailing bytes, or a violated storage invariant. Distinct
    /// from [`DecryptionFailed`](Self::DecryptionFailed), which is an authentication failure
    /// of a sealed blob (wrong key or tampered ciphertext).
    #[error("invalid archive")]
    ArchiveInvalid,
    /// An injected crypto provider cannot supply a required cipher suite — e.g. a PQ
    /// provider built without ML-KEM support. Surfaces at client construction, not deep
    /// in a session.
    #[error("crypto provider does not support the required cipher suite")]
    UnsupportedCipherSuite,
    /// An observed cipher-suite pair does not match the session's expected [`ApqCipherSuite`],
    /// or is not a coherent APQ combination (unrecognized suite, or a classical suite in the PQ
    /// slot). Distinct from [`UnsupportedCipherSuite`](Self::UnsupportedCipherSuite),
    /// which is a local provider-capability gap.
    #[error("cipher suite mismatch")]
    CipherSuiteMismatch,
    /// The draft -02 bookkeeping failed verification: an `APQInfo` GroupContext extension is
    /// missing or inconsistent across a pair's halves, an `AppDataUpdate` epoch attestation
    /// does not match the actual post-commit epochs, or the two halves' rosters diverge.
    #[error("APQInfo missing or inconsistent")]
    ApqInfoMismatch,
}

pub type Result<T> = std::result::Result<T, CombinerError>;
