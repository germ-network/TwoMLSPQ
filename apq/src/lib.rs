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

mod client;
mod group;
#[cfg(feature = "cryptokit")]
pub mod pq_ratchet;

pub use client::{CombinerClient, MlsClient, OurConfig};
#[cfg(feature = "cryptokit")]
pub use client::{PqConfig, PqMlsClient};

pub use group::{
    create_bound_classical_send_group, create_bound_combiner_send_group,
    create_combiner_send_group, create_group_with_member, decode_apq_welcome, encode_apq_welcome,
    export_and_register_psk, export_psk, join_combiner_group, join_group_from_welcome,
    register_psk, register_psk_stores, sender_client_id, CombinerGroup, MlsGroup, PqMlsGroup,
    APQ_TAG,
};
#[cfg(feature = "cryptokit")]
pub use group::{
    export_and_register_psk_pq, export_psk_pq, pq_create_group_with_member,
    pq_join_group_from_welcome,
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
}

pub type Result<T> = std::result::Result<T, CombinerError>;
