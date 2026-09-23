//! Session migration export: `TwoMlsPqSession::migration_export`, the
//! session-level analogue of `TwoMlsPqInvitation::migration_export`. Emits
//! everything twomlspq-swift's `SessionMigration.mintArchive` needs to mint a
//! native `SessionArchive`: each group half as a swift-mls format-2 snapshot
//! (mls-rs's `Group::export_for_swift`, slice A) plus the combiner/session
//! metadata as flat records.
//!
//! Admits an established session — an established initiator or acceptor need
//! not be quiescent first: a parked side-band leg, an in-flight PQ round
//! (`pq_inflight`), and an owed classical bind (`owed_bind`) are all carried
//! in the export rather than required to settle before migrating, so the
//! round in progress completes normally on whichever engine finishes it:
//!
//!   * one still holding a parked return welcome (an acceptor's
//!     `pending_outbound`) — the export drops that parked copy rather than
//!     refusing it. The same welcome rides `current_staple` until the
//!     acceptor's own first send-group commit, and the native session
//!     re-staples `currentStaple` the same way, so nothing is stranded;
//!   * a born-dedicated acceptor, once its establishment envelope has
//!     installed AND its recv-classical leaf has caught up to the dedicated
//!     identity. Its recv-PQ leaf, which nothing in Rust ever catches up,
//!     exports as `pq_leaf_custody` instead of refusing (see the custody gate
//!     below).
//!
//! Refuses (rather than mis-maps) the states the native archive cannot
//! represent:
//!
//!   * pre-establishment initiator (no recv group yet): the parked §A.1
//!     envelope and app payload have no native slots, so the migrated session
//!     could never complete establishment;
//!   * a born-dedicated acceptor pre-install, or installed but pre-convergence:
//!     until the peer folds the classical catch-up Upd, the recv-classical
//!     leaf still presents the invitation identity's key, and mls-rs replaces
//!     that leaf's only signer exactly when the catch-up commit lands — before
//!     then there is nothing native could sign that leaf with;
//!   * mid-rotation (`staged_candidates` / `deferred_candidate`): the Rust
//!     model holds up to `CANDIDATE_WINDOW` full successor identities where the
//!     native one holds a single rotation candidate;
//!   * post-rotation leaf-lag: every group half's own leaf must present the
//!     identity's per-half signing key, or (recv-PQ only) resolve through the
//!     custody gate — anything else refuses. Applies to a born-dedicated
//!     session too, for every half EXCEPT its already-custodied recv-PQ leaf
//!     (e.g. a lagging send-PQ leaf after a rotation, which has no custody
//!     slot of its own yet);
//!   * a wedged or bind-broken side-band: the native archive carries no wedge
//!     verdict, so the migrated session would report healthy and deadlock.
//!
//! These refusals return `SessionNotReady` — retryable in principle, once the
//! session advances past the blocking state. One retry ceiling: custody also
//! requires the leaf's id still be within the `auth.mine` history window (8
//! entries) — past enough further rotations without ever migrating, that
//! stops being true and the refusal becomes permanent. Rare in practice, but
//! not retryable when it happens. `ArchiveInvalid` means something else
//! entirely: the stored state is corrupt and retrying will not help — e.g. a
//! stored group whose cipher suite no longer matches the session's expected
//! suite (checked before any half's signer touches a provider, since deriving
//! a key through the wrong suite's provider is unrecoverable rather than a
//! clean failure), or a custodied PQ signer that doesn't derive to its
//! presented key.
//!
//! A pending mls-rs commit or a signer-rotating pending self-Update fails
//! inside `export_for_swift` itself.
//!
//! Emits PLAINTEXT SECRET material (group snapshots, signing keys, HPKE
//! secrets, any mid-round KEM material) — the caller seals; this inherits the
//! `ArchiveSink` contract, exactly as the invitation export does. No `Debug`
//! on any record: a derived impl would print plaintext key material.

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::{CipherSuiteProvider, MlsMessage};
use zeroize::Zeroizing;

use crate::key_package_store::{CombinerGroup, KeyPackageSecret, SyntheticKeyPackageStore};
use crate::{Result, TwoMlsPqError};

use super::frames::PQ_REKEY_UPD_TAG;
use super::pq_ops::PqInflight;
use super::{SessionInner, TwoMlsPqSession};

/// One Combiner group half-pair: each present half's swift-mls format-2
/// snapshot bytes (`Group::export_for_swift` output — plaintext secret
/// material). `pq` is `None` where the PQ half is deferred (an acceptor's send
/// group before the A.3 bootstrap).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationGroupHalf {
    pub classical: Vec<u8>,
    pub pq: Option<Vec<u8>>,
}

/// The session's signing identity — the Rust-side image of twomlspq-swift's
/// `MigratedSessionIdentity`. Byte conventions match the invitation export:
/// Ed25519 signing keys normalized to the bare 32-byte raw representation, PQ
/// HPKE secrets the CryptoKit 96-byte `integrityCheckedRepresentation`,
/// `*_key_package` the BARE RFC 9420 `KeyPackage` bytes. `signature_key` /
/// `pq_signature_key` are derived from the chosen key packages (the same
/// source the mint cross-checks against).
///
/// A session identity's retained key packages are normally CONSUMED (mls-rs
/// deletes each on join), so an established session usually holds none: the
/// export then mints a fresh, self-consistent key package pair under the
/// session's signing keys (the identity key packages are dormant in an
/// established session — every post-establishment flow keys off the group
/// snapshots or the session-owned bootstrap KP). `classical_init_secret_key`
/// is always `None`: the mint admits one only for a pre-establishment
/// initiator, which this export refuses wholesale.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationIdentity {
    pub client_id: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub pq_signing_key: Vec<u8>,
    pub pq_signature_key: Vec<u8>,
    pub classical_leaf_secret_key: Vec<u8>,
    pub classical_init_secret_key: Option<Vec<u8>>,
    pub pq_leaf_secret_key: Vec<u8>,
    pub classical_key_package: Vec<u8>,
    pub pq_key_package: Vec<u8>,
}

/// One party's AS credential sequence (see `apq::authentication::PartySequence`).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationPartySequence {
    pub history: Vec<Vec<u8>>,
    pub authorized_next: Vec<Vec<u8>>,
    pub pinned: Vec<Vec<u8>>,
}

/// The staged Upd(self) awaiting the peer's fold: `pending_proposal_hash` +
/// `pending_proposal_message` combined into the native `PendingProposal`
/// shape.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationProposal {
    pub proposing: Vec<u8>,
    pub message: Vec<u8>,
    pub hash: Vec<u8>,
}

/// A digested proposal (offered / queued) in the native
/// `DigestedProposalArchive` shape.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationDigestedProposal {
    pub digest: Vec<u8>,
    pub proposing: Vec<u8>,
    pub message: Vec<u8>,
}

/// One `stagedUpdates` entry: the digest + message of a staged Upd(self).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationStagedUpdate {
    pub digest: Vec<u8>,
    pub message: Vec<u8>,
}

/// A PQ commit awaiting its classical bind (see `SessionInner::owed_bind`).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationOwedBind {
    pub pq_commit: Vec<u8>,
    pub t_epoch: u64,
    pub pq_epoch: u64,
}

/// One cross-party PSK ledger entry. `component_id` is `u32` on the Rust side;
/// the Swift mapper narrows it (checked) to the native `UInt16`.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationPskEntry {
    pub epoch: u64,
    pub component_id: u32,
    pub psk_id: Vec<u8>,
    pub psk: Vec<u8>,
}

/// One epoch-keyed byte entry (listen rendezvous, header receive keys,
/// attachment-CEK ledgers) — flat list form; the Swift side rebuilds its
/// dictionaries.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationEpochEntry {
    pub epoch: u64,
    pub bytes: Vec<u8>,
}

/// A combiner key package pair as BARE RFC 9420 `KeyPackage` bytes (the
/// published form is MLSMessage-framed; the native mint decodes bare).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationCombinerKp {
    pub classical: Vec<u8>,
    pub pq: Vec<u8>,
}

/// The session-owned A.3 bootstrap KP secret (PQ): both HPKE secrets are the
/// CryptoKit 96-byte representation, `key_package` the BARE `KeyPackage` bytes.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationBootstrapKp {
    pub leaf_secret_key: Vec<u8>,
    pub init_secret_key: Vec<u8>,
    pub key_package: Vec<u8>,
}

/// Custody over the PQ signing key that one of this session's own PQ leaves still
/// presents in place of the identity's — today, a born-dedicated acceptor's recv-PQ
/// leaf, which keeps presenting the INVITATION identity's key because nothing in
/// Rust ever catches it up (see the module note). Only the PQ pair: every classical
/// own leaf must already present the identity's key, and mls-rs drops the old
/// classical signer at that catch-up, so no classical half is ever left to custody.
/// A follow-up reuses this for a lagging send-PQ leaf after a rotation.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationPqLeafCustody {
    pub client_id: Vec<u8>,
    pub pq_signing_key: Vec<u8>,
    pub pq_signature_key: Vec<u8>,
}

/// The archivable `PqInflight` round state in the native `MigratedPQInflight`
/// shape: the A.4 variants carry the round's KEM material, `RekeyInitiated`
/// the leg-1 Upd' (lifted out of the retained side-band frame, whose `0x1B`
/// tag is stripped).
#[derive(Clone, uniffi::Enum)]
pub enum SessionMigrationPqInflight {
    BootstrapInitiated,
    BootstrapResponded,
    /// ML-KEM-768 `integrityCheckedRepresentation` (96 B) decapsulation key +
    /// the encapsulation key.
    Initiating {
        secret_key: Vec<u8>,
        ek: Vec<u8>,
    },
    Responding {
        secret: Vec<u8>,
        wire_ct: Vec<u8>,
    },
    RekeyInitiated {
        upd_message: Vec<u8>,
    },
    RekeyResponded,
}

/// The full migration export of one session (GER-2433 C1):
/// `TwoMlsPqSession::migration_export`'s return, the Rust-side image of
/// twomlspq-swift's `MigratedSession`. The four native manifest fields
/// (`sendPQEpoch` etc.) are deliberately ABSENT — the mint derives them from
/// the restored groups so an export cannot disagree with its own snapshots.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationExport {
    pub state_seq: u64,
    /// Whether this session initiated (native `initiated`). Sourced as
    /// "no acceptor-side bootstrap-KP commitment" — `receive` always pins one,
    /// `initiate` never does.
    pub initiated: bool,
    pub identity: SessionMigrationIdentity,
    pub auth_mine: SessionMigrationPartySequence,
    pub auth_theirs: SessionMigrationPartySequence,
    pub send_group: SessionMigrationGroupHalf,
    /// `Some` on every export the gates admit (see the module note) — the
    /// field stays `Option` because the native shape allows a
    /// pre-establishment initiator even though this export refuses one.
    pub recv_group: Option<SessionMigrationGroupHalf>,
    pub current_staple: Vec<u8>,
    pub pending_proposal: Option<SessionMigrationProposal>,
    /// The native model retains EVERY Upd(self) staged this recv epoch; the
    /// Rust session holds only the latest, so this is the pending proposal
    /// (when one is outstanding) as a one-element list.
    pub staged_updates: Vec<SessionMigrationStagedUpdate>,
    pub joined_welcome_digest: Option<Vec<u8>>,
    pub bootstrap_kp_secret: Option<SessionMigrationBootstrapKp>,
    pub expected_bootstrap_kp_commitment: Option<Vec<u8>>,
    pub pq_turn_mine: bool,
    pub owed_bind: Option<SessionMigrationOwedBind>,
    pub pq_inflight: Option<SessionMigrationPqInflight>,
    pub pending_side_band: Option<Vec<u8>>,
    pub peer_applied_send_epoch: Option<u64>,
    pub last_cross_injected: Option<u64>,
    pub last_cross_injected_pq: Option<u64>,
    pub last_send_pq_exported: Option<u64>,
    pub offered_proposal: Option<SessionMigrationDigestedProposal>,
    pub queued_proposal: Option<SessionMigrationDigestedProposal>,
    pub send_cross_psk_ledger: Vec<SessionMigrationPskEntry>,
    pub spawn_token: Option<Vec<u8>>,
    pub listen_rendezvous: Vec<SessionMigrationEpochEntry>,
    pub recv_header_keys: Vec<SessionMigrationEpochEntry>,
    pub recv_header_keys_pq: Vec<SessionMigrationEpochEntry>,
    pub send_attachment_ledger: Vec<SessionMigrationEpochEntry>,
    pub recv_attachment_ledger: Vec<SessionMigrationEpochEntry>,
    pub initial_their_kp: Option<SessionMigrationCombinerKp>,
    /// `requires_establishment_envelope` under its native name.
    pub owes_establishment_envelope: bool,
    /// `Some` exactly when the recv-PQ leaf still presents a key other than the
    /// identity's — a born-dedicated acceptor's uncaught-up PQ leaf.
    pub pq_leaf_custody: Option<SessionMigrationPqLeafCustody>,
}

/// The stored Ed25519 secrets use the mls-rs provider convention — the
/// cryptokit bridge stores `raw ‖ public` (64 B), awslc the bare raw (32 B).
/// The migration consumer wants the bare rawRepresentation (same rule as the
/// invitation export; the mint re-derives the public as a cross-check).
fn bare_ed25519(stored: &[u8]) -> Result<Vec<u8>> {
    match stored.len() {
        32 => Ok(stored.to_vec()),
        64 => Ok(stored[..32].to_vec()),
        _ => Err(TwoMlsPqError::ArchiveInvalid),
    }
}

/// Decode a bare RFC 9420 `KeyPackage` from a retained `KeyPackageSecret` and
/// check its credential binds `client_id` (the mint re-runs this check; a
/// mismatch here marks a corrupt store, so fail at the export).
fn decode_checked_kp(kpd_bytes: &[u8], client_id: &[u8]) -> Result<mls_rs::KeyPackage> {
    let kp = mls_rs::KeyPackage::mls_decode(&mut &kpd_bytes[..])
        .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    let basic = kp
        .signing_identity()
        .credential
        .as_basic()
        .ok_or(TwoMlsPqError::ArchiveInvalid)?;
    if basic.identifier != client_id {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    Ok(kp)
}

/// Pick the half's identity key package: a retained store entry whose
/// credential binds `client_id`, or — the normal case for an established
/// session, whose key packages were consumed by their joins — a freshly
/// minted one, captured out of the store again so the export leaves no
/// residue (single-homed, mirroring the `initiate` bootstrap-KP capture).
fn identity_kp(
    store: &SyntheticKeyPackageStore,
    client_id: &[u8],
    generate: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<KeyPackageSecret> {
    for (id, kpd) in store.all_entries() {
        if decode_checked_kp(&kpd.key_package_bytes, client_id).is_ok() {
            return Ok((id, kpd));
        }
    }
    let (generated, captured) = store.capture(generate);
    generated?;
    let mut captured = captured.into_iter();
    let secret = match (captured.next(), captured.next()) {
        (Some(secret), None) => secret,
        _ => return Err(TwoMlsPqError::Mls),
    };
    store.remove_entry(&secret.0);
    Ok(secret)
}

/// Strip the MLSMessage framing off a published key package, emitting the bare
/// RFC 9420 bytes the native mint decodes.
fn bare_kp(framed: &[u8]) -> Result<Vec<u8>> {
    let msg = MlsMessage::from_bytes(framed).map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    let kp = msg
        .into_key_package()
        .ok_or(TwoMlsPqError::ArchiveInvalid)?;
    kp.mls_encode_to_vec()
        .map_err(|_| TwoMlsPqError::ArchiveInvalid)
}

/// One group half-pair → format-2 snapshots. Flushes each half first (the
/// same discipline `export_state` follows) so the export sees the state a
/// persistence push would write. `export_for_swift` hard-errors on a pending
/// commit or a signer-rotating pending self-Update — the export inherits
/// those refusals.
fn export_group_half(group: &mut CombinerGroup) -> Result<SessionMigrationGroupHalf> {
    group
        .classical
        .write_to_storage()
        .map_err(|_| TwoMlsPqError::Mls)?;
    let classical = group
        .classical
        .export_for_swift()
        .map_err(|_| TwoMlsPqError::Mls)?;
    let pq = match group.pq.as_mut() {
        Some(pq) => {
            pq.write_to_storage().map_err(|_| TwoMlsPqError::Mls)?;
            Some(pq.export_for_swift().map_err(|_| TwoMlsPqError::Mls)?)
        }
        None => None,
    };
    Ok(SessionMigrationGroupHalf { classical, pq })
}

/// The live PQ round state → the export enum. `Responding` requires its
/// retained wire CT (a v2-restored round's is unrecoverable — fail rather
/// than mint a round that can never re-wrap); `RekeyInitiated` lifts the
/// leg-1 Upd' out of the retained side-band frame (tag stripped).
fn export_pq_inflight(inner: &SessionInner) -> Result<Option<SessionMigrationPqInflight>> {
    let inflight = match inner.pq_inflight.as_ref() {
        None => return Ok(None),
        Some(inflight) => inflight,
    };
    Ok(Some(match inflight {
        PqInflight::Initiating(eph) => {
            let dk = eph.decapsulation_key();
            // CryptoKit 96-byte representation guard — same constraint as the
            // identity PQ secrets (an awslc build's 2400-byte form fails HERE).
            if dk.len() != 96 {
                return Err(TwoMlsPqError::ArchiveInvalid);
            }
            SessionMigrationPqInflight::Initiating {
                secret_key: dk.to_vec(),
                ek: eph.encapsulation_key(),
            }
        }
        PqInflight::Responding { secret, wire_ct } => SessionMigrationPqInflight::Responding {
            secret: secret.to_vec(),
            wire_ct: wire_ct.clone().ok_or(TwoMlsPqError::ArchiveInvalid)?,
        },
        PqInflight::RekeyInitiated => {
            let frame = inner
                .pending_side_band
                .as_ref()
                .ok_or(TwoMlsPqError::ArchiveInvalid)?;
            let upd = match frame.frame.split_first() {
                Some((&tag, upd)) if tag == PQ_REKEY_UPD_TAG => upd,
                _ => return Err(TwoMlsPqError::ArchiveInvalid),
            };
            SessionMigrationPqInflight::RekeyInitiated {
                upd_message: upd.to_vec(),
            }
        }
        PqInflight::RekeyResponded => SessionMigrationPqInflight::RekeyResponded,
        PqInflight::BootstrapInitiated => SessionMigrationPqInflight::BootstrapInitiated,
        PqInflight::BootstrapResponded => SessionMigrationPqInflight::BootstrapResponded,
    }))
}

/// The signing key one group half's own leaf currently presents. Generic over both
/// concrete group configs (classical and PQ) so the custody gate can apply it to either.
pub(super) fn own_signature_key<Cfg: mls_rs::client_builder::MlsConfig>(
    group: &mls_rs::Group<Cfg>,
) -> Result<Vec<u8>> {
    Ok(group
        .current_member_signing_identity()
        .map_err(|_| TwoMlsPqError::Mls)?
        .signature_key
        .as_bytes()
        .to_vec())
}

/// A PQ half's own leaf, once it no longer presents the identity's key: builds custody
/// over its signer, provided the leaf's own credential is one of THIS session's own past
/// identities (`auth.mine` history, not the peer's) and the signer derives to the
/// presented key. Derivation runs through the EXPECTED suite's provider (never one chosen
/// by the group's own stored suite — the caller checks that separately, first).
pub(super) fn leaf_pq_custody(
    group: &crate::key_package_store::PqMlsGroup,
    presented: &[u8],
    identity_client_id: &[u8],
    auth_mine_history: &[Vec<u8>],
) -> Result<SessionMigrationPqLeafCustody> {
    let client_id = apq::sender_client_id(group, group.current_member_index())
        .map_err(|_| TwoMlsPqError::Mls)?;
    if client_id == identity_client_id || !auth_mine_history.iter().any(|id| id == &client_id) {
        return Err(TwoMlsPqError::SessionNotReady);
    }
    let signer = group.signer_for_swift_export();
    let derived = crate::providers::pq_envelope_suite()?
        .signature_key_derive_public(signer)
        .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    if derived.as_bytes() != presented {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    Ok(SessionMigrationPqLeafCustody {
        client_id,
        pq_signing_key: bare_ed25519(signer.as_bytes())?,
        pq_signature_key: presented.to_vec(),
    })
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Export this session as the migration payload for the twomlspq-swift
    /// session mint: every group half as a format-2 snapshot plus the session
    /// metadata `SessionMigration.mintArchive` mints a native `SessionArchive`
    /// from.
    ///
    /// Admits only an established session — including one with a parked
    /// side-band leg, an in-flight PQ round, or an owed bind, all carried so
    /// the round completes after migration — see the module note for the
    /// refused states (`SessionNotReady`; `ArchiveInvalid` for torn or
    /// unrecoverable state; `Mls` when a group half refuses its own export,
    /// e.g. a pending commit).
    ///
    /// Emits PLAINTEXT SECRET material — the caller seals (the `ArchiveSink`
    /// contract). PQ secret material is exported in the CryptoKit 96-byte
    /// representation, correct only under the `cryptokit` provider build;
    /// under `awslc` the length guards fail the export as `ArchiveInvalid`.
    pub fn migration_export(&self) -> Result<SessionMigrationExport> {
        let mut inner = self.lock();
        let initiated = inner.expected_bootstrap_kp_commitment.is_none();

        // The unmigratable states (module note): pre-establishment, mid-rotation, a
        // born-dedicated session not yet installed, or a torn side-band. An
        // acceptor's parked return welcome is fine — dropped below, not refused
        // here, because the app never drains it and the same welcome still rides
        // `current_staple` — so only an initiator's park blocks the export
        // (already implied by `recv_group.is_none()`; kept as belt-and-braces).
        if inner.recv_group.is_none()
            || (inner.pending_outbound.is_some() && initiated)
            || inner.initial_app_payload.is_some()
            || inner.initial_return_kp.is_some()
            || !inner.staged_candidates.is_empty()
            || inner.deferred_candidate.is_some()
            || (inner.requires_establishment_envelope && inner.establishment_envelope.is_none())
            || inner.pq_wedged.is_some()
            || inner.bind_apply_broken
        {
            return Err(TwoMlsPqError::SessionNotReady);
        }

        // SUITE CHECK FIRST, before any crypto: a stored group half whose cipher
        // suite disagrees with the session's own declared suite is corrupt — and
        // must never reach a provider it doesn't belong to (see the module note).
        let expected_suite = inner.client.combiner().cipher_suite();
        for half in [
            inner
                .send_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?,
            inner
                .recv_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?,
        ] {
            let pq_ok = half
                .pq
                .as_ref()
                .is_none_or(|pq| pq.cipher_suite() == expected_suite.pq);
            if half.classical.cipher_suite() != expected_suite.classical || !pq_ok {
                return Err(TwoMlsPqError::ArchiveInvalid);
            }
        }

        // The identity: signing keys from the session client, key packages
        // picked (or freshly minted) per half — see `identity_kp`.
        let client = inner.client.combiner();
        let client_id = client.client_id().to_vec();
        let (_, classical_kpd) = identity_kp(client.classical_kp_store(), &client_id, || {
            client
                .generate_classical_key_package()
                .map_err(|_| TwoMlsPqError::Mls)
        })?;
        let (_, pq_kpd) = identity_kp(client.pq_kp_store(), &client_id, || {
            client
                .generate_pq_key_package()
                .map_err(|_| TwoMlsPqError::Mls)
        })?;
        let classical_kp = decode_checked_kp(&classical_kpd.key_package_bytes, &client_id)?;
        let pq_kp = decode_checked_kp(&pq_kpd.key_package_bytes, &client_id)?;
        // HPKE secret representation guard: classical X25519 raw (32 B), PQ the
        // CryptoKit 96 B form — anything else fails HERE rather than surfacing
        // as an opaque Swift `archiveInvalid` (the invitation export's rule).
        for (len, bytes) in [
            (32, &classical_kpd.leaf_node_key),
            (96, &pq_kpd.leaf_node_key),
        ] {
            if bytes.len() != len {
                return Err(TwoMlsPqError::ArchiveInvalid);
            }
        }
        let identity = SessionMigrationIdentity {
            client_id,
            signing_key: bare_ed25519(client.classical_signing_key())?,
            signature_key: classical_kp
                .signing_identity()
                .signature_key
                .as_bytes()
                .to_vec(),
            pq_signing_key: bare_ed25519(client.pq_signing_key())?,
            pq_signature_key: pq_kp.signing_identity().signature_key.as_bytes().to_vec(),
            classical_leaf_secret_key: classical_kpd.leaf_node_key.to_vec(),
            // Always None: the mint admits a classical init secret only for a
            // pre-establishment initiator, which this export refuses.
            classical_init_secret_key: None,
            pq_leaf_secret_key: pq_kpd.leaf_node_key.to_vec(),
            classical_key_package: classical_kpd.key_package_bytes.clone(),
            pq_key_package: pq_kpd.key_package_bytes.clone(),
        };

        // The custody gate: every group half's own leaf must present the
        // identity's per-half signing key, except a born-dedicated acceptor's
        // recv-PQ leaf, which nothing in Rust ever catches up (module note) —
        // captured as `pq_leaf_custody` instead of matched. The mint's custody
        // arms resolve a presented key against identity ∪ rotationCandidate ∪
        // recvLeafPrincipal; anything else admitted here would fail the mint as
        // `archiveInvalid` (corruption semantics on a healthy session), so this
        // refuses as `SessionNotReady` first — before the export ever surfaces
        // an `Mls` error for merely not having converged yet.
        let send = inner
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let recv = inner
            .recv_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        if own_signature_key(&send.classical)? != identity.signature_key
            || own_signature_key(&recv.classical)? != identity.signature_key
        {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        if let Some(pq) = send.pq.as_ref() {
            if own_signature_key(pq)? != identity.pq_signature_key {
                return Err(TwoMlsPqError::SessionNotReady);
            }
        }
        let pq_leaf_custody = match recv.pq.as_ref() {
            None => None,
            Some(pq) => {
                let presented = own_signature_key(pq)?;
                if presented == identity.pq_signature_key {
                    None
                } else if inner.requires_establishment_envelope {
                    let auth_mine_history = inner.with_auth(|core| core.mine.to_parts().0);
                    Some(leaf_pq_custody(
                        pq,
                        &presented,
                        &identity.client_id,
                        &auth_mine_history,
                    )?)
                } else {
                    // The existing post-rotation leaf-lag refusal for a
                    // non-dedicated session: no custody slot to fall back to.
                    return Err(TwoMlsPqError::SessionNotReady);
                }
            }
        };

        let send_group = export_group_half(
            inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?,
        )?;
        let recv_group = inner
            .recv_group
            .as_mut()
            .map(export_group_half)
            .transpose()?;

        let (auth_mine, auth_theirs) = inner.with_auth(|core| {
            let seq = |s: &apq::authentication::PartySequence| {
                let (history, authorized_next, pinned) = s.to_parts();
                SessionMigrationPartySequence {
                    history,
                    authorized_next,
                    pinned,
                }
            };
            (seq(&core.mine), seq(&core.theirs))
        });

        // The staged Upd(self) pair is set together on every established-session
        // path. Hash-without-message is the §A.1 pre-establishment marker
        // (prepare_pre_establishment), which the establishment cutover does NOT
        // clear: a prepare-then-never-encrypt initiator can carry it across the
        // cutover, and the next `prepare_to_encrypt` overwrites both — so past
        // the gates it is stale dead state, dropped rather than exported (the
        // native side has no hash-only marker). Message-without-hash is torn.
        let pending_proposal = match (
            &inner.pending_proposal_hash,
            &inner.pending_proposal_message,
        ) {
            (Some(hash), Some((proposing, message))) => Some(SessionMigrationProposal {
                proposing: proposing.clone(),
                message: message.clone(),
                hash: hash.clone(),
            }),
            (None, None) | (Some(_), None) => None,
            (None, Some(_)) => return Err(TwoMlsPqError::ArchiveInvalid),
        };
        let staged_updates = pending_proposal
            .iter()
            .map(|p| SessionMigrationStagedUpdate {
                digest: p.hash.clone(),
                message: p.message.clone(),
            })
            .collect();

        let pq_inflight = export_pq_inflight(&inner)?;

        // The bootstrap KP secret is a PQ key package: both HPKE secrets in the
        // CryptoKit 96 B form, the public half as BARE KeyPackage bytes.
        let bootstrap_kp_secret = inner
            .bootstrap_kp_secret
            .as_ref()
            .map(|secret| {
                let kpd = &secret.1;
                if kpd.leaf_node_key.len() != 96 || kpd.init_key.len() != 96 {
                    return Err(TwoMlsPqError::ArchiveInvalid);
                }
                Ok(SessionMigrationBootstrapKp {
                    leaf_secret_key: kpd.leaf_node_key.to_vec(),
                    init_secret_key: kpd.init_key.to_vec(),
                    key_package: kpd.key_package_bytes.clone(),
                })
            })
            .transpose()?;

        let epoch_entries =
            |map: &std::collections::BTreeMap<u64, Vec<u8>>| -> Vec<SessionMigrationEpochEntry> {
                map.iter()
                    .map(|(&epoch, bytes)| SessionMigrationEpochEntry {
                        epoch,
                        bytes: bytes.clone(),
                    })
                    .collect()
            };
        let ledger_entries = |ledger: &std::collections::VecDeque<(u64, Zeroizing<Vec<u8>>)>| {
            ledger
                .iter()
                .map(|(epoch, component)| SessionMigrationEpochEntry {
                    epoch: *epoch,
                    bytes: component.to_vec(),
                })
                .collect()
        };

        Ok(SessionMigrationExport {
            state_seq: inner.state_seq,
            initiated,
            identity,
            auth_mine,
            auth_theirs,
            send_group,
            recv_group,
            current_staple: inner.current_staple.clone(),
            pending_proposal,
            staged_updates,
            joined_welcome_digest: inner.joined_welcome_digest.clone(),
            bootstrap_kp_secret,
            expected_bootstrap_kp_commitment: inner
                .expected_bootstrap_kp_commitment
                .as_ref()
                .map(|c| c.as_bytes().to_vec()),
            pq_turn_mine: inner.pq_turn_mine,
            owed_bind: inner.owed_bind.as_ref().map(|o| SessionMigrationOwedBind {
                pq_commit: o.pq_commit.clone(),
                t_epoch: o.t_epoch,
                pq_epoch: o.pq_epoch,
            }),
            pq_inflight,
            pending_side_band: inner.pending_side_band.as_ref().map(|r| r.frame.clone()),
            peer_applied_send_epoch: inner.peer_applied_send_epoch,
            last_cross_injected: inner.last_cross_injected,
            last_cross_injected_pq: inner.last_cross_injected_pq,
            last_send_pq_exported: inner.last_send_pq_exported,
            // Mind the live tuples' asymmetric field order: offered is
            // (digest, proposal, proposing), queued (digest, proposing, proposal).
            offered_proposal: inner.offered_proposal.as_ref().map(
                |(digest, proposal, proposing)| SessionMigrationDigestedProposal {
                    digest: digest.clone(),
                    proposing: proposing.clone(),
                    message: proposal.clone(),
                },
            ),
            queued_proposal: inner
                .queued_proposal
                .as_ref()
                .map(
                    |(digest, proposing, proposal)| SessionMigrationDigestedProposal {
                        digest: digest.clone(),
                        proposing: proposing.clone(),
                        message: proposal.clone(),
                    },
                ),
            send_cross_psk_ledger: inner
                .send_psk_ledger
                .iter()
                .map(|(epoch, exported)| SessionMigrationPskEntry {
                    epoch: *epoch,
                    component_id: exported.component_id(),
                    psk_id: exported.psk_id().to_vec(),
                    psk: exported.psk().raw_value().to_vec(),
                })
                .collect(),
            spawn_token: inner.spawn_token.clone(),
            listen_rendezvous: epoch_entries(&inner.listen_rendezvous),
            recv_header_keys: epoch_entries(&inner.recv_header_keys),
            recv_header_keys_pq: epoch_entries(&inner.recv_header_keys_pq),
            send_attachment_ledger: ledger_entries(&inner.send_attachment_ledger),
            recv_attachment_ledger: ledger_entries(&inner.recv_attachment_ledger),
            initial_their_kp: inner
                .initial_their_kp
                .as_ref()
                .map(|kp| -> Result<SessionMigrationCombinerKp> {
                    Ok(SessionMigrationCombinerKp {
                        classical: bare_kp(&kp.classical)?,
                        pq: bare_kp(&kp.pq)?,
                    })
                })
                .transpose()?,
            // Always false on an admitted export — the pre-install latch above
            // refuses otherwise — kept for native-shape parity.
            owes_establishment_envelope: inner.requires_establishment_envelope
                && inner.establishment_envelope.is_none(),
            pq_leaf_custody,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cryptokit")]
    use crate::test_utils::{
        commitment_of, establish_confirmed_sessions, make_classical_kp, make_client,
        make_combiner_kp,
    };
    #[cfg(feature = "cryptokit")]
    use crate::{assert_ok, assert_some, TwoMlsPqError};

    // Migration happy paths require the CryptoKit 96-byte ML-KEM representation;
    // an awslc build's 2400-byte decapsulation keys trip the export's length
    // guards by design (migration targets the CryptoKit-based swift engine).

    /// An established (classical) session exports: the initiator's send group
    /// carries its PQ half, its recv group is still classical-only pre-A.3, and
    /// the identity round-trips a self-consistent key-package pair.
    #[cfg(feature = "cryptokit")]
    #[test]
    fn test_migration_export_established_session() {
        let (alice, bob) = establish_confirmed_sessions();

        let export = assert_ok!(alice.migration_export());
        assert!(export.initiated);
        assert!(export.send_group.pq.is_some());
        let recv = assert_some!(export.recv_group);
        assert!(recv.pq.is_none());
        assert!(export.expected_bootstrap_kp_commitment.is_none());
        assert!(!export.identity.client_id.is_empty());
        assert!(!export.identity.classical_key_package.is_empty());
        assert!(!export.identity.pq_key_package.is_empty());
        assert!(export.identity.classical_init_secret_key.is_none());

        let bob_export = assert_ok!(bob.migration_export());
        assert!(!bob_export.initiated);
        assert!(bob_export.expected_bootstrap_kp_commitment.is_some());
        // The acceptor's send group is classical-only until the A.3 bootstrap.
        assert!(bob_export.send_group.pq.is_none());
        assert!(assert_some!(bob_export.recv_group).pq.is_some());
    }

    /// A pre-establishment initiator (no recv group; the parked §A.1 envelope
    /// has no native slot) is refused, not mis-mapped.
    #[cfg(feature = "cryptokit")]
    #[test]
    fn test_migration_export_refuses_pre_establishment() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(super::TwoMlsPqSession::initiate(alice, bob_kp, None));
        assert!(matches!(
            session.migration_export(),
            Err(TwoMlsPqError::SessionNotReady)
        ));
    }

    /// A fresh acceptor (recv group joined, its send-PQ half still deferred) exports fine
    /// with its parked return welcome still UNDRAINED: the app never drains an
    /// acceptor's `pending_outbound`, so refusing it would mean no acceptor session ever
    /// migrates. The export drops the parked copy; the same welcome still rides
    /// `current_staple` until this acceptor's own first send-group commit.
    #[cfg(feature = "cryptokit")]
    #[test]
    fn test_migration_export_acceptor_pre_bootstrap() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let bob_inv = assert_ok!(crate::key_packages::TwoMlsPqInvitation::restore(
            assert_ok!(bob.generate_invitation(true))
        ));
        let bob_kp = bob_inv.combiner_key_package();
        let alice_s = assert_ok!(super::TwoMlsPqSession::initiate(
            std::sync::Arc::clone(&alice),
            bob_kp,
            None
        ));
        let commitment = commitment_of(&alice_s);
        let opened =
            assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
        let bob_s = assert_ok!(bob_inv.receive(
            assert_some!(opened.welcome),
            alice_kp,
            commitment,
            b"tok".to_vec(),
            None,
            None,
            None,
        ));
        let export = assert_ok!(bob_s.migration_export());
        assert!(!export.initiated);
        assert!(export.send_group.pq.is_none());
        assert!(assert_some!(export.recv_group).pq.is_some());
        assert!(export.pq_leaf_custody.is_none());
    }
}
