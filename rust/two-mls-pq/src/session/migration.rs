//! Session migration export: `TwoMlsPqSession::migration_export`, the
//! session-level analogue of `TwoMlsPqInvitation::migration_export`. Emits
//! everything twomlspq-swift's `SessionMigration.mintArchive` needs to mint a
//! native `SessionArchive`: each group half as a swift-mls format-2 snapshot
//! (mls-rs's `Group::export_for_swift_with_pending_signers`, slice A) plus the
//! combiner/session metadata as flat records.
//!
//! Admits every reachable deployed session: an established initiator or
//! acceptor need not be quiescent first, and no reachable state is refused
//! merely for not having converged. A parked side-band leg, an in-flight
//! (even mis-signed) PQ round (`pq_inflight`), an owed classical bind
//! (`owed_bind`), a wedged PQ side-band, mid-rotation state (up to
//! `CANDIDATE_WINDOW` staged candidates), and a lagging own leaf on any half
//! are all carried rather than required to settle first:
//!
//!   * a parked return welcome (acceptor's `pending_outbound`, or an
//!     initiator's parked §A.1 envelope): the export drops the parked copy
//!     rather than refusing it. It still rides `current_staple` until this
//!     party's first send-group commit, matching how the native session
//!     re-staples `currentStaple`, so nothing is stranded;
//!   * a pre-establishment initiator (`recv_group: None`): carries
//!     `initial_their_kp`, `initial_app_payload`, the retained return KP's
//!     init secret, and the pre-committed A.3 bootstrap KP secret/commitment.
//!     `leaf_keys.recv_classical`/`recv_pq` carry reservations, not live
//!     custody;
//!   * a born-dedicated acceptor at any point from receive through
//!     convergence: `owes_establishment_envelope` reports whether the signed
//!     delegation has landed, and `leaf_keys` resolves custody for whichever
//!     identity each leaf currently presents (invitation pre-convergence,
//!     dedicated after);
//!   * every own leaf's signing key is resolved by a key-custody search, not
//!     an identity-equality check: the leaf's presented key is derive-matched
//!     against a candidate pool built from the identity's own keys, every
//!     half's current signer (`signer_for_swift_export`), staged rotation
//!     candidates, and pending self-Update signers. This is what lets a
//!     post-rotation leaf-lag or mid-rotation desync still export — some pool
//!     candidate derives to whatever is presented. Emitted as
//!     `leaf_keys.<half>.current`;
//!   * `leaf_keys` requires all four groups (`send_classical`,
//!     `recv_classical`, `send_pq`, `recv_pq`), never `None`: a group that
//!     doesn't exist yet carries a reservation in `current` (the key it will
//!     present once created or joined) with empty `pending` — see
//!     `reservation` — except a pre-A.3 acceptor's send-PQ, which is empty
//!     because A.3 founding mints its own key;
//!   * generalized catch-up: any own leaf whose presented credential lags
//!     `auth.mine`'s current one gets a synthesized `pending[mine.current]`
//!     entry carrying the identity's current key of that half's kind — see
//!     `catch_up_pending_entry` and `fold_in_catch_up`. `send_classical` is the
//!     exception: it carries `current` only, since its own next commit mints
//!     fresh for whatever id it then presents;
//!   * every staged rotation candidate rides `pending[candidate id]` in
//!     `recv_classical` — see `recv_classical_pending`. A candidate
//!     whose id equals `auth.mine`'s current one can leave two
//!     differently-keyed offers outstanding for that one target (the
//!     identity's own self-catch-up, and the same-id candidate's
//!     re-proposal), and only one key can ride `pending[mine.current]`.
//!     `recv_classical_pending` resolves it in priority order: (a) an entry a
//!     `prepare_to_encrypt` has already framed, if it targets `mine.current`
//!     — a framed entry can never be dropped; (b) else the identity's key, if
//!     a real identity-signed offer is outstanding; (c) else the same-id
//!     candidate's own (pinned, not scanned) key; (d) else the synthesized
//!     catch-up, if the leaf still lags. `own_offer_window` applies the same
//!     priority to its own window so the two never disagree. `pending`
//!     entries are deduplicated by target, not by signing key, since these
//!     two mechanisms can otherwise leave two different keys claiming one
//!     target;
//!   * the no-custody case: a leaf whose secret exists nowhere in the
//!     candidate pool is carried as unsignable
//!     (`deployed_state.no_custody.<half>`) rather than erred. Confirmed
//!     reachable on `recv_pq` (see
//!     `test_migration_export_carries_no_custody_from_an_unchecked_join_signer`):
//!     send-PQ's signer at `initiate` time gets bound into recv-PQ at the A.3
//!     join, then a later A.5 own-leaf catch-up rotates send-PQ on, leaving
//!     recv-PQ presenting a key nothing in the pool can derive. Decrypting
//!     needs only the shared secret, not the signer, so this stays
//!     receive-only unless send-PQ independently lags again and a later
//!     catch-up tries to sign with the missing key. Native must never sign
//!     with such a leaf; it should surface a heal-needed condition instead;
//!   * recv-classical's own-offer window: outstanding own Update proposals a
//!     peer might still fold by reference, carried up to `OWN_OFFER_WINDOW`
//!     in `deployed_state.own_offers` (`None` when there is no recv group or
//!     nothing outstanding) — see that constant's and `own_offer_window`'s
//!     docs for the cap and the accepted residual risk past it. Epoch, group
//!     id and sender leaf index are hoisted onto the window; order is
//!     meaningful — selection order, presentation-changing offers before
//!     refreshes, deterministic `proposal_ref` order otherwise. An entry is
//!     excluded from the window only while a `prepare_to_encrypt` has
//!     already framed it (its HPKE pair rides the snapshot via
//!     `Placement::Snapshot` instead, and the framed copy wins at apply). At
//!     rest, recency is unrecoverable, so every outstanding own offer is a
//!     window candidate with a `Placement::Detached`, always-populated
//!     `leaf_secret`;
//!   * a migrated stale `pending_proposal` (see `own_offer_window`'s doc on
//!     how one goes stale) blocks the PQ side-band from auto-opening a new
//!     round until the next send — this matches native, which never
//!     proactively clears a stale pending proposal on an epoch advance
//!     either;
//!
//! `leaf_keys`, `initial_app_payload`, and `deployed_state` may still change
//! shape before the Swift mapper consumes them. The legacy `pq_leaf_custody`
//! field stays populated with its original, narrower (history-window-checked,
//! born-dedicated-only) gating for back-compat, but its own failure never
//! blocks the export; only `leaf_keys` is authoritative.
//!
//! What still refuses is corrupt or genuinely impossible data, never a
//! reachable one:
//!
//!   * a stored group whose cipher suite disagrees with the session's own
//!     declared suite (checked before any signer touches a provider, since
//!     deriving through the wrong suite is unrecoverable, not a clean
//!     failure) — `ArchiveInvalid`;
//!   * `bind_apply_broken` (a torn receive path): in-memory only, since a
//!     session restored from its persisted row is built by the converter
//!     from those rows alone, which never recorded this flag. Still
//!     reachable on the current process, and the native archive carries no
//!     torn-receive verdict — `Mls` (retryable: reload from the persisted
//!     row and export that instead);
//!   * `initial_return_kp` set on a pre-establishment initiator: never
//!     reachable from this product's own wrapper (only `setInitialAppPayload`
//!     is ever called), so a live value is corrupt, not merely unusual —
//!     `ArchiveInvalid`;
//!   * a torn `pending_proposal` (a hash with no message, or vice versa), an
//!     unrecoverable PQ round secret representation, or any other
//!     structurally impossible combination this module already guards —
//!     `ArchiveInvalid`.
//!
//! A pending mls-rs commit still fails inside
//! `export_for_swift_with_pending_signers` itself, surfaced as `Mls` — the
//! one case a group half refuses its own export outright (an in-flight local
//! commit has no meaningful snapshot to take). Key-package generation failure
//! is likewise `Mls`: environmental and retryable, never `ArchiveInvalid`.
//!
//! Emits plaintext secret material (group snapshots, signing keys, HPKE
//! secrets, any mid-round KEM material) — the caller seals; this inherits the
//! `ArchiveSink` contract, exactly as the invitation export does. No `Debug`
//! on any record: a derived impl would print plaintext key material.

use std::sync::Arc;

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::{CipherSuiteProvider, MlsMessage};
use zeroize::Zeroizing;

use crate::key_package_store::{KeyPackageSecret, SyntheticKeyPackageStore};
use crate::{Result, TwoMlsPqError};

use super::frames::PQ_REKEY_UPD_TAG;
use super::pq_ops::{PqInflight, PqWedge};
use super::{SessionInner, TwoMlsPqPrincipal, TwoMlsPqSession};

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
/// is `Some` only for a pre-establishment initiator: the mint takes an init
/// secret there, and `identity_kp` on that path is the RETAINED return key
/// package (minted before `createTwoMLSGroup`/`setInitialAppPayload`), not a
/// fresh one. `None` on every established session.
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

/// Custody over the PQ signing key an own PQ leaf still presents in place of
/// the identity's — a born-dedicated acceptor's uncaught-up recv-PQ leaf. PQ
/// only: mls-rs drops the old classical signer at catch-up, so no classical
/// half is ever left to custody.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationPqLeafCustody {
    pub client_id: Vec<u8>,
    pub pq_signing_key: Vec<u8>,
    pub pq_signature_key: Vec<u8>,
}

/// One own leaf's resolved custody pair: the secret behind whatever key it
/// currently presents, plus that secret's derived public half (cross-check echo).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationKeyPair {
    pub signing_key: Vec<u8>,
    pub signature_key: Vec<u8>,
}

/// One identity a half may still commit to once a peer's commit lands: a
/// pending self-Update, a staged rotation candidate, or the generalized
/// catch-up entry (`target` = `auth.mine`'s current id).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationPendingLeafKey {
    /// Non-empty; unique within its group's `pending`.
    pub target: Vec<u8>,
    pub key: SessionMigrationKeyPair,
}

/// One group's full key custody: `current` is `None` only in the no-custody
/// case (nothing derives to what the leaf presents or will present) — the
/// half is unsignable and the mint must never try. `pending` is deduplicated
/// by target, not by signing key.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationGroupKeys {
    pub current: Option<SessionMigrationKeyPair>,
    pub pending: Vec<SessionMigrationPendingLeafKey>,
}

/// Every own leaf's resolved custody. All four groups are always present: a
/// group that doesn't exist yet carries a reservation in `current` (the key
/// it will present once created or joined) with `pending` empty, except a
/// pre-A.3 acceptor's `send_pq`, which is empty (A.3 founding mints its key).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationLeafKeys {
    pub send_classical: SessionMigrationGroupKeys,
    pub recv_classical: SessionMigrationGroupKeys,
    pub send_pq: SessionMigrationGroupKeys,
    pub recv_pq: SessionMigrationGroupKeys,
}

/// The most recently staged rotation candidate, classical only. Its
/// `signing_key`/`signature_key` must equal the same candidate's `pending`
/// entry in `recv_classical`. `None` when the newest candidate's id
/// equals `auth.mine`'s current one — a same-id candidate is a self-catch-up
/// mechanism, not a rotation target (see `recv_classical_pending`).
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationRotationCandidate {
    pub target_client_id: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub proposed_at_recv_epoch: u64,
}

/// One own Update proposal still outstanding in recv-classical's proposal
/// cache — carried so a peer's later by-reference fold of an older own offer
/// still resolves after migration, since mls-rs never retains the signed
/// message bytes. Epoch, group id and sender leaf index are the same for
/// every offer in a window, so they're hoisted onto
/// `SessionMigrationOwnOfferWindow` instead of repeated per entry.
///
/// The entry a `prepare_to_encrypt` has framed is never a window member (its
/// HPKE pair already rides the snapshot, and the framed copy wins at apply);
/// at rest, nothing is framed, so every window entry is `Placement::Detached`
/// and `leaf_secret` is always present.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationOwnOffer {
    pub proposal_ref: Vec<u8>,
    /// MLS-encoded `Proposal`, always an Update — non-Update entries are
    /// filtered out.
    pub proposal: Vec<u8>,
    /// The proposed leaf's HPKE private key, carried alongside this entry
    /// rather than inside the snapshot. Always populated — a selected entry
    /// with no matching secret is corrupt data (`ArchiveInvalid`).
    pub leaf_secret: Vec<u8>,
}

/// Recv-classical's own-offer window — see `own_offer_window`'s doc for
/// selection, banding and the cap. `offers` starts at band 2
/// (presentation-changing), then band 3 (refreshes, deterministic
/// `proposal_ref` order); past the cap, which refreshes drop is arbitrary.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationOwnOfferWindow {
    pub epoch: u64,
    pub group_id: Vec<u8>,
    pub sender_leaf_index: u32,
    pub offers: Vec<SessionMigrationOwnOffer>,
}

/// Per-half "no secret exists anywhere for what this leaf presents" — the
/// no-custody case (see the module doc). Confirmed reachable on `recv_pq`, a
/// join-time gap, not corruption. The mint must never sign with that half;
/// it should surface a heal-needed condition instead.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationNoCustody {
    pub send_classical: bool,
    pub send_pq: bool,
    pub recv_classical: bool,
    pub recv_pq: bool,
}

/// `deployed_state.pq_wedged`'s kind, mapping 1:1 from `PqWedge` (see that type's doc for
/// the recovery/diagnosis split).
#[derive(Clone, uniffi::Enum)]
pub enum SessionMigrationPqWedgeKind {
    Bootstrap,
    Ratchet,
    Rekey,
}

/// Deployed-only carry state with no confirmed native slot yet — kept
/// separate so a later release can add support without another core-shape
/// FFI break. `Some` whenever any part of it is non-empty or true.
#[derive(Clone, uniffi::Record)]
pub struct SessionMigrationDeployedState {
    /// Recv-classical's own-offer window — see `SessionMigrationOwnOfferWindow` and
    /// `own_offer_window`'s docs. `None` when there is no recv group, or nothing
    /// outstanding to carry.
    pub own_offers: Option<SessionMigrationOwnOfferWindow>,
    /// Carried rather than refused — classical messaging is unaffected by a PQ
    /// side-band wedge.
    pub pq_wedged: Option<SessionMigrationPqWedgeKind>,
    pub no_custody: SessionMigrationNoCustody,
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
    /// `None` exactly for a pre-establishment initiator — the one state
    /// with no recv group at all. `Some` otherwise.
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
    /// `Some` exactly when the recv-PQ leaf still presents a key other than
    /// the identity's — a born-dedicated acceptor's uncaught-up PQ leaf. Kept
    /// for back-compat with narrower, history-window-checked gating;
    /// `leaf_keys` is authoritative and never gates the export.
    pub pq_leaf_custody: Option<SessionMigrationPqLeafCustody>,
    /// Every own leaf's resolved signing custody — replaces the
    /// identity-equality gate and `pq_leaf_custody`'s narrow special case.
    /// This shape may still change before the Swift mapper consumes it.
    pub leaf_keys: SessionMigrationLeafKeys,
    /// The newest staged candidate — `None` when there is none, or when its
    /// id equals `auth.mine`'s current one (a same-id candidate never
    /// exports here; see `recv_classical_pending`). Its key equals
    /// `leaf_keys.{send,recv}_classical.pending`'s entry for the same target.
    pub rotation_candidate: Option<SessionMigrationRotationCandidate>,
    /// The host's app-layer welcome riding a pre-establishment initiator's
    /// envelope. `None` on every established session; exported only for a
    /// pre-join initiator, and only when non-empty.
    pub initial_app_payload: Option<Vec<u8>>,
    /// Deployed-only carry state (own-offer window, `pq_wedged`, per-half no-custody) —
    /// `Some` whenever any of it is non-empty or true. See `SessionMigrationDeployedState`.
    pub deployed_state: Option<SessionMigrationDeployedState>,
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

/// Whether `payload` carries `kp_bytes` anywhere inside it, bare or
/// MLSMessage-framed: framing only wraps a payload, never transforms its
/// bytes, so the bare form stays a substring of the framed one either way.
fn payload_contains_kp(payload: &[u8], kp_bytes: &[u8]) -> bool {
    !kp_bytes.is_empty() && payload.windows(kp_bytes.len()).any(|w| w == kp_bytes)
}

/// Pick the half's identity key package: a retained store entry whose
/// credential binds `client_id`, or — the normal case for an established
/// session, whose key packages were consumed by their joins — a freshly
/// minted one, captured out of the store again so the export leaves no
/// residue (single-homed, mirroring the `initiate` bootstrap-KP capture).
///
/// `prefer_within` (the pre-establishment initiator's `initial_app_payload`)
/// breaks a tie among several retained entries binding `client_id`: the one
/// whose bytes occur inside it is the KP the peer will actually use. Not
/// shown reachable today, so an unresolved tie falls back to
/// first-in-storage-order.
fn identity_kp(
    store: &SyntheticKeyPackageStore,
    client_id: &[u8],
    prefer_within: Option<&[u8]>,
    generate: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<KeyPackageSecret> {
    let bound: Vec<KeyPackageSecret> = store
        .all_entries()
        .into_iter()
        .filter(|(_, kpd)| decode_checked_kp(&kpd.key_package_bytes, client_id).is_ok())
        .collect();
    if let Some(payload) = prefer_within {
        if bound.len() > 1 {
            if let Some(preferred) = bound
                .iter()
                .find(|(_, kpd)| payload_contains_kp(payload, &kpd.key_package_bytes))
            {
                return Ok(preferred.clone());
            }
        }
    }
    if let Some(first) = bound.into_iter().next() {
        return Ok(first);
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

/// The signing key one group half's own leaf currently presents. Generic
/// over both group configs so the custody search can apply it to either.
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

/// A PQ half's own leaf that no longer presents the identity's key: builds
/// custody over its signer, provided the leaf's credential is one of this
/// session's own past identities and the signer derives to the presented
/// key. Derivation runs through the expected suite's provider, never the
/// group's own stored suite — the caller checks that separately, first.
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

/// One custody-search step: normalize a candidate secret to bare Ed25519
/// (32 B) and derive its public key through `provider`. `None` for anything
/// that isn't a plausible Ed25519 secret, or the provider refuses. Normalize
/// before deriving: the cryptokit bridge traps on input shorter than 32
/// bytes, so this turns a mismatched-length candidate into a clean "no
/// match" instead of a process abort.
fn candidate_public_key(
    provider: &impl CipherSuiteProvider,
    secret_bytes: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let bare = bare_ed25519(secret_bytes).ok()?;
    let sk = mls_rs::crypto::SignatureSecretKey::new(bare.clone());
    let pk = provider.signature_key_derive_public(&sk).ok()?;
    Some((bare, pk.as_bytes().to_vec()))
}

/// Search `pool` for the secret behind `presented`, deriving each candidate
/// through `provider` — this half's own expected suite provider. First
/// match wins; under well-formed data at most one secret can derive to a
/// given key. `None` (not an error) means the no-custody case.
fn find_custody(
    provider: &impl CipherSuiteProvider,
    presented: &[u8],
    pool: &[Vec<u8>],
) -> Option<Vec<u8>> {
    pool.iter().find_map(|candidate| {
        let (bare, derived) = candidate_public_key(provider, candidate)?;
        (derived == presented).then_some(bare)
    })
}

/// The `SigningIdentity`'s ClientId (Basic credential) — every credential this crate ever
/// mints is Basic, so anything else is corrupt/impossible.
fn signing_identity_client_id(identity: &mls_rs::identity::SigningIdentity) -> Result<Vec<u8>> {
    identity
        .credential
        .as_basic()
        .map(|basic| basic.identifier.clone())
        .ok_or(TwoMlsPqError::ArchiveInvalid)
}

/// One half's `pending_updates` signers, mapped onto
/// `SessionMigrationPendingLeafKey` — dropping any orphan
/// (`signing_identity == None`): the proposal cache was cleared while the
/// pending secret survived, so no peer can ever commit it by reference.
fn pending_leaf_keys(
    provider: &impl CipherSuiteProvider,
    signers: &[mls_rs::group::SwiftExportPendingSigner],
) -> Result<Vec<SessionMigrationPendingLeafKey>> {
    // A born-dedicated acceptor left unfolded can re-propose the same signer
    // ~10^5 times. Dedupe by normalized secret bytes before deriving — an
    // ML-DSA derive is the expensive step — to bound cost by distinct keys.
    let mut seen = std::collections::HashSet::new();
    signers
        .iter()
        .filter_map(|signer| {
            let identity = signer.signing_identity.as_ref()?;
            let secret_bytes = signer.signer.as_bytes();
            let dedupe_key = bare_ed25519(secret_bytes).unwrap_or_else(|_| secret_bytes.to_vec());
            if !seen.insert(dedupe_key) {
                return None;
            }
            Some((|| {
                let target = signing_identity_client_id(identity)?;
                let (signing_key, signature_key) = candidate_public_key(provider, secret_bytes)
                    .ok_or(TwoMlsPqError::ArchiveInvalid)?;
                Ok(SessionMigrationPendingLeafKey {
                    target,
                    key: SessionMigrationKeyPair {
                        signing_key,
                        signature_key,
                    },
                })
            })())
        })
        .collect()
}

/// `pending_leaf_keys`'s counterpart for recv-classical's `Detached`-placed
/// entries. A `Detached` entry with no signer (a same-identity refresh) is
/// dropped, same as a signer-less `Snapshot` entry: only a leaf that rotates
/// its signing identity is a candidate a peer could ever commit by
/// reference.
fn pending_leaf_keys_from_detached(
    provider: &impl CipherSuiteProvider,
    detached: &[mls_rs::group::SwiftExportDetachedPending],
) -> Result<Vec<SessionMigrationPendingLeafKey>> {
    let mut seen = std::collections::HashSet::new();
    detached
        .iter()
        .filter_map(|entry| {
            let signer = entry.signer.as_ref()?;
            let identity = entry.signing_identity.as_ref()?;
            let secret_bytes = signer.as_bytes();
            let dedupe_key = bare_ed25519(secret_bytes).unwrap_or_else(|_| secret_bytes.to_vec());
            if !seen.insert(dedupe_key) {
                return None;
            }
            Some((|| {
                let target = signing_identity_client_id(identity)?;
                let (signing_key, signature_key) = candidate_public_key(provider, secret_bytes)
                    .ok_or(TwoMlsPqError::ArchiveInvalid)?;
                Ok(SessionMigrationPendingLeafKey {
                    target,
                    key: SessionMigrationKeyPair {
                        signing_key,
                        signature_key,
                    },
                })
            })())
        })
        .collect()
}

/// The leaf HPKE public key an MLS Update proposal names — the join key between an
/// `own_offer_window` entry's bare-encoded `proposal` and the `leaf_public_key`
/// `export_for_swift_placing_pending`'s `place` callback and `Detached` entries use.
pub(super) fn update_leaf_public_key(proposal_bytes: &[u8]) -> Option<Vec<u8>> {
    let proposal = mls_rs::group::proposal::Proposal::mls_decode(&mut &proposal_bytes[..]).ok()?;
    let mls_rs::group::proposal::Proposal::Update(update) = proposal else {
        return None;
    };
    Some(update.hpke_public_key().as_ref().to_vec())
}

/// The (credential id, signature key) an MLS Update proposal names — what `own_offer_
/// window`'s same-id filter and `recv_classical_pending`'s resolution both key their
/// per-target grouping on, and what native's own check 6 compares a window offer
/// against. `None` if the bytes don't decode as an Update, or the credential isn't
/// Basic (this crate never proposes anything else).
pub(super) fn decoded_update_target(proposal_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let proposal = mls_rs::group::proposal::Proposal::mls_decode(&mut &proposal_bytes[..]).ok()?;
    let mls_rs::group::proposal::Proposal::Update(update) = proposal else {
        return None;
    };
    let identity = update.signing_identity();
    let client_id = identity.credential.as_basic()?.identifier.clone();
    Some((client_id, identity.signature_key.as_bytes().to_vec()))
}

/// The leaf HPKE public key of the session's single staged Update
/// (`staged_updates`), if still present in recv-classical's own-proposal
/// cache. Test-only: an independent cross-check for `own_offer_window`'s
/// `framed_leaf_key`. Gated on `cryptokit`, not just `#[cfg(test)]`, since
/// every call site is a migration test requiring the CryptoKit
/// representation.
#[cfg(all(test, feature = "cryptokit"))]
pub(super) fn staged_update_leaf_key<Cfg: mls_rs::client_builder::MlsConfig>(
    recv_classical: &mls_rs::Group<Cfg>,
    latest_own_offer: Option<&[u8]>,
    provider: &impl CipherSuiteProvider,
) -> Result<Option<Vec<u8>>> {
    let Some(latest) = latest_own_offer else {
        return Ok(None);
    };
    let Ok(latest_hash) = provider.hash(latest) else {
        return Ok(None);
    };
    for entry in recv_classical
        .own_proposals_for_swift_export()
        .map_err(map_swift_export_err)?
    {
        if entry.message_hash == latest_hash {
            return Ok(update_leaf_public_key(&entry.proposal));
        }
    }
    Ok(None)
}

/// Dedupe `pending` entries by `key.signing_key`: a leaf re-proposing the
/// same target every frame collapses to one entry, including a real mls-rs
/// signer entry against a generalized catch-up entry for the same target
/// when the two carry the identical key. Stable — first occurrence wins.
/// Does not resolve the same-id-candidate case, where two different keys
/// compete for the same target — see `recv_classical_pending`.
fn dedupe_pending(pending: &mut Vec<SessionMigrationPendingLeafKey>) {
    let mut seen = std::collections::HashSet::new();
    pending.retain(|entry| seen.insert(entry.key.signing_key.clone()));
}

/// Dedupe a custody candidate pool by normalized secret bytes, before any
/// search: `find_custody` derives every pool entry through each half's
/// provider in turn, so an undeduped pool with ~10^5 copies of one secret
/// would run that many redundant (ML-DSA, for PQ) derives instead of one.
fn dedupe_secret_bytes(pool: &mut Vec<Vec<u8>>) {
    let mut seen = std::collections::HashSet::new();
    pool.retain(|candidate| {
        let key = bare_ed25519(candidate).unwrap_or_else(|_| candidate.clone());
        seen.insert(key)
    });
}

/// One own leaf's full custody resolution: the presented key searched
/// against `pool` through `provider`, plus this half's own pending signers.
/// Staged-candidate entries are appended by the caller, since those are
/// session-global state this function can't see.
fn resolve_leaf_key<Cfg: mls_rs::client_builder::MlsConfig>(
    group: &mls_rs::Group<Cfg>,
    provider: &impl CipherSuiteProvider,
    pool: &[Vec<u8>],
    pending_signers: &[mls_rs::group::SwiftExportPendingSigner],
) -> Result<(SessionMigrationGroupKeys, bool)> {
    let presented = own_signature_key(group)?;
    let current =
        find_custody(provider, &presented, pool).map(|signing_key| SessionMigrationKeyPair {
            signing_key,
            signature_key: presented,
        });
    let no_custody = current.is_none();
    let mut pending = pending_leaf_keys(provider, pending_signers)?;
    dedupe_pending(&mut pending);
    Ok((SessionMigrationGroupKeys { current, pending }, no_custody))
}

/// A group that doesn't exist yet holds a reservation key in `current` (the
/// key it will present once created or joined), with `pending` empty.
/// `current: None` is the reservation's own no-custody case, since native's
/// `validateLeafKeys` requires `current` to be `nil` exactly when the group's
/// role is in `noCustody`.
fn reservation(current: Option<SessionMigrationKeyPair>) -> (SessionMigrationGroupKeys, bool) {
    let no_custody = current.is_none();
    (
        SessionMigrationGroupKeys {
            current,
            pending: Vec::new(),
        },
        no_custody,
    )
}

/// The generalized catch-up: `Some(pending[mine_current] = identity_pair)`
/// when `group`'s presented credential (not raw key) is behind
/// `mine_current`. `None` when the leaf already presents it.
fn catch_up_pending_entry<Cfg: mls_rs::client_builder::MlsConfig>(
    group: &mls_rs::Group<Cfg>,
    mine_current: &[u8],
    identity_pair: &SessionMigrationKeyPair,
) -> Result<Option<SessionMigrationPendingLeafKey>> {
    let own_credential = apq::sender_client_id(group, group.current_member_index())
        .map_err(|_| TwoMlsPqError::Mls)?;
    if own_credential == mine_current {
        return Ok(None);
    }
    Ok(Some(SessionMigrationPendingLeafKey {
        target: mine_current.to_vec(),
        key: identity_pair.clone(),
    }))
}

/// Folds a generalized catch-up entry into a half's real pending — PQ
/// halves only (recv-classical uses `recv_classical_pending`, which resolves
/// the same-id ambiguity this simpler fold cannot). A real entry already targeting the catch-up's
/// target is superseded by it.
fn fold_in_catch_up(
    mut real_pending: Vec<SessionMigrationPendingLeafKey>,
    catch_up: Option<SessionMigrationPendingLeafKey>,
) -> Vec<SessionMigrationPendingLeafKey> {
    if let Some(catch_up) = catch_up {
        real_pending.retain(|p| p.target != catch_up.target);
        real_pending.push(catch_up);
    }
    dedupe_pending(&mut real_pending);
    real_pending
}

/// `recv_classical`'s `pending`, grouped by target from `framed` (see the
/// module doc), `real_pending` (this group's own outstanding offers), and
/// each staged candidate's synthesized entry. Every target other than
/// `mine_current` is unambiguous.
///
/// `mine_current` can have two real, differently-keyed offers at once — the
/// identity's self-catch-up and a same-id candidate's re-proposal — and only
/// one key can ever occupy `pending[mine_current]`. See the module doc for
/// the priority order, which `own_offer_window` mirrors so the two never
/// disagree. `same_id_candidate_key` is pinned to the staged candidate's own
/// derived key rather than scanned off `real_pending`/`candidates`, since
/// their iteration order is unspecified and not guaranteed stable across the
/// two functions.
#[allow(clippy::too_many_arguments)]
fn recv_classical_pending(
    real_pending: Vec<SessionMigrationPendingLeafKey>,
    framed: Option<&SessionMigrationPendingLeafKey>,
    candidates: &[Arc<TwoMlsPqPrincipal>],
    classical_provider: &impl CipherSuiteProvider,
    mine_current: &[u8],
    identity_pair: &SessionMigrationKeyPair,
    same_id_candidate_key: Option<&SessionMigrationKeyPair>,
    catch_up: Option<SessionMigrationPendingLeafKey>,
) -> Result<Vec<SessionMigrationPendingLeafKey>> {
    let mut by_target: std::collections::HashMap<Vec<u8>, SessionMigrationKeyPair> =
        std::collections::HashMap::new();
    let mut framed_mine_current: Option<SessionMigrationKeyPair> = None;
    if let Some(entry) = framed {
        if entry.target == mine_current {
            framed_mine_current = Some(entry.key.clone());
        } else {
            by_target
                .entry(entry.target.clone())
                .or_insert_with(|| entry.key.clone());
        }
    }
    let mut mine_current_identity = false;
    let mut mine_current_candidate = false;
    for entry in real_pending {
        if entry.target == mine_current {
            if entry.key.signing_key == identity_pair.signing_key {
                mine_current_identity = true;
            } else {
                mine_current_candidate = true;
            }
        } else {
            by_target.entry(entry.target).or_insert(entry.key);
        }
    }
    for candidate in candidates {
        let target = candidate.client_id().bytes;
        let (signing_key, signature_key) = candidate_public_key(
            classical_provider,
            candidate.combiner().classical_signing_key(),
        )
        .ok_or(TwoMlsPqError::ArchiveInvalid)?;
        let key = SessionMigrationKeyPair {
            signing_key,
            signature_key,
        };
        if target == mine_current {
            if key.signing_key == identity_pair.signing_key {
                mine_current_identity = true;
            } else {
                mine_current_candidate = true;
            }
        } else {
            by_target.entry(target).or_insert(key);
        }
    }
    let mine_current_key = framed_mine_current
        .or_else(|| mine_current_identity.then(|| identity_pair.clone()))
        .or_else(|| {
            mine_current_candidate
                .then_some(same_id_candidate_key.cloned())
                .flatten()
        })
        .or_else(|| catch_up.map(|c| c.key));
    if let Some(key) = mine_current_key {
        by_target.insert(mine_current.to_vec(), key);
    }
    let mut pending: Vec<SessionMigrationPendingLeafKey> = by_target
        .into_iter()
        .map(|(target, key)| SessionMigrationPendingLeafKey { target, key })
        .collect();
    pending.sort_by(|a, b| a.target.cmp(&b.target));
    Ok(pending)
}

/// KP′'s presented PQ signature key, decoded WITHOUT the credential-id check
/// `decode_checked_kp` applies: a card initiator that rotated while stalled at A.3 still
/// has KP′ present the OLD (pre-rotation) identity, so it need not bind the CURRENT
/// identity's client id.
fn kp_signature_key(kp_bytes: &[u8]) -> Result<Vec<u8>> {
    let kp = mls_rs::KeyPackage::mls_decode(&mut &kp_bytes[..])
        .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    Ok(kp.signing_identity().signature_key.as_bytes().to_vec())
}

/// Maps one swift_export failure. `SwiftExportPendingCommitUnsupported` is
/// unreachable for this crate — every Rust commit is built and applied in
/// one call — but stays `Mls` (retryable) in case it ever occurs. Every
/// other failure is corrupt/impossible data — `ArchiveInvalid`.
fn map_swift_export_err(err: mls_rs::client::MlsError) -> TwoMlsPqError {
    match err {
        mls_rs::client::MlsError::SwiftExportPendingCommitUnsupported => TwoMlsPqError::Mls,
        _ => TwoMlsPqError::ArchiveInvalid,
    }
}

/// One `Group::export_for_swift_with_pending_signers()` call, flushed to
/// storage first so the export sees what a persistence push would write.
/// Inherits the pending-commit refusal, surfaced as `Mls` — see
/// `map_swift_export_err`.
fn export_mls_half<Cfg: mls_rs::client_builder::MlsConfig>(
    group: &mut mls_rs::Group<Cfg>,
) -> Result<(Vec<u8>, Vec<mls_rs::group::SwiftExportPendingSigner>)> {
    group.write_to_storage().map_err(|_| TwoMlsPqError::Mls)?;
    group
        .export_for_swift_with_pending_signers()
        .map_err(map_swift_export_err)
}

/// The own-offer window's cap: a fixed bound on carried state, not a
/// measurement of real depth. Trades session stability (a peer folding an
/// offer this window dropped permanently wedges that session) for app
/// stability (bounded export size). One carried offer is on the order of a
/// few hundred bytes (see `test_own_offer_window_entry_size_estimate`), so
/// the cap's worst case (band 2 full) is on the order of tens of MB.
pub(super) const OWN_OFFER_WINDOW: usize = 102_400;

/// Recv-classical's own-offer window: Update proposals from the own-proposal
/// cache, excluding the entry `staged_updates`/`pending_proposal` frame while
/// a `prepare_to_encrypt` is outstanding (its HPKE pair already rides the
/// snapshot, so a second copy here would duplicate it). At rest, nothing is
/// excluded this way. What remains is capped at `cap`, in two bands: band 2
/// (presentation-changing — proposed identity differs from what the leaf
/// currently presents) first, then band 3 (same-identity refreshes), each in
/// deterministic `proposal_ref` order. Only band 3 truncates in practice,
/// since a peer can only ever fold a band-2 offer — but band 2 alone can
/// exceed `cap` (e.g. a born-dedicated acceptor left unfolded, re-proposing
/// catch-up ~10^5 times); that is an accepted residual risk (a peer folding
/// an offer this window already dropped permanently wedges that one
/// session), not a hazard this ordering introduces.
///
/// `cap` is a parameter so tests can exercise banding/truncation against a
/// small window; production always passes `OWN_OFFER_WINDOW`.
///
/// The framed entry is identified by re-hashing `latest_own_offer` (the
/// session's `pending_proposal_message`) the same way the proposal cache's
/// own key is computed — `own_proposals_for_swift_export` has no other
/// ordering or sequence signal to find it by. At rest `latest_own_offer` is
/// `None`, so nothing is excluded on that basis.
///
/// `mine_current`/`identity_key`/`same_id_candidate_key` resolve the one
/// target that can have two real, differently-keyed offers outstanding at
/// once — a same-id staged candidate alongside the identity's own
/// self-catch-up (see `recv_classical_pending`'s doc for the priority order,
/// which this mirrors so the window and `pending[mine_current]` never
/// disagree). Only a presentation-changing (band 2) entry, never a same-key
/// refresh, may set the identity- or candidate-offer flags — conflating the
/// two is exactly how the window and `pending[mine_current]` could disagree,
/// since `recv_classical_pending` only ever counts a signer-carrying entry
/// toward its own resolution. A same-key refresh always survives regardless
/// of that resolution (native check 6): its key always matches what the leaf
/// presents.
///
/// Returns the window offers and, piggybacked on the same scan, the framed
/// entry's own leaf key — `migration_export` uses this to avoid a second
/// pass over the same (potentially ~10^5-entry) cache.
pub(super) fn own_offer_window<Cfg: mls_rs::client_builder::MlsConfig>(
    recv_classical: &mls_rs::Group<Cfg>,
    latest_own_offer: Option<&[u8]>,
    provider: &impl CipherSuiteProvider,
    cap: usize,
    mine_current: &[u8],
    identity_key: &[u8],
    same_id_candidate_key: Option<&SessionMigrationKeyPair>,
) -> Result<(Vec<SessionMigrationOwnOffer>, Option<Vec<u8>>)> {
    let presented_key = own_signature_key(recv_classical)?;
    let presented_client_id =
        apq::sender_client_id(recv_classical, recv_classical.current_member_index())
            .map_err(|_| TwoMlsPqError::Mls)?;
    let latest_hash: Option<Vec<u8>> = latest_own_offer.and_then(|bytes| provider.hash(bytes).ok());

    let mut band2 = Vec::new();
    let mut band3 = Vec::new();
    let mut mine_current_identity_offer = false;
    let mut mine_current_candidate_offer = false;
    let mut framed_leaf_key = None;
    let mut framed_mine_current_key: Option<Vec<u8>> = None;

    for entry in recv_classical
        .own_proposals_for_swift_export()
        .map_err(map_swift_export_err)?
    {
        let Some((proposed_client_id, proposed_key)) = decoded_update_target(&entry.proposal)
        else {
            continue;
        };
        // A same-key, same-id entry is a plain refresh (`propose_update` with
        // no signer, changing nothing the leaf presents). `recv_classical_pending`
        // only counts a signer-carrying entry toward its own identity/candidate
        // resolution, so a refresh must never set these flags either —
        // otherwise the window and `pending[mine_current]` can disagree.
        let presentation_changes =
            proposed_key != presented_key || proposed_client_id != presented_client_id;
        if latest_hash.as_deref() == Some(entry.message_hash.as_slice()) {
            // The framed entry never joins the window, but if it presentation-
            // changes and targets `mine_current`, its key still decides
            // `pending[mine_current]` below — it can never be dropped.
            framed_leaf_key = update_leaf_public_key(&entry.proposal);
            if presentation_changes && proposed_client_id == mine_current {
                framed_mine_current_key = Some(proposed_key);
            }
            continue;
        }
        if presentation_changes && proposed_client_id == mine_current {
            if proposed_key == identity_key {
                mine_current_identity_offer = true;
            } else {
                mine_current_candidate_offer = true;
            }
        }
        let mapped = SessionMigrationOwnOffer {
            proposal_ref: entry.proposal_ref,
            proposal: entry.proposal,
            // Filled in by the caller from the placement export's `Detached`
            // list; empty here is a safe "not yet filled" sentinel, since a
            // real HPKE secret is never actually empty.
            leaf_secret: Vec::new(),
        };
        let entry = (Some(proposed_client_id), proposed_key, mapped);
        if presentation_changes {
            band2.push(entry);
        } else {
            band3.push(entry);
        }
    }

    // Mirrors `recv_classical_pending`'s priority: the framed entry wins if
    // it targets `mine_current`; else the identity, if outstanding; else the
    // same-id candidate's pinned key; else `None`.
    let mine_current_pending_key: Option<Vec<u8>> = framed_mine_current_key.or_else(|| {
        if mine_current_identity_offer {
            Some(identity_key.to_vec())
        } else if mine_current_candidate_offer {
            same_id_candidate_key.map(|k| k.signature_key.clone())
        } else {
            None
        }
    });
    // Native check 6: an offer survives if its key matches what the leaf
    // currently presents (a refresh, regardless of `mine_current_pending_key`),
    // or matches `pending[id]` for whatever id it targets.
    let keep = |client_id: &Option<Vec<u8>>, key: &[u8]| {
        if key == presented_key.as_slice() {
            return true;
        }
        match client_id {
            Some(id) if id.as_slice() == mine_current => {
                mine_current_pending_key.as_deref() == Some(key)
            }
            _ => true,
        }
    };
    let mut band2: Vec<SessionMigrationOwnOffer> = band2
        .into_iter()
        .filter(|(id, key, _)| keep(id, key))
        .map(|(_, _, offer)| offer)
        .collect();
    let mut band3: Vec<SessionMigrationOwnOffer> = band3
        .into_iter()
        .filter(|(id, key, _)| keep(id, key))
        .map(|(_, _, offer)| offer)
        .collect();
    band2.sort_by(|a, b| a.proposal_ref.cmp(&b.proposal_ref));
    band3.sort_by(|a, b| a.proposal_ref.cmp(&b.proposal_ref));

    let mut out = band2;
    out.extend(band3);
    let mut seen = std::collections::HashSet::new();
    out.retain(|e| seen.insert(e.proposal_ref.clone()));
    out.truncate(cap);
    Ok((out, framed_leaf_key))
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Export this session as the migration payload for the twomlspq-swift
    /// session mint: every group half as a format-2 snapshot plus session
    /// metadata `SessionMigration.mintArchive` mints a native
    /// `SessionArchive` from. See the module note for the totality rule and
    /// what still refuses.
    ///
    /// Emits plaintext secret material — the caller seals (the
    /// `ArchiveSink` contract). PQ secrets use the CryptoKit 96-byte
    /// representation; under `awslc` the length guards fail as
    /// `ArchiveInvalid`.
    pub fn migration_export(&self) -> Result<SessionMigrationExport> {
        let mut inner = self.lock();
        let initiated = inner.expected_bootstrap_kp_commitment.is_none();

        // `bind_apply_broken` is in-memory only: a restored session's
        // converter never sets it from persisted rows, so it can only be
        // live on the current process. Not corrupt — reload and export that
        // row instead, so `Mls` (retryable), not `ArchiveInvalid`.
        if inner.bind_apply_broken {
            return Err(TwoMlsPqError::Mls);
        }
        // `initial_return_kp` is never set by this product's own wrapper
        // (only `setInitialAppPayload` is ever called) — impossible, not
        // merely unreached, so a live value here is corrupt.
        if inner.recv_group.is_none() && inner.initial_return_kp.is_some() {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }
        // `initial_app_payload` is exported only for a pre-join initiator,
        // and must be non-empty there (native's mint enforces the same
        // rule) — the wrapper always attaches a real payload before
        // establishment and clears it at the cutover, so either violation
        // is corruption, caught here rather than at the mint.
        match (
            inner.recv_group.is_none(),
            inner.initial_app_payload.as_ref(),
        ) {
            (true, Some(payload)) if payload.is_empty() => {
                return Err(TwoMlsPqError::ArchiveInvalid)
            }
            (false, Some(_)) => return Err(TwoMlsPqError::ArchiveInvalid),
            _ => {}
        }

        // Suite check first, before any crypto: a stored group half whose
        // cipher suite disagrees with the session's declared suite must
        // never reach a provider it doesn't belong to. `recv_group` missing
        // is the legitimate pre-establishment case, simply skipped.
        let expected_suite = inner.client.combiner().cipher_suite();
        let send_ref = inner
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::ArchiveInvalid)?;
        for half in std::iter::once(send_ref).chain(inner.recv_group.as_ref()) {
            let pq_ok = half
                .pq
                .as_ref()
                .is_none_or(|pq| pq.cipher_suite() == expected_suite.pq);
            if half.classical.cipher_suite() != expected_suite.classical || !pq_ok {
                return Err(TwoMlsPqError::ArchiveInvalid);
            }
        }

        // The identity: signing keys from the session client, key packages
        // picked (or minted) per half — see `identity_kp`. An owned `Arc`
        // clone so `client` outlives the later mutable passes below.
        let client_principal = std::sync::Arc::clone(&inner.client);
        let client = client_principal.combiner();
        let client_id = client.client_id().to_vec();
        let (_, classical_kpd) = identity_kp(
            client.classical_kp_store(),
            &client_id,
            inner.initial_app_payload.as_deref(),
            || {
                client
                    .generate_classical_key_package()
                    .map_err(|_| TwoMlsPqError::Mls)
            },
        )?;
        let (_, pq_kpd) = identity_kp(client.pq_kp_store(), &client_id, None, || {
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
        // A pre-establishment initiator's `identity_kp` picks the retained
        // return key package, never a freshly minted one, so its init
        // secret is real and joinable — supply it. `None`
        // post-establishment: an established session's KP mints fresh, with
        // no return-channel meaning.
        let classical_init_secret_key = if inner.recv_group.is_none() {
            if classical_kpd.init_key.len() != 32 {
                return Err(TwoMlsPqError::ArchiveInvalid);
            }
            Some(classical_kpd.init_key.to_vec())
        } else {
            None
        };
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
            classical_init_secret_key,
            pq_leaf_secret_key: pq_kpd.leaf_node_key.to_vec(),
            classical_key_package: classical_kpd.key_package_bytes.clone(),
            pq_key_package: pq_kpd.key_package_bytes.clone(),
        };

        // `auth.mine`'s canonical current identity — the target of the generalized
        // catch-up and the same-id candidate resolution below. Every session is seeded
        // with an id at construction, so an empty `mine` here is corrupt, not merely
        // unusual. Computed early (immutable `with_auth` read) because the own-offer
        // window's same-id filter needs it before the mutable export pass.
        let mine_current = inner
            .with_auth(|core| core.mine.current().map(<[u8]>::to_vec))
            .ok_or(TwoMlsPqError::ArchiveInvalid)?;
        let identity_classical_pair = SessionMigrationKeyPair {
            signing_key: identity.signing_key.clone(),
            signature_key: identity.signature_key.clone(),
        };
        let identity_pq_pair = SessionMigrationKeyPair {
            signing_key: identity.pq_signing_key.clone(),
            signature_key: identity.pq_signature_key.clone(),
        };

        // The own-offer window and its leaf-key sets are computed first, from
        // immutable reads, before any mutable export pass: `place` (below)
        // needs both already built.
        let classical_provider = crate::providers::classical_envelope_suite()?;
        let pq_provider = crate::providers::pq_envelope_suite()?;
        // The staged same-id candidate's own public key, if any — pinned here
        // once rather than left for `own_offer_window` and
        // `recv_classical_pending` to each scan for it independently, so the
        // two can never disagree.
        let same_id_candidate_key = inner
            .staged_candidates
            .iter()
            .find(|c| c.client_id().bytes == mine_current)
            .map(|c| {
                let (signing_key, signature_key) =
                    candidate_public_key(&classical_provider, c.combiner().classical_signing_key())
                        .ok_or(TwoMlsPqError::ArchiveInvalid)?;
                Ok::<_, TwoMlsPqError>(SessionMigrationKeyPair {
                    signing_key,
                    signature_key,
                })
            })
            .transpose()?;
        let latest_own_offer = inner
            .pending_proposal_message
            .as_ref()
            .map(|(_, m)| m.as_slice());
        // `own_offer_window` returns the framed entry's leaf key alongside the
        // window in one pass, avoiding a second scan; `staged_update_leaf_key`
        // stays for tests to cross-check independently.
        let (mut own_offer_window_entries, framed_leaf_key) = match inner.recv_group.as_ref() {
            Some(recv) => own_offer_window(
                &recv.classical,
                latest_own_offer,
                &classical_provider,
                OWN_OFFER_WINDOW,
                &mine_current,
                &identity_classical_pair.signature_key,
                same_id_candidate_key.as_ref(),
            )?,
            None => (Vec::new(), None),
        };
        let entry_leaf_keys: Vec<Option<Vec<u8>>> = own_offer_window_entries
            .iter()
            .map(|o| update_leaf_public_key(&o.proposal))
            .collect();
        let window_leaf_key_set: std::collections::HashSet<Vec<u8>> =
            entry_leaf_keys.iter().flatten().cloned().collect();

        // Flush + export every existing group half — mutable pass first, so
        // every later step works from owned bytes and a settled borrow of
        // `inner`.
        let send_classical = {
            let g = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::ArchiveInvalid)?;
            export_mls_half(&mut g.classical)?
        };
        let send_pq = {
            let g = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::ArchiveInvalid)?;
            g.pq.as_mut().map(export_mls_half).transpose()?
        };
        // recv-classical only: `export_for_swift_placing_pending` instead of
        // `export_for_swift_with_pending_signers`. `place` sorts each entry by
        // leaf HPKE key: the framed entry stays in the snapshot (`Snapshot`),
        // every other window-carried entry is pulled out (`Detached`),
        // everything else is dropped (`Omit`).
        let recv_classical = match inner.recv_group.as_mut() {
            Some(g) => {
                g.classical
                    .write_to_storage()
                    .map_err(|_| TwoMlsPqError::Mls)?;
                let place = |pk: &[u8]| -> mls_rs::group::SwiftExportPendingPlacement {
                    use mls_rs::group::SwiftExportPendingPlacement as Placement;
                    if framed_leaf_key.as_deref() == Some(pk) {
                        Placement::Snapshot
                    } else if window_leaf_key_set.contains(pk) {
                        Placement::Detached
                    } else {
                        Placement::Omit
                    }
                };
                let (bytes, signers, detached) = g
                    .classical
                    .export_for_swift_placing_pending(place)
                    .map_err(map_swift_export_err)?;
                Some((bytes, signers, detached))
            }
            None => None,
        };
        // Fill in each carried window offer's leaf secret from the matching
        // `Detached` entry. Every remaining entry is `Detached`-placed by
        // construction, so a miss here means either an undecodable proposal
        // (impossible) or the placement export's own list disagreeing with
        // what it was asked to detach — corrupt either way.
        if let Some((_, _, detached)) = recv_classical.as_ref() {
            let secret_by_leaf: std::collections::HashMap<&[u8], &[u8]> = detached
                .iter()
                .map(|d| (d.leaf_public_key.as_slice(), d.secret.as_slice()))
                .collect();
            for (entry, leaf_key) in own_offer_window_entries
                .iter_mut()
                .zip(entry_leaf_keys.iter())
            {
                entry.leaf_secret = leaf_key
                    .as_deref()
                    .and_then(|k| secret_by_leaf.get(k))
                    .map(|s| s.to_vec())
                    .ok_or(TwoMlsPqError::ArchiveInvalid)?;
            }
        }
        let recv_pq = inner
            .recv_group
            .as_mut()
            .and_then(|g| g.pq.as_mut())
            .map(export_mls_half)
            .transpose()?;

        // The custody search: per-half key custody by presented key.
        // `send_ref`/`recv_ref` are a fresh immutable borrow — the mutable
        // pass above has already ended.
        let send_ref = inner
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::ArchiveInvalid)?;
        let recv_ref = inner.recv_group.as_ref();

        // The candidate pool: the identity's own keys, every half's current
        // signer, every staged candidate's keys, and every pending-update
        // signer — searched per half through that half's expected provider,
        // never the group's own stored suite.
        let mut pool: Vec<Vec<u8>> = vec![
            client.classical_signing_key().to_vec(),
            client.pq_signing_key().to_vec(),
            send_ref
                .classical
                .signer_for_swift_export()
                .as_bytes()
                .to_vec(),
        ];
        if let Some(pq) = send_ref.pq.as_ref() {
            pool.push(pq.signer_for_swift_export().as_bytes().to_vec());
        }
        if let Some(recv) = recv_ref {
            pool.push(recv.classical.signer_for_swift_export().as_bytes().to_vec());
            if let Some(pq) = recv.pq.as_ref() {
                pool.push(pq.signer_for_swift_export().as_bytes().to_vec());
            }
        }
        for candidate in inner.staged_candidates.iter() {
            pool.push(candidate.combiner().classical_signing_key().to_vec());
            pool.push(candidate.combiner().pq_signing_key().to_vec());
        }
        for pending in [
            Some(&send_classical.1),
            send_pq.as_ref().map(|(_, p)| p),
            recv_classical.as_ref().map(|(_, p, _)| p),
            recv_pq.as_ref().map(|(_, p)| p),
        ]
        .into_iter()
        .flatten()
        {
            for signer in pending {
                pool.push(signer.signer.as_bytes().to_vec());
            }
        }
        // A born-dedicated acceptor left unfolded can push ~10^5 pending
        // signers, virtually all one key. Dedupe by normalized secret before
        // any search, so this doesn't turn into O(N) expensive (ML-DSA)
        // derives instead of O(1).
        dedupe_secret_bytes(&mut pool);

        let recv_classical_catch_up = match recv_ref {
            Some(recv) => {
                catch_up_pending_entry(&recv.classical, &mine_current, &identity_classical_pair)?
            }
            None => None,
        };

        // send_classical always exists, and carries `current` only: its own next
        // commit mints a fresh key for whatever id it then presents, so native
        // needs no pending key in advance (and restore rejects one).
        let (send_classical_leaf, send_classical_no_custody) = {
            let (leaf, no_custody) = resolve_leaf_key(
                &send_ref.classical,
                &classical_provider,
                &pool,
                &send_classical.1,
            )?;
            (
                SessionMigrationGroupKeys {
                    current: leaf.current,
                    pending: Vec::new(),
                },
                no_custody,
            )
        };

        // send_pq: empty for a pre-A.3 acceptor (the group isn't founded yet, and
        // A.3 founding mints its own key), otherwise resolved plus the generalized
        // catch-up (no candidates: rotation is classical-only).
        let (send_pq_leaf, send_pq_no_custody) = match send_ref.pq.as_ref().zip(send_pq.as_ref()) {
            Some((group, (_, pending))) => {
                let (leaf, no_custody) = resolve_leaf_key(group, &pq_provider, &pool, pending)?;
                let catch_up = catch_up_pending_entry(group, &mine_current, &identity_pq_pair)?;
                let pending = fold_in_catch_up(leaf.pending, catch_up);
                (
                    SessionMigrationGroupKeys {
                        current: leaf.current,
                        pending,
                    },
                    no_custody,
                )
            }
            None => (
                SessionMigrationGroupKeys {
                    current: None,
                    pending: Vec::new(),
                },
                false,
            ),
        };

        // recv_classical: the reservation for a pre-join initiator (the
        // retained return KeyPackage's key — the same key `identity_kp`
        // already picked), otherwise resolved plus Detached signers folded
        // by `recv_classical_pending`.
        let (recv_classical_leaf, recv_classical_no_custody) = match recv_ref
            .map(|recv| &recv.classical)
            .zip(recv_classical.as_ref())
        {
            Some((group, (_, snapshot_signers, detached))) => {
                let (leaf, no_custody) =
                    resolve_leaf_key(group, &classical_provider, &pool, snapshot_signers)?;
                // `leaf.pending` is the one `Snapshot`-placed (framed) entry,
                // if any. Kept separate from the `Detached` (window-surviving)
                // entries so `recv_classical_pending` can apply its
                // framed-wins priority explicitly.
                let framed = leaf.pending.first().cloned();
                let mut real_pending =
                    pending_leaf_keys_from_detached(&classical_provider, detached)?;
                dedupe_pending(&mut real_pending);
                let pending = recv_classical_pending(
                    real_pending,
                    framed.as_ref(),
                    &inner.staged_candidates,
                    &classical_provider,
                    &mine_current,
                    &identity_classical_pair,
                    same_id_candidate_key.as_ref(),
                    recv_classical_catch_up.clone(),
                )?;
                (
                    SessionMigrationGroupKeys {
                        current: leaf.current,
                        pending,
                    },
                    no_custody,
                )
            }
            None => reservation(Some(identity_classical_pair.clone())),
        };

        // recv_pq: the reservation for a pre-A.3 initiator — KP′'s presented
        // key, resolved by the same custody search as every other half (it
        // may still name a pre-rotation identity, see the module doc).
        // Otherwise resolved plus the generalized catch-up.
        let (recv_pq_leaf, recv_pq_no_custody) = match recv_ref
            .and_then(|recv| recv.pq.as_ref())
            .zip(recv_pq.as_ref())
        {
            Some((group, (_, pending))) => {
                let (leaf, no_custody) = resolve_leaf_key(group, &pq_provider, &pool, pending)?;
                let catch_up = catch_up_pending_entry(group, &mine_current, &identity_pq_pair)?;
                let pending = fold_in_catch_up(leaf.pending, catch_up);
                (
                    SessionMigrationGroupKeys {
                        current: leaf.current,
                        pending,
                    },
                    no_custody,
                )
            }
            None => {
                // Every reachable pre-A.3-initiator state has
                // `bootstrap_kp_secret` (the twin-field invariant on
                // `SessionInner`).
                let secret = inner
                    .bootstrap_kp_secret
                    .as_ref()
                    .ok_or(TwoMlsPqError::ArchiveInvalid)?;
                let presented = kp_signature_key(&secret.1.key_package_bytes)?;
                // A reservation's `current` must never be the no-custody case:
                // native's check 3 requires `no_custody` to name only existing
                // groups. This lookup should always resolve (KP′'s key is
                // minted from the same identity pair this pool carries), but
                // fails loudly rather than silently mis-deriving
                // `no_custody.recv_pq` should that invariant ever break.
                let signing_key = find_custody(&pq_provider, &presented, &pool)
                    .ok_or(TwoMlsPqError::ArchiveInvalid)?;
                reservation(Some(SessionMigrationKeyPair {
                    signing_key,
                    signature_key: presented,
                }))
            }
        };

        let leaf_keys = SessionMigrationLeafKeys {
            send_classical: send_classical_leaf,
            recv_classical: recv_classical_leaf,
            send_pq: send_pq_leaf,
            recv_pq: recv_pq_leaf,
        };

        // The rotation candidate: the newest staged candidate — `None` when
        // its id equals `mine_current` (a self-catch-up mechanism, not a
        // rotation target to report; its key still rides `pending`
        // regardless). `staged_candidates` non-empty implies `recv_group`
        // exists, so the current epoch is always available here.
        let rotation_candidate = match inner.staged_candidates.last() {
            Some(candidate) if candidate.client_id().bytes != mine_current => {
                let (signing_key, signature_key) = candidate_public_key(
                    &classical_provider,
                    candidate.combiner().classical_signing_key(),
                )
                .ok_or(TwoMlsPqError::ArchiveInvalid)?;
                Some(SessionMigrationRotationCandidate {
                    target_client_id: candidate.client_id().bytes,
                    signing_key,
                    signature_key,
                    proposed_at_recv_epoch: recv_ref
                        .map(|recv| recv.classical.current_epoch())
                        .ok_or(TwoMlsPqError::ArchiveInvalid)?,
                })
            }
            _ => None,
        };

        // `pq_leaf_custody` (back-compat): narrow, history-window-checked
        // gating, best-effort — swallowed to `None` rather than propagated,
        // since `leaf_keys` is authoritative and must never be blocked by
        // this field's stricter rules.
        let pq_leaf_custody = match recv_ref.and_then(|recv| recv.pq.as_ref()) {
            None => None,
            Some(pq) => {
                let presented = own_signature_key(pq)?;
                if presented == identity.pq_signature_key {
                    None
                } else if inner.requires_establishment_envelope {
                    let auth_mine_history = inner.with_auth(|core| core.mine.to_parts().0);
                    leaf_pq_custody(pq, &presented, &identity.client_id, &auth_mine_history).ok()
                } else {
                    None
                }
            }
        };

        // The deployed-only carry: `Some` whenever any part of it is
        // non-empty or true. `own_offer_window_entries` was computed early
        // and had its `leaf_secret`s filled in already — not recomputed here.
        let pq_wedged = inner.pq_wedged.map(|w| match w {
            PqWedge::Bootstrap => SessionMigrationPqWedgeKind::Bootstrap,
            PqWedge::Ratchet => SessionMigrationPqWedgeKind::Ratchet,
            PqWedge::Rekey => SessionMigrationPqWedgeKind::Rekey,
        });
        let own_offers = recv_ref
            .filter(|_| !own_offer_window_entries.is_empty())
            .map(|recv| SessionMigrationOwnOfferWindow {
                epoch: recv.classical.current_epoch(),
                group_id: recv.classical.group_id().to_vec(),
                sender_leaf_index: recv.classical.current_member_index(),
                offers: own_offer_window_entries,
            });
        let deployed_state = if pq_wedged.is_some()
            || send_classical_no_custody
            || send_pq_no_custody
            || recv_classical_no_custody
            || recv_pq_no_custody
            || own_offers.is_some()
        {
            Some(SessionMigrationDeployedState {
                own_offers,
                pq_wedged,
                no_custody: SessionMigrationNoCustody {
                    send_classical: send_classical_no_custody,
                    send_pq: send_pq_no_custody,
                    recv_classical: recv_classical_no_custody,
                    recv_pq: recv_pq_no_custody,
                },
            })
        } else {
            None
        };

        let send_group = SessionMigrationGroupHalf {
            classical: send_classical.0,
            pq: send_pq.map(|(bytes, _)| bytes),
        };
        let recv_group = recv_classical.map(|(classical, _, _)| SessionMigrationGroupHalf {
            classical,
            pq: recv_pq.map(|(bytes, _)| bytes),
        });

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

        // The staged Upd(self) pair is set together on every
        // established-session path. Hash-without-message is the §A.1
        // pre-establishment marker: a prepare-then-never-encrypt initiator
        // can carry it across the establishment cutover (which doesn't clear
        // it) as stale dead state, dropped rather than exported.
        // Message-without-hash is torn.
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
            // A born-dedicated acceptor pre-install can leave this `true` on
            // an admitted export — the mint installs the envelope when it
            // lands, with custody already resolved from the real I_c/I_pq
            // signers (leaf_keys, above).
            owes_establishment_envelope: inner.requires_establishment_envelope
                && inner.establishment_envelope.is_none(),
            pq_leaf_custody,
            leaf_keys,
            rotation_candidate,
            initial_app_payload: inner.initial_app_payload.clone(),
            deployed_state,
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

    /// A pre-establishment initiator with no app payload set still exports:
    /// `identity_kp` mints a fresh classical KP, so `classical_init_secret_key`
    /// is still populated from it, even though this app never takes this
    /// exact path (see the payload-attached test below for the one it does).
    #[cfg(feature = "cryptokit")]
    #[test]
    fn test_migration_export_pre_establishment_bare_initiator() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(super::TwoMlsPqSession::initiate(alice, bob_kp, None));
        let export = assert_ok!(session.migration_export());
        assert!(export.recv_group.is_none());
        assert!(!export.send_group.classical.is_empty());
        assert!(export.send_group.pq.is_some());
        assert!(export.initial_app_payload.is_none());
        assert_some!(export.initial_their_kp.as_ref());
        assert_eq!(
            export
                .identity
                .classical_init_secret_key
                .as_ref()
                .map(Vec::len),
            Some(32)
        );
        assert!(export.bootstrap_kp_secret.is_some());
        assert!(export.expected_bootstrap_kp_commitment.is_none());
        // Reservations: recv_classical/recv_pq don't exist yet, but still carry
        // a reservation key with empty pending.
        assert!(export.leaf_keys.recv_classical.current.is_some());
        assert!(export.leaf_keys.recv_classical.pending.is_empty());
        assert!(export.leaf_keys.recv_pq.current.is_some());
        assert!(export.leaf_keys.recv_pq.pending.is_empty());
        assert!(export.leaf_keys.send_classical.current.is_some());
    }

    /// The real app's shape: `PQSession.swift` mints and retains a return KP
    /// before attaching the app payload. Proves `identity_kp` picks that
    /// retained KP rather than minting a fresh one, by round-tripping the
    /// exact KP bytes.
    #[cfg(feature = "cryptokit")]
    #[test]
    fn test_migration_export_pre_establishment_initiator_with_payload() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(super::TwoMlsPqSession::initiate(
            std::sync::Arc::clone(&alice),
            bob_kp,
            None
        ));
        // Mirrors `PQSession.swift`'s `createTwoMLSGroup`: mint (and retain) the return
        // KP BEFORE attaching the payload.
        let return_kp =
            assert_ok!(alice.generate_key_package(crate::MlsCipherSuite::x25519_chacha()));
        assert_ok!(session.set_initial_app_payload(b"host-signed-establishment".to_vec()));
        // A parked pre-establishment app message: every pre-establishment
        // `encrypt` re-staples the payload onto a fresh §A.1 envelope. Proves
        // the session can still send before establishment with the payload
        // attached.
        assert_ok!(session.prepare_to_encrypt(None));
        let framed = assert_ok!(session.encrypt(b"hello-before-establishment".to_vec()));
        assert!(!framed.cipher_text.is_empty());

        let export = assert_ok!(session.migration_export());
        assert!(export.recv_group.is_none());
        assert_eq!(
            export.initial_app_payload.as_deref(),
            Some(b"host-signed-establishment".as_slice())
        );
        // `identity_kp` picked the RETAINED return KP, not a fresh mint — compare bare
        // forms (`export.identity.classical_key_package` is bare; `return_kp` is the
        // published, MLSMessage-framed form `generate_key_package` returns).
        assert_eq!(
            export.identity.classical_key_package,
            assert_ok!(super::bare_kp(&return_kp))
        );
        assert_eq!(
            export
                .identity
                .classical_init_secret_key
                .as_ref()
                .map(Vec::len),
            Some(32)
        );
        assert!(export.bootstrap_kp_secret.is_some());
        assert!(!assert_some!(export.initial_their_kp.as_ref())
            .classical
            .is_empty());
    }

    /// `initial_return_kp` is never set by this repo's own wrapper, so it's
    /// treated as impossible: setting it directly must fail the export as
    /// `ArchiveInvalid`.
    #[cfg(feature = "cryptokit")]
    #[test]
    fn test_migration_export_rejects_initial_return_kp_as_impossible() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(super::TwoMlsPqSession::initiate(alice, bob_kp, None));
        assert_ok!(session.set_initial_return_key_package(b"bare-classical-kp".to_vec()));
        assert!(matches!(
            session.migration_export(),
            Err(TwoMlsPqError::ArchiveInvalid)
        ));
    }

    /// A fresh acceptor exports fine with its parked return welcome still
    /// undrained: the app never drains `pending_outbound`, so refusing it
    /// would mean no acceptor session ever migrates. The export drops the
    /// parked copy; it still rides `current_staple` until this acceptor's
    /// first send-group commit.
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
