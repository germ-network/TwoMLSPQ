use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use apq::storage::PersistableGroupStorage;
use mls_rs::identity::{basic::BasicCredential, SigningIdentity};
use mls_rs::{
    group::{proposal::Proposal, ProposalMessageDescription, ProposalSender, ReceivedMessage},
    psk::{ExternalPskId, PreSharedKey},
    storage_provider::in_memory::InMemoryPreSharedKeyStorage,
    GroupStateStorage, MlsMessage,
};

use apq::authentication::{AuthCoreHandle, PartySequence};
use apq::component::{
    commit_attestation, read_apqinfo, verify_apqinfo_deferred, verify_apqinfo_pair,
    verify_deferred_pq_info, ApqInfo, ApqInfoUpdate, EPOCH_UNBOUND,
};
use apq::{
    create_bound_classical_send_group, create_combiner_send_group, create_group_with_member,
    decode_apq_welcome, encode_apq_welcome, export_psk, forget_psk,
    join_combiner_group_from_halves, join_group_from_welcome, register_psk, sender_client_id,
    GroupCreation, PskDomain, APQ_TAG,
};

use crate::key_package_store::CombinerGroup;

use crate::{
    key_packages::{
        parse_mls_key_package, validate_combiner_kp, CombinerKeyPackage, TwoMlsPqPrincipal,
    },
    Archive, ClientId, CombinerGroupId, CommitResult, DecryptResult, EncryptResult,
    EpochRendezvous, ListenChannels, MlsGroupId, MlsSenderMessage, PrepareEncryptResult,
    PrincipalState, RendezvousId, Result, SessionId, TwoMlsPqError,
};

use zeroize::Zeroizing;

use crate::providers;

struct SessionInner {
    client: Arc<TwoMlsPqPrincipal>,
    /// The cipher-suite pair this session is locked to — a fixed property, captured from the
    /// constructing client. The APQ mode is derived from it (`ApqCipherSuite::mode`). Peer key
    /// packages and welcomes are validated against it before any group is built or joined.
    suite: apq::ApqCipherSuite,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    pending_proposal_hash: Option<Vec<u8>>,
    /// The staple every outbound message frame carries: the send group's latest classical
    /// commit (ratchet, rotation, or A.3 bind), or — until the first commit exists — the
    /// send group's own APQWelcome. Never empty once the send group exists; re-sent on
    /// every frame so any single received frame heals the peer up to our current epoch.
    current_staple: Vec<u8>,
    /// Upd(self) proposal for the peer's send group, stapled onto the next outbound
    /// frame, with the identity it proposes (the credential its new leaf carries):
    /// `(proposing, proposal bytes)`.
    pending_proposal_message: Option<(Vec<u8>, Vec<u8>)>,
    /// SHA-256 of the welcome our recv group was joined from (`None` until then). Welcomes
    /// are re-delivered as a matter of course (the peer re-staples until its first commit,
    /// plus optional standalone delivery), so processing keys off this record: a matching
    /// arrival is skipped idempotently, a *different* welcome on a live recv group is an
    /// error. The joined group id itself needs no separate record — it is live on
    /// `recv_group`.
    joined_welcome_digest: Option<Vec<u8>>,
    /// The peer's stapled Upd proposal awaiting app approval: `(digest, proposal bytes,
    /// proposing)` where `proposing` is the candidate credential the Upd's new leaf
    /// carries. It enters our send group's proposal cache only via `queue_proposal`.
    offered_proposal: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// The app-approved proposal awaiting our next commit: `(digest, proposing)`.
    /// The one app-approved peer proposal awaiting our next commit: `(digest,
    /// proposing, proposal bytes)`. Validated and **un-cached** at `queue_proposal`
    /// time (nothing lingers in the send group's cache), then re-applied to the send
    /// group at commit — so replacing the slot is a clean overwrite and only ever one
    /// Update is folded. Single occupancy, latest-wins, cleared on a recv-epoch advance.
    queued_proposal: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// In-flight rotation candidates, oldest → newest, admission-bounded at
    /// `CANDIDATE_WINDOW`. Frames in flight may each propose a different candidate and
    /// the peer's commit picks the winner, so a proposed candidate's principal is
    /// **never evicted** — it is retained until canonicalization prunes the whole set
    /// (dropping a still-committable candidate would strand the session: the peer could
    /// commit a credential whose signing key we no longer hold).
    staged_candidates: Vec<Arc<TwoMlsPqPrincipal>>,
    /// A single deferred rotation request parked while `staged_candidates` is full
    /// (id only; the principal is minted on promotion). Bounding the in-flight pool by
    /// deferral rather than eviction keeps every sent candidate committable. Promoted —
    /// and proposed in place of the default self-refresh — on the next routine round
    /// once a canonicalization frees a window slot. A newer `stage_rotation` replaces
    /// it (a deferred id was never on the wire).
    deferred_candidate: Option<Vec<u8>>,
    /// The session-canonical Authentication Service state (both parties' credential
    /// sequences). Every client this session drives resolves to it via its rebindable
    /// `AuthView` — the auth analogue of `track_psk_stores`.
    auth_core: AuthCoreHandle,
    pq_inflight: Option<PqInflight>,
    session_id: SessionId,
    my_state: PrincipalState,
    their_state: PrincipalState,
    /// Responder-side side-band frame awaiting pickup by `pq_take_pending_outbound`.
    /// Single slot: responder operations refuse to start while a frame is waiting.
    pending_pq_outbound: Option<Vec<u8>>,
    /// Whose move the PQ side-band is: the initiator owes the A.4 bootstrap; thereafter
    /// completing an operation passes the turn to the peer.
    pq_turn_mine: bool,
    /// Cross-party TwoMLS-PSKs of OUR send group's recent epochs, owned by the session
    /// (destined for the session archive; the mls-rs secret stores are ephemeral plumbing,
    /// filled just-in-time by `inject_send_psks`). The peer binds the PSK of our send
    /// group's epoch *as they last observed it*, so a frame that crossed one of our
    /// commits can reference an epoch mls-rs can no longer export — the ledger keeps a
    /// window instead of re-deriving at the current epoch only. Each entry is
    /// `(send_classical_epoch, ExportedPsk)`: the epoch is the one-export-per-epoch guard
    /// (the -02 exporter tree consumes each component's leaf on first export), and the
    /// [`ExportedPsk`] carries the store key + value the peer's commit will look up.
    send_psk_ledger: VecDeque<(u64, apq::ExportedPsk)>,
    /// PSK ids evicted from the ledger (or consumed one-shot) but possibly still present in
    /// the mls-rs secret stores from an earlier injection; the next `inject_send_psks`
    /// deletes them so the stores never resolve PSKs the session no longer vouches for.
    retired_send_psks: Vec<ExternalPskId>,
    /// The peer send-group (recv-group) classical epoch we last bound a cross-party
    /// TwoMLS-PSK from, or `None` if we never have (an initiator before its first full
    /// commit; the acceptor is seeded at establishment, which binds the peer's epoch 1).
    /// The cross-party injection is **event-driven**: a full commit re-injects only when the
    /// peer's send group has advanced past this watermark — i.e. there is new peer entropy to
    /// entangle with (a peer full commit or an A.3 bind, both of which advance the peer's
    /// classical epoch). Re-injecting an unchanged epoch would derive the identical
    /// `SafeExportSecret` leaf (consumed, and adding no entropy), so we skip it. Rides the
    /// archive so a restore does not re-bind an epoch already bound.
    last_cross_injected: Option<u64>,
    /// The A.5 analogue of [`last_cross_injected`] for the recv-PQ mirror (the peer's
    /// send-PQ): the peer send-PQ epoch we last cross-injected during a PQ re-key. Two
    /// consecutive re-keys with no PQ commit from the peer in between leave this epoch
    /// unchanged, so the second re-key skips the redundant cross-injection.
    last_cross_injected_pq: Option<u64>,
    /// The send-PQ epoch we last pre-registered a cross-party PSK from (the send-PQ analogue
    /// of the classical `send_psk_ledger`). The A.5 pre-register runs on every apply, but our
    /// send-PQ only advances when we commit, so this guards against re-exporting an
    /// already-consumed leaf across re-keys.
    last_send_pq_exported: Option<u64>,
    /// Per-epoch listen addresses derived from the send group's classical half
    /// (`exportSecret("rendezvous", "TwoMLS", 32)` — the classical backend's convention).
    /// Exporters are only derivable at the current epoch, so each value is captured when
    /// its epoch is live: traffic posted at a prior epoch's address must still land.
    /// Keyed by classical epoch; the window follows mls-rs's own epoch retention (see
    /// `record_listen_rendezvous`) — current epoch + the prior epochs mls-rs retains.
    listen_rendezvous: BTreeMap<u64, Vec<u8>>,
    /// Header-encryption receive window: `header_key(send_group.classical)` per retained
    /// classical epoch of MY send group. The peer seals frames to me under my send group
    /// (their recv group) as they last applied it, so opening trial-decrypts over this
    /// window (a frame that crossed one of my commits opens with the older entry).
    /// Captured live-at-epoch in lockstep with `listen_rendezvous` and retained by the
    /// same rule, so a frame that can still be routed can still be opened. Session-owned,
    /// so it rides the archive.
    recv_header_keys: BTreeMap<u64, Vec<u8>>,
    /// The PQ side-band's header receive window: `header_key_pq(send_group.pq, e)` per
    /// recent `pq_epoch` of my own send-PQ group (the peer seals side-band frames under
    /// their recv-PQ, which is my send-PQ). Separate from `recv_header_keys` so the
    /// side-band's outer seal tracks the PQ ratchet's cadence rather than the async
    /// classical one. Keyed by `pq_epoch`; retained "keep newest `PQ_HEADER_WINDOW`" —
    /// session-owned, with no rendezvous or mls-rs coupling (PQ keeps no rendezvous).
    recv_header_keys_pq: BTreeMap<u64, Vec<u8>>,
    /// The group-state storage backing the send group's classical half, captured from
    /// the client that CONSTRUCTED the session. The retention probe must read this
    /// handle, not one reached through `self.client`: a Phase 8 rotation replaces
    /// `self.client` with the new principal's client (whose injected storage is a fresh,
    /// empty map), while the send group keeps flushing into the storage it was built
    /// with — probing the new client's handle would prune every prior epoch's listen
    /// address right after rotation.
    send_group_storage: PersistableGroupStorage,
    /// Every PSK store backing one of this session's group configs: the constructing
    /// client's stores, plus the stores of any later client that joins or stands up a
    /// group half (the A.4 bootstrap and the return-welcome join run on the CURRENT
    /// principal, which a Phase 8 rotation may have replaced since construction). External
    /// PSKs are registered into ALL of these (`register_psk`): an mls-rs group resolves
    /// PSKs from the store of the client that created it, so registering only through
    /// `self.client` would strand every group created before the latest rotation.
    psk_stores: Vec<InMemoryPreSharedKeyStorage>,
    /// The client whose PSK stores `psk_stores` last absorbed — the dedup key for
    /// `track_psk_stores` (compared by Arc identity, so re-tracking the same client
    /// is free and only a rotation-installed client grows the registry).
    psk_stores_from: Arc<TwoMlsPqPrincipal>,
    /// The opaque spawn token this acceptor session was created under (see
    /// `TwoMlsPqInvitation::receive`); `None` on initiator sessions. `forwarded`
    /// matches replayed initial frames against it. Opaque — this library never
    /// interprets the bytes. Must be serialized when `archive()` is implemented, or
    /// restored sessions stop acknowledging replayed initial frames.
    spawn_token: Option<Vec<u8>>,
}

/// Ledger depth for `send_psk_ledger`: one entry per send-group epoch. The peer references
/// the epoch it last observed, so the window must cover every unilateral send-group commit
/// (queued-proposal ratchet, principal rotation, PQ bind) that can cross one in-flight peer
/// frame. That count is protocol-unbounded in principle — a host looping rotations while a
/// peer frame is in transit can outrun any fixed window and permanently desync the
/// direction (the failed frame is a commit, so there is no recovery) — but each entry is
/// one 32-byte secret, so we keep a generous window and rely on hosts not committing
/// unboundedly between peer frames.
const SEND_PSK_WINDOW: usize = 8;

/// Retained staged rotation candidates. Only one is usually in flight; the window
/// exists because the peer's commit picks the winner among candidates proposed on
/// different frames, so recently staged principals must survive until one wins.
const CANDIDATE_WINDOW: usize = 4;

/// A TwoMLSPQ session holding two asymmetric Combiner send groups.
#[derive(uniffi::Object)]
pub struct TwoMlsPqSession {
    inner: Mutex<SessionInner>,
}

mod frames;
pub use frames::fuzz_decode_message_frame;
use frames::*;
pub use frames::{pq_frame_kind, OpenedFrame, OpenedFrameKind, PqFrameKind};

// Rendezvous derivation, shared with the classical backend so both stacks address
// transport channels the same way: exportSecret(label, context, 32) on a group's
// classical half. Both members of a group derive identical values; outsiders cannot.
const RENDEZVOUS_LABEL: &[u8] = b"rendezvous";
const RENDEZVOUS_CONTEXT: &[u8] = b"TwoMLS";
const RENDEZVOUS_LEN: usize = 32;

/// PQ ratchet round state carried between the messages of one exchange.
enum PqInflight {
    /// Initiator holds the ephemeral (decapsulation key) until it receives the ciphertext.
    Initiating(apq::pq_ratchet::PqEphemeral),
    /// Responder holds the shared secret until it receives the stapled bind. `Zeroizing` wipes the
    /// secret from memory on drop, whether it is consumed by the bind or abandoned.
    Responding(Zeroizing<Vec<u8>>),
    /// A.5 initiator awaiting the responder's Commit' (+ counter-Upd'). `rotating`
    /// carries the credential-handoff ClientId from `pq_rekey_begin` so the final
    /// commit also hands our own send-PQ leaf to the new principal's signing key.
    RekeyInitiated { rotating: Option<ClientId> },
    /// A.5 responder awaiting the initiator's final Commit'.
    RekeyResponded,
}

// The session archive layout version. The byte covers the WHOLE layout. Still pre-release, so
// a layout change need not bump it — an archive from an older/other build simply fails to
// decode (`ArchiveInvalid`) and is regenerated; no migration.
// The header carries the concrete `ApqCipherSuite` pair (4 bytes, classical then pq,
// big-endian) in place of the old PQ-mode byte: the suite is a stored session property, and a
// restored archive whose pair differs from this build's pinned suite fails loudly.
// v3 (header encryption): the archive gained the per-epoch header receive window
// (`recv_header_keys`), so a restored session can still open frames sealed under a recent
// send-group epoch.
// v4 (PQ-family side-band keys): added the PQ header window (`recv_header_keys_pq`), so a
// restored session opens PQ side-band frames sealed under a recent pq_epoch too.
// v6 (draft-02 conformance, phase A): no layout change — a pure compatibility cut. v5-era
// groups carry no APQInfo GroupContext extension and their leaves lack the AppDataUpdate /
// APQInfo capabilities, so a restored v5 session could never verify or carry the -02
// machinery; reject the blob instead of resurrecting a permanently non-conformant session.
// v7 (draft-02 conformance, phase B): the send-PSK ledger entries changed shape — each now
// carries (send epoch, component_id, psk_id, value) for the -02 application PSK, replacing the
// (external id, value) pair, so v6 blobs no longer decode.
// v8 (event-driven cross-party injection): the transient PSK memo is gone, replaced by three
// small epoch watermarks (`last_cross_injected`, `last_cross_injected_pq`,
// `last_send_pq_exported`) that gate the cross-party injections, so the archive layout changed.
const SESSION_ARCHIVE_VERSION: u8 = 8;

// In its own module because the derive-generated impls reference the std `Result`, which
// the crate-local `Result` alias would shadow (same pattern as `invitation::wire`).
mod archive_wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use mls_rs::psk::{ExternalPskId, PreSharedKey};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// One exported mls-rs group snapshot (plaintext secret material — the enclosing
    /// archive carries the sealing obligation, see [`super::TwoMlsPqSession::archive`]).
    /// A one-field struct so `Option<GroupBlob>` composes with the `byte_vec` framing
    /// (the `with` module has no Option-awareness).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct GroupBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) bytes: Zeroizing<Vec<u8>>,
    }

    /// One Combiner group: the classical half's snapshot and, when live, the PQ half's.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct GroupEntry {
        pub(super) classical: GroupBlob,
        pub(super) pq: Option<GroupBlob>,
    }

    /// One session-owned cross-party PSK ledger entry: the send-group classical epoch it
    /// was exported at, and the application PSK's parts (`component_id`, `psk_id`, value).
    /// The store key is recomputed on restore via `ExportedPsk::from_parts`.
    /// `PreSharedKey`'s codec keeps the payload `Zeroizing` through decode.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct PskEntry {
        pub(super) epoch: u64,
        pub(super) component_id: u32,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) psk_id: Vec<u8>,
        pub(super) psk: PreSharedKey,
    }

    /// One per-epoch listen address (rendezvous exporter, captured at its live epoch).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct ListenEntry {
        pub(super) epoch: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) addr: Vec<u8>,
    }

    /// One per-epoch header receive key (header-encryption exporter of the send group,
    /// captured at its live epoch alongside the listen address).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct HeaderKeyEntry {
        pub(super) epoch: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) key: Vec<u8>,
    }

    /// `PrincipalState` on the wire: `Sync { client_id: active }` when `pending_new` is
    /// `None`, else `Pending { old: active, new: pending_new }`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WirePrincipalState {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) active: Vec<u8>,
        pub(super) pending_new: Option<Vec<u8>>,
    }

    /// The peer's stapled Upd awaiting app approval: (digest, proposal bytes).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct OfferedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) digest: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) proposal: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) proposing: Vec<u8>,
    }

    /// An opaque ClientId on the wire.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct IdBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) bytes: Vec<u8>,
    }

    /// One party's AS credential sequence (see `apq::authentication::PartySequence`).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WirePartySequence {
        pub(super) history: Vec<IdBlob>,
        pub(super) authorized_next: Vec<IdBlob>,
    }

    /// The staged Upd(self) with the identity it proposes.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WireStagedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) proposing: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) message: Vec<u8>,
    }

    /// The app-approved proposal awaiting our next commit (digest, proposing, and the
    /// proposal message bytes re-applied at commit).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WireQueuedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) digest: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) proposing: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) proposal: Vec<u8>,
    }

    /// A session-owned signing identity on the wire: the ClientId, each MLS half's signing
    /// key, and each half's retained key packages. Rebuilt via `apq::ArchivedIdentity` with
    /// the key-package stores preloaded from `*_kps` (the signing keys ARE the identity; the
    /// app owns only the opaque ClientId). The key packages carry any minted-but-unconsumed
    /// material — critically an initiator's return-group key package, which the peer's return
    /// welcome addresses; a bare identity (empty `*_kps`) could not join it after restore.
    /// Carries the session's current client and, when a rotation is staged, the successor
    /// (whose stores are empty). `Zeroizing` wipes the decoded keys on drop.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct SigningIdentityBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) client_id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) classical_signing_key: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) pq_signing_key: Zeroizing<Vec<u8>>,
        /// Retained key packages per half, `(storage id, KeyPackageData)`. Each half's
        /// `KeyPackageData` embeds via its own canonical MLS encoding (as in the invitation
        /// archive), so it stays correct if mls-rs evolves the (non_exhaustive) struct.
        pub(super) classical_kps: Vec<KeyPackageSecret>,
        pub(super) pq_kps: Vec<KeyPackageSecret>,
    }

    /// The initiator's held A.3 ephemeral (`PqInflight::Initiating`) on the wire: the
    /// decapsulation key (kept `Zeroizing`) and the encapsulation key. Round-trips via
    /// `apq::pq_ratchet::PqEphemeral`'s byte accessors.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct PqEphemeralBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) dk: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) ek: Vec<u8>,
    }

    /// The responder's held A.3 shared secret (`PqInflight::Responding`) on the wire.
    /// `Zeroizing` wipes it on drop; a one-field struct so `Option<SecretBlob>` composes
    /// with the byte_vec framing (the `with` module has no Option-awareness).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct SecretBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) bytes: Zeroizing<Vec<u8>>,
    }

    /// The archivable `PqInflight` round state, tag-dispatched by `kind` so all four
    /// variants share one optional-payload struct — the flat-struct style the rest of
    /// this module uses in place of codec enums. The A.5 markers carry no secrets (their
    /// round state lives in the group snapshots); the A.3 variants carry the round's KEM
    /// material (see [`super::TwoMlsPqSession::archive`] for why persisting it is sound).
    ///
    /// - `0` `Initiating`     — `ephemeral` set; `secret`/`rotating` absent.
    /// - `1` `Responding`     — `secret` set; `ephemeral`/`rotating` absent.
    /// - `2` `RekeyInitiated` — `rotating` optional; no KEM payload.
    /// - `3` `RekeyResponded` — no payload.
    ///
    /// `from_archive` rejects any other `kind`, or a payload that does not match `kind`,
    /// as `ArchiveInvalid`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WirePqInflight {
        pub(super) kind: u8,
        pub(super) ephemeral: Option<PqEphemeralBlob>,
        pub(super) secret: Option<SecretBlob>,
        pub(super) rotating: Option<Vec<u8>>,
    }

    /// The persisted form of a `TwoMlsPqSession`. Everything a session needs to resume,
    /// self-contained (no restoring client is passed): the current signing identity,
    /// identity/turn state, both group snapshots, the cross-party PSK ledger, the
    /// per-epoch listen map, the spawn token, a staged-but-uncommitted rotation, the full
    /// PQ round state, and every parked one-shot frame (dropping a parked side-band frame
    /// whose turn already flipped would desync the side-band permanently).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct SessionArchive {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) session_id: Vec<u8>,
        /// The session's current client signing identity, rebuilt byte-exact on restore
        /// so restore is self-contained (no client argument).
        pub(super) client: SigningIdentityBlob,
        pub(super) my_state: WirePrincipalState,
        pub(super) their_state: WirePrincipalState,
        pub(super) pq_turn_mine: bool,
        pub(super) spawn_token: Option<Vec<u8>>,
        /// Required: every constructor creates a send group, so its absence marks a
        /// forged or corrupt archive.
        pub(super) send_group: GroupEntry,
        pub(super) recv_group: Option<GroupEntry>,
        pub(super) send_psk_ledger: Vec<PskEntry>,
        pub(super) retired_send_psks: Vec<ExternalPskId>,
        pub(super) last_cross_injected: Option<u64>,
        pub(super) last_cross_injected_pq: Option<u64>,
        pub(super) last_send_pq_exported: Option<u64>,
        pub(super) listen_rendezvous: Vec<ListenEntry>,
        pub(super) recv_header_keys: Vec<HeaderKeyEntry>,
        pub(super) recv_header_keys_pq: Vec<HeaderKeyEntry>,
        pub(super) pending_outbound: Option<Vec<u8>>,
        pub(super) pending_proposal_hash: Option<Vec<u8>>,
        /// The commit-or-welcome staple every outbound frame re-sends. Never empty on a
        /// valid archive (validated on restore: non-empty, first byte 0x00 or 0x01).
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) current_staple: Vec<u8>,
        pub(super) pending_proposal_message: Option<WireStagedProposal>,
        pub(super) joined_welcome_digest: Option<Vec<u8>>,
        pub(super) offered_proposal: Option<OfferedProposal>,
        pub(super) queued_proposal: Option<WireQueuedProposal>,
        /// Rotation candidates staged by `stage_rotation` and not yet resolved: the
        /// minted successor identities, rebuilt on restore into `staged_candidates`.
        pub(super) staged_candidates: Vec<SigningIdentityBlob>,
        /// A parked next-rotation request (id only) not yet promoted to in-flight.
        pub(super) deferred_candidate: Option<Vec<u8>>,
        /// The Authentication Service state: both parties' credential sequences.
        pub(super) auth_mine: WirePartySequence,
        pub(super) auth_theirs: WirePartySequence,
        pub(super) pending_pq_outbound: Option<Vec<u8>>,
        pub(super) pq_inflight: Option<WirePqInflight>,
    }
}

/// `PrincipalState` → its wire form.
fn wire_principal_state(state: &PrincipalState) -> archive_wire::WirePrincipalState {
    match state {
        PrincipalState::Sync { client_id } => archive_wire::WirePrincipalState {
            active: client_id.bytes.clone(),
            pending_new: None,
        },
        PrincipalState::Pending { old, new } => archive_wire::WirePrincipalState {
            active: old.bytes.clone(),
            pending_new: Some(new.bytes.clone()),
        },
    }
}

/// Wire form → `PrincipalState`.
fn principal_state_from_wire(wire: archive_wire::WirePrincipalState) -> PrincipalState {
    match wire.pending_new {
        None => PrincipalState::Sync {
            client_id: ClientId { bytes: wire.active },
        },
        Some(new) => PrincipalState::Pending {
            old: ClientId { bytes: wire.active },
            new: ClientId { bytes: new },
        },
    }
}

/// A client's signing identity → its wire form (ClientId + each half's signing key).
/// The signing keys are session-owned state; the archive rebuilds the client from them.
fn signing_identity_blob(identity: &TwoMlsPqPrincipal) -> archive_wire::SigningIdentityBlob {
    let client = identity.combiner();
    archive_wire::SigningIdentityBlob {
        client_id: client.client_id().to_vec(),
        classical_signing_key: Zeroizing::new(client.classical_signing_key().to_vec()),
        pq_signing_key: Zeroizing::new(client.pq_signing_key().to_vec()),
        // Carry the client's retained key packages so a restored initiator can still join
        // its return welcome (its return-group key package rides here).
        classical_kps: client.classical_kp_store().all_entries(),
        pq_kps: client.pq_kp_store().all_entries(),
    }
}

/// A signing-identity blob → a rebuilt session-owned `TwoMlsPqPrincipal` with its key-package
/// stores preloaded from the blob (empty for a bare identity, e.g. a staged successor).
fn principal_from_wire(blob: archive_wire::SigningIdentityBlob) -> Result<Arc<TwoMlsPqPrincipal>> {
    TwoMlsPqPrincipal::from_signing_keys(
        blob.client_id,
        blob.classical_signing_key,
        blob.classical_kps,
        blob.pq_signing_key,
        blob.pq_kps,
    )
}

/// `PqInflight` → its wire form. The A.3 variants carry the round's KEM material; the
/// A.5 markers carry only a discriminant (and an optional rotation ClientId).
fn wire_pq_inflight(inflight: &PqInflight) -> archive_wire::WirePqInflight {
    use archive_wire::{PqEphemeralBlob, SecretBlob, WirePqInflight};
    match inflight {
        PqInflight::Initiating(eph) => WirePqInflight {
            kind: 0,
            ephemeral: Some(PqEphemeralBlob {
                dk: eph.decapsulation_key(),
                ek: eph.encapsulation_key(),
            }),
            secret: None,
            rotating: None,
        },
        PqInflight::Responding(s) => WirePqInflight {
            kind: 1,
            ephemeral: None,
            secret: Some(SecretBlob { bytes: s.clone() }),
            rotating: None,
        },
        PqInflight::RekeyInitiated { rotating } => WirePqInflight {
            kind: 2,
            ephemeral: None,
            secret: None,
            rotating: rotating.as_ref().map(|id| id.bytes.clone()),
        },
        PqInflight::RekeyResponded => WirePqInflight {
            kind: 3,
            ephemeral: None,
            secret: None,
            rotating: None,
        },
    }
}

/// Wire form → `PqInflight`, rejecting an unknown `kind` or a payload that does not match
/// the discriminant (a forged or corrupt archive) as `ArchiveInvalid`.
fn pq_inflight_from_wire(wire: archive_wire::WirePqInflight) -> Result<PqInflight> {
    use archive_wire::WirePqInflight;
    match wire {
        WirePqInflight {
            kind: 0,
            ephemeral: Some(eph),
            secret: None,
            rotating: None,
        } => Ok(PqInflight::Initiating(
            apq::pq_ratchet::PqEphemeral::from_bytes(&eph.dk, &eph.ek),
        )),
        WirePqInflight {
            kind: 1,
            ephemeral: None,
            secret: Some(s),
            rotating: None,
        } => Ok(PqInflight::Responding(s.bytes)),
        WirePqInflight {
            kind: 2,
            ephemeral: None,
            secret: None,
            rotating,
        } => Ok(PqInflight::RekeyInitiated {
            rotating: rotating.map(|bytes| ClientId { bytes }),
        }),
        WirePqInflight {
            kind: 3,
            ephemeral: None,
            secret: None,
            rotating: None,
        } => Ok(PqInflight::RekeyResponded),
        _ => Err(TwoMlsPqError::ArchiveInvalid),
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Initiator step 1 — generate an ML-KEM ephemeral and return the encapsulation-key message
    /// (tag 0x05). The decapsulation key is held until the ciphertext arrives.
    pub fn pq_ratchet_begin(&self) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        // A.3 is post-A.4 (both PQ halves live), so the recv group always exists here —
        // guard explicitly, both because the ratchet is meaningless pre-establishment and
        // because the header seal below needs the recv group's key.
        if inner.recv_group.is_none() {
            return Err(TwoMlsPqError::SessionNotEstablished);
        }
        if inner.pq_inflight.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let eph = apq::pq_ratchet::generate_ephemeral(&providers::pq_kem()?)?;
        let mut msg = vec![PQ_EK_TAG];
        msg.extend_from_slice(&eph.encapsulation_key());
        let sealed = inner.seal_side_band(&msg)?;
        inner.pq_inflight = Some(PqInflight::Initiating(eph));
        Ok(sealed)
    }

    /// Responder — encapsulate a fresh secret to the initiator's EK, hold it, and return the
    /// ciphertext message (tag 0x07).
    pub fn pq_ratchet_respond(&self, ek_msg: Vec<u8>) -> Result<()> {
        let ek_msg = self.lock().open_or_raw(ek_msg);
        let (&tag, ek) = ek_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_EK_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pq_inflight.is_some() || inner.pending_pq_outbound.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let (s, ct) = apq::pq_ratchet::encapsulate(&providers::pq_kem()?, ek)?;
        inner.pq_inflight = Some(PqInflight::Responding(Zeroizing::new(s)));
        let mut msg = vec![PQ_CT_TAG];
        msg.extend_from_slice(&ct);
        inner.pending_pq_outbound = Some(msg);
        Ok(())
    }

    /// Initiator step 2 — decapsulate S, inject it into the send group's PQ half via a pathless
    /// commit, bind the exported apq_psk into the classical half, and staple an app message.
    /// Returns the bind frame (tag 0x09).
    pub fn pq_ratchet_bind(&self, ct_msg: Vec<u8>, app: Vec<u8>) -> Result<()> {
        let ct_msg = self.lock().open_or_raw(ct_msg);
        let (&tag, ct) = ct_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_CT_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pending_pq_outbound.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // Staple-stacking guard: a prepared-but-unsent classical commit is sitting in
        // `current_staple` waiting for its `encrypt`. The bind commit below would replace
        // it, and a displaced commit never rides a frame again — the peer would hit the
        // epoch-ahead desync with zero loss on the wire. Retriable: bind after `encrypt`.
        if inner.pending_proposal_hash.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // Capture the departing epoch's PSK before the classical bind commit below.
        inner.remember_send_psk()?;
        let eph = match inner.pq_inflight.take() {
            Some(PqInflight::Initiating(eph)) => eph,
            _ => return Err(TwoMlsPqError::SessionNotReady),
        };
        let s = Zeroizing::new(apq::pq_ratchet::decapsulate(
            &providers::pq_kem()?,
            &eph,
            ct,
        )?);
        let stores = inner.psk_stores.clone();
        let send = inner
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_pq = send.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        // The bind is a -02 FULL commit: both halves carry the AppDataUpdate attesting
        // the absolute post-commit epochs of both groups, computed before either commit.
        let attestation = ApqInfoUpdate {
            t_epoch: send.classical.current_epoch() + 1,
            pq_epoch: send_pq.current_epoch() + 1,
        };
        let (pq_commit, apq_psk) =
            apq::pq_ratchet::inject_and_commit(send_pq, &s, &stores, attestation)?;
        let cl_builder = send
            .classical
            .commit_builder()
            .custom_proposal(attestation.to_custom_proposal()?);
        let cl_out = apq_psk
            .add_to_commit(cl_builder)?
            .build()
            .map_err(|_| TwoMlsPqError::Mls)?;
        send.classical
            .apply_pending_commit()
            .map_err(|_| TwoMlsPqError::Mls)?;
        // The bind is a bare PSK commit (the queued peer proposal is not cached — it is
        // re-applied only at the routine fold), so the roster is unchanged; assert it.
        apq::ensure_two_party(&send.classical)?;
        // The bind consumed the one-shot apq PSK; drop it from every store it was
        // registered into (the session registry plus the group-captured handles).
        send.forget_psk(apq_psk.storage_id());
        apq::forget_psk_stores(&stores, apq_psk.storage_id());
        let cl_commit = cl_out
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        let app_ct = send
            .classical
            .encrypt_application_message(&app, vec![])
            .map_err(|_| TwoMlsPqError::Mls)?
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        // This commit advanced our send-group epoch, so any queued or offered peer
        // proposal (an Update bound to the prior send epoch) is now stale and cannot be
        // committed — drop it. The peer re-proposes at the new epoch once it observes
        // this bind's staple (the receiver freely drops; the proposer re-sends).
        inner.queued_proposal = None;
        inner.offered_proposal = None;
        // Our send group advanced: record the new epoch's PSK in the session ledger.
        inner.remember_send_psk()?;
        // The bind's classical commit becomes the staple subsequent message frames
        // re-send — if the BIND frame itself is lost, the classical stream still heals.
        // (A message frame can overtake the BIND; the peer then lacks the APQ-PSK and the
        // staple fails retriably until the BIND lands — same as today's ordering.)
        inner.current_staple = cl_commit.clone();
        // Our operation is complete once the peer applies; the turn passes.
        inner.pq_turn_mine = false;
        inner.pending_pq_outbound = Some(encode_pq_bind(pq_commit, cl_commit, app_ct));
        // The bind committed classically in our send group — capture the new
        // epoch's listen address — and advanced our send-PQ's pq_epoch — capture its
        // new header key.
        inner.record_listen_rendezvous()?;
        inner.record_pq_header_key()?;
        Ok(())
    }

    /// Responder — apply the stapled bind: register the held secret, apply the PQ partial commit
    /// and classical commit on the recv group, and return the decrypted app message.
    pub fn pq_ratchet_apply(&self, bind_msg: Vec<u8>) -> Result<Vec<u8>> {
        let bind_msg = self.lock().open_or_raw(bind_msg);
        let (pq_commit, cl_commit, app_ct) = decode_pq_bind(&bind_msg)?;
        let mut inner = self.lock();
        let s = match inner.pq_inflight.take() {
            Some(PqInflight::Responding(s)) => s,
            _ => return Err(TwoMlsPqError::SessionNotReady),
        };
        let stores = inner.psk_stores.clone();
        let recv = inner
            .recv_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let recv_pq = recv.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        let (apq_psk, pq_attestation) =
            apq::pq_ratchet::apply_injected_commit(recv_pq, &s, &pq_commit, &stores)?;
        let cl = MlsMessage::from_bytes(&cl_commit).map_err(|_| TwoMlsPqError::Mls)?;
        let cl_attestation = match recv
            .classical
            .process_incoming_message(cl)
            .map_err(|_| TwoMlsPqError::Mls)?
        {
            ReceivedMessage::Commit(desc) => {
                commit_attestation(&desc)?.ok_or(TwoMlsPqError::ApqInfoMismatch)?
            }
            _ => return Err(TwoMlsPqError::ApqInfoMismatch),
        };
        // -02 FULL verification: both halves carried the AppDataUpdate, the two copies
        // agree, and they attest the actual post-apply epochs of both groups.
        //
        // Verify/apply boundary: per-half AppDataUpdate validity (correct proposal type,
        // committer-sent, and new-epoch == pre-commit context.epoch + 1) is enforced
        // PRE-apply by the MlsRules filter (see `apq::rules`), so a structurally bad
        // attestation is rejected before either group state moves. What remains here — the
        // CROSS-half agreement and the match against the actual post-apply epochs — is
        // necessarily post-apply, because comparing the two halves' epochs requires both
        // commits to have been applied (mls-rs `process_incoming_message` validates and
        // applies atomically; there is no inspect-without-apply short of a fork change).
        // That residual check still gates every observable effect: it runs BEFORE the
        // stapled app message is decrypted (line below), BEFORE the one-shot apq PSK is
        // forgotten, and BEFORE the turn passes — so on a bad attestation from our sole
        // counterparty no plaintext is released and no turn/PSK state is confirmed. The
        // only thing an attestation forgery can force is a self-inflicted epoch advance
        // that then errors out, which is within the two-party DoS threat model.
        if cl_attestation != pq_attestation
            || pq_attestation.pq_epoch != recv_pq.current_epoch()
            || cl_attestation.t_epoch != recv.classical.current_epoch()
        {
            return Err(TwoMlsPqError::ApqInfoMismatch);
        }
        // Peer commits (the PQ partial above is checked inside `apply_injected_commit`)
        // must never change the two-party shape.
        apq::ensure_two_party(&recv.classical)?;
        // The bind consumed the one-shot apq PSK; drop it from every store it was
        // registered into (the session registry plus the group-captured handles).
        recv.forget_psk(apq_psk.storage_id());
        apq::forget_psk_stores(&stores, apq_psk.storage_id());
        let app = MlsMessage::from_bytes(&app_ct).map_err(|_| TwoMlsPqError::Mls)?;
        let out = match recv
            .classical
            .process_incoming_message(app)
            .map_err(|_| TwoMlsPqError::Mls)?
        {
            ReceivedMessage::ApplicationMessage(m) => Ok(m.data().to_vec()),
            _ => Err(TwoMlsPqError::DecryptionFailed),
        };
        // We finished receiving this operation; the next one is ours to start.
        inner.pq_turn_mine = true;
        out
    }

    /// A.5 initiator — propose Upd'(self) into the peer's send-PQ (our recv mirror) and
    /// return the 0x0F frame. Requires both PQ halves live (post-A.4 only), the turn, and
    /// no other side-band operation in flight. Proposal only: no epochs move until the
    /// responder commits.
    ///
    /// `rotating` is the A.5 credential handoff: it must name the session's CURRENT
    /// principal (a Phase 8 rotation has already swapped `self.client` to it), and the Upd'
    /// then moves our leaf's signing key to that principal, announcing its ClientId in the
    /// proposal's authenticated_data — the same announcement convention as the Phase 8
    /// classical rotation commit. The leaf's credential BYTES stay what they were:
    /// `BasicIdentityProvider` requires a stable identity across leaf updates, so principal
    /// identity travels at the announcement level, not in the Basic Credential.
    pub fn pq_rekey_begin(&self, rotating: Option<ClientId>) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        if !inner.pq_turn_mine || inner.pending_pq_outbound.is_some() || inner.pq_inflight.is_some()
        {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        if inner
            .send_group
            .as_ref()
            .and_then(|g| g.pq.as_ref())
            .is_none()
        {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let handoff = match &rotating {
            Some(new_id) => {
                if inner.client.client_id() != *new_id {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                let (new_signer, new_public) = inner.client.combiner().pq_signature_keypair();
                Some((new_signer, new_public, new_id.bytes.clone()))
            }
            None => None,
        };
        let recv_pq = inner
            .recv_group
            .as_mut()
            .and_then(|g| g.pq.as_mut())
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let proposal = match handoff {
            Some((new_signer, new_public, announced_id)) => {
                // The PQ leaf catches up in the credential sequence: the new leaf
                // carries the CANONICAL credential (already committed classically),
                // validated by the AS's catch-up rule.
                let identity = SigningIdentity::new(
                    BasicCredential::new(announced_id.clone()).into_credential(),
                    new_public,
                );
                recv_pq
                    .propose_update_with_identity(new_signer, identity, announced_id)
                    .map_err(map_credential_err)?
            }
            None => recv_pq
                .propose_update(Vec::new())
                .map_err(|_| TwoMlsPqError::Mls)?,
        };
        let mut msg = vec![PQ_REKEY_UPD_TAG];
        msg.extend_from_slice(&proposal.to_bytes().map_err(|_| TwoMlsPqError::Mls)?);
        let sealed = inner.seal_side_band(&msg)?;
        inner.pq_inflight = Some(PqInflight::RekeyInitiated { rotating });
        Ok(sealed)
    }

    /// A.5 responder — commit the initiator's Upd' on our own send-PQ with an updatePath
    /// and a PSK exported from our recv-PQ mirror (the initiator derives the same PSK from
    /// its send-PQ), then park the `[Commit'][counter-Upd'(self)]` frame (0x11) for pickup
    /// via `pq_take_pending_outbound`.
    ///
    /// Returns the ClientId the initiator announced in the Upd's authenticated_data when
    /// this rekey carries an A.5 credential handoff (see `pq_rekey_begin`), else `None`.
    /// By the time this returns, the initiator's leaf in our send-PQ has already moved
    /// to the new principal's signing key. The classical Phase 8 commit remains the
    /// authoritative identity-rotation channel — this reports the PQ half catching up
    /// and does not touch the session's principal state.
    pub fn pq_rekey_respond(&self, upd_msg: Vec<u8>) -> Result<Option<ClientId>> {
        let upd_msg = self.lock().open_or_raw(upd_msg);
        let (&tag, proposal_bytes) = upd_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_REKEY_UPD_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let proposal_msg =
            MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let mut inner = self.lock();
        if inner.pending_pq_outbound.is_some() || inner.pq_inflight.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // Cross-PSK from our recv-PQ mirror (§A.5: "Export PSK from [ASG-PQ]"), but only
        // when the peer's send-PQ has advanced since we last cross-injected it — the same
        // event-driven rule as the classical ratchet (see `last_cross_injected_pq`). Across
        // two consecutive re-keys without a PQ commit from the peer in between, this recv-PQ
        // epoch is unchanged and already entangled, so we skip re-deriving a consumed leaf
        // (the commit still rotates our leaf via the updatePath). The initiator registers
        // the same value from its own send-PQ at this epoch.
        let recv_pq_epoch = inner
            .recv_group
            .as_ref()
            .and_then(|g| g.pq.as_ref())
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .current_epoch();
        let cross_psk = if inner.last_cross_injected_pq == Some(recv_pq_epoch) {
            None
        } else {
            let recv_pq = inner
                .recv_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let exported = export_psk(recv_pq, PskDomain::CrossParty)?;
            inner.register_psk(exported.storage_id(), exported.psk());
            inner.last_cross_injected_pq = Some(recv_pq_epoch);
            Some(exported)
        };
        // Snapshot of the peer's canonical history for the announced-id check below
        // (taken before the group borrow).
        let canonical_theirs = inner.with_auth(|core| core.theirs.to_parts().0);
        let rotated;
        let commit_bytes = {
            let send_pq = inner
                .send_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let my_index = send_pq.current_member_index();
            match send_pq
                .process_incoming_message(proposal_msg)
                .map_err(|_| TwoMlsPqError::Mls)?
            {
                ReceivedMessage::Proposal(desc) => {
                    // Only the peer's own-leaf Update is a legitimate A.5 opener.
                    require_peer_update(&desc, my_index)?;
                    rotated = (!desc.authenticated_data.is_empty()).then(|| ClientId {
                        bytes: desc.authenticated_data.clone(),
                    });
                }
                _ => return Err(TwoMlsPqError::Mls),
            }
            // The classical ratchet leads the credential sequence; a PQ handoff may
            // only catch a leaf up to an ALREADY-canonical identity.
            if let Some(announced) = &rotated {
                if !canonical_theirs.iter().any(|h| h == &announced.bytes) {
                    return Err(TwoMlsPqError::CredentialRejected);
                }
            }
            let builder = send_pq.commit_builder();
            let builder = match &cross_psk {
                Some(psk) => psk.add_to_commit(builder)?,
                None => builder,
            };
            let out = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
            send_pq
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
            // The commit folded the peer's Upd' from the cache: reject a roster change
            // (only an Update is legitimate there — an Add would grow the roster
            // through OUR commit).
            apq::ensure_two_party(send_pq)?;
            out.commit_message
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        // Our send-PQ commit above consumed the one-shot cross-party PSK (when one rode
        // it); drop it from the ephemeral store now the commit is applied.
        if let Some(psk) = &cross_psk {
            inner.forget_psk(psk.storage_id());
        }
        // Counter-Upd'(self) for the initiator's send-PQ (our recv mirror).
        let counter = {
            let recv_pq = inner
                .recv_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            recv_pq
                .propose_update(Vec::new())
                .map_err(|_| TwoMlsPqError::Mls)?
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        inner.pq_inflight = Some(PqInflight::RekeyResponded);
        inner.pending_pq_outbound = Some(encode_pq_rekey_commit(commit_bytes, counter));
        // Our send-PQ's pq_epoch advanced (updatePath commit) — capture its new key.
        inner.record_pq_header_key()?;
        Ok(rotated)
    }

    /// Apply an A.5 rekey Commit' (0x11). As the initiator mid-operation (frame carries
    /// the counter-Upd'), apply the peer's commit to our recv mirror, commit the
    /// counter-Upd' on our own send-PQ with the freshly-exported cross-PSK, park the
    /// final 0x11, and return `true` (pick it up via `pq_take_pending_outbound`). As the
    /// responder (empty counter slot), apply the final commit, take the turn, and return
    /// `false` — the operation is complete.
    pub fn pq_rekey_apply(&self, msg: Vec<u8>) -> Result<bool> {
        let msg = self.lock().open_or_raw(msg);
        let (commit_bytes, counter_bytes) = decode_pq_rekey_commit(&msg)?;
        let mut inner = self.lock();
        // Reject unsolicited commits before parsing or registering anything.
        if !matches!(
            inner.pq_inflight,
            Some(PqInflight::RekeyInitiated { .. }) | Some(PqInflight::RekeyResponded)
        ) {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let commit_msg = MlsMessage::from_bytes(&commit_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let client = inner.client.clone();
        // Both roles pre-register their own send-PQ cross-party PSK so the peer's commit
        // (which cross-injects from its recv-PQ mirror = our send-PQ) can resolve it. Export
        // it at most once per send-PQ epoch (`last_send_pq_exported`): the value stays in the
        // store, and re-exporting a consumed leaf across two re-keys without our send-PQ
        // advancing would fail. (The send-PQ analogue of the classical `send_psk_ledger`.)
        let pre_registered_send_pq: Option<ExternalPskId> = {
            let inner: &mut SessionInner = &mut inner;
            let send_pq_epoch = inner
                .send_group
                .as_ref()
                .and_then(|g| g.pq.as_ref())
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .current_epoch();
            if inner.last_send_pq_exported != Some(send_pq_epoch) {
                let send_pq = inner
                    .send_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let exported = export_psk(send_pq, PskDomain::CrossParty)?;
                inner.register_psk(exported.storage_id(), exported.psk());
                inner.last_send_pq_exported = Some(send_pq_epoch);
                // Held so we can drop it once the peer's commit (below) has resolved it —
                // it is consumed within this same call. When the export is skipped
                // (watermark already at this epoch) the peer's commit skips referencing it
                // too, so there is nothing new to forget.
                Some(exported.storage_id().clone())
            } else {
                None
            }
        };
        match inner.pq_inflight.take() {
            Some(PqInflight::RekeyInitiated { rotating }) => {
                if counter_bytes.is_empty() {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                let counter_msg =
                    MlsMessage::from_bytes(&counter_bytes).map_err(|_| TwoMlsPqError::Mls)?;
                // Apply the responder's Commit' to our recv mirror, then export the
                // cross-PSK from its NEW epoch (§A.5: "Export PSK from [BSG-PQ]").
                let exported = {
                    let inner: &mut SessionInner = &mut inner;
                    let recv_pq = inner
                        .recv_group
                        .as_mut()
                        .and_then(|g| g.pq.as_mut())
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    match recv_pq
                        .process_incoming_message(commit_msg)
                        .map_err(|_| TwoMlsPqError::Mls)?
                    {
                        // A.5 commits are PQ-group-only and carry no AppDataUpdate —
                        // the bumped pq_epoch reconciles at the next A.3 bind. An
                        // attestation smuggled in here is rejected.
                        ReceivedMessage::Commit(desc) => {
                            if commit_attestation(&desc)?.is_some() {
                                return Err(TwoMlsPqError::ApqInfoMismatch);
                            }
                        }
                        _ => return Err(TwoMlsPqError::Mls),
                    }
                    // A peer commit must never change the two-party shape.
                    apq::ensure_two_party(&*recv_pq)?;
                    let recv_pq_epoch = recv_pq.current_epoch();
                    // The apply just advanced recv-PQ, so this is a fresh epoch — inject and
                    // bump the watermark (a later respond at this epoch skips). Guarded by
                    // the watermark for symmetry with the classical / respond paths.
                    if inner.last_cross_injected_pq == Some(recv_pq_epoch) {
                        None
                    } else {
                        let exported = export_psk(recv_pq, PskDomain::CrossParty)?;
                        inner.last_cross_injected_pq = Some(recv_pq_epoch);
                        Some(exported)
                    }
                };
                if let Some(psk) = &exported {
                    inner.register_psk(psk.storage_id(), psk.psk());
                }
                // The responder's Commit' we just applied to our recv-PQ mirror consumed the
                // send-PQ cross-PSK we pre-registered above; drop it from the store.
                if let Some(id) = &pre_registered_send_pq {
                    inner.forget_psk(id);
                }
                // Commit the counter-Upd' on our own send-PQ. If this rekey carries a
                // credential handoff, the commit's updatePath also moves OUR committer
                // leaf to the new principal's signing key (the Upd' in `pq_rekey_begin`
                // covered our leaf in the peer's send-PQ; this covers the other group).
                let handoff = match &rotating {
                    Some(new_id) => {
                        // The session client must not have changed mid-operation.
                        if client.client_id() != *new_id {
                            return Err(TwoMlsPqError::SessionNotReady);
                        }
                        Some(client.combiner().pq_signature_keypair())
                    }
                    None => None,
                };
                let commit2 = {
                    let send_pq = inner
                        .send_group
                        .as_mut()
                        .and_then(|g| g.pq.as_mut())
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    let my_index = send_pq.current_member_index();
                    match send_pq
                        .process_incoming_message(counter_msg)
                        .map_err(map_credential_err)?
                    {
                        // The counter slot may only carry the peer's own-leaf Update.
                        ReceivedMessage::Proposal(desc) => require_peer_update(&desc, my_index)?,
                        _ => return Err(TwoMlsPqError::Mls),
                    }
                    let handoff = match handoff {
                        Some((new_signer, new_public)) => {
                            // Catch-up: the moved leaf carries the canonical credential.
                            let identity = SigningIdentity::new(
                                BasicCredential::new(client.client_id().bytes.clone())
                                    .into_credential(),
                                new_public,
                            );
                            Some((new_signer, identity))
                        }
                        None => None,
                    };
                    let mut builder = send_pq.commit_builder();
                    if let Some(psk) = &exported {
                        builder = psk.add_to_commit(builder)?;
                    }
                    if let Some((new_signer, identity)) = handoff {
                        builder = builder.set_new_signing_identity(new_signer, identity);
                    }
                    let out = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
                    send_pq
                        .apply_pending_commit()
                        .map_err(|_| TwoMlsPqError::Mls)?;
                    // The commit folded the peer-supplied counter proposal: reject a
                    // roster change (only an Update is legitimate there).
                    apq::ensure_two_party(send_pq)?;
                    out.commit_message
                        .to_bytes()
                        .map_err(|_| TwoMlsPqError::Mls)?
                };
                // Our counter commit above consumed the recv-PQ cross-PSK we exported and
                // registered for it; drop it now the commit is applied.
                if let Some(psk) = &exported {
                    inner.forget_psk(psk.storage_id());
                }
                // Our operation completes once the peer applies; the turn passes.
                inner.pq_turn_mine = false;
                inner.pending_pq_outbound = Some(encode_pq_rekey_commit(commit2, Vec::new()));
                // Our send-PQ's pq_epoch advanced (the counter-Upd' commit) — capture it.
                inner.record_pq_header_key()?;
                Ok(true)
            }
            Some(PqInflight::RekeyResponded) => {
                if !counter_bytes.is_empty() {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                match recv_pq
                    .process_incoming_message(commit_msg)
                    .map_err(|_| TwoMlsPqError::Mls)?
                {
                    // Like the responder's Commit' above: A.5 carries no AppDataUpdate.
                    ReceivedMessage::Commit(desc) => {
                        if commit_attestation(&desc)?.is_some() {
                            return Err(TwoMlsPqError::ApqInfoMismatch);
                        }
                    }
                    _ => return Err(TwoMlsPqError::Mls),
                }
                // A peer commit must never change the two-party shape.
                apq::ensure_two_party(recv_pq)?;
                // The initiator's final Commit' we just applied consumed the send-PQ
                // cross-PSK we pre-registered above; drop it from the store.
                if let Some(id) = &pre_registered_send_pq {
                    inner.forget_psk(id);
                }
                // We finished receiving this operation; the next one is ours to start.
                inner.pq_turn_mine = true;
                Ok(false)
            }
            // Unreachable: the guard at the top of this function admits only the two
            // rekey states. Kept (with the state restored) purely as exhaustiveness
            // defense should the guard and this match ever drift apart.
            other => {
                inner.pq_inflight = other;
                Err(TwoMlsPqError::SessionNotReady)
            }
        }
    }
}

/// The rendezvous exporter both routing surfaces derive:
/// `exportSecret("rendezvous", "TwoMLS", 32)` on a group's classical (message) half.
/// Listen-side and post-side addresses align because they are this one derivation.
fn rendezvous_secret(group: &crate::key_package_store::MlsGroup) -> Result<Vec<u8>> {
    group
        .export_secret(RENDEZVOUS_LABEL, RENDEZVOUS_CONTEXT, RENDEZVOUS_LEN)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

// Header encryption: the outer symmetric seal that turns every rendezvous-channel frame
// into one opaque blob (no plaintext tag, group id, epoch, or Welcome metadata). The key
// is an exporter of a group's half under a label distinct from the rendezvous and PSK
// exporters, so the derivations never collide. Both parties compute the same key on the
// same group at the same epoch; outsiders cannot.
//
// Two key families, one per stream, so each header key tracks the clock of the frames it
// protects (the classical and PQ ratchets run on independent, async cadences):
//   * message-path frames (0x01/0x03) seal under the CLASSICAL half's exporter, keyed by
//     the classical epoch — `header_key` / `recv_header_keys`;
//   * PQ side-band frames (0x05–0x11) seal under the PQ half's exporter, keyed by
//     `pq_epoch` — `header_key_pq` / `recv_header_keys_pq`.
// The one exception is the pre-A.4 BOOTSTRAP_KP, whose recv-PQ group does not exist yet;
// it falls back to the classical seal (see `SessionInner::seal_side_band`).
//
// The two families only choose which group HALF derives the key; the AEAD that consumes
// it is a single configured choice (`providers::HEADER_AEAD_SUITE`), independent of the
// group suites, and the key length is that AEAD's key size (`header_key_len`) — so the
// header seal is crypto-agile as its own layer.
const HEADER_KEY_LABEL: &[u8] = b"germ.network.twomlspq.headerKey.v1";
const HEADER_KEY_PQ_LABEL: &[u8] = b"germ.network.twomlspq.headerKey.pq.v1";
// PQ header window depth: the side-band is turn-based with one op in flight, so `pq_epoch`
// advances slowly; a few recent keys cover any lag. Session-owned secrets, so this is a
// plain "keep newest N", not tied to mls-rs retention or the (classical-only) rendezvous.
const PQ_HEADER_WINDOW: usize = 4;

/// The header key length: the key size of the configured header AEAD
/// (`providers::HEADER_AEAD_SUITE`), so the exporter output always matches whatever cipher
/// seals the frame — no hardcoded assumption of a 32-byte (ChaCha) key.
fn header_key_len() -> Result<usize> {
    use mls_rs::CipherSuiteProvider;
    Ok(providers::header_aead_suite()?.aead_key_size())
}

/// Derive the message-path header key for a group at its current classical epoch:
/// `exportSecret(label, group_id, header_key_len())` on the classical half. Context = the
/// group id (domain separation on top of the group-specific exporter, matching the
/// classical stack's convention).
fn header_key(group: &crate::key_package_store::MlsGroup) -> Result<Vec<u8>> {
    group
        .export_secret(HEADER_KEY_LABEL, group.group_id(), header_key_len()?)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

/// Derive the PQ side-band header key for a group at its current `pq_epoch`:
/// `exportSecret(pq_label, group_id, header_key_len())` on the PQ half. Same exporter shape
/// as `header_key` (both halves are `Group<_>`), a distinct label, and keyed by the PQ
/// clock so the side-band's outer seal rotates with the PQ ratchet, not classical traffic.
fn header_key_pq(group: &crate::key_package_store::PqMlsGroup) -> Result<Vec<u8>> {
    group
        .export_secret(HEADER_KEY_PQ_LABEL, group.group_id(), header_key_len()?)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

/// The APQ epoch pair for a combiner group: the PQ side-band epoch (0 while that
/// half is deferred) and the classical message epoch. Single home for the
/// pq-zero-when-deferred rule, shared by `epochs()` and `encrypt()`.
fn apq_epochs(group: &CombinerGroup) -> crate::ApqEpochs {
    crate::ApqEpochs {
        pq_epoch: group.pq.as_ref().map(|p| p.current_epoch()).unwrap_or(0),
        classical_epoch: group.classical.current_epoch(),
    }
}

impl SessionInner {
    /// Register an exported PSK into every store this session's groups resolve from.
    fn register_psk(&self, psk_id: &ExternalPskId, psk: &PreSharedKey) {
        apq::register_psk_stores(&self.psk_stores, psk_id, psk);
    }

    /// Drop a one-shot exported PSK from every store this session's groups resolve from —
    /// the counterpart of [`SessionInner::register_psk`]. Used to bound the ephemeral PQ
    /// store: an A.5 cross-party PSK is consumed within the same call that registers it, so
    /// it is forgotten once the consuming commit/apply completes (the leaf can never be
    /// referenced again — the send-PQ / recv-PQ watermarks keep both parties in lockstep).
    fn forget_psk(&self, psk_id: &ExternalPskId) {
        apq::forget_psk_stores(&self.psk_stores, psk_id);
    }

    /// Track `client`'s PSK stores so future `register_psk` calls reach any group half
    /// this client creates or joins for the session (A.4 bootstrap, return-welcome join).
    /// Idempotent per client: the common paths re-track the construction client, and
    /// only a Phase 8 rotation actually introduces new stores.
    fn track_psk_stores(&mut self, client: &Arc<TwoMlsPqPrincipal>) {
        if Arc::ptr_eq(client, &self.psk_stores_from) {
            return;
        }
        self.psk_stores_from = Arc::clone(client);
        self.psk_stores
            .push(client.combiner().classical().secret_store());
        self.psk_stores.push(client.combiner().pq().secret_store());
    }

    /// Capture the send group's classical-half rendezvous exporter at its current epoch.
    /// Idempotent per epoch. Called wherever that epoch can advance — group creation,
    /// the A.2/rotation commits in `prepare_to_encrypt`, the A.3 bind — and from
    /// `should_listen_on` as a backstop.
    ///
    /// The listen window follows mls-rs's own epoch retention rather than a second,
    /// invented knob: on each new epoch the group is flushed (`write_to_storage`,
    /// which applies mls-rs's `max_epoch_retention` trim) and addresses whose epoch
    /// the injected group-state storage no longer retains are dropped with it.
    fn record_listen_rendezvous(&mut self) -> Result<()> {
        let Some(send) = self.send_group.as_mut() else {
            return Ok(());
        };
        let group = send.message_group();
        let epoch = group.current_epoch();
        if self.listen_rendezvous.contains_key(&epoch) {
            return Ok(());
        }
        let secret = rendezvous_secret(group)?;
        // The header receive key for this epoch is captured in lockstep with the listen
        // address: both are send-group exporters only derivable while this epoch is live,
        // and retaining them together keeps "routable ⟺ openable" exact.
        let header = header_key(group)?;
        self.listen_rendezvous.insert(epoch, secret);
        self.recv_header_keys.insert(epoch, header);

        send.message_group_mut()
            .write_to_storage()
            .map_err(|_| TwoMlsPqError::Mls)?;
        let group_id = send.message_group().group_id().to_vec();
        // Probe the storage captured at session construction — the one the send group
        // actually flushes into. NOT `self.client`'s: after a Phase 8 rotation that is
        // the new principal's client with a fresh, empty storage, and probing it would
        // prune every prior epoch's listen address (dropping in-flight traffic).
        let storage = &self.send_group_storage;
        let retain = |e: u64| e == epoch || matches!(storage.epoch(&group_id, e), Ok(Some(_)));
        self.listen_rendezvous.retain(|&e, _| retain(e));
        self.recv_header_keys.retain(|&e, _| retain(e));
        Ok(())
    }

    /// Capture my send-PQ group's header key at its current `pq_epoch` into the PQ
    /// receive window. Idempotent per `pq_epoch`; a no-op until the send-PQ half exists
    /// (deferred on the acceptor until the A.4 bootstrap). Called wherever the send-PQ
    /// group is created or its `pq_epoch` advances — group creation (`initiate`,
    /// `pq_bootstrap_respond`), the A.3 bind (`pq_ratchet_bind`), and the A.5 commits
    /// (`pq_rekey_respond` / `pq_rekey_apply`). Retention is a plain keep-newest window
    /// (these are session-owned secrets; the PQ side-band has no rendezvous and no
    /// mls-rs-retention story to follow).
    fn record_pq_header_key(&mut self) -> Result<()> {
        let Some(send) = self.send_group.as_ref() else {
            return Ok(());
        };
        let Some(send_pq) = send.pq.as_ref() else {
            return Ok(());
        };
        let epoch = send_pq.current_epoch();
        if self.recv_header_keys_pq.contains_key(&epoch) {
            return Ok(());
        }
        self.recv_header_keys_pq
            .insert(epoch, header_key_pq(send_pq)?);
        // Keep only the newest PQ_HEADER_WINDOW epochs.
        while self.recv_header_keys_pq.len() > PQ_HEADER_WINDOW {
            if let Some(&oldest) = self.recv_header_keys_pq.keys().next() {
                self.recv_header_keys_pq.remove(&oldest);
            }
        }
        Ok(())
    }

    /// Seal an outbound frame under the header key of MY recv group (the peer's send
    /// group) at its current classical epoch: `[random nonce][AEAD ct+tag]`, empty AAD.
    /// The peer opens it from its own send-group window (`recv_header_keys`). Requires a
    /// recv group — the one pre-establishment frame (the initiator's initial welcome on
    /// the invitation channel) has no symmetric key and is not sealed here.
    fn seal(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let recv = self
            .recv_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?;
        self.seal_with(&header_key(&recv.classical)?, frame)
    }

    /// Seal a PQ side-band frame under the PQ family — `header_key_pq(recv_group.pq)` at
    /// its current `pq_epoch`, the peer opening it from its own send-PQ window. Falls back
    /// to the classical `seal` when the recv-PQ group does not exist yet: the only such
    /// frame is the pre-A.4 `BOOTSTRAP_KP` (its recv-PQ is the group the bootstrap is
    /// creating), a one-time establishment frame whose cadence is irrelevant, and the
    /// receiver opens it from its classical window via the dual-window `try_open`.
    fn seal_side_band(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let recv = self
            .recv_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?;
        match recv.pq.as_ref() {
            Some(pq) => self.seal_with(&header_key_pq(pq)?, frame),
            None => self.seal(frame),
        }
    }

    /// Seal `frame` under `key`: `[random nonce][AEAD ct+tag]`, empty AAD.
    fn seal_with(&self, key: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
        use mls_rs::CipherSuiteProvider;
        let cs = providers::header_aead_suite()?;
        let mut out = vec![0u8; cs.aead_nonce_size()];
        cs.random_bytes(&mut out).map_err(|_| TwoMlsPqError::Mls)?;
        let ct = cs
            .aead_seal(key, frame, None, &out)
            .map_err(|_| TwoMlsPqError::Mls)?;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Remove the header seal if this window can, else return the blob unchanged. Lets the
    /// receive entry points (`process_incoming`, the `pq_*` receivers) accept either the
    /// sealed blob straight off the wire OR the already-opened `frame` a host took from
    /// `open_incoming` — an honestly-sealed frame always opens, an already-plaintext frame
    /// fails AEAD auth under every key and passes through. (This is a receiver convenience;
    /// the metadata-hiding property is a sender guarantee — every outbound frame is sealed
    /// — so accepting an opened frame here downgrades nothing an observer can see.)
    fn open_or_raw(&self, blob: Vec<u8>) -> Vec<u8> {
        match self.try_open(&blob) {
            Ok(Some(frame)) => frame,
            _ => blob,
        }
    }

    /// Trial-decrypt an inbound blob against the header receive window, newest epoch
    /// first (the common case is the newest or second-newest key). `None` if no window
    /// key opens it — an out-of-window or garbage frame, indistinguishable by
    /// construction. Every candidate key is an honestly-derived secret, so trial
    /// decryption with a non-committing AEAD is safe here (no attacker-chosen keys, so no
    /// partitioning oracle).
    fn try_open(&self, blob: &[u8]) -> Result<Option<Vec<u8>>> {
        use mls_rs::CipherSuiteProvider;
        let cs = providers::header_aead_suite()?;
        let nonce_size = cs.aead_nonce_size();
        if blob.len() < nonce_size {
            return Ok(None);
        }
        let (nonce, ct) = blob.split_at(nonce_size);
        // Both families use the same AEAD; only the key set differs. A message frame
        // authenticates only under a classical-window key and a side-band frame only
        // under a PQ-window key (the pre-A.4 BOOTSTRAP_KP under classical), so trying
        // both windows resolves either without ambiguity. Newest epoch first in each.
        let windows = [&self.recv_header_keys, &self.recv_header_keys_pq];
        for keys in windows {
            for key in keys.values().rev() {
                if let Ok(pt) = cs.aead_open(key, ct, None, nonce) {
                    return Ok(Some(pt.to_vec()));
                }
            }
        }
        Ok(None)
    }

    /// Record the cross-party TwoMLS-PSK for our send group's current epoch in the
    /// session-owned ledger. Called after every commit we apply on the send group (and
    /// lazily from `inject_send_psks`), so the ledger always covers the epochs the peer
    /// might still reference.
    fn remember_send_psk(&mut self) -> Result<()> {
        let epoch = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .classical
            .current_epoch();
        // The -02 exporter tree consumes each component's leaf on first export, so a
        // given (send group, epoch) can be exported at most once: skip if this epoch is
        // already ledgered (this is called repeatedly per epoch, e.g. from every
        // `inject_send_psks`, and — after an archive/restore — for an epoch already
        // consumed and carried in the restored ledger).
        if self.send_psk_ledger.iter().any(|(e, _)| *e == epoch) {
            return Ok(());
        }
        let send = self
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let exported = export_psk(&mut send.classical, PskDomain::CrossParty)?;
        self.send_psk_ledger.push_back((epoch, exported));
        while self.send_psk_ledger.len() > SEND_PSK_WINDOW {
            if let Some((_, evicted)) = self.send_psk_ledger.pop_front() {
                self.retired_send_psks.push(evicted.storage_id().clone());
            }
        }
        Ok(())
    }

    /// Live-inject the session's PSK ledger, immediately before processing a frame whose
    /// commit may reference one of these PSKs. Injection targets the stores each live
    /// group actually resolves from (captured at the group's creation — the current
    /// client's stores are the wrong target after a principal rotation), plus the current
    /// client's stores for joins that are about to create a group. Retired ids are then
    /// deleted from the same targets, so the stores' contents stay bounded by the ledger
    /// and nothing remains resolvable that the session no longer vouches for.
    fn inject_send_psks(&mut self) -> Result<()> {
        self.remember_send_psk()?;
        for (_, exported) in &self.send_psk_ledger {
            let (psk_id, psk) = (exported.storage_id(), exported.psk());
            register_psk(self.client.combiner(), psk_id, psk);
            if let Some(recv) = &self.recv_group {
                recv.register_psk(psk_id, psk);
            }
            if let Some(send) = &self.send_group {
                send.register_psk(psk_id, psk);
            }
        }
        for psk_id in self.retired_send_psks.drain(..) {
            forget_psk(self.client.combiner(), &psk_id);
            if let Some(recv) = &self.recv_group {
                recv.forget_psk(&psk_id);
            }
            if let Some(send) = &self.send_group {
                send.forget_psk(&psk_id);
            }
        }
        Ok(())
    }

    /// Join the recv groups from an APQWelcome — idempotently. Welcomes cannot be assumed
    /// to arrive exactly once: the peer re-staples its welcome on every message frame
    /// until its first commit, and hosts may also deliver the standalone copy. Processing
    /// therefore keys off the recorded digest of the welcome we actually joined from:
    /// - first delivery → join, record the digest;
    /// - byte-identical re-delivery → no-op (the join consumed the one key package, so a
    ///   second attempt would fail, and must never be reached);
    /// - a *different* welcome while the recv group is live → `UnexpectedWelcome` (an
    ///   unexpected re-invite on an established session).
    fn process_welcome(&mut self, welcome: &[u8]) -> Result<()> {
        let digest = crate::sha256(welcome);
        if self.recv_group.is_some() {
            return if self.joined_welcome_digest.as_deref() == Some(digest.as_slice()) {
                Ok(())
            } else {
                Err(TwoMlsPqError::UnexpectedWelcome)
            };
        }

        let client = self.client.clone();
        // The joins below resolve PSKs from the CURRENT client's stores (a Phase 8
        // rotation may have replaced the constructing client) — track them first.
        self.track_psk_stores(&client);

        // Live-inject the session-held cross-party TwoMLS-PSKs (our send group's
        // recent epochs) before joining the peer's bound groups.
        if self.send_group.is_some() {
            self.inject_send_psks()?;
        }

        let (classical_welcome, pq_welcome) = decode_apq_welcome(welcome)?;
        // Reject a welcome whose suite(s) don't match this session's fixed pair before
        // joining — an early, clear failure instead of an opaque late mls-rs error.
        validate_welcome_halves(self.suite, &classical_welcome, &pq_welcome)?;
        // The joins validate every leaf in the received tree, including a creator this
        // session may not know yet (the peer's dedicated establishment principal) —
        // open the AS adoption window strictly around them; the creator is recorded
        // as the peer's canonical identity right below.
        client
            .combiner()
            .auth_view()
            .with(|core| core.adopting = true);
        // An empty PQ slot is the acceptor's deferred (A.4) return welcome: join the
        // classical group only; the PQ half arrives with the bootstrap flow.
        let suite = self.suite;
        let joined: Result<CombinerGroup> = (|| {
            if pq_welcome.is_empty() {
                let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
                // -02 joiner verification, deferred shape: the classical half's APQInfo
                // must record the PQ side as pending (EPOCH_UNBOUND) with a non-empty
                // pre-allocated group id — the id the A.4 bootstrap must later use. A
                // welcome without an APQInfo at all is a downgrade attempt.
                verify_apqinfo_deferred(&classical, suite)?;
                Ok(CombinerGroup::from_client(
                    client.combiner(),
                    classical,
                    None,
                ))
            } else {
                // Join the PQ group first, then re-derive the intra-party APQ-PSK from it.
                let mut pq = join_group_from_welcome(client.pq(), &pq_welcome)?;
                let exported = export_psk(&mut pq, PskDomain::Apq)?;
                self.register_psk(exported.storage_id(), exported.psk());
                // Join the classical group (bound with the cross-party + APQ PSKs).
                let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
                // -02 joiner verification, full-pair shape: both halves carry a
                // coherent, mutually consistent APQInfo naming exactly these groups,
                // and both rosters hold the same two identities.
                verify_apqinfo_pair(&classical, &pq, suite)?;
                apq::component::ensure_membership_consistent(&classical, &pq)?;
                Ok(CombinerGroup::from_client(
                    client.combiner(),
                    classical,
                    Some(pq),
                ))
            }
        })();
        client
            .combiner()
            .auth_view()
            .with(|core| core.adopting = false);
        let recv_group = joined?;
        // Adopt the peer's principal from the send group's creator leaf. The peer may
        // have created this group under a dedicated per-session principal
        // (`TwoMlsPqInvitation::receive(new_client_id:)`) whose id differs from the
        // invitation identity we initiated toward. Authenticity: the cross-party PSK
        // bound into this welcome is derivable only inside OUR send group, so the
        // creator is provably the invitation holder — the id itself is app-layer
        // meaning, exactly like a rotation commit's authenticated_data announcement.
        let creator_id = {
            let classical = &recv_group.classical;
            let mine = classical.current_member_index();
            // Both groups in this protocol are exactly two members: the creator (leaf 0)
            // and the added member. The peer is whichever leaf isn't ours.
            let peer_index = if mine == 0 { 1 } else { 0 };
            sender_client_id(classical, peer_index)?
        };
        self.with_auth(|core| core.theirs.commit(creator_id.clone()));
        self.their_state = PrincipalState::Sync {
            client_id: ClientId { bytes: creator_id },
        };
        self.recv_group = Some(recv_group);
        self.joined_welcome_digest = Some(digest);
        Ok(())
    }

    /// Run `f` against the session-canonical AS core.
    fn with_auth<R>(&self, f: impl FnOnce(&mut apq::authentication::AuthCore) -> R) -> R {
        let mut core = self.auth_core.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut core)
    }

    /// Validate that `proposal_bytes` is the peer's own-leaf Update carrying credential
    /// `proposing`, leaving the send group's proposal cache **untouched**. Only
    /// `process_incoming_message` authenticates the sender's signature and leaf, and it
    /// caches the proposal — so process to validate, then immediately `clear_proposal_cache`.
    /// This mutates no session state (the caller records the approval only on `Ok`), so a
    /// rejected `queue_proposal` is a pure no-op and there is nothing cached to poison the
    /// next commit; the approved proposal is re-applied to the group at commit time.
    fn validate_offered_update(&mut self, proposal_bytes: &[u8], proposing: &[u8]) -> Result<()> {
        let msg = MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let send = self
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let my_index = send.classical.current_member_index();
        let processed = send.classical.process_incoming_message(msg);
        send.classical.clear_proposal_cache();
        let desc = match processed.map_err(map_credential_err)? {
            ReceivedMessage::Proposal(desc) => desc,
            _ => return Err(TwoMlsPqError::Mls),
        };
        require_peer_update(&desc, my_index)?;
        let leaf_id = match &desc.proposal {
            Proposal::Update(update) => match &update.signing_identity().credential {
                mls_rs::identity::Credential::Basic(basic) => basic.identifier.as_slice(),
                _ => return Err(TwoMlsPqError::ProposalRejected),
            },
            _ => return Err(TwoMlsPqError::ProposalRejected),
        };
        if leaf_id != proposing {
            return Err(TwoMlsPqError::ProposalRejected);
        }
        Ok(())
    }

    /// Routine round (A.2): commit in OUR OWN send group — only the owner commits — and
    /// stage an Upd(self) proposal for the peer's send group to staple alongside. With an
    /// app-approved queued proposal (already cached in the send group via `queue_proposal`),
    /// the commit consumes it and additionally refreshes the cross-party TwoMLS-PSK
    /// exported from the recv group (the peer derives the same PSK from its send group).
    /// `selected` names the staged rotation candidate whose credential this round's
    /// Upd(self) proposes (`prepare_to_encrypt(Some(id))`); `None` re-proposes the
    /// session's current identity. Different rounds may select different candidates —
    /// the peer's commit picks the winner.
    fn prepare_ratchet_commit(
        &mut self,
        selected: Option<ClientId>,
    ) -> Result<crate::PrepareEncryptResult> {
        let folded = self.queued_proposal.take();
        let did_commit = folded.is_some();

        // Commit our send group only when consuming the peer's approved Upd (cached via
        // `queue_proposal` in the current epoch — committing on routine rounds would
        // invalidate the peer's epoch-bound proposal). The commit also refreshes the
        // cross-party TwoMLS-PSK exported from the recv group.
        if did_commit {
            // Capture the departing epoch's PSK before committing past it: a peer frame in
            // flight may reference it, and mls-rs can only export the current epoch.
            self.remember_send_psk()?;

            // Cross-party TwoMLS-PSK from our recv group — but only when the peer's send
            // group has advanced since we last bound it (event-driven; see
            // `last_cross_injected`). If it is unchanged, the entanglement from our previous
            // injection still holds and re-deriving would consume the same exporter leaf for
            // no new entropy, so this commit carries no cross-party PSK (it still folds the
            // peer's Upd and refreshes our own leaf via the updatePath). The durable copy is
            // the peer's problem (it is THEIR send-group PSK, held in their ledger); we
            // derive and live-inject into the send group's stores just before the commit.
            let recv_epoch = self
                .recv_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .classical
                .current_epoch();
            let cross_psk = if self.last_cross_injected == Some(recv_epoch) {
                None
            } else {
                let recv = self
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let exported = export_psk(&mut recv.classical, PskDomain::CrossParty)?;
                let send = self
                    .send_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.register_psk(exported.storage_id(), exported.psk());
                // Advance the watermark now — deliberately BEFORE the build/apply below,
                // not after. `export_psk` has already consumed the recv exporter leaf, and
                // that consumption is irreversible (once per epoch, for FS). So this is not
                // a "commit succeeded" flag; it records "this leaf is spent." If build/apply
                // then fails, no commit reaches the peer (no divergence), and a retry at this
                // same `recv_epoch` MUST take the skip branch above — a second export of the
                // spent leaf would error. The prior binding's entanglement still holds and the
                // next peer advance re-triggers a fresh injection. The only observable cost of
                // a mid-commit failure is that this one recv-epoch's re-binding is skipped and
                // the folded peer proposal is dropped (the peer re-proposes on its next
                // advance) — both self-healing, neither a security property.
                self.last_cross_injected = Some(recv_epoch);
                Some(exported)
            };
            // Own-leaf catch-up: when the session's canonical identity has moved past
            // this send group's creator leaf (the peer's commit of our proposal is the
            // canonical step; our own groups lag), this commit's updatePath moves the
            // leaf to the current identity. A commit folding an Update always carries
            // a path (RFC 9420), so the handoff cannot be silently dropped.
            let current_id = self.client.client_id();
            let handoff = {
                let send = self
                    .send_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let mine = send.classical.current_member_index();
                if sender_client_id(&send.classical, mine)? != current_id.bytes {
                    let (signer, public) = self.client.combiner().classical_signature_keypair();
                    let identity = SigningIdentity::new(
                        BasicCredential::new(current_id.bytes.clone()).into_credential(),
                        public,
                    );
                    Some((signer, identity))
                } else {
                    None
                }
            };
            // Re-apply the one approved peer proposal (validated and un-cached at
            // `queue_proposal`), so the commit folds exactly it — build immediately, so
            // only ever one Update is cached at build time.
            if let Some((_, _, proposal_bytes)) = &folded {
                let msg = MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
                let send = self
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.classical
                    .process_incoming_message(msg)
                    .map_err(map_credential_err)?;
            }
            let commit_output = {
                let send = self
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let mut builder = send.classical.commit_builder();
                if let Some(psk) = &cross_psk {
                    builder = psk.add_to_commit(builder)?;
                }
                if let Some((signer, identity)) = handoff {
                    builder = builder.set_new_signing_identity(signer, identity);
                }
                builder.build().map_err(map_credential_err)?
            };
            {
                let send = self
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.classical
                    .apply_pending_commit()
                    .map_err(|_| TwoMlsPqError::Mls)?;
                // This commit folds the app-approved peer proposal from the cache: if
                // the peer smuggled anything but an Update there (an Add would grow the
                // roster through OUR commit), reject the result.
                apq::ensure_two_party(&send.classical)?;
                // The commit consumed the one-shot recv-group PSK (when one rode it); drop
                // it from the store.
                if let Some(psk) = &cross_psk {
                    send.forget_psk(psk.storage_id());
                }
            }
            // OUR commit of the peer's approved Upd is the canonical step of THEIR
            // credential sequence: the committed credential defines their next identity.
            if let Some((_, proposing, _)) = &folded {
                if *proposing != self.their_state.client_id().bytes {
                    self.with_auth(|core| core.theirs.commit(proposing.clone()));
                    self.their_state = PrincipalState::Sync {
                        client_id: ClientId {
                            bytes: proposing.clone(),
                        },
                    };
                }
            }
            // Our send group advanced: record the new epoch's PSK in the session ledger.
            self.remember_send_psk()?;
            // The new commit becomes the staple every frame re-sends until superseded.
            self.current_staple = commit_output
                .commit_message
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?;
            // This fold advanced our send epoch, so any still-unapproved offer is now
            // bound to the prior epoch — drop it (the queued one was consumed by the
            // `take` above). Mirrors the A.3 bind's clear; the peer re-proposes at the
            // new epoch once it sees this commit's staple.
            self.offered_proposal = None;
        }

        // Upd(self) into the peer's send group — a proposal only; the peer commits it.
        // The proposal carries an identity: a selected staged candidate (the app's
        // offer for its next credential), or the session's current identity whenever
        // the recv-group leaf still lags it (converging e.g. the dedicated
        // establishment principal into the founding leaf); otherwise a plain key
        // refresh of the unchanged leaf.
        // Steer a deferred rotation onto this round: when the app did not explicitly
        // select a candidate and a slot has freed (a prior canonicalization cleared the
        // pool), promote the parked request — mint, admit, authorize — and propose it
        // this round in place of the default self-refresh.
        let selected = match selected {
            Some(id) => Some(id),
            None if self.staged_candidates.len() < CANDIDATE_WINDOW => {
                match self.deferred_candidate.take() {
                    Some(id) => {
                        let candidate = TwoMlsPqPrincipal::new(id.clone())?;
                        candidate.combiner().auth_view().rebind(&self.auth_core);
                        self.with_auth(|core| core.mine.authorize(id.clone()));
                        self.staged_candidates.push(candidate);
                        // A rotation to this candidate is now in flight (proposed this
                        // round, awaiting the peer's commit) — report it as `Pending`.
                        // A prior canonicalization set `Sync` when it committed an
                        // earlier candidate; without this, the promoted rotation would
                        // be invisible in `my_principal_state`.
                        self.my_state = PrincipalState::Pending {
                            old: self.client.client_id(),
                            new: ClientId { bytes: id.clone() },
                        };
                        Some(ClientId { bytes: id })
                    }
                    None => None,
                }
            }
            None => None,
        };
        let proposing_client = match &selected {
            Some(id) => Some(Arc::clone(
                self.staged_candidates
                    .iter()
                    .find(|c| c.client_id() == *id)
                    .ok_or(TwoMlsPqError::SessionNotReady)?,
            )),
            None => None,
        };
        let proposal_msg = {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let leaf_id = {
                let mine = recv.classical.current_member_index();
                sender_client_id(&recv.classical, mine)?
            };
            let identity_source = match &proposing_client {
                Some(candidate) => Some(Arc::clone(candidate)),
                None if leaf_id != self.client.client_id().bytes => Some(Arc::clone(&self.client)),
                None => None,
            };
            match identity_source {
                Some(source) => {
                    let (signer, public) = source.combiner().classical_signature_keypair();
                    let identity = SigningIdentity::new(
                        BasicCredential::new(source.client_id().bytes).into_credential(),
                        public,
                    );
                    recv.classical
                        .propose_update_with_identity(signer, identity, Vec::new())
                        .map_err(map_credential_err)?
                }
                None => recv
                    .classical
                    .propose_update(Vec::new())
                    .map_err(|_| TwoMlsPqError::Mls)?,
            }
        };
        let proposing = proposing_client
            .map(|c| c.client_id().bytes)
            .unwrap_or_else(|| self.client.client_id().bytes);
        let proposal_bytes = proposal_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
        // The binding value is the SHA-256 of the staged Upd(self) proposal — the same
        // value the receiver reports as `QueuedRemoteProposal.digest`, and the classical
        // backend's convention. `encrypt` carries it as the app message's authenticated
        // data, so the staple is verifiable against the frame it rides in.
        let proposal_hash = crate::sha256(&proposal_bytes);
        self.pending_proposal_message = Some((proposing, proposal_bytes));

        let their_id = self.their_state.client_id();
        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: if did_commit { Some(their_id) } else { None },
            did_commit,
        })
    }
}

// Two constructors' shared assembly — the parameter list mirrors their divergent
// inputs one-to-one, so a params struct would just restate it with extra ceremony.
#[allow(clippy::too_many_arguments)]
fn build_session(
    client: Arc<TwoMlsPqPrincipal>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    session_id: SessionId,
    their_id: ClientId,
    initiated: bool,
    joined_welcome_digest: Option<Vec<u8>>,
) -> Arc<TwoMlsPqSession> {
    let my_id = client.client_id();
    let suite = client.combiner().cipher_suite();
    // The constructing client's AS state becomes the session-canonical core; every
    // client adopted later (rotation candidates, restored clients) rebinds to it.
    let auth_core = client.combiner().auth_view().core();
    let send_group_storage = client.combiner().classical_group_storage().clone();
    let psk_stores = vec![
        client.combiner().classical().secret_store(),
        client.combiner().pq().secret_store(),
    ];
    let psk_stores_from = Arc::clone(&client);
    // The own APQWelcome doubles as the initial staple until the first send-group commit
    // replaces it (both constructors have it in hand as `pending_outbound`).
    let current_staple = pending_outbound.clone().unwrap_or_default();
    Arc::new(TwoMlsPqSession {
        inner: Mutex::new(SessionInner {
            client,
            suite,
            send_group,
            recv_group,
            pending_outbound,
            pending_proposal_hash: None,
            current_staple,
            pending_proposal_message: None,
            joined_welcome_digest,
            offered_proposal: None,
            queued_proposal: None,
            staged_candidates: Vec::new(),
            deferred_candidate: None,
            auth_core,
            pq_inflight: None,
            session_id,
            my_state: PrincipalState::Sync { client_id: my_id },
            their_state: PrincipalState::Sync {
                client_id: their_id,
            },
            pq_turn_mine: initiated,
            pending_pq_outbound: None,
            send_psk_ledger: VecDeque::new(),
            retired_send_psks: Vec::new(),
            last_cross_injected: None,
            last_cross_injected_pq: None,
            last_send_pq_exported: None,
            listen_rendezvous: BTreeMap::new(),
            recv_header_keys: BTreeMap::new(),
            recv_header_keys_pq: BTreeMap::new(),
            send_group_storage,
            psk_stores,
            psk_stores_from,
            spawn_token: None,
        }),
    })
}

/// Validate one welcome half's cipher suite against the expected value. A Welcome carries its
/// suite in cleartext (`MlsMessage::cipher_suite`), so this catches a mismatch before join.
fn check_welcome_suite(welcome: &[u8], expected: mls_rs::CipherSuite) -> Result<()> {
    let msg = mls_rs::MlsMessage::from_bytes(welcome).map_err(|_| TwoMlsPqError::Mls)?;
    if msg.cipher_suite() == Some(expected) {
        Ok(())
    } else {
        Err(TwoMlsPqError::CipherSuiteMismatch)
    }
}

/// Validate a bootstrap PQ key package's cipher suite against the expected value before a group
/// is stood up around it — the A.4 key-package counterpart to [`check_welcome_suite`], so a
/// mismatched peer KP fails early as `CipherSuiteMismatch` instead of deep inside mls-rs.
fn check_key_package_suite(kp: &[u8], expected: mls_rs::CipherSuite) -> Result<()> {
    let parsed = parse_mls_key_package(kp.to_vec())?;
    if mls_rs::CipherSuite::new(parsed.cipher_suite.value()) == expected {
        Ok(())
    } else {
        Err(TwoMlsPqError::CipherSuiteMismatch)
    }
}

/// Map an mls-rs processing error, surfacing Authentication Service refusals as the
/// retryable `CredentialRejected` (the staple re-rides every frame: app authorizes,
/// re-delivery succeeds) instead of the opaque `Mls`.
fn map_credential_err(e: mls_rs::error::MlsError) -> TwoMlsPqError {
    use mls_rs::error::MlsError;
    match e {
        MlsError::InvalidSuccessor | MlsError::IdentityProviderError(_) => {
            TwoMlsPqError::CredentialRejected
        }
        _ => TwoMlsPqError::Mls,
    }
}

/// Require that a processed proposal is an Update from the peer's leaf — the only
/// proposal kind members of this protocol ever exchange. An MLS Update always covers
/// its sender's own leaf, so a member sender other than ourselves pins it to the one
/// other member (the rules filter re-checks the same at commit time; this rejects at
/// ingest, before the proposal enters any cache).
fn require_peer_update(desc: &ProposalMessageDescription, my_index: u32) -> Result<()> {
    let is_update = matches!(desc.proposal, Proposal::Update(_));
    let from_peer = matches!(desc.sender, ProposalSender::Member(index) if index != my_index);
    if is_update && from_peer {
        Ok(())
    } else {
        Err(TwoMlsPqError::ProposalRejected)
    }
}

/// Validate the cipher suite(s) in an APQ welcome's already-decoded halves against the session's
/// expected pair. An empty PQ half (the acceptor's A.4-deferred return welcome) validates the
/// classical half only.
fn validate_welcome_halves(
    expected: apq::ApqCipherSuite,
    classical_welcome: &[u8],
    pq_welcome: &[u8],
) -> Result<()> {
    if !classical_welcome.is_empty() {
        check_welcome_suite(classical_welcome, expected.classical)?;
    }
    if !pq_welcome.is_empty() {
        check_welcome_suite(pq_welcome, expected.pq)?;
    }
    Ok(())
}

impl TwoMlsPqSession {
    /// Lock the session state, recovering from a poisoned mutex rather than propagating a panic.
    /// A poisoned lock means a prior holder panicked mid-update; we surface the inner state and let
    /// the normal `Option`/`PrincipalState` checks reject any half-applied operation. Used everywhere so
    /// the lock policy is uniform and panic-free (the crate denies `unwrap`/`expect`/`panic`).
    fn lock(&self) -> std::sync::MutexGuard<'_, SessionInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record the opaque spawn token this acceptor session was created under. Called by
    /// `TwoMlsPqInvitation::receive` right after a successful `accept`; `forwarded`
    /// matches replayed initial frames against it.
    pub(crate) fn set_spawn_token(&self, token: Vec<u8>) {
        self.lock().spawn_token = Some(token);
    }

    /// Test-only: the plaintext initial welcome — the initiator's `current_staple` before
    /// its first commit, which is exactly the plaintext `APQWelcome_A`. Production delivers
    /// this only inside the §A.1 envelope (`pending_outbound` → `TwoMlsPqInvitation::
    /// open_initial`); tests that drive `accept`/`receive` directly use this to skip the
    /// envelope round-trip. The real envelope path is exercised by `establish_sessions` and
    /// the dedicated envelope tests.
    #[cfg(test)]
    pub(crate) fn test_initial_welcome(&self) -> Vec<u8> {
        self.lock().current_staple.clone()
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Create a session as the initiating party targeting `their_key_package`.
    ///
    /// `app_payload` is the host's opaque app-layer welcome (identity introduction, signed
    /// keys, …), or `None`. It is composed with the MLS welcome and HPKE-sealed to the
    /// peer's KP′ inside the library, so `pending_outbound()` returns one opaque envelope —
    /// the first frame's metadata (including the app-layer welcome that identifies the
    /// initiator) is hidden without the host having to compose the envelope itself. The
    /// peer recovers both halves with `TwoMlsPqInvitation::open_initial`, then joins with
    /// `receive`.
    #[uniffi::constructor]
    pub fn initiate(
        client: Arc<TwoMlsPqPrincipal>,
        their_key_package: CombinerKeyPackage,
        app_payload: Option<Vec<u8>>,
    ) -> Result<Arc<Self>> {
        validate_combiner_kp(client.combiner().cipher_suite(), &their_key_package)?;
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(client.client_id(), their_id.clone())?;

        let (send_group, apq_welcome) = create_combiner_send_group(
            &their_key_package.classical,
            &their_key_package.pq,
            client.combiner(),
        )?;

        // The first frame has no symmetric key yet, so it is not header-sealed; instead the
        // library HPKE-envelopes `[app_payload ∥ APQWelcome_A]` to the peer's KP′ (§A.1), and
        // `pending_outbound` returns that opaque envelope. The peer opens it with
        // `TwoMlsPqInvitation::open_initial`.
        let envelope = crate::key_packages::seal_initial_envelope(
            &their_key_package,
            app_payload.as_deref(),
            &apq_welcome,
        )?;

        let session = build_session(
            client,
            Some(send_group),
            None,
            // `build_session` seeds `current_staple` from this — it MUST be the plaintext
            // `APQWelcome_A` (the message-frame staple form, first byte 0x01, that the peer
            // idempotently skips), not the sealed envelope. `pending_outbound` is replaced
            // with the envelope just below.
            Some(apq_welcome),
            session_id,
            their_id,
            true,
            None,
        );
        session.lock().pending_outbound = Some(envelope);
        // Seed the PSK ledger with the send group's establishment epoch, and capture
        // the establishment epoch's listen address (and the send-PQ header key when the
        // send-PQ half exists — the initiator's does at `initiate`; the acceptor's is
        // deferred to the A.4 bootstrap, so this is a no-op there).
        session.lock().remember_send_psk()?;
        session.lock().record_listen_rendezvous()?;
        session.lock().record_pq_header_key()?;
        Ok(session)
    }

    /// Join a session from an APQWelcome produced by the remote `initiate`.
    /// Retrieve this party's return Welcome via `pending_outbound`.
    ///
    /// `client` must be dedicated to the acceptor role: `accept` clears its key-package store
    /// once the join has consumed the invitation key package (so nothing migrates into the
    /// session archive). Do NOT reuse one `TwoMlsPqPrincipal` for both `initiate` and a direct
    /// `accept` — `initiate` retains its return-group key package in that same store for the
    /// peer's return welcome, and this clear would drop it. The normal entry point,
    /// `TwoMlsPqInvitation::receive`, always builds a fresh invitation-derived client, so this
    /// only concerns direct callers of `accept`.
    #[uniffi::constructor]
    pub fn accept(
        client: Arc<TwoMlsPqPrincipal>,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        Self::accept_with(client, None, welcome, their_key_package)
    }
}

impl TwoMlsPqSession {
    /// `accept` with an optional dedicated session principal: when `session_client` is
    /// `Some`, the send group (Group_B) is created under it — its ClientId is the send
    /// group's creator leaf credential, so the peer sees the dedicated principal from the
    /// very first frame — while the receive-group join still uses `client` (the
    /// invitation-derived identity, which necessarily holds the key-package private
    /// material the welcome was addressed to). This is establishment-time principal
    /// selection: no rotation commit, so nothing can displace the welcome staple and the
    /// `peer_confirmed` rotation gate never applies.
    ///
    /// The session's owned signing identity becomes `session_client`; the receive group
    /// keeps operating with the invitation identity's keys embedded in its own snapshot
    /// (leaf credential bytes there stay fixed, exactly as under a Phase 8 rotation).
    pub(crate) fn accept_with(
        client: Arc<TwoMlsPqPrincipal>,
        session_client: Option<Arc<TwoMlsPqPrincipal>>,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        validate_combiner_kp(client.combiner().cipher_suite(), &their_key_package)?;
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let their_id = their_parsed.client_id;
        // The session id derives from the FOUNDING pair — the invitation identity the
        // peer initiated toward — never the dedicated principal, so both sides compute
        // the same value (the initiator derives it from the key package it addressed).
        let session_id = crate::derive_session_id(client.client_id(), their_id.clone())?;

        // Decode the incoming welcome once; validate its cipher suite(s) before joining, so a
        // mismatch fails early and clearly rather than deep inside mls-rs — then join the
        // already-decoded halves (no second decode). Same pattern as the `process_incoming`
        // receive path.
        let (recv_classical, recv_pq) = decode_apq_welcome(&welcome)?;
        validate_welcome_halves(client.combiner().cipher_suite(), &recv_classical, &recv_pq)?;
        let mut recv_group =
            join_combiner_group_from_halves(&recv_classical, &recv_pq, client.combiner())?;
        // Bind the welcome to the supplied key package: the creator leaf of every joined
        // half must carry the identity the key package names. Without this, a caller
        // could be handed a welcome from one principal alongside a key package from
        // another and silently establish against the wrong identity (the initiator's
        // later welcome-join deliberately ADOPTS the creator id — that dedicated-
        // principal exception is the acceptor→initiator direction, not this one).
        {
            let mine = recv_group.classical.current_member_index();
            let creator_index = if mine == 0 { 1 } else { 0 };
            if sender_client_id(&recv_group.classical, creator_index)? != their_id.bytes {
                return Err(TwoMlsPqError::RemoteIdentityMismatch);
            }
            if let Some(pq) = recv_group.pq.as_ref() {
                let mine = pq.current_member_index();
                let creator_index = if mine == 0 { 1 } else { 0 };
                if sender_client_id(pq, creator_index)? != their_id.bytes {
                    return Err(TwoMlsPqError::RemoteIdentityMismatch);
                }
            }
        }
        // The invitation's key package has served its one purpose: mls-rs obtained it to join
        // the receive group. The store is only that serving interface, so drop the acceptor's
        // key-package material now — nothing migrates from the invitation into the session (or
        // its archive). This is what actually clears it: mls-rs's own post-join delete is
        // deferred to the group's next `write_to_storage`, which is after `accept` returns.
        // It clears the WHOLE store, which is why `client` must be dedicated to accepting (see
        // the fn docs); `initiate` deliberately does NOT purge, since it must retain its
        // return-group key package. Last-resort reuse is unaffected: it lives on the invitation,
        // which keeps its own captured material and rebuilds a fresh serving store per `receive`.
        client.combiner().classical_kp_store().purge_all();
        client.combiner().pq_kp_store().purge_all();
        // A.4: the send group's PQ half is deferred — classical only, bound to the
        // cross-party PSK. The bootstrap flow stands it up off the critical path, so the
        // return welcome carries an empty PQ slot. Created under the dedicated session
        // principal when one was supplied: its ClientId becomes the creator leaf
        // credential the peer reads out of this welcome (`create_bound…` registers the
        // cross-party PSK into that same client's stores, so the creation commit
        // resolves it there).
        let group_client = session_client.as_ref().unwrap_or(&client);
        // AS seeding for the dedicated principal: its canonical sequence is a genuine
        // two-element succession — the invitation identity the peer addressed, then
        // the dedicated id its send group is created under. The invitation-derived
        // client (which joined the recv group above and seeded `theirs` in ITS core)
        // rebinds to the canonical core, which re-records the peer.
        if let Some(dedicated) = session_client.as_ref() {
            let invitation_id = client.client_id().bytes;
            let dedicated_id = dedicated.client_id().bytes;
            let peer_id = their_id.bytes.clone();
            dedicated.combiner().auth_view().with(move |core| {
                core.mine = PartySequence::seeded(invitation_id);
                core.mine.commit(dedicated_id);
                core.theirs.commit(peer_id);
            });
            client
                .combiner()
                .auth_view()
                .rebind(&dedicated.combiner().auth_view().core());
        }
        let recv_cross_epoch = recv_group.classical.current_epoch();
        let (send_group, classical_welcome) = create_bound_classical_send_group(
            &their_key_package.classical,
            group_client.combiner(),
            &mut recv_group.classical,
        )?;
        let apq_welcome = encode_apq_welcome(classical_welcome, Vec::new());

        let session = build_session(
            // The session's owned client — signing identity, send-group storage, and
            // `my_principal_state` — is the dedicated principal when supplied.
            Arc::clone(group_client),
            Some(send_group),
            Some(recv_group),
            Some(apq_welcome),
            session_id,
            their_id,
            false,
            // Record which welcome the recv group was joined from: welcomes are
            // re-delivered as a matter of course, and this digest is what makes the
            // repeats skip idempotently instead of re-joining.
            Some(crate::sha256(&welcome)),
        );
        // The receive group was joined under the invitation-derived client, so its half
        // resolves PSKs from THOSE stores; with a dedicated session client they are
        // distinct from the session's own — track both so `register_psk` reaches every
        // group config this session drives.
        if session_client.is_some() {
            session.lock().track_psk_stores(&client);
        }
        // Establishment bound the peer's send group at `recv_cross_epoch` (the cross-party
        // PSK that seeds our send group's PQ inheritance). Record the watermark so the first
        // routine full commit does not redundantly re-bind that same, unadvanced epoch.
        session.lock().last_cross_injected = Some(recv_cross_epoch);
        // Seed the PSK ledger with the send group's establishment epoch, and capture
        // the establishment epoch's listen address (and the send-PQ header key when the
        // send-PQ half exists — the initiator's does at `initiate`; the acceptor's is
        // deferred to the A.4 bootstrap, so this is a no-op there).
        session.lock().remember_send_psk()?;
        session.lock().record_listen_rendezvous()?;
        session.lock().record_pq_header_key()?;
        Ok(session)
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Restore a session from a serialised archive (see `archive` for the single-use
    /// contract). Self-contained: the archive carries the session's signing identity, so
    /// restore rebuilds the exact client internally — no client argument, matching the
    /// classical stack's fully-internalized MLS state. The rebuilt client is byte-exact
    /// (same ClientId and signing keys), giving continuity for any group or leaf created
    /// after the restore; the group snapshots supply their own signing keys as before.
    #[uniffi::constructor]
    pub fn from_archive(archive: Archive) -> Result<Arc<Self>> {
        use mls_rs::mls_rs_codec::MlsDecode;

        // Header: [version][classical u16 BE][pq u16 BE]. The archived suite pair must equal
        // this build's pinned suite — fail loudly across builds rather than misinterpret the
        // group snapshots (equality also confirms the pair is a coherent APQ combination).
        let mut rest = match archive.bytes.as_slice() {
            [SESSION_ARCHIVE_VERSION, s0, s1, s2, s3, rest @ ..]
                if apq::ApqCipherSuite::from_wire([*s0, *s1, *s2, *s3])
                    == crate::providers::APQ_SUITE =>
            {
                rest
            }
            _ => return Err(TwoMlsPqError::ArchiveInvalid),
        };
        let wire = archive_wire::SessionArchive::mls_decode(&mut rest)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        if !rest.is_empty() {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }

        // Structural invariants the live session maintains; reject blobs that violate
        // them rather than resurrecting an impossible state.
        if wire.send_psk_ledger.len() > SEND_PSK_WINDOW {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }
        let digest_ok = |d: &[u8]| d.len() == 32;
        if wire
            .pending_proposal_hash
            .as_deref()
            .is_some_and(|d| !digest_ok(d))
            || wire
                .offered_proposal
                .as_ref()
                .is_some_and(|o| !digest_ok(&o.digest))
            || wire
                .queued_proposal
                .as_ref()
                .is_some_and(|q| !digest_ok(&q.digest))
            || wire
                .joined_welcome_digest
                .as_deref()
                .is_some_and(|d| !digest_ok(d))
        {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }
        if wire
            .listen_rendezvous
            .iter()
            .any(|e| e.addr.len() != RENDEZVOUS_LEN)
        {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }
        let hk_len = header_key_len()?;
        if wire
            .recv_header_keys
            .iter()
            .chain(wire.recv_header_keys_pq.iter())
            .any(|e| e.key.len() != hk_len)
        {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }
        // The staple is never empty on a live session (set at construction), and its
        // first byte is one of the two staple forms: APQWelcome (0x01) or MLSMessage
        // (0x00). This check also structurally rejects pre-v2 archive layouts, whose
        // bytes can otherwise alias into these fields (an Option-None byte reads as an
        // empty byte_vec).
        if !matches!(wire.current_staple.first(), Some(&0x00) | Some(&APQ_TAG)) {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }

        let my_state = principal_state_from_wire(wire.my_state);
        let their_state = principal_state_from_wire(wire.their_state);

        // Rebuild the session's current client byte-exact from its archived signing
        // identity, and re-mint any staged-but-uncommitted rotation successor. All group
        // storage and PSK plumbing below re-homes onto this client.
        let client = principal_from_wire(wire.client)?;
        let staged_candidates = wire
            .staged_candidates
            .into_iter()
            .map(principal_from_wire)
            .collect::<Result<Vec<_>>>()?;
        // Rebuild the canonical AS core from the archived sequences onto the rebuilt
        // client's view, and point every candidate's view at it.
        let seq = |w: archive_wire::WirePartySequence| {
            apq::authentication::PartySequence::from_parts(
                w.history.into_iter().map(|b| b.bytes).collect(),
                w.authorized_next.into_iter().map(|b| b.bytes).collect(),
            )
        };
        let (auth_mine, auth_theirs) = (seq(wire.auth_mine), seq(wire.auth_theirs));
        client.combiner().auth_view().with(move |core| {
            core.mine = auth_mine;
            core.theirs = auth_theirs;
        });
        let auth_core_restored = client.combiner().auth_view().core();
        for candidate in &staged_candidates {
            candidate.combiner().auth_view().rebind(&auth_core_restored);
        }
        let pq_inflight = wire.pq_inflight.map(pq_inflight_from_wire).transpose()?;

        let group_state = |entry: archive_wire::GroupEntry| apq::CombinerGroupState {
            classical: entry.classical.bytes,
            pq: entry.pq.map(|blob| blob.bytes),
        };
        let send_group =
            apq::load_combiner_group(client.combiner(), &group_state(wire.send_group))?;
        let recv_group = match wire.recv_group {
            Some(entry) => Some(apq::load_combiner_group(
                client.combiner(),
                &group_state(entry),
            )?),
            None => None,
        };

        // The imports above re-homed every group's captured storage and PSK handles onto
        // `client`, so the plumbing collapses to `client`'s handles exactly as
        // `build_session` derives them — the multi-store history a rotation accumulated
        // existed only to serve groups born on pre-rotation clients, and those bindings
        // are dissolved by the import.
        let send_group_storage = client.combiner().classical_group_storage().clone();
        let suite = client.combiner().cipher_suite();
        let psk_stores = vec![
            client.combiner().classical().secret_store(),
            client.combiner().pq().secret_store(),
        ];
        let psk_stores_from = Arc::clone(&client);
        Ok(Arc::new(TwoMlsPqSession {
            inner: Mutex::new(SessionInner {
                client,
                suite,
                send_group: Some(send_group),
                recv_group,
                pending_outbound: wire.pending_outbound,
                pending_proposal_hash: wire.pending_proposal_hash,
                current_staple: wire.current_staple,
                pending_proposal_message: wire
                    .pending_proposal_message
                    .map(|p| (p.proposing, p.message)),
                joined_welcome_digest: wire.joined_welcome_digest,
                offered_proposal: wire
                    .offered_proposal
                    .map(|o| (o.digest, o.proposal, o.proposing)),
                queued_proposal: wire
                    .queued_proposal
                    .map(|q| (q.digest, q.proposing, q.proposal)),
                staged_candidates,
                deferred_candidate: wire.deferred_candidate,
                auth_core: auth_core_restored,
                pq_inflight,
                session_id: SessionId {
                    bytes: wire.session_id,
                },
                my_state,
                their_state,
                pq_turn_mine: wire.pq_turn_mine,
                pending_pq_outbound: wire.pending_pq_outbound,
                send_psk_ledger: wire
                    .send_psk_ledger
                    .into_iter()
                    .map(|entry| {
                        apq::ExportedPsk::from_parts(entry.component_id, entry.psk_id, entry.psk)
                            .map(|exported| (entry.epoch, exported))
                    })
                    .collect::<std::result::Result<_, _>>()?,
                retired_send_psks: wire.retired_send_psks,
                last_cross_injected: wire.last_cross_injected,
                last_cross_injected_pq: wire.last_cross_injected_pq,
                last_send_pq_exported: wire.last_send_pq_exported,
                listen_rendezvous: wire
                    .listen_rendezvous
                    .into_iter()
                    .map(|entry| (entry.epoch, entry.addr))
                    .collect(),
                recv_header_keys: wire
                    .recv_header_keys
                    .into_iter()
                    .map(|entry| (entry.epoch, entry.key))
                    .collect(),
                recv_header_keys_pq: wire
                    .recv_header_keys_pq
                    .into_iter()
                    .map(|entry| (entry.epoch, entry.key))
                    .collect(),
                send_group_storage,
                psk_stores,
                psk_stores_from,
                spawn_token: wire.spawn_token,
            }),
        }))
    }

    /// Welcome bytes to deliver to the remote party to complete group establishment.
    /// Returns `None` once consumed or when both groups are live.
    pub fn pending_outbound(&self) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        let frame = inner.pending_outbound.take()?;
        // The acceptor's return welcome (recv group already exists) is sealed like any
        // rendezvous-channel frame — the peer opens it from its send-group window. The
        // initiator's initial welcome (no recv group yet) travels the invitation channel
        // instead and is delivered as-is; the host envelopes it via
        // `hpke_seal_to_key_package`, and the invitation opens it before `receive`.
        if inner.recv_group.is_some() {
            inner.seal(&frame).ok()
        } else {
            Some(frame)
        }
    }

    /// True once both directions' PQ halves are live (post-A.4 bootstrap).
    pub fn is_fully_established(&self) -> bool {
        let inner = self.lock();
        matches!(
            (&inner.send_group, &inner.recv_group),
            (Some(s), Some(r)) if s.pq.is_some() && r.pq.is_some()
        )
    }

    /// Whose move the PQ side-band is: true when this side owes the next operation.
    /// The initiator owes the A.4 bootstrap; completing an operation passes the turn.
    pub fn my_pq_turn(&self) -> bool {
        self.lock().pq_turn_mine
    }

    /// Consume the side-band frame parked by the responder-side operations
    /// (`pq_ratchet_respond` / `pq_ratchet_bind` / `pq_bootstrap_respond`). Single slot,
    /// single delivery: those operations refuse to start while a frame is waiting.
    pub fn pq_take_pending_outbound(&self) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        let frame = inner.pending_pq_outbound.take()?;
        // Side-band frames seal under the PQ family (the responder is post-establishment,
        // so its recv-PQ group exists); the classical fallback in `seal_side_band` is
        // never hit here.
        inner.seal_side_band(&frame).ok()
    }

    /// The send group's APQ epoch pair (PQ side-band, classical message group).
    /// Zeros until the corresponding group exists.
    pub fn epochs(&self) -> crate::ApqEpochs {
        let inner = self.lock();
        inner
            .send_group
            .as_ref()
            .map(apq_epochs)
            .unwrap_or(crate::ApqEpochs {
                pq_epoch: 0,
                classical_epoch: 0,
            })
    }

    /// A.4 initiator — emit this side's PQ key package (tag 0x0B) so the peer can stand
    /// up its deferred send-group PQ half. The key package's private material is retained
    /// in this client, so the returned welcome can be joined by `pq_bootstrap_apply`.
    ///
    /// `rotating` must name the session's CURRENT principal (like `pq_rekey_begin`); the KP'
    /// below is generated by that client, so the new leaf carries its credential without
    /// further work — the check is all a bootstrap-time handoff needs.
    pub fn pq_bootstrap_begin(&self, rotating: Option<ClientId>) -> Result<Vec<u8>> {
        let inner = self.lock();
        if !inner.pq_turn_mine {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        if let Some(new_id) = rotating {
            if inner.client.client_id() != new_id {
                return Err(TwoMlsPqError::SessionNotReady);
            }
        }
        let ready = inner.send_group.is_some()
            && inner
                .recv_group
                .as_ref()
                .map(|g| g.pq.is_none())
                .unwrap_or(false);
        if !ready {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let kp = inner.client.combiner().generate_pq_key_package()?;
        let mut msg = vec![PQ_BOOTSTRAP_KP_TAG];
        msg.extend_from_slice(&kp);
        // Side-band frame. Pre-A.4 our recv-PQ (Group_B.pq) is the group the bootstrap
        // is creating, so `seal_side_band` falls back to the classical seal for exactly
        // this frame; the peer opens it from its classical window.
        inner.seal_side_band(&msg)
    }

    /// A.4 responder — stand up the deferred send-group PQ half around the peer's key
    /// package and return the bootstrap frame (tag 0x0D) carrying its Welcome.
    /// PQ-groups-only: no classical commit rides here — the new half's APQ-PSK reaches
    /// the classical group at the next A.3 bind. Taking this turn makes the next
    /// operation ours.
    pub fn pq_bootstrap_respond(&self, kp_msg: Vec<u8>) -> Result<()> {
        let kp_msg = self.lock().open_or_raw(kp_msg);
        let (&tag, kp) = kp_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_BOOTSTRAP_KP_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pending_pq_outbound.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // Validate the peer's PQ key package suite before building a group around it — an early,
        // clear CipherSuiteMismatch rather than a late opaque mls-rs error.
        check_key_package_suite(kp, inner.suite.pq)?;
        // The bootstrap KP must name the established peer: the new PQ half's added leaf
        // becomes a sender identity this library reports, so an unexpected principal is
        // rejected before any group is stood up around it.
        if parse_mls_key_package(kp.to_vec())?.client_id != inner.their_state.client_id() {
            return Err(TwoMlsPqError::RemoteIdentityMismatch);
        }
        let client = inner.client.clone();
        let suite = inner.suite;
        // The new PQ half resolves PSKs from the CURRENT client's stores (A.4 runs on
        // the principal a Phase 8 rotation may have installed) — track them.
        inner.track_psk_stores(&client);
        let frame = {
            let send = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if send.pq.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // The classical half's creation-time APQInfo pre-allocated this PQ half's
            // group id at establishment: create the group under exactly that id, and
            // record the mirror view {t: EPOCH_UNBOUND, pq: 1} in the new half's own
            // APQInfo (no classical commit rides A.4, so its classical epoch is the
            // deferred sentinel until the next A.3 bind attests both).
            let classical_info = read_apqinfo(&send.classical)?;
            let pq_gid = classical_info.pq_session_group_id.clone();
            let info = ApqInfo::new(
                suite,
                classical_info.t_session_group_id.clone(),
                pq_gid.clone(),
                EPOCH_UNBOUND,
                1,
            );
            let (pq_group, pq_welcome) = create_group_with_member(
                client.pq(),
                kp,
                &[],
                GroupCreation::new(pq_gid, &info, None)?,
            )?;
            // PQ-groups-only (spec A.4): no classical bind here. The new PQ half's
            // secrecy reaches ASG-cl at the next A.3 ratchet; until then ASG-cl keeps
            // the PQ-derived security chained in at establishment.
            send.set_pq(pq_group, client.combiner());
            encode_bootstrap_bind(pq_welcome)
        };
        inner.pq_turn_mine = true;
        inner.pending_pq_outbound = Some(frame);
        // Our send-PQ half now exists (Group_B.pq) — capture its header key so we can
        // open side-band frames the peer seals to it.
        inner.record_pq_header_key()?;
        Ok(())
    }

    /// A.4 initiator completion — join the peer's new PQ group (our key package's
    /// private material is retained in this client) and register its APQ-PSK.
    /// PQ-groups-only, like the responder side: no classical commit is applied here.
    /// The turn passes to the peer.
    pub fn pq_bootstrap_apply(&self, bind_msg: Vec<u8>) -> Result<()> {
        let bind_msg = self.lock().open_or_raw(bind_msg);
        let pq_welcome = decode_bootstrap_bind(&bind_msg)?;
        let mut inner = self.lock();
        // Validate the peer's PQ welcome suite before joining — an early, clear
        // CipherSuiteMismatch rather than a late opaque mls-rs error (matches the establishment
        // welcome path).
        check_welcome_suite(&pq_welcome, inner.suite.pq)?;
        let client = inner.client.clone();
        let suite = inner.suite;
        // The joined PQ half resolves PSKs from the CURRENT client's stores — track them.
        inner.track_psk_stores(&client);
        {
            let recv = inner
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if recv.pq.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            let pq = join_group_from_welcome(client.pq(), &pq_welcome)?;
            // -02 verification: the joined group must be the one whose id the classical
            // half's APQInfo pre-allocated at establishment, and its own APQInfo must be
            // the deferred mirror ({t: EPOCH_UNBOUND, pq: 1}, same identity fields).
            // Strict roster-set equality across the halves is NOT checked here — under
            // the AS lag model the classical half's leaves may trail a canonicalized
            // rotation while the fresh PQ half carries current principals; per-leaf
            // membership is enforced by the AS (`validate_member`) inside the join.
            let classical_info = read_apqinfo(&recv.classical)?;
            verify_deferred_pq_info(&pq, &classical_info, suite)?;
            recv.set_pq(pq, client.combiner());
        }
        inner.pq_turn_mine = false;
        Ok(())
    }

    pub fn is_established(&self) -> bool {
        let inner = self.lock();
        inner.send_group.is_some() && inner.recv_group.is_some()
    }

    pub fn has_receive_group(&self) -> bool {
        self.lock().recv_group.is_some()
    }

    pub fn active_session_id(&self) -> SessionId {
        self.lock().session_id.clone()
    }

    pub fn my_principal_state(&self) -> PrincipalState {
        self.lock().my_state.clone()
    }

    pub fn their_principal_state(&self) -> PrincipalState {
        self.lock().their_state.clone()
    }

    pub fn receive_group_id(&self) -> Option<CombinerGroupId> {
        let inner = self.lock();
        inner.recv_group.as_ref().map(|rg| CombinerGroupId {
            classical: MlsGroupId {
                bytes: rg.classical.group_id().to_vec(),
            },
            // Empty until the deferred PQ half is bootstrapped (A.4).
            pq: MlsGroupId {
                bytes: rg
                    .pq
                    .as_ref()
                    .map(|pq| pq.group_id().to_vec())
                    .unwrap_or_default(),
            },
        })
    }

    /// Prepare a pending proposal nonce and stage it for binding into the next outbound message.
    /// Returns `Err(SessionNotReady)` until both groups are established.
    ///
    /// - `proposing: None` with a queued remote proposal → folding commit — folds the approved Upd (epoch advance + PSK refresh), `did_commit: true`
    /// - `proposing: Some(new_id)` → rotation commit with new leaf credential, `did_commit: true`
    /// - Otherwise → recv self-Update only, `did_commit: false`
    pub fn prepare_to_encrypt(&self, proposing: Option<ClientId>) -> Result<PrepareEncryptResult> {
        let mut inner = self.lock();
        let result = inner.prepare_ratchet_commit(proposing)?;
        // A committing round advanced the send group's classical epoch — capture
        // the new epoch's listen address.
        inner.record_listen_rendezvous()?;
        Ok(result)
    }

    /// Encrypt `app_message` using the PQ send group.
    /// Must be called after `prepare_to_encrypt`; the pending proposal hash is used as
    /// authenticated data and cleared on return.
    /// The output is always one message frame `[staple][proposal][app]`: the staple (our
    /// latest send-group commit, or our APQWelcome until the first commit) rides every
    /// frame, so a peer that missed a frame is healed by the next one. `pending_outbound`
    /// is NOT consumed here — the staple carries the welcome; the standalone copy stays
    /// available for hosts that also deliver it separately (processing is idempotent).
    pub fn encrypt(&self, app_message: Vec<u8>) -> Result<EncryptResult> {
        let mut inner = self.lock();

        let proposal_hash = inner
            .pending_proposal_hash
            .take()
            .ok_or(TwoMlsPqError::SessionNotReady)?;

        let (app_bytes, epochs) = {
            let send = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;

            let cipher_msg = send
                .message_group_mut()
                .encrypt_application_message(&app_message, proposal_hash)
                .map_err(|_| TwoMlsPqError::Mls)?;

            let epochs = apq_epochs(send);
            let bytes = cipher_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
            (bytes, epochs)
        };

        // Every prepare path stages a proposal, and the staple is set at construction —
        // an empty slot here means encrypt was reached outside the prepare contract.
        let (proposing, proposal) = inner
            .pending_proposal_message
            .take()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        if inner.current_staple.is_empty() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let frame = encode_message_frame(
            &inner.current_staple,
            encode_proposal_section(&proposing, &proposal),
            app_bytes,
        );
        // Header encryption: seal the whole frame into one opaque blob before it leaves
        // the library. `encrypt` only runs post-establishment (prepare needs the recv
        // group), so the seal key is always available.
        let cipher_text = inner.seal(&frame)?;

        let sender = inner.my_state.client_id();
        let recipient = inner.their_state.client_id();

        Ok(EncryptResult {
            cipher_text,
            sender,
            recipient,
            epochs,
        })
    }

    /// Remove the header seal from an inbound rendezvous-channel blob, returning the
    /// plaintext frame and its routing kind, or `None` if no key in the header receive
    /// window opens it (an out-of-window or garbage blob — indistinguishable by
    /// construction, the same "unknown, drop it" signal the reconnect path assigns).
    ///
    /// This is the single entry point for frames that arrive on a rendezvous address. The
    /// host dispatches on `OpenedFrame.kind`: `Message` → `process_incoming(frame)`;
    /// `PqSideBand { kind }` → the `pq_*` method that `kind` names. The old plaintext
    /// entry points keep their signatures and now take the opened `frame`.
    ///
    /// (The initiator's initial welcome does NOT come through here — it arrives on the
    /// invitation channel and goes to `TwoMlsPqInvitation::receive`.)
    ///
    /// Observability: an opened frame whose leading tag is unrecognized is
    /// `DecryptionFailed`, but a blob no window key opens is a silent `None`. Desyncs that
    /// mls-rs would once have surfaced loudly can therefore read as `None` here; a host
    /// tracking liveness should treat a run of `None`s on a live session as a reconnect
    /// signal.
    pub fn open_incoming(&self, blob: Vec<u8>) -> Result<Option<OpenedFrame>> {
        let inner = self.lock();
        let Some(frame) = inner.try_open(&blob)? else {
            return Ok(None);
        };
        let kind = frame
            .first()
            .copied()
            .and_then(opened_frame_kind)
            .ok_or(TwoMlsPqError::DecryptionFailed)?;
        Ok(Some(OpenedFrame { kind, frame }))
    }

    /// Process an incoming message.
    ///
    /// - APQWelcome (0x01) → join recv groups, idempotently (a re-delivered welcome is a
    ///   no-op); `Ok(None)`
    /// - Message frame (0x03) `[staple][proposal][app]` → apply the staple idempotently
    ///   (join from a welcome staple if this is its first delivery; apply a commit staple
    ///   at the recv group's current epoch, skip an older one), decrypt the app message,
    ///   and stage the stapled Upd(sender) for app approval; `DecryptResult`
    ///
    /// A commit staple *ahead* of the recv group's next epoch is `EpochDesync`: the
    /// bridging commit no longer rides any frame (only the sender's latest staples), so
    /// the direction needs the reconnect path — surfaced before the app ciphertext is
    /// touched, and distinguishable from a transient `DecryptionFailed`.
    ///
    /// PQ side-band frames (0x05–0x11) are **not** handled here — the host routes them to
    /// the `pq_*` entry points by frame kind (`pq_frame_kind`). Passing one here returns
    /// `SessionNotReady` rather than attempting (and failing) MLS decryption. Anything
    /// else — including bare MLS ciphertext, which no longer occurs on the send path — is
    /// rejected as `DecryptionFailed`.
    pub fn process_incoming(&self, ciphertext: Vec<u8>) -> Result<Option<DecryptResult>> {
        // Header encryption: accept either the sealed blob off the wire or the frame a
        // host already took from `open_incoming` (see `open_or_raw`). The initiator's
        // initial welcome (invitation channel, unsealed) passes through untouched.
        let ciphertext = self.lock().open_or_raw(ciphertext);
        // Standalone APQWelcome: the initiator's welcome arrives this way over the
        // invitation channel, and hosts may also deliver the acceptor's return welcome
        // standalone. The same welcome also rides message-frame staples, so processing
        // must be (and is) idempotent — see `process_welcome`.
        if ciphertext.first() == Some(&APQ_TAG) {
            let mut inner = self.lock();
            let prior_their = inner.their_state.client_id();
            inner.process_welcome(&ciphertext)?;
            let adopted_their = inner.their_state.client_id();
            // A first-delivery join that adopts a different peer principal (the peer
            // established under a dedicated per-session principal) must be observable
            // on THIS delivery too, not only on the stapled one — otherwise which
            // signal the app gets would depend on which copy of the welcome arrived
            // first. Re-deliveries and unchanged-principal joins stay `None`.
            if adopted_their != prior_their {
                return Ok(Some(DecryptResult {
                    application_message: None,
                    proposal: None,
                    remote_commit: Some(CommitResult {
                        new_sender: Some(adopted_their),
                        new_recipient: inner.my_state.client_id(),
                    }),
                }));
            }
            return Ok(None);
        }

        // The message frame: the sender's latest send-group staple (commit-or-welcome) +
        // an Upd(sender) proposal addressed to OUR send group + the app message. Apply
        // the staple idempotently, decrypt the app message, and stage the proposal for
        // app approval — it enters our send group only via `queue_proposal`.
        if ciphertext.first() == Some(&MESSAGE_FRAME_TAG) {
            let (staple, proposal_bytes, app_bytes) = decode_message_frame(&ciphertext)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.lock();

            // The staple slot self-discriminates: an APQWelcome starts 0x01, an
            // MLSMessage 0x00. Track whether THIS frame advanced the recv group, and any
            // rotation handoff announced in the commit's authenticated_data.
            let mut staple_applied = false;
            let mut new_sender: Option<ClientId> = None;
            let mut canonicalized_own: Option<Vec<u8>> = None;

            if staple.first() == Some(&APQ_TAG) {
                // Welcome staple: joins on first delivery, skips repeats. The sender
                // re-staples its welcome until its first commit exists, so repeats are
                // the common case, not an anomaly. A first-delivery join adopts the
                // peer's principal from the creator leaf (see `process_welcome`); when
                // the peer established under a dedicated per-session principal, that id
                // differs from the invitation identity we initiated toward — surface it
                // like a rotation handoff so the app observes the change on this frame.
                let prior_their = inner.their_state.client_id();
                inner.process_welcome(&staple)?;
                let adopted_their = inner.their_state.client_id();
                if adopted_their != prior_their {
                    staple_applied = true;
                    new_sender = Some(adopted_their);
                }
            } else {
                let commit_msg =
                    MlsMessage::from_bytes(&staple).map_err(|_| TwoMlsPqError::DecryptionFailed)?;
                let commit_epoch = commit_msg.epoch().ok_or(TwoMlsPqError::DecryptionFailed)?;
                let current_epoch = inner
                    .recv_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?
                    .classical
                    .current_epoch();
                match commit_epoch.cmp(&current_epoch) {
                    // Already applied off an earlier frame — the staple rides every
                    // frame precisely so repeats are cheap skips.
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        // The commit may bind the cross-party TwoMLS-PSK of our send
                        // group — possibly at an epoch we've since moved past (their
                        // frame can cross one of our commits). Live-inject the
                        // session-held ledger before processing.
                        if inner.send_group.is_some() {
                            inner.inject_send_psks()?;
                        }
                        let recv = inner
                            .recv_group
                            .as_mut()
                            .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                        let mine = recv.classical.current_member_index();
                        let peer_index = if mine == 0 { 1 } else { 0 };
                        let prior_peer = sender_client_id(&recv.classical, peer_index)?;
                        let prior_own = sender_client_id(&recv.classical, mine)?;
                        let staple_attestation =
                            match recv.classical.process_incoming_message(commit_msg) {
                                Ok(ReceivedMessage::Commit(desc)) => commit_attestation(&desc)?,
                                Ok(_) => return Err(TwoMlsPqError::DecryptionFailed),
                                Err(e) => {
                                    return Err(match map_credential_err(e) {
                                        TwoMlsPqError::CredentialRejected => {
                                            TwoMlsPqError::CredentialRejected
                                        }
                                        // Preserve the transient, retriable semantics of a
                                        // staple that cannot process YET (e.g. a message
                                        // frame overtaking its A.3 BIND).
                                        _ => TwoMlsPqError::DecryptionFailed,
                                    });
                                }
                            };
                        // A staple commit is normally a PARTIAL (no AppDataUpdate); one
                        // that DOES attest (a bare attestation commit, or an A.3 bind
                        // classical half applied out of band) must attest truthfully:
                        // the actual post-apply classical epoch and the recv-PQ's actual
                        // current epoch.
                        if let Some(attestation) = staple_attestation {
                            let pq_epoch = recv
                                .pq
                                .as_ref()
                                .map(|pq| pq.current_epoch())
                                .ok_or(TwoMlsPqError::ApqInfoMismatch)?;
                            if attestation.t_epoch != recv.classical.current_epoch()
                                || attestation.pq_epoch != pq_epoch
                            {
                                return Err(TwoMlsPqError::ApqInfoMismatch);
                            }
                        }
                        // A peer commit must never change the two-party shape (an Add
                        // would plant a shadow member whose credential we would report
                        // as a sender identity).
                        apq::ensure_two_party(&recv.classical)?;
                        staple_applied = true;
                        // Identity changes travel IN the leaves now (the AS validated
                        // them during processing): the peer's own-leaf move is its
                        // catch-up to a credential our commit already canonicalized —
                        // surface it as `new_sender`; OUR leaf moving means the peer
                        // committed one of our candidate proposals — the canonical
                        // step of our own sequence (handled below, outside the borrow).
                        let new_peer = sender_client_id(&recv.classical, peer_index)?;
                        let new_own = sender_client_id(&recv.classical, mine)?;
                        if new_peer != prior_peer {
                            new_sender = Some(ClientId { bytes: new_peer });
                        }
                        if new_own != prior_own {
                            canonicalized_own = Some(new_own);
                        }
                    }
                    std::cmp::Ordering::Greater => {
                        // The peer is more than one commit ahead of us: the bridging
                        // commit no longer rides any frame (only the latest staples).
                        // Not transient — surface the desync before touching the app
                        // ciphertext so the host can route to reconnect.
                        return Err(TwoMlsPqError::EpochDesync);
                    }
                }
            }

            if let Some(new_id) = &new_sender {
                inner.with_auth(|core| core.theirs.commit(new_id.bytes.clone()));
                inner.their_state = PrincipalState::Sync {
                    client_id: new_id.clone(),
                };
            }

            // The peer committed one of our candidate Upds: that commit DEFINES our
            // next canonical credential. Swap the session to the winning candidate's
            // principal; our own send-group leaf and the PQ leaves catch up on later
            // commits (the lag the AS's history window tolerates).
            if let Some(new_own) = canonicalized_own {
                if new_own == inner.client.client_id().bytes {
                    // The leaf converged to the identity the session already runs
                    // (e.g. the recv-group leaf catching up to the dedicated
                    // establishment principal): canonical state, no client swap.
                    inner.with_auth(|core| core.mine.commit(new_own));
                } else {
                    let winner = inner
                        .staged_candidates
                        .iter()
                        .find(|c| c.client_id().bytes == new_own)
                        .cloned()
                        .ok_or(TwoMlsPqError::CredentialRejected)?;
                    inner.with_auth(|core| core.mine.commit(new_own));
                    inner.track_psk_stores(&winner);
                    inner.client = winner;
                    inner.staged_candidates.clear();
                    inner.my_state = PrincipalState::Sync {
                        client_id: inner.client.client_id(),
                    };
                }
            }

            let (app_data, sender_id, epoch, group_id) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .classical
                    .process_incoming_message(app_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::ApplicationMessage(desc) => {
                        let sender = ClientId {
                            bytes: sender_client_id(&recv.classical, desc.sender_index)?,
                        };
                        let ep = recv.classical.current_epoch();
                        let gid = recv.classical.group_id().to_vec();
                        (desc.data().to_vec(), sender, ep, gid)
                    }
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            // Stage the stapled Upd(sender) proposal for app approval. The section is
            // self-describing — `[proposing][proposal message]` — so the candidate
            // credential is surfaced to the app BEFORE the proposal touches any group;
            // `queue_proposal` verifies the declared identity against the Update's
            // actual leaf.
            let (proposing, proposal_msg_bytes) = decode_proposal_section(&proposal_bytes)?;
            let digest = crate::sha256(&proposal_msg_bytes);
            inner.offered_proposal = Some((digest.clone(), proposal_msg_bytes, proposing.clone()));
            let proposal = Some(crate::QueuedRemoteProposal {
                digest,
                sender: sender_id.clone(),
                proposing: ClientId { bytes: proposing },
                // The ordering context is the SHA-256 of the receive group's
                // (classical, message-half) group id — `proposal_context`'s value.
                context: crate::sha256(&group_id),
            });

            // Surfaced only on the frame whose staple was actually applied; repeats of
            // the same commit are silent skips. (Known edge, pre-existing: if the staple
            // applies but the app message fails in this same frame, `new_sender` is
            // never surfaced — the retry skips the already-applied staple. This covers
            // the welcome-join principal adoption above too: the event signal can be
            // lost, so treat `their_principal_state()` as the truth and `new_sender`
            // as a hint.)
            let remote_commit = if staple_applied {
                Some(CommitResult {
                    new_sender,
                    new_recipient: inner.my_state.client_id(),
                })
            } else {
                None
            };

            return Ok(Some(DecryptResult {
                application_message: Some(MlsSenderMessage {
                    app_message_data: app_data,
                    sender_client_id: sender_id,
                    epoch,
                }),
                proposal,
                remote_commit,
            }));
        }

        // PQ side-band frames are driven through the dedicated `pq_*` API, not this
        // method — they are stateful exchanges, not self-contained decryptable messages.
        // Reject all seven explicitly so a host that misroutes one gets a clear signal
        // instead of an opaque `DecryptionFailed`. See `pq_frame_kind`.
        if ciphertext.first().copied().is_some_and(|b| {
            b == PQ_EK_TAG
                || b == PQ_CT_TAG
                || b == PQ_BIND_TAG
                || b == PQ_BOOTSTRAP_KP_TAG
                || b == PQ_BOOTSTRAP_BIND_TAG
                || b == PQ_REKEY_UPD_TAG
                || b == PQ_REKEY_COMMIT_TAG
        }) {
            return Err(TwoMlsPqError::SessionNotReady);
        }

        // Nothing else is a valid frame. Bare MLS ciphertext no longer occurs on the
        // send path (every outbound frame is a tagged message frame), so unrecognized
        // plaintext fails loudly here rather than being fed to the MLS parser.
        Err(TwoMlsPqError::DecryptionFailed)
    }

    /// The SHA-256 of the receive group's classical (message-half) group id — the
    /// binding context for identity introductions, matching the classical backend's
    /// convention and `QueuedRemoteProposal.context`. Always the classical half:
    /// message ordering rides it, and it exists from establishment (the PQ half may
    /// still be deferred pre-A.4).
    pub fn proposal_context(&self) -> Option<Vec<u8>> {
        let inner = self.lock();
        inner
            .recv_group
            .as_ref()
            .map(|rg| crate::sha256(rg.classical.group_id()))
    }

    /// Where to post outbound frames: the recv group's classical-half exporter at its
    /// current epoch. The recv group *is* the peer's send group, so this value appears
    /// in the peer's `should_listen_on` set. `None` until the recv group exists (the
    /// initiator pre-return-welcome delivers via the invitation channel instead).
    pub fn send_rendezvous(&self) -> Result<Option<RendezvousId>> {
        let inner = self.lock();
        let Some(recv) = inner.recv_group.as_ref() else {
            return Ok(None);
        };
        Ok(Some(RendezvousId {
            bytes: rendezvous_secret(recv.message_group())?,
        }))
    }

    /// Serialise the session for persistence; restore with `from_archive`. Archive is
    /// **total** — a session is ALWAYS archivable, in any state, so this never refuses.
    ///
    /// The bytes are **plaintext secret material** (the current signing identity, group
    /// snapshots including signing keys and epoch secrets, the PSK ledger, and any
    /// mid-round KEM material) — seal them before persisting (`apq::archive::seal` is the
    /// provided tool; the key belongs in the platform keystore). An archive is a **move,
    /// not a copy**: any further use of the live session (or of a second restore) rewinds
    /// the sender ratchet, which re-derives AEAD keys/nonces for new plaintexts. The
    /// caller owns single-use/latest-only discipline, as with invitation archives.
    ///
    /// A mid-A.3 PQ round is serialized whole (`Initiating` holds the decapsulation key,
    /// `Responding` the held shared secret). This does not weaken the ratchet in a way
    /// the archive doesn't already: the blob carries the PSK ledger, epoch secrets, and
    /// leaf signing keys, and the seal-before-persisting contract covers the round
    /// material alongside them; the marginal exposure is at most one round of PCS against
    /// an archive thief who already holds the epoch secrets. The alternative is unsound:
    /// a responder that discarded its held secret could never process the initiator's
    /// incoming bind (0x09) — a permanent side-band desync — so serialization is the only
    /// correct choice.
    pub fn archive(&self) -> Result<Archive> {
        use mls_rs::mls_rs_codec::{MlsEncode, MlsSize};

        let mut inner = self.lock();
        let pq_inflight = inner.pq_inflight.as_ref().map(wire_pq_inflight);
        let client = signing_identity_blob(&inner.client);
        let staged_candidates = inner
            .staged_candidates
            .iter()
            .map(|c| signing_identity_blob(c))
            .collect::<Vec<_>>();
        let (auth_mine, auth_theirs) = inner.with_auth(|core| {
            let seq = |s: &apq::authentication::PartySequence| {
                let (history, authorized_next) = s.to_parts();
                archive_wire::WirePartySequence {
                    history: history
                        .into_iter()
                        .map(|bytes| archive_wire::IdBlob { bytes })
                        .collect(),
                    authorized_next: authorized_next
                        .into_iter()
                        .map(|bytes| archive_wire::IdBlob { bytes })
                        .collect(),
                }
            };
            (seq(&core.mine), seq(&core.theirs))
        });

        // Prune the listen map against the same retention window whose epochs the
        // exported snapshots carry, so the archive is internally consistent.
        inner.record_listen_rendezvous()?;

        let group_entry = |state: apq::CombinerGroupState| archive_wire::GroupEntry {
            classical: archive_wire::GroupBlob {
                bytes: state.classical,
            },
            pq: state.pq.map(|bytes| archive_wire::GroupBlob { bytes }),
        };
        let send_group = group_entry(
            inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .export_state()?,
        );
        let recv_group = match inner.recv_group.as_mut() {
            Some(recv) => Some(group_entry(recv.export_state()?)),
            None => None,
        };

        let archive =
            archive_wire::SessionArchive {
                session_id: inner.session_id.bytes.clone(),
                client,
                my_state: wire_principal_state(&inner.my_state),
                their_state: wire_principal_state(&inner.their_state),
                pq_turn_mine: inner.pq_turn_mine,
                spawn_token: inner.spawn_token.clone(),
                send_group,
                recv_group,
                send_psk_ledger: inner
                    .send_psk_ledger
                    .iter()
                    .map(|(epoch, exported)| archive_wire::PskEntry {
                        epoch: *epoch,
                        component_id: exported.component_id(),
                        psk_id: exported.psk_id().to_vec(),
                        psk: exported.psk().clone(),
                    })
                    .collect(),
                retired_send_psks: inner.retired_send_psks.clone(),
                last_cross_injected: inner.last_cross_injected,
                last_cross_injected_pq: inner.last_cross_injected_pq,
                last_send_pq_exported: inner.last_send_pq_exported,
                listen_rendezvous: inner
                    .listen_rendezvous
                    .iter()
                    .map(|(&epoch, addr)| archive_wire::ListenEntry {
                        epoch,
                        addr: addr.clone(),
                    })
                    .collect(),
                recv_header_keys: inner
                    .recv_header_keys
                    .iter()
                    .map(|(&epoch, key)| archive_wire::HeaderKeyEntry {
                        epoch,
                        key: key.clone(),
                    })
                    .collect(),
                recv_header_keys_pq: inner
                    .recv_header_keys_pq
                    .iter()
                    .map(|(&epoch, key)| archive_wire::HeaderKeyEntry {
                        epoch,
                        key: key.clone(),
                    })
                    .collect(),
                pending_outbound: inner.pending_outbound.clone(),
                pending_proposal_hash: inner.pending_proposal_hash.clone(),
                current_staple: inner.current_staple.clone(),
                pending_proposal_message: inner.pending_proposal_message.as_ref().map(
                    |(proposing, message)| archive_wire::WireStagedProposal {
                        proposing: proposing.clone(),
                        message: message.clone(),
                    },
                ),
                joined_welcome_digest: inner.joined_welcome_digest.clone(),
                offered_proposal: inner.offered_proposal.as_ref().map(
                    |(digest, proposal, proposing)| archive_wire::OfferedProposal {
                        digest: digest.clone(),
                        proposal: proposal.clone(),
                        proposing: proposing.clone(),
                    },
                ),
                queued_proposal: inner.queued_proposal.as_ref().map(
                    |(digest, proposing, proposal)| archive_wire::WireQueuedProposal {
                        digest: digest.clone(),
                        proposing: proposing.clone(),
                        proposal: proposal.clone(),
                    },
                ),
                staged_candidates,
                deferred_candidate: inner.deferred_candidate.clone(),
                auth_mine,
                auth_theirs,
                pending_pq_outbound: inner.pending_pq_outbound.clone(),
                pq_inflight,
            };

        // Exact-size preallocation: a growing Vec would strand unwiped partial copies of
        // the secrets in freed allocations. The final `Archive.bytes` handed across the
        // FFI is an unwiped copy regardless — hence the sealing obligation above.
        // Header: [version][classical u16 BE][pq u16 BE] — 5 bytes.
        let mut out = Zeroizing::new(Vec::with_capacity(5 + archive.mls_encoded_len()));
        out.push(SESSION_ARCHIVE_VERSION);
        out.extend_from_slice(&inner.suite.to_wire());
        archive
            .mls_encode(&mut out)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        Ok(Archive {
            bytes: out.to_vec(),
        })
    }

    /// Approve the peer's stapled Upd proposal (identified by its digest). Validated and
    /// stored in the session's single queued slot; the next `prepare_to_encrypt(None)`
    /// re-applies and commits it (with a cross-party PSK refresh). Single-occupancy,
    /// latest-wins; a rejected call is a no-op.
    pub fn queue_proposal(&self, digest: Vec<u8>) -> Result<()> {
        let mut inner = self.lock();
        let (offered, proposal_bytes, proposing) = inner
            .offered_proposal
            .take()
            .ok_or(TwoMlsPqError::ProposalRejected)?;
        // The offer's digest must match the value the app approved.
        if offered != digest {
            inner.offered_proposal = Some((offered, proposal_bytes, proposing));
            return Err(TwoMlsPqError::ProposalRejected);
        }
        // Validate without leaving the send group's cache touched (see
        // `validate_offered_update`). On success, record the authorization and the queued
        // proposal; on ANY rejection, restore the offer so the call is a pure no-op.
        match inner.validate_offered_update(&proposal_bytes, &proposing) {
            Ok(()) => {
                // Approving the proposal IS the app's authorization of the credential it
                // carries (the running tally — a later queue replaces both the
                // authorization and the queued proposal while no commit has happened).
                inner.with_auth(|core| core.theirs.authorize(proposing.clone()));
                inner.queued_proposal = Some((digest, proposing, proposal_bytes));
                Ok(())
            }
            Err(e) => {
                inner.offered_proposal = Some((offered, proposal_bytes, proposing));
                Err(e)
            }
        }
    }

    /// The remote credential currently queued for the next commit (the app's running
    /// tally), or `None`. Lets the app decide whether a newly-received proposal should
    /// replace it (queue the newer one) or be kept (do nothing); the library's own
    /// policy is latest-wins, and the slot is cleared when the send epoch advances (a
    /// fold or an A.3 bind).
    pub fn queued_remote_successor(&self) -> Option<ClientId> {
        self.lock()
            .queued_proposal
            .as_ref()
            .map(|(_, proposing, _)| ClientId {
                bytes: proposing.clone(),
            })
    }

    /// Stage a new principal for the next rotation commit, minting its signing keys
    /// internally: the MLS signing keys are session-owned state, so the app supplies only
    /// the opaque ClientId. Call before `prepare_to_encrypt(Some(new_client_id))`, which
    /// commits the handoff.
    ///
    /// Idempotent-ish, matching the classical `propose`: staging the id already staged is
    /// a no-op (the existing staged identity — and its freshly minted keys — is kept); a
    /// different id replaces the staged identity.
    pub fn stage_rotation(&self, new_client_id: Vec<u8>) -> Result<()> {
        // Empty is reserved: the rotation commit announces the id in authenticated_data,
        // and empty AD is the "ratchet commit" discriminator — the handoff would be
        // structurally invisible to the peer.
        if new_client_id.is_empty() {
            return Err(TwoMlsPqError::InvalidClientId);
        }
        let mut inner = self.lock();
        // Already in flight, or already the parked next request → no-op.
        if inner
            .staged_candidates
            .iter()
            .any(|staged| staged.client_id().bytes == new_client_id)
            || inner.deferred_candidate.as_deref() == Some(new_client_id.as_slice())
        {
            return Ok(());
        }
        if inner.staged_candidates.len() < CANDIDATE_WINDOW {
            // Admit into the in-flight pool: mint, rebind the candidate's clients to the
            // session-canonical AS core, and authorize the id for OUR sequence (the peer's
            // provider learns it from the proposal we send; ours needs it for the local
            // commit apply). It is proposable this round via `prepare_to_encrypt(Some(id))`.
            let candidate = TwoMlsPqPrincipal::new(new_client_id.clone())?;
            candidate.combiner().auth_view().rebind(&inner.auth_core);
            inner.with_auth(|core| core.mine.authorize(new_client_id.clone()));
            inner.staged_candidates.push(candidate);
        } else {
            // Pool full — never evict a sent candidate. Park this request in the single
            // deferred slot; it is promoted and proposed on the next routine round once a
            // canonicalization frees a slot. Not authorized yet (it is not on the wire),
            // keeping `mine.authorized_next` aligned with the retained principals.
            inner.deferred_candidate = Some(new_client_id.clone());
        }
        let old = inner.my_state.client_id();
        inner.my_state = PrincipalState::Pending {
            old,
            new: ClientId {
                bytes: new_client_id,
            },
        };
        Ok(())
    }

    /// Acknowledge a replayed initial frame routed here by the invitation's forward
    /// table. `spawn_token` is the caller's opaque identifier for the frame (the same
    /// value it computes for `TwoMlsPqInvitation::forward_group_id`); it must equal the
    /// token this session was spawned under. Returns `Ok(None)`: a PQ initiator cannot
    /// staple a private message pre-establishment, so a replay of the initial frame
    /// never carries an undelivered payload. A mismatched token is a mis-route
    /// (`DecryptionFailed`); initiator-side sessions have no spawn token and refuse
    /// (`SessionNotReady`).
    pub fn forwarded(&self, spawn_token: Vec<u8>) -> Result<Option<MlsSenderMessage>> {
        let inner = self.lock();
        let expected = inner
            .spawn_token
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        if *expected != spawn_token {
            return Err(TwoMlsPqError::DecryptionFailed);
        }
        Ok(None)
    }

    /// The combiner group ids and per-epoch rendezvous addresses the transport should
    /// listen on. Addresses derive from the send group's classical half, one per
    /// classical epoch, retained across epochs so traffic posted at a prior epoch's
    /// address still lands. The peer derives its post address from its recv group —
    /// the same MLS group — so the values align by construction.
    pub fn should_listen_on(&self) -> Result<ListenChannels> {
        let mut inner = self.lock();
        inner.record_listen_rendezvous()?;
        let send = inner
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_group = CombinerGroupId {
            classical: MlsGroupId {
                bytes: send.classical.group_id().to_vec(),
            },
            // Empty until the deferred PQ half is bootstrapped (A.4).
            pq: MlsGroupId {
                bytes: send
                    .pq
                    .as_ref()
                    .map(|pq| pq.group_id().to_vec())
                    .unwrap_or_default(),
            },
        };
        let rendezvous_by_epoch = inner
            .listen_rendezvous
            .iter()
            .map(|(epoch, bytes)| EpochRendezvous {
                epoch: *epoch,
                rendezvous_id: RendezvousId {
                    bytes: bytes.clone(),
                },
            })
            .collect();
        Ok(ListenChannels {
            send_group,
            rendezvous_by_epoch,
        })
    }
}

#[cfg(test)]
mod tests;
