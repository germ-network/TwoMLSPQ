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
    commit_attestation, read_app_binding, read_apqinfo, verify_app_binding,
    verify_apqinfo_deferred, verify_apqinfo_pair, verify_deferred_pq_info, verify_pq_half_unbound,
    ApqInfo, ApqInfoUpdate, EPOCH_UNBOUND,
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
    /// The `state_seq` at which `current_staple` was last set (the commit — or the birth
    /// welcome — that produced it). An outbound frame stapling this commit publishes
    /// stored-private-key material that was persisted at this seq, so it is the frame's
    /// `depends_on_seq`: the app waits for this seq to be durable before transmitting. A
    /// routine frame re-stapling an already-persisted commit therefore imposes no wait. Live
    /// state (re-derivable from the archived `state_seq` on restore — not itself serialized).
    current_staple_seq: u64,
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
    /// Monotonic per-session mutation counter, bumped once per state-advancing FFI call
    /// (see `mutate_and_persist`). Serialized in the archive so it continues across a
    /// restore; stamps each pushed blob and feeds `depends_on_seq` on outbound frames. `u64`
    /// so it cannot overflow (2^64 mutations is unreachable — ~585k years at 1M/s); the bump
    /// is a `checked_add` that hard-errors rather than wrapping, since a wrap would corrupt
    /// the app's `durable >= depends_on` transmit gate.
    state_seq: u64,
    my_state: PrincipalState,
    their_state: PrincipalState,
    /// The current round's outbound side-band frame, UNSEALED and RETAINED for re-send —
    /// the side-band analogue of [`current_staple`](Self::current_staple), and set by both
    /// roles (initiator `*_begin`/`pq_ratchet_bind`, responder `*_respond`).
    ///
    /// Retained rather than handed out once: a side-band frame is the only carrier of its
    /// PQ half, so a lost one has no other way to reach the peer. The A.3 bind is the sharp
    /// case — its classical commit re-staples on message frames, but the peer cannot apply
    /// that staple without the PQ commit riding this frame, so the classical stream stalls
    /// retriably "until the BIND lands" and a take-once bind that never lands stalls it
    /// forever. Re-sending until the step advances heals that, exactly as `current_staple`
    /// heals the classical stream.
    ///
    /// Lifecycle: REPLACED when this side produces the round's next frame, CLEARED when
    /// this side's part in the round completes (the `*_apply` receivers). An initiator's
    /// terminal bind therefore lingers until the peer opens the next round — deliberate:
    /// it is precisely the frame that must land, and duplicates are benign discards on the
    /// receiver (see `pq_ratchet_apply`). Single slot: a round has one frame in flight, and
    /// the turn plus `pq_inflight` — not slot occupancy — are what gate a new operation.
    ///
    /// Sealing happens at hand-out ([`pq_pending_outbound`]), not here: `seal_side_band`
    /// draws a fresh random nonce per call and mutates nothing, so re-sealing the same
    /// frame is safe and each re-send tracks the current PQ header epoch. A host that
    /// chunks needs the opposite — a base that holds still — and asks for it with
    /// [`SideBandSealing::Stable`], served from `pq_outbound_seal`.
    pending_pq_outbound: Option<Vec<u8>>,
    /// The `SideBandSealing::Stable` seal cache: `(frame, sealed)`.
    ///
    /// SELF-VALIDATING BY CONSTRUCTION — it stores the frame it sealed, and a hand-out
    /// re-seals whenever that no longer matches the live `pending_pq_outbound`. The
    /// alternative (a bare `Option<Vec<u8>>` invalidated at each set site) would be an
    /// invariant a dozen call sites had to remember, and the failure would be silent and
    /// bad: handing a chunking host the seal of a superseded frame. Comparing two short
    /// frames costs nothing next to the AEAD it skips.
    ///
    /// Live-only, deliberately not archived: a restore restarts the chunking pass with a
    /// fresh base, which a host must already tolerate (a lost pass demands the same).
    ///
    /// Epoch note: a cached seal keeps the epoch it was sealed at, so it ages where a
    /// `Fresh` re-seal would not. For the PQ family that is near-moot — `seal_side_band`
    /// seals under recv-PQ, which advances only when the PEER commits, and applying a peer
    /// commit clears the retained frame anyway; the peer's `recv_pq_header_keys` window
    /// covers the rest. The exception is the ONE frame taking the classical fallback, the
    /// pre-A.4 `BOOTSTRAP_KP`: its key tracks the CLASSICAL epoch, which ordinary messaging
    /// advances, so a long `Stable` pass over it could age past the peer's classical window.
    /// `Fresh` (today's only caller) re-seals per hand-out and never meets this.
    pq_outbound_seal: Option<(Vec<u8>, Vec<u8>)>,
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
    /// The peer's published combiner key package this session initiated toward —
    /// retained so every pre-establishment `encrypt` can HPKE-seal a fresh §A.1
    /// envelope to its KP′ (§A.1: the initiator keeps sending app messages, stapling
    /// the welcome, until the acceptor's return welcome arrives). `None` on acceptor
    /// sessions; cleared at the establishment cutover (`process_welcome`) — the
    /// envelope machinery is obsolete once the peer provably joined. Rides the archive
    /// so a session restored at birth (the app captures at reply) can still send first.
    initial_their_kp: Option<CombinerKeyPackage>,
    /// The host's app-layer welcome riding every pre-establishment envelope (see
    /// `set_initial_app_payload`): establishment-SELF-SUFFICIENT by contract (it
    /// carries the MLS welcome + return key package inside, e.g. a signed identity
    /// envelope), so composed envelopes omit the bare sections while it is set.
    /// Initiator-only; cleared at the establishment cutover; rides the archive.
    initial_app_payload: Option<Vec<u8>>,
    /// The initiator's return-group combiner key package for the bare-section envelope
    /// shape (no `initial_app_payload` — hosts that deliver establishment material
    /// unwrapped; see `set_initial_return_key_package`). Initiator-only; cleared at
    /// the establishment cutover; rides the archive.
    initial_return_kp: Option<CombinerKeyPackage>,
    /// The foreign persistence hook this session pushes to after every state-advancing
    /// mutation (see `mutate_and_persist`). `None` opts out of push persistence (tests,
    /// benches, fuzz). Not part of the archive — it is live plumbing supplied at every
    /// construction/restore.
    sink: Option<Arc<dyn crate::ArchiveSink>>,
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
pub use frames::{pq_frame_kind, OpenedFrame, OpenedFrameKind, PqFrameKind, SideBandSealing};

mod messaging;
use messaging::*;

mod pq_ops;
use pq_ops::*;

mod archive;
// Tests poke the wire structs directly (`super::archive_wire::...`); the lib itself
// only reaches them through `archive`'s own endpoints.
#[cfg(test)]
use archive::archive_wire;

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
    /// Retain an initiator's side-band `frame` for re-send, seeding the
    /// [`SideBandSealing::Stable`] cache with `sealed` — the very bytes the `*_begin` call
    /// is about to return.
    ///
    /// The seed is what makes `begin`'s return and a subsequent `Stable` hand-out AGREE.
    /// Without it the first peek re-seals (a fresh nonce), so a chunking host that sent
    /// `begin`'s return and then peeked for the rest of the pass would cut pieces from two
    /// different seals — which reassemble into nothing. `Fresh` hosts are unaffected: they
    /// re-seal per send by definition, and the seeded cache is inert for them (and
    /// self-validating, so it cannot go stale).
    ///
    /// Responder frames need no equivalent: `*_respond` hands nothing back, so its frame
    /// only ever reaches the wire through a hand-out.
    fn retain_side_band(&mut self, frame: Vec<u8>, sealed: &[u8]) {
        self.pq_outbound_seal = Some((frame.clone(), sealed.to_vec()));
        self.pending_pq_outbound = Some(frame);
    }

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
        // App-state binding: the return group must carry back exactly this session's own
        // binding — the acceptor mirrors the (verified) binding of the welcome it replies
        // to, so on an honest peer both directions match. An absent or different binding
        // here is a strip/downgrade or wrong-relationship welcome, refused before any
        // session state adopts the join. Covers both the deferred (A.4) and full-pair
        // welcome shapes; the binding lives on the classical half.
        let own_binding = match self.send_group.as_ref() {
            Some(send) => read_app_binding(&send.classical)?,
            // Structurally unreachable: every constructor and restore path produces a
            // send group. Refuse rather than skip the check.
            None => return Err(TwoMlsPqError::SessionNotEstablished),
        };
        verify_app_binding(&recv_group.classical, own_binding.as_deref())?;
        if let Some(pq) = recv_group.pq.as_ref() {
            verify_pq_half_unbound(pq)?;
        }
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
        // Establishment cutover: the peer provably joined (its return welcome created
        // our recv group), so the initiator's pre-establishment envelope machinery is
        // obsolete — clear the retained seal target / payload / return KP and any
        // parked envelope. From here the 0x03 message path takes over (its staple
        // still re-sends the welcome until our first commit; the peer skips repeats
        // idempotently). Acceptors never reach this line (their recv group exists
        // from birth, so re-deliveries return early above) and never set these fields.
        self.initial_their_kp = None;
        self.initial_app_payload = None;
        self.initial_return_kp = None;
        self.pending_outbound = None;
        Ok(())
    }

    /// Run `f` against the session-canonical AS core.
    fn with_auth<R>(&self, f: impl FnOnce(&mut apq::authentication::AuthCore) -> R) -> R {
        let mut core = self.auth_core.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut core)
    }

    /// Compose and HPKE-seal a §A.1 envelope from the retained pre-establishment state,
    /// optionally stapling `stapled` (a `[0x13][app ciphertext]` frame from a
    /// pre-establishment `encrypt`). Initiator-only, pre-establishment-only: requires
    /// the retained seal target (`initial_their_kp`) and the birth welcome still being
    /// the staple — both are cleared at the establishment cutover, and no commit can
    /// replace the staple before it (a fold needs a recv group). Sections follow the
    /// either/or rule (see `seal_initial_envelope`): the self-sufficient host payload
    /// alone, or the bare welcome + return key package.
    fn compose_initial_envelope(&self, stapled: Option<&[u8]>) -> Result<Vec<u8>> {
        let their_kp = self
            .initial_their_kp
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        if self.current_staple.first() != Some(&APQ_TAG) {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let return_kp_blob = self
            .initial_return_kp
            .as_ref()
            .map(|kp| crate::key_packages::encode_combiner_key_package(kp.clone()));
        let (app_payload, welcome, return_kp) = match &self.initial_app_payload {
            Some(payload) => (Some(payload.as_slice()), None, None),
            None => (
                None,
                Some(self.current_staple.as_slice()),
                return_kp_blob.as_deref(),
            ),
        };
        crate::key_packages::seal_initial_envelope(
            their_kp,
            app_payload,
            welcome,
            return_kp,
            stapled,
        )
    }

    /// The current epoch of each PQ half (`None` when the half is absent), as
    /// `(send_pq_epoch, recv_pq_epoch)`. This is the PQ-epoch manifest that
    /// `build_archive_wire` records and that `reconcile_persisted` validates; it is also
    /// the signal `process_incoming` uses to decide Core vs. Checkpoint — a frame that
    /// leaves both epochs untouched is classical-only (Core), any change means a PQ half
    /// was created or advanced and must be captured by a Checkpoint.
    fn pq_epochs(&self) -> (Option<u64>, Option<u64>) {
        let epoch = |g: &Option<CombinerGroup>| {
            g.as_ref()
                .and_then(|g| g.pq.as_ref())
                .map(|p| p.current_epoch())
        };
        (epoch(&self.send_group), epoch(&self.recv_group))
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
            current_staple_seq: 0,
            joined_welcome_digest,
            offered_proposal: None,
            queued_proposal: None,
            staged_candidates: Vec::new(),
            deferred_candidate: None,
            auth_core,
            pq_inflight: None,
            session_id,
            state_seq: 0,
            my_state: PrincipalState::Sync { client_id: my_id },
            their_state: PrincipalState::Sync {
                client_id: their_id,
            },
            pq_turn_mine: initiated,
            pending_pq_outbound: None,
            pq_outbound_seal: None,
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
            // Set by `initiate` right after construction (acceptors never need them);
            // cleared at the establishment cutover.
            initial_their_kp: None,
            initial_app_payload: None,
            initial_return_kp: None,
            // Attached post-construction via `install_sink` (which also pushes the baseline
            // checkpoint); a fresh session starts with no persistence hook.
            sink: None,
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

    /// The persistence choke point: run a state-advancing mutation under the lock, bump the
    /// mutation counter, then push the resulting blob to the sink (if any) OUTSIDE the lock.
    /// `kind` is the blob a mutation of this shape produces — `Core` for classical mutations,
    /// `Checkpoint` for PQ-touching ones (see the footprint table). Pushes even when `f`
    /// returns `Err` (partial mutations are real — e.g. the eager cross-injection watermark
    /// advance); an encode failure after a *successful* mutation is surfaced so the app
    /// retries rather than transmitting against an un-persisted state.
    fn mutate_and_persist<T>(
        &self,
        kind: crate::BlobKind,
        f: impl FnOnce(&mut SessionInner) -> Result<T>,
    ) -> Result<T> {
        let mut inner = self.lock();
        // Bump BEFORE running the mutation so a staple-setting mutation can record the seq this
        // push will land at (that seq feeds `depends_on_seq` on the frame it produces).
        // `checked_add` never wraps (2^64 mutations is unreachable — ~585k years at 1M/s); if it
        // somehow saturated we run the mutation without persisting rather than corrupt the seq
        // ordering that gates transmission. No panic (the crate denies it).
        match inner.state_seq.checked_add(1) {
            Some(s) => inner.state_seq = s,
            None => return f(&mut inner),
        }
        let seq = inner.state_seq;
        let result = f(&mut inner);
        let Some(sink) = inner.sink.clone() else {
            return result;
        };
        let encoded = match kind {
            crate::BlobKind::Core => archive::encode_core(&mut inner),
            crate::BlobKind::Checkpoint => archive::encode_checkpoint(&mut inner),
        };
        drop(inner);
        match encoded {
            Ok(bytes) => {
                sink.persist(seq, kind, bytes);
                result
            }
            // Encode failed AFTER the mutation (unreachable in practice): if the mutation
            // succeeded, surface the encode error (app retries); otherwise keep its error.
            Err(e) => match result {
                Ok(_) => Err(e),
                Err(_) => result,
            },
        }
    }

    /// Bump the counter and push a fresh blob of `kind` for a mutator that can't run inside
    /// `mutate_and_persist` (e.g. it re-acquires the lock internally). Call at the end, after
    /// the mutator has released the lock: it encodes the CURRENT state, so it captures the
    /// mutation even though the bump happens in a separate lock acquisition (mutations are
    /// serialized per session, so nothing slips between). No-ops without a sink.
    fn persist_after(&self, kind: crate::BlobKind) {
        let mut inner = self.lock();
        match inner.state_seq.checked_add(1) {
            Some(s) => inner.state_seq = s,
            None => return,
        }
        let seq = inner.state_seq;
        if let Some(sink) = inner.sink.clone() {
            let bytes = match kind {
                crate::BlobKind::Core => archive::encode_core(&mut inner),
                crate::BlobKind::Checkpoint => archive::encode_checkpoint(&mut inner),
            };
            if let Ok(bytes) = bytes {
                drop(inner);
                sink.persist(seq, kind, bytes);
            }
        }
    }

    /// Shared body of the two pre-establishment attach setters: guard (initiator-only —
    /// only an initiated session retains a seal target — and pre-establishment only),
    /// apply the field, regenerate the parked envelope, and stamp `current_staple_seq`
    /// so frames that re-staple the new material gate on THIS mutation's persistence
    /// (`depends_on_seq`).
    fn set_initial_field(&self, apply: impl FnOnce(&mut SessionInner)) -> Result<()> {
        self.mutate_and_persist(crate::BlobKind::Core, |inner| {
            if inner.recv_group.is_some() || inner.initial_their_kp.is_none() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            apply(inner);
            let envelope = inner.compose_initial_envelope(None)?;
            inner.pending_outbound = Some(envelope);
            inner.current_staple_seq = inner.state_seq;
            Ok(())
        })
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Create a session as the initiating party targeting `their_key_package`.
    ///
    /// The first frame — and every pre-establishment `encrypt` after it — is a §A.1
    /// envelope HPKE-sealed to the peer's KP′ inside the library: `pending_outbound()`
    /// returns it opaque, the peer recovers the sections with
    /// `TwoMlsPqInvitation::open_initial` and joins with `receive`. An app-layer
    /// welcome (identity introduction, signed keys, …) is attached AFTER construction
    /// with `set_initial_app_payload` — such a payload typically signs over the
    /// welcome (read it via `initial_welcome`) and the return key package, so it
    /// cannot exist before `initiate` returns; the pre-v15 `app_payload` parameter is
    /// gone for the same reason (v16). Until the peer's return welcome arrives,
    /// `prepare_to_encrypt`/`encrypt` keep producing fresh envelopes, each stapling
    /// the current app message (§A.1: the initiator sends app messages immediately).
    ///
    /// `app_binding` is the optional app-state binding: opaque bytes welded into the send
    /// group's GroupContext (an `AppBinding` extension, the APQInfo mechanism) at this
    /// moment and immutable for the session's lifetime — the binding of the session to the
    /// app's IMMUTABLE relationship identity, which the two mutable agents (rotation
    /// lifecycle) cannot carry. The peer verifies it at `receive(expected_app_binding:)`,
    /// mirrors it onto the return group, and this session requires the return welcome to
    /// carry it back unchanged; read it back any time (e.g. after a restore) with
    /// [`app_binding`](Self::app_binding). Pass a DIGEST, not raw identifiers — the first
    /// adopter binds `H(domain-tag ‖ role-ordered did:did)`, sharing its canonicalization
    /// with the delegation binding so the two cannot drift; this library never interprets
    /// the bytes. An EMPTY binding is rejected as `AppBindingMismatch` (reserved — an
    /// accidentally empty digest must not mint a bound-to-nothing session; `None` is the
    /// unbound state, the AppBinding analogue of the empty-ClientId rule).
    #[uniffi::constructor]
    pub fn initiate(
        client: Arc<TwoMlsPqPrincipal>,
        their_key_package: CombinerKeyPackage,
        app_binding: Option<Vec<u8>>,
    ) -> Result<Arc<Self>> {
        // Empty bindings are reserved as invalid (see `AppBindingMismatch`): reject before
        // anything — even the AS peer admission inside group creation — is touched.
        // `GroupCreation::with_app_binding` enforces the same rule at the choke point.
        if app_binding.as_deref().is_some_and(<[u8]>::is_empty) {
            return Err(TwoMlsPqError::AppBindingMismatch);
        }
        validate_combiner_kp(client.combiner().cipher_suite(), &their_key_package)?;
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(client.client_id(), their_id.clone())?;

        let (send_group, apq_welcome) = create_combiner_send_group(
            &their_key_package.classical,
            &their_key_package.pq,
            client.combiner(),
            app_binding.as_deref(),
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
        {
            // Pre-establishment frames have no symmetric key: every one is a §A.1
            // envelope HPKE-sealed to the peer's KP′. Retain the key package (the seal
            // target), then park the birth envelope — `pending_outbound` returns it
            // opaque; the peer opens it with `TwoMlsPqInvitation::open_initial`. The
            // same retained state lets every pre-establishment `encrypt` (and a
            // session restored at birth) compose a fresh envelope stapling the
            // current app message.
            let mut inner = session.lock();
            inner.initial_their_kp = Some(their_key_package);
            let envelope = inner.compose_initial_envelope(None)?;
            inner.pending_outbound = Some(envelope);
        }
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
    ///
    /// `expected_app_binding` is the app-state binding this welcome must carry (see
    /// `TwoMlsPqInvitation::receive`, which documents the semantics): `Some` requires the
    /// joined group's `AppBinding` to be byte-equal, `None` requires it to carry none —
    /// any other combination is `AppBindingMismatch`, raised before this client's
    /// key-package store is cleared.
    #[uniffi::constructor]
    pub fn accept(
        client: Arc<TwoMlsPqPrincipal>,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
        expected_app_binding: Option<Vec<u8>>,
    ) -> Result<Arc<Self>> {
        Self::accept_with(
            client,
            None,
            welcome,
            their_key_package,
            None,
            expected_app_binding,
        )
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
    ///
    /// `expected_app_binding` is verified against the joined welcome's `AppBinding`
    /// extension (exact match, including None==None) BEFORE any state is touched — the
    /// key-package store purge, the AS seeding, and (on the invitation path) every
    /// invitation mutation all come after, so a rejected welcome leaves the caller intact.
    /// The return group is then created carrying the verified incoming binding, so both
    /// directions hold identical bytes. An empty expectation is rejected up front: empty
    /// is reserved (no group can carry an empty binding), so it could never match.
    pub(crate) fn accept_with(
        client: Arc<TwoMlsPqPrincipal>,
        session_client: Option<Arc<TwoMlsPqPrincipal>>,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
        spawn_token: Option<Vec<u8>>,
        expected_app_binding: Option<Vec<u8>>,
    ) -> Result<Arc<Self>> {
        // Empty bindings are reserved as invalid (see `AppBindingMismatch`); an empty
        // expectation is unsatisfiable, so reject it before the join rather than let it
        // surface as a confusing post-join mismatch.
        if expected_app_binding
            .as_deref()
            .is_some_and(<[u8]>::is_empty)
        {
            return Err(TwoMlsPqError::AppBindingMismatch);
        }
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
        // App-state binding: the joined welcome must carry exactly the binding the caller
        // expects (a wrong or stripped binding is a wrong-relationship welcome; a binding
        // the caller did not state is never silently accepted). Checked before the
        // key-package purge and AS seeding below — and, on the invitation path, before
        // any invitation state is claimed — so a rejected welcome leaves everything
        // reusable. The binding lives on the classical (message) half; the PQ half
        // inherits coverage through the APQInfo half-binding verified at join.
        verify_app_binding(&recv_group.classical, expected_app_binding.as_deref())?;
        if let Some(pq) = recv_group.pq.as_ref() {
            verify_pq_half_unbound(pq)?;
        }
        // The verified binding is mirrored onto the return group below, so the session
        // carries identical bytes in both directions.
        let app_binding = read_app_binding(&recv_group.classical)?;
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
            app_binding.as_deref(),
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
        // R1: set the spawn token during construction so it rides the baseline checkpoint
        // `install_sink` later pushes (the old post-construction `set_spawn_token`, run after
        // the session was already handed to the caller, could be missed).
        if let Some(token) = spawn_token {
            session.lock().spawn_token = Some(token);
        }
        Ok(session)
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Attach the persistence hook (see [`crate::ArchiveSink`]) this session pushes to after
    /// every state-advancing mutation, and immediately push a baseline `Checkpoint` at the
    /// current `state_seq` so the sink starts from a complete snapshot. Call once, right after
    /// construction or restore and before using the session — mutations made before installing
    /// are not pushed (a fresh session has none; a restored one re-baselines here). Installing
    /// does not itself advance `state_seq`. Once-only: a second call returns
    /// `SinkAlreadyInstalled` rather than silently orphaning the first sink.
    pub fn install_sink(&self, sink: Arc<dyn crate::ArchiveSink>) -> Result<()> {
        let mut inner = self.lock();
        // Install exactly once. A second call would silently orphan the first sink (all future
        // pushes go to the new one), so reject it rather than fail quietly at restore time.
        if inner.sink.is_some() {
            return Err(TwoMlsPqError::SinkAlreadyInstalled);
        }
        inner.sink = Some(Arc::clone(&sink));
        let seq = inner.state_seq;
        let bytes = archive::encode_checkpoint(&mut inner)?;
        drop(inner);
        sink.persist(seq, crate::BlobKind::Checkpoint, bytes);
        Ok(())
    }

    /// The session's current persistence `state_seq` (the monotonic mutation counter). Lets
    /// the app correlate a frame's `depends_on_seq` against its own durable high-water mark,
    /// and gate transmission of the key-material-bearing frames whose return type does not
    /// carry the seq — the establishment envelope from `pending_outbound` and the PQ side-band
    /// frames from `pq_take_pending_outbound` (both publish stored-private-key material, so the
    /// app should read `state_seq()` right after taking them and wait for it to be durable
    /// before transmitting).
    pub fn state_seq(&self) -> u64 {
        self.lock().state_seq
    }

    /// Welcome bytes to deliver to the remote party to complete group establishment.
    /// Returns `None` once consumed or when both groups are live.
    pub fn pending_outbound(&self) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        // `take` is the state change; a `None` here is not one, so no bump/push.
        let frame = inner.pending_outbound.take()?;
        // The acceptor's return welcome (recv group already exists) is sealed like any
        // rendezvous-channel frame — the peer opens it from its send-group window. The
        // initiator's parked blob (no recv group yet) is already the §A.1 envelope —
        // composed at `initiate` and regenerated by the attach setters — and travels
        // the invitation channel as-is; the invitation opens it with `open_initial`.
        let out = if inner.recv_group.is_some() {
            inner.seal(&frame).ok()
        } else {
            Some(frame)
        };
        // The take advanced state (whatever the seal returned) — persist Core. Push keyed on
        // the take, not `out`: an (unreachable) post-establishment seal failure still consumed
        // the parked frame.
        if let Some(s) = inner.state_seq.checked_add(1) {
            inner.state_seq = s;
        }
        let seq = inner.state_seq;
        if let Some(sink) = inner.sink.clone() {
            if let Ok(bytes) = archive::encode_core(&mut inner) {
                drop(inner);
                sink.persist(seq, crate::BlobKind::Core, bytes);
            }
        }
        out
    }

    /// The plaintext birth `APQWelcome_A` (the message-frame staple form, first byte
    /// 0x01) while it is still the current staple — for the host to bind into its
    /// app-layer identity envelope at reply time (e.g. sign over the welcome + the
    /// return key package, then attach the result via `set_initial_app_payload`).
    /// `None` once the first send-group commit replaced the staple. Read-only.
    pub fn initial_welcome(&self) -> Option<Vec<u8>> {
        let inner = self.lock();
        (inner.current_staple.first() == Some(&APQ_TAG)).then(|| inner.current_staple.clone())
    }

    /// Attach (or replace) the host's app-layer welcome on this initiated session. The
    /// payload MUST be establishment-self-sufficient — it carries the MLS welcome
    /// (`initial_welcome`) and the initiator's return key package inside (e.g. a signed
    /// identity envelope) — because composed envelopes then omit the bare sections (the
    /// either/or rule on `seal_initial_envelope`). Regenerates the parked
    /// `pending_outbound` envelope and rides every later pre-establishment `encrypt`.
    ///
    /// Initiator-only, pre-establishment only (`SessionNotReady` otherwise).
    /// CAPTURE ORDERING: the retained state persists (a session captured at birth can
    /// still send first after restore), so capture AFTER this call — a snapshot taken
    /// between `initiate` and this attach restores a replier whose re-staples carry no
    /// identity payload.
    pub fn set_initial_app_payload(&self, payload: Vec<u8>) -> Result<()> {
        self.set_initial_field(|inner| inner.initial_app_payload = Some(payload))
    }

    /// Attach the initiator's return-group combiner key package for the BARE envelope
    /// shape (no self-sufficient `set_initial_app_payload`): pre-establishment
    /// envelopes then carry `[welcome][return_kp]`, so any single frame is a complete
    /// establishment vector for the invitation holder. Unused when a host payload is
    /// attached (the payload carries the key package itself). Same guards, capture
    /// ordering, and envelope regeneration as `set_initial_app_payload`.
    pub fn set_initial_return_key_package(&self, key_package: CombinerKeyPackage) -> Result<()> {
        self.set_initial_field(|inner| inner.initial_return_kp = Some(key_package))
    }

    /// True once both directions' PQ halves are live (post-A.4 bootstrap).
    pub fn is_fully_established(&self) -> bool {
        let inner = self.lock();
        matches!(
            (&inner.send_group, &inner.recv_group),
            (Some(s), Some(r)) if s.pq.is_some() && r.pq.is_some()
        )
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

    /// The app-state binding this session was created with (`initiate`'s `app_binding`,
    /// or the binding the accepted welcome carried), or `None` for an unbound session.
    /// Welded into the send group's GroupContext at creation and immutable for the
    /// session's lifetime, it rides the persisted group state — a restored session's
    /// owner re-verifies here that the session still belongs to the relationship it was
    /// pinned to. The bytes are opaque to this library (the adopter's digest); errors
    /// only if the extension is present but undecodable (corruption must not read back
    /// as "unbound").
    pub fn app_binding(&self) -> Result<Option<Vec<u8>>> {
        let inner = self.lock();
        match inner.send_group.as_ref() {
            Some(send) => Ok(read_app_binding(&send.classical)?),
            None => Ok(None),
        }
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
}

#[cfg(test)]
mod tests;
