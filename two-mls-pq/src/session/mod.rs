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
    ExportedPsk, GroupCreation, PskDomain, APQ_TAG,
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

/// A retained outbound side-band frame: the plaintext to re-send, plus its
/// [`SideBandSealing::Stable`] seal cache.
///
/// The frame is kept UNSEALED and sealed at hand-out — `seal_side_band` draws a fresh
/// random nonce per call and mutates nothing, so re-sealing is safe and a `Fresh` re-send
/// tracks the current header epoch. A chunking host needs the opposite (a base that holds
/// still) and asks for it with `Stable`, served from `seal`.
///
/// The cache lives INSIDE the frame it seals, which is what makes the invariant
/// structural: replacing or clearing the frame drops its cache with it, so no set site can
/// forget to invalidate and hand a chunking host the seal of a superseded frame. (An
/// earlier draft kept the two in separate fields and needed the cache to store its own copy
/// of the frame to validate against — co-location deletes the problem instead of policing
/// it.)
///
/// `seal` is live-only and deliberately not archived: a restore restarts a chunking pass
/// with a fresh base, which a host must already tolerate — a lost pass demands the same.
/// The frame itself rides the archive, so re-sending resumes across a restore either way.
///
/// Epoch note: a cached seal keeps the epoch it was sealed at, where a `Fresh` re-seal
/// would not. Near-moot for the PQ family (`seal_side_band` seals under recv-PQ, which
/// advances only when the PEER commits, and applying a peer commit clears the retained
/// frame anyway; the peer's `recv_pq_header_keys` window covers the rest). The exception is
/// the one frame taking the classical fallback, the pre-A.4 `BOOTSTRAP_KP`: its key tracks
/// the CLASSICAL epoch that ordinary messaging advances, so a long `Stable` pass over it
/// could age past the peer's classical window. `Fresh` never meets this.
/// A PQ commit that has landed, waiting for the classical commit that binds its entropy into
/// the classical half.
///
/// The two epochs are RESERVATIONS. They were computed as `current + 1` of each half before
/// the PQ commit, they ride both commits as the -02 `AppDataUpdate`, and they are checked
/// twice by the receiver: pre-apply per half against `context.epoch + 1` (`apq::rules`), and
/// post-apply across halves against both groups' actual epochs (`apply_bind`). Nothing here
/// makes them true — the two rules on `SessionInner::owed_bind` do. `discharge_owed_bind`
/// re-checks both against the live groups rather than trusting them, because the cost of
/// being wrong is a bind the peer rejects with the PQ leaf already spent, which no retry
/// can rebuild.
struct OwedBind {
    /// The applied PQ commit's bytes, verbatim, for the bind frame's first section. Public —
    /// this is a commit message, not key material.
    pq_commit: Vec<u8>,
    /// The classical epoch this bind's commit must land on.
    t_epoch: u64,
    /// The PQ epoch the landed commit produced, and which `apq_psk` must be exported from.
    pq_epoch: u64,
}

/// The leaf-identity moves an applied peer commit carried. Both `None` on the ordinary
/// round, where the commit refreshes leaf keys without touching a credential.
///
/// Identity travels IN the leaves (the AS validates it during processing), so what an
/// applied commit MOVED is the only evidence of a credential step — and the two directions
/// mean different things, which is why they are separate fields rather than a flag:
///
/// - `new_sender` — the PEER's leaf moved: its catch-up to a credential our own commit
///   already canonicalized. Reported to the app as the frame's new sender.
/// - `canonicalized_own` — OUR leaf moved: the peer committed one of our candidate Upds,
///   and that commit DEFINES our next canonical credential (the Phase-8 canonical step).
///
/// Every arm that applies a peer classical commit must report these, because the session's
/// principal state, the AS sequences, and the group leaves are only consistent if they move
/// together — see `process_incoming`, where both staple arms feed one bookkeeping block.
struct LeafChanges {
    new_sender: Option<ClientId>,
    canonicalized_own: Option<Vec<u8>>,
}

/// What a staple's classical commit is, relative to our recv group's epoch. The single home
/// of the re-staple ordering discipline (`staple_epoch_action`), so the two staple forms — a
/// plain commit and a bind's `APQPrivateMessage` — cannot drift on how repeats and gaps are
/// handled.
enum StapleAction {
    /// Older than our epoch: already applied off an earlier frame. The staple rides every
    /// frame precisely so repeats are cheap skips.
    Skip,
    /// Exactly our next epoch: this frame's commit is live and its arm must apply it.
    Apply,
}

/// No frame here is ever terminal: every side-band frame is answered by its round's next
/// leg (the last leg of every round is a stapled bind, which travels the message path),
/// so the answer is what replaces or clears the slot — no retirement stamp exists.
struct RetainedFrame {
    frame: Vec<u8>,
    seal: Option<Vec<u8>>,
}

impl RetainedFrame {
    /// Retain `frame`, seeding the `Stable` cache with `sealed` — the bytes a `*_begin` is
    /// about to return to the caller.
    ///
    /// The seed is what makes `begin`'s return and a subsequent `Stable` hand-out AGREE.
    /// Without it the first peek re-seals (a fresh nonce), so a chunking host that sent
    /// `begin`'s return and then peeked for the rest of the pass would cut pieces from two
    /// different seals — which reassemble into nothing, silently. `Fresh` hosts are
    /// unaffected: they re-seal per send by definition.
    fn seeded(frame: Vec<u8>, sealed: &[u8]) -> Self {
        Self {
            frame,
            seal: Some(sealed.to_vec()),
        }
    }

    /// Retain `frame` with no cached seal — for the responder frames, which are never
    /// handed back from their producing call and so only ever reach the wire through a
    /// hand-out.
    fn unsealed(frame: Vec<u8>) -> Self {
        Self { frame, seal: None }
    }
}

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
    /// The round's outbound side-band frame, retained for re-send. Set by both roles
    /// (initiator `*_begin`, responder `*_respond`), REPLACED when this side produces the
    /// round's next side-band frame, and CLEARED when the peer's answer proves it landed:
    /// the initiator clears at its bind (the inbound CT / Welcome' / Commit' answered its
    /// begin frame), the responder at the staple arm (the stapled bind answered its
    /// reply). A round's closing bind parks NOTHING here — it travels the message path as
    /// the staple — so the slot is empty whenever no round is open.
    ///
    /// One slot serves all three flows because they are mutually exclusive: every A.3, A.4
    /// and A.5 entry point gates on `pq_inflight`, so only one round is ever open.
    pending_side_band: Option<RetainedFrame>,
    /// A PQ commit has landed and its classical partner is OWED — the APQ pair is
    /// half-committed. Set by `commit_pq_and_owe_bind` (A.3's and A.4's trigger), consumed
    /// by `discharge_owed_bind` on the next classical COMMIT.
    ///
    /// Holds public bytes and two integers, never key material: the `apq_psk` is exported at
    /// discharge, not here, precisely so nothing derived has to wait (or be archived) across
    /// a wait we do not bound.
    ///
    /// While this is `Some`, two rules hold, and they are what make the reserved epochs in
    /// `OwedBind` true rather than hopeful:
    ///   * no further PQ commit may land (A.3/A.4 bind and A.5's commits refuse) — a second
    ///     one would move `pq_epoch` out from under the reservation. `begin` is unaffected:
    ///     an EK or an `Upd'` commits nothing, so PQ may start its next step.
    ///   * the next classical commit MUST be this bind — a routine fold taking that epoch
    ///     would strand `t_epoch` one behind, and the peer would reject the bind pre-apply
    ///     with our PQ leaf already spent.
    owed_bind: Option<OwedBind>,
    /// Whose move the PQ side-band is: the initiator owes the A.4 bootstrap; thereafter
    /// completing an operation passes the turn to the peer.
    pq_turn_mine: bool,
    /// Set when applying a peer's bind staple failed AFTER the round's secret was consumed
    /// (`apply_bind` past its `take` of `pq_inflight`). The staple re-rides every frame and
    /// can never apply now, so every inbound frame carrying it fails before its app message
    /// — receiving is broken while sending still works. In-memory only (inbound processing
    /// persists on success, so this is never written to a blob), which is exactly why it
    /// heals on restore: reloading the last persisted state predates the failed take. Read
    /// by `pq_receive_broken`; a host decides how fatal that is (see
    /// [`TwoMlsPqError::BindApplyFailed`]).
    bind_apply_broken: bool,
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
    /// The highest epoch of OUR send group the peer has demonstrably APPLIED — the
    /// evidence-gating watermark (book: Protocol Flows, "Evidence-gating"). `None` until the
    /// peer's first frame.
    ///
    /// The peer builds its `Upd(self)` in its recv group, which IS our send group, so an offer
    /// that VALIDATES against our send group proves the peer reached the epoch we are sitting
    /// at. Set at receive off every frame's offer — evidence rides every frame, which is what
    /// keeps the license from deadlocking (a peer's cross-injected PSK proves the same thing
    /// but rides commits only; see the book's note) — but ONLY when the offer validates
    /// (`validate_offered_update`): the raw epoch field is unauthenticated, and trusting it
    /// would let a malicious peer splice a higher epoch and forge the license. A valid offer
    /// proves exactly our current send epoch, so that is what this is stamped to.
    ///
    /// What it licenses: a commit that does NOT fold an approved proposal (the discharge of an
    /// owed bind). A fold needs no separate check — it IS the evidence, folding a proposal
    /// `validate_offered_update` already accepted. Without the license a discharge could commit
    /// past a bind the peer has not applied, superseding the only staple its PQ half ever rides.
    ///
    /// Monotone, and never exceeds our own send epoch (it is stamped TO it, and the peer cannot
    /// have applied a commit we never made). Rides the archive — losing it would re-license a
    /// commit the evidence no longer supports.
    peer_applied_send_epoch: Option<u64>,
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
    /// The initiator's CLASSICAL return key package (a bare MLS KeyPackage message) for
    /// the bare-section envelope shape (no `initial_app_payload` — hosts that deliver
    /// establishment material unwrapped; see `set_initial_return_key_package`). Classical
    /// only by design (§A.1): the acceptor's send group starts classical-only, and the
    /// initiator's PQ key package travels later, in the A.4 side-band, hash-bound to
    /// `bootstrap_kp`. Initiator-only; cleared at the establishment cutover; rides the
    /// archive.
    initial_return_kp: Option<Vec<u8>>,
    /// The initiator's PRE-COMMITTED A.4 bootstrap key package (PQ suite), minted at
    /// `initiate` so the host can pin `H(bootstrap_kp)` inside its signed establishment
    /// payload (`bootstrap_kp_commitment()`). `pq_bootstrap_begin` sends exactly these
    /// bytes — never a fresh mint — so the KP′ the peer builds BSG-PQ around is the one
    /// the establishment signature committed to. These public bytes ride the archive so
    /// a session restored between reply and A.4 still opens the round with the committed
    /// KP. Initiator-only; consumed at `begin` (the retained side-band frame carries it
    /// from then on).
    bootstrap_kp: Option<Vec<u8>>,
    /// The pre-committed KP's PRIVATE half, session-owned: the signed commitment
    /// obligates this session to JOIN the Welcome' built around `bootstrap_kp`, so the
    /// secret lives here (riding the archive) rather than in the client's key-package
    /// store — a Phase 8 rotation swaps the client, and a store-homed secret would
    /// strand the round (KP′ sent and accepted, Welcome' unjoinable). Injected
    /// just-in-time into the CURRENT client's store by `pq_bootstrap_bind` immediately
    /// before the join (the `inject_send_psks` pattern: the mls-rs stores are ephemeral
    /// plumbing) and consumed on success. Initiator-only.
    bootstrap_kp_secret: Option<crate::key_package_store::KeyPackageSecret>,
    /// The acceptor's pinned `H(initiator's PQ keyPackage)`, threaded in from the signed
    /// establishment payload via `receive`/`accept`. `pq_bootstrap_respond` refuses to
    /// stand up BSG-PQ around a KP′ that hashes to anything else
    /// (`BootstrapKpMismatch`); when pinned, this check REPLACES the
    /// names-the-established-peer equality — it is strictly stronger (it pins the exact
    /// committed bytes, identity included), and unlike the live-principal equality it
    /// still admits the committed KP after a Phase 8 rotation (PQ leaves lag
    /// credentials by design; A.5 catches them up). Acceptor-only; rides the archive.
    expected_bootstrap_kp_commitment: Option<Vec<u8>>,
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

pub(crate) mod frames;
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
    /// Both PQ halves live — i.e. A.4 has completed on this side. The inner-lock twin of
    /// [`TwoMlsPqSession::is_fully_established`], for guards that already hold the lock.
    fn pq_halves_live(&self) -> bool {
        matches!(
            (&self.send_group, &self.recv_group),
            (Some(s), Some(r)) if s.pq.is_some() && r.pq.is_some()
        )
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

    /// Export the cross-party TwoMLS-PSK from our recv-PQ mirror at its current epoch and
    /// stamp `last_cross_injected_pq` to that epoch — the two are ONE step everywhere they
    /// appear, because the export spends a one-shot exporter leaf and the watermark is what
    /// stops a later same-epoch export re-consuming the (now gone) leaf and failing opaquely.
    /// The caller decides what to do with the result: take its raw value as the injected
    /// secret S, or `register_psk` it for the peer's commit to resolve.
    fn export_cross_from_recv_pq(&mut self) -> Result<ExportedPsk> {
        let (exported, epoch) = {
            let recv_pq = self
                .recv_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let epoch = recv_pq.current_epoch();
            (export_psk(recv_pq, PskDomain::CrossParty)?, epoch)
        };
        self.last_cross_injected_pq = Some(epoch);
        Ok(exported)
    }

    /// The send-PQ twin of [`SessionInner::export_cross_from_recv_pq`], stamping
    /// `last_send_pq_exported`. Used where WE are the party whose send-PQ the round rekeyed
    /// (A.4's/A.5's responder re-deriving S, A.5's initiator pre-registering for the peer).
    fn export_cross_from_send_pq(&mut self) -> Result<ExportedPsk> {
        let (exported, epoch) = {
            let send_pq = self
                .send_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let epoch = send_pq.current_epoch();
            (export_psk(send_pq, PskDomain::CrossParty)?, epoch)
        };
        self.last_send_pq_exported = Some(epoch);
        Ok(exported)
    }

    /// The trigger half of the bind both A.3 and A.4 close their round with: inject `s` into
    /// our send-PQ with a pathless commit, and OWE the classical half.
    ///
    /// The rounds differ ONLY in where `s` comes from — A.3 decapsulates it from the peer's
    /// CT, A.4 exports it from the group it just joined — so everything from here down is
    /// shared. That is the point: A.4's bind is not *like* A.3's, it IS A.3's.
    ///
    /// **Why the halves split here.** The PQ half has no choice: `apq_psk` is exported from
    /// its POST-commit epoch, so the classical commit cannot even be built until the PQ one
    /// has applied. The classical half is the opposite — applying it advances the epoch our
    /// ordinary traffic rides, onto a commit whose `apq_psk` the peer can only derive from
    /// this bind's PQ half. Applied here, every frame we send before the bind lands would be
    /// undeliverable; and for A.4 the trigger is INBOUND (a welcome arrived), which says
    /// nothing about whether we have anything to send at all. So the classical commit waits
    /// for the next classical COMMIT and rides it — see `discharge_owed_bind`.
    ///
    /// A -02 FULL commit: both halves carry the AppDataUpdate attesting the absolute
    /// post-commit epochs of both groups, computed before either commit.
    fn commit_pq_and_owe_bind(&mut self, s: &[u8]) -> Result<()> {
        let stores = self.psk_stores.clone();
        let send = self
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_pq = send.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        // The attestation is a RESERVATION, not a prediction. It rides both commits, and each
        // half is checked pre-apply against `context.epoch + 1` (`apq::rules`) and post-apply
        // against both groups' actual epochs (`apply_bind`). The classical commit that carries
        // it is owed — it lands on the next classical COMMIT, which may be some rounds off —
        // so `t_epoch` is only correct because nothing else may take that epoch in the
        // meantime, and `pq_epoch` only because no further PQ commit may land. Those are the
        // two rules the owed bind imposes, and `discharge_owed_bind` re-checks both rather
        // than trusting them.
        let attestation = ApqInfoUpdate {
            t_epoch: send.classical.current_epoch() + 1,
            pq_epoch: send_pq.current_epoch() + 1,
        };
        // S is folded into the new PQ epoch and wiped here: it is the secret we must not
        // hold, and this commit is what discharges it. The `apq_psk` export is deliberately
        // NOT done now — it spends the exporter leaf irreversibly, so exporting before the
        // classical half is ready would mean holding live key material (and archiving it)
        // across an unbounded wait. See `apq::pq_ratchet::export_apq_psk`.
        let pq_commit = apq::pq_ratchet::inject_and_commit(send_pq, s, &stores, attestation)?;
        // The APQ pair is now half-committed: PQ has moved, classical is owed. Nothing is
        // held but public bytes and two integers.
        self.owed_bind = Some(OwedBind {
            pq_commit,
            t_epoch: attestation.t_epoch,
            pq_epoch: attestation.pq_epoch,
        });
        Ok(())
    }

    /// The classical half of the bind, run from the classical committing round that carries
    /// it: export the reserved `apq_psk`, hand back the attestation and PSK for the caller to
    /// fold into the commit it is already building, and yield the PQ commit the frame carries.
    ///
    /// Returns `None` when no bind is owed — the overwhelmingly common case, an ordinary
    /// committing round.
    ///
    /// **This CHECKS the reservation rather than trusting it.** Both epochs were fixed before
    /// the PQ commit and ride both halves as the -02 attestation; the receiver rejects a stale
    /// one pre-apply, by which time our PQ leaf is spent and no retry can rebuild the round.
    /// So a violated reservation must fail HERE, loudly, on our side, where nothing has been
    /// sent yet — not on the peer's.
    fn discharge_owed_bind(
        &mut self,
    ) -> Result<Option<(Vec<u8>, apq::ExportedPsk, ApqInfoUpdate)>> {
        let Some(owed) = self.owed_bind.take() else {
            return Ok(None);
        };
        let stores = self.psk_stores.clone();
        let send = self
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_pq = send.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;

        // Rule: the next classical COMMIT is this bind. If a routine fold took the epoch we
        // reserved, `t_epoch` is stale and the bind is already doomed.
        if send.classical.current_epoch() + 1 != owed.t_epoch {
            return Err(TwoMlsPqError::EpochDesync);
        }
        // Rule: no further PQ commit while a bind is owed. If one landed, `pq_epoch` is stale
        // AND the export below would take the wrong epoch's leaf.
        if send_pq.current_epoch() != owed.pq_epoch {
            return Err(TwoMlsPqError::EpochDesync);
        }

        // Spend the exporter leaf now — the one moment it is needed. The responder re-derives
        // the same value from its own mirror as it applies the PQ commit, so this never goes
        // on the wire.
        let apq_psk = apq::pq_ratchet::export_apq_psk(send_pq, &stores)?;
        let attestation = ApqInfoUpdate {
            t_epoch: owed.t_epoch,
            pq_epoch: owed.pq_epoch,
        };
        // The turn passes HERE, not at the trigger. The round's terminal send is the commit
        // this discharge rides, and until that exists we may still open the NEXT round — which
        // is the point of waiting: its `begin` frame parks in `pending_side_band` and rides the
        // same `EncryptResult` as this bind, so the next round costs no extra trip (both land
        // before the peer takes a turn).
        //
        // The two rounds are then in flight together but on DIFFERENT paths — this one's bind
        // in the STAPLE, the next one's EK in the side-band slot — so they never contend, and
        // each is persisted by its own path's rules.
        //
        // Rule 2 is therefore not covered by the turn and is checked explicitly at each bind
        // entry point (`owed_bind.is_some()`).
        self.pq_turn_mine = false;
        Ok(Some((owed.pq_commit, apq_psk, attestation)))
    }

    /// Classify a staple's classical commit against our recv group's epoch — the one place
    /// the re-staple ordering lives, called by BOTH staple arms so a change to how repeats or
    /// gaps are handled can never land in one and not the other. `Greater` (a commit we never
    /// saw sits between) is re-establish territory, surfaced as `EpochDesync` before the app
    /// ciphertext is touched.
    fn staple_epoch_action(&self, commit: &MlsMessage) -> Result<StapleAction> {
        let commit_epoch = commit.epoch().ok_or(TwoMlsPqError::DecryptionFailed)?;
        let current = self
            .recv_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?
            .classical
            .current_epoch();
        match commit_epoch.cmp(&current) {
            std::cmp::Ordering::Less => Ok(StapleAction::Skip),
            std::cmp::Ordering::Equal => Ok(StapleAction::Apply),
            std::cmp::Ordering::Greater => Err(TwoMlsPqError::EpochDesync),
        }
    }

    /// The apply both A.3 and A.4 close their round with: apply the peer's pathless PQ commit
    /// to our recv-PQ with the injected secret `s`, apply the classical commit, and verify the
    /// -02 FULL attestation across both halves. Returns the leaf-identity changes the classical
    /// half carried, for the caller's AS bookkeeping (see [`LeafChanges`]).
    ///
    /// Run from the STAPLE slot, because the bind is an `APQPrivateMessage` there rather than a
    /// frame of its own. It therefore does NOT touch the app message: that is the enclosing
    /// message frame's own section, which the ordinary path decrypts once this returns — the
    /// same order as before, since the classical commit has applied by then.
    ///
    /// `inject_send_psks` runs INSIDE this method (not at the call site, as the plain
    /// commit-staple arm does it): the deliberate difference is that this is a self-contained
    /// method whose one caller latches a failure of it as an irrecoverable bind-apply, so
    /// keeping the precondition inside the latched region is what makes an inject failure land
    /// there rather than escape unlatched.
    ///
    /// As with `commit_pq_and_owe_bind`, the rounds differ only in where `s` came from: A.3
    /// held it from encapsulating, A.4 re-derives it by exporting from its own copy of the
    /// group it created. Everything below is identical.
    fn apply_bind(
        &mut self,
        s: &[u8],
        stores: &[InMemoryPreSharedKeyStorage],
        pq_commit: &[u8],
        cl_commit: &[u8],
    ) -> Result<LeafChanges> {
        // The classical half is a FULL folding commit, so it may bind the cross-party
        // TwoMLS-PSK of our send group -- possibly at an epoch we've since moved past
        // (the peer's frame can cross one of our commits). Live-inject the session-held
        // ledger before processing, exactly as the plain commit-staple arm does.
        if self.send_group.is_some() {
            self.inject_send_psks()?;
        }
        let recv = self
            .recv_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let recv_pq = recv.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        let (apq_psk, pq_attestation) =
            apq::pq_ratchet::apply_injected_commit(recv_pq, s, pq_commit, stores)?;
        let cl = MlsMessage::from_bytes(cl_commit).map_err(|_| TwoMlsPqError::Mls)?;
        // Snapshot both leaves before the apply: the bind's classical half is the peer's
        // routine FULL commit (the discharge only ever rides a round that folds our
        // approved Upd), so a credential can move here exactly as on a plain commit
        // staple — see `LeafChanges`.
        let mine = recv.classical.current_member_index();
        let peer_index = if mine == 0 { 1 } else { 0 };
        let prior_peer = sender_client_id(&recv.classical, peer_index)?;
        let prior_own = sender_client_id(&recv.classical, mine)?;
        // The specific error here does not reach the host: `s` is already consumed, so the
        // sole caller (the bind-staple arm) latches ANY failure of this method as
        // `BindApplyFailed` and re-establish is the only recovery — a credential refusal is no
        // more retriable in place than any other, since the round cannot be re-applied without
        // the spent secret. So map to the plain `Mls`; the caller's latch is authoritative.
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
        // That residual check still gates every observable effect: it runs BEFORE the frame's
        // app message is decrypted (the caller does that only if this returns Ok), BEFORE the
        // one-shot apq PSK is forgotten, and BEFORE the turn passes — so on a bad attestation
        // from our sole counterparty no plaintext is released and no turn/PSK state is
        // confirmed. The only thing an attestation forgery can force is a self-inflicted epoch
        // advance that then errors out, which is within the two-party DoS threat model.
        if cl_attestation != pq_attestation
            || pq_attestation.pq_epoch != recv_pq.current_epoch()
            || cl_attestation.t_epoch != recv.classical.current_epoch()
        {
            return Err(TwoMlsPqError::ApqInfoMismatch);
        }
        // Peer commits (the PQ partial above is checked inside `apply_injected_commit`)
        // must never change the two-party shape.
        apq::ensure_two_party(&recv.classical)?;
        // Read the leaves back only once the roster is re-asserted, as the plain arm does.
        let new_peer = sender_client_id(&recv.classical, peer_index)?;
        let new_own = sender_client_id(&recv.classical, mine)?;
        // The bind consumed the one-shot apq PSK; drop it from every store it was
        // registered into (the session registry plus the group-captured handles).
        recv.forget_psk(apq_psk.storage_id());
        apq::forget_psk_stores(stores, apq_psk.storage_id());
        Ok(LeafChanges {
            new_sender: (new_peer != prior_peer).then_some(ClientId { bytes: new_peer }),
            canonicalized_own: (new_own != prior_own).then_some(new_own),
        })
    }

    /// Seal the retained side-band frame for hand-out, filling its `Stable` cache on a
    /// miss. `None` when the slot is empty (the quiescent case — nothing to re-send).
    fn hand_out(&mut self, sealing: SideBandSealing) -> Option<Vec<u8>> {
        // Lift the frame out before sealing: `seal_side_band` borrows the whole inner, so
        // it cannot run while a slot borrow is live.
        let (frame, cached) = {
            let retained = self.pending_side_band.as_ref()?;
            (retained.frame.clone(), retained.seal.clone())
        };
        if let (SideBandSealing::Stable, Some(sealed)) = (sealing, cached) {
            return Some(sealed);
        }
        let sealed = self.seal_side_band(&frame).ok()?;
        if matches!(sealing, SideBandSealing::Stable) {
            if let Some(retained) = self.pending_side_band.as_mut() {
                retained.seal = Some(sealed.clone());
            }
        }
        Some(sealed)
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
        // meaning, exactly like a rotation commit's leaf-credential announcement.
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
        let (app_payload, welcome, return_kp) = match &self.initial_app_payload {
            Some(payload) => (Some(payload.as_slice()), None, None),
            None => (
                None,
                Some(self.current_staple.as_slice()),
                self.initial_return_kp.as_deref(),
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
            pending_side_band: None,
            owed_bind: None,
            send_psk_ledger: VecDeque::new(),
            retired_send_psks: Vec::new(),
            last_cross_injected: None,
            // No evidence until the peer's first frame: a fresh session has nothing
            // outstanding to be licensed for, and its first commit is a fold (whose offer is
            // its own evidence).
            peer_applied_send_epoch: None,
            // Not written to any blob — a restore lands before any failed take (see the
            // field), so it always starts clear.
            bind_apply_broken: false,
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
            bootstrap_kp: None,
            bootstrap_kp_secret: None,
            expected_bootstrap_kp_commitment: None,
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
            // Pre-commit the A.4 bootstrap key package (§A.1): mint it NOW, so the host
            // can pin H(bootstrap_kp) inside the signed establishment payload it is about
            // to compose (`bootstrap_kp_commitment()`). Custody is SESSION-OWNED: the
            // signed commitment obligates this session to produce — and be able to join —
            // exactly these bytes, so both halves live in session state (public bytes +
            // the KeyPackageSecret, both riding the archive) rather than in the client's
            // store, which a Phase 8 rotation swaps out from under the round. The secret
            // is captured out of the generate and removed from the store (single-homed);
            // `pq_bootstrap_bind` injects it just-in-time before the Welcome' join, the
            // same pattern `inject_send_psks` uses for PSKs.
            {
                let client = Arc::clone(&inner.client);
                let pq_store = client.combiner().pq_kp_store();
                let (generated, captured) =
                    pq_store.capture(|| client.combiner().generate_pq_key_package());
                let kp = generated?;
                // Exactly-one extraction (mirrors `invitation.rs::single_captured`): a
                // generate inserts exactly one key package, so anything else means the
                // store-global capture slot recorded a concurrent generate/injection on
                // this shared client. Fail loudly rather than `pop()` the last insert and
                // silently pair the signed commitment with the wrong secret (an
                // unjoinable A.4 round the peer has already pinned).
                let mut captured = captured.into_iter();
                let secret = match (captured.next(), captured.next()) {
                    (Some(secret), None) => secret,
                    _ => return Err(TwoMlsPqError::Mls),
                };
                pq_store.remove_entry(&secret.0);
                inner.bootstrap_kp = Some(kp);
                inner.bootstrap_kp_secret = Some(secret);
            }
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
    /// `accept` — `initiate` retains its return-group key package in that same store (for the
    /// peer's return welcome), and this clear would drop it. (The pre-committed A.4 bootstrap
    /// KP is immune: its secret is SESSION-owned, held out of the store precisely so no store
    /// lifecycle — this purge, or a Phase 8 client swap — can strand the committed round.)
    /// The normal entry point, `TwoMlsPqInvitation::receive`, always builds a fresh
    /// invitation-derived client, so this only concerns direct callers of `accept`.
    ///
    /// `expected_app_binding` is the app-state binding this welcome must carry (see
    /// `TwoMlsPqInvitation::receive`, which documents the semantics): `Some` requires the
    /// joined group's `AppBinding` to be byte-equal, `None` requires it to carry none —
    /// any other combination is `AppBindingMismatch`, raised before this client's
    /// key-package store is cleared.
    ///
    /// `their_classical_key_package` is the initiator's CLASSICAL return key package (a
    /// bare MLS KeyPackage message — §A.1: the return group starts classical-only), and
    /// `bootstrap_kp_commitment` is `H(initiator's PQ keyPackage)` from the SIGNED
    /// establishment payload — the A.4 bootstrap KP′ must hash to it before BSG-PQ is
    /// built around it (see `pq_bootstrap_respond`).
    #[uniffi::constructor]
    pub fn accept(
        client: Arc<TwoMlsPqPrincipal>,
        welcome: Vec<u8>,
        their_classical_key_package: Vec<u8>,
        bootstrap_kp_commitment: Vec<u8>,
        expected_app_binding: Option<Vec<u8>>,
    ) -> Result<Arc<Self>> {
        Self::accept_with(
            client,
            None,
            welcome,
            their_classical_key_package,
            bootstrap_kp_commitment,
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
        their_classical_key_package: Vec<u8>,
        bootstrap_kp_commitment: Vec<u8>,
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
        // A commitment of the wrong length could never match any KP′ — reject it here,
        // before any state is touched, rather than let it surface as a confusing A.4
        // failure long after establishment.
        if bootstrap_kp_commitment.len() != 32 {
            return Err(TwoMlsPqError::BootstrapKpMismatch);
        }
        // The return key package is classical-only by design (§A.1): the send group this
        // side is about to create starts with no PQ half, and the initiator's PQ key
        // package arrives in A.4, pinned by `bootstrap_kp_commitment`.
        check_key_package_suite(
            &their_classical_key_package,
            client.combiner().cipher_suite().classical,
        )?;
        let their_parsed = parse_mls_key_package(their_classical_key_package.clone())?;
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
            &their_classical_key_package,
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
        // Pin the initiator's A.4 bootstrap KP commitment (from the SIGNED establishment
        // payload): `pq_bootstrap_respond` refuses to stand up BSG-PQ around a KP′ that
        // hashes to anything else.
        session.lock().expected_bootstrap_kp_commitment = Some(bootstrap_kp_commitment);
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
    /// (`initial_welcome`), the initiator's CLASSICAL return key package, and the
    /// bootstrap KP commitment (`bootstrap_kp_commitment()`) inside (e.g. a signed
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

    /// Attach the initiator's CLASSICAL return key package (a bare MLS KeyPackage
    /// message — §A.1: the acceptor's send group starts classical-only, and the PQ key
    /// package travels in A.4, pinned by `bootstrap_kp_commitment`) for the BARE
    /// envelope shape (no self-sufficient `set_initial_app_payload`):
    /// pre-establishment envelopes then carry `[welcome][return_kp]`, so any single
    /// frame is a complete establishment vector for the invitation holder. Unused when
    /// a host payload is attached (the payload carries the key package itself). Same
    /// guards, capture ordering, and envelope regeneration as
    /// `set_initial_app_payload`.
    pub fn set_initial_return_key_package(&self, key_package: Vec<u8>) -> Result<()> {
        self.set_initial_field(|inner| inner.initial_return_kp = Some(key_package))
    }

    /// `H(bootstrap_kp)` — the SHA-256 commitment to the A.4 bootstrap key package this
    /// session pre-committed at `initiate`. The host binds it inside its SIGNED
    /// establishment payload (next to the classical return key package), and the peer
    /// threads it back through `receive`/`accept`, where `pq_bootstrap_respond`
    /// enforces it — anchoring the ML-KEM key material to the host's signed
    /// establishment rather than resting it on classical channel auth alone.
    ///
    /// `None` on acceptor sessions and once EITHER consumer of the retained KP has run:
    /// `pq_bootstrap_begin`, or the Part 3 parallel `pq_bootstrap_envelope` (whose FIRST
    /// emit registers the round and consumes the KP). **Read it before emitting**: it is
    /// available from `initiate`, the signed reply must carry it, and the parallel frame
    /// ships alongside that reply — compose-the-reply-then-emit is the only order that
    /// works, and this accessor going quiet afterwards is the tell if the order slips.
    pub fn bootstrap_kp_commitment(&self) -> Option<Vec<u8>> {
        self.lock().bootstrap_kp.as_deref().map(crate::sha256)
    }

    /// True once both directions' PQ halves are live (post-A.4 bootstrap).
    pub fn is_fully_established(&self) -> bool {
        self.lock().pq_halves_live()
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
