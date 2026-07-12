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
pub use frames::{pq_frame_kind, OpenedFrame, OpenedFrameKind, PqFrameKind};

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
        Self::accept_with(client, None, welcome, their_key_package, None)
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
        spawn_token: Option<Vec<u8>>,
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
    /// does not itself advance `state_seq`.
    pub fn install_sink(&self, sink: Arc<dyn crate::ArchiveSink>) -> Result<()> {
        let mut inner = self.lock();
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
        // initiator's initial welcome (no recv group yet) travels the invitation channel
        // instead and is delivered as-is; the host envelopes it via
        // `hpke_seal_to_key_package`, and the invitation opens it before `receive`.
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
