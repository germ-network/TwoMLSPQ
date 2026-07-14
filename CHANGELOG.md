# @germ-network/abstract-two-mls

## 0.1.0

### Minor Changes

- [#8](https://github.com/germ-network/AbstractTwoMLS/pull/8) [`23b987a`](https://github.com/germ-network/AbstractTwoMLS/commit/23b987aedc8a55a95ca4d52b05ed1c97d6ead436) Thanks [@germ-mark](https://github.com/germ-mark)! - Adopt TwoMLSPQ v0.4.1 (binding contracts 14–16): §A.1 replier-first sends

  The initiator sends app messages immediately after `reply` — before the
  acceptor's return welcome exists. Pre-establishment `prepareToEncrypt` is a
  NO-OP round (`proposalMessage` empty; `proposalHash` is the WELCOME digest —
  the one carve-out on the hash == sha256(proposalMessage) guarantee) and
  `encrypt` emits a fresh §A.1 envelope re-stapling the attached app payload plus
  the current message, so ANY single frame both establishes the acceptor and
  delivers. Later pre-establishment frames from the same initiator route
  `.forward`; the spawned session acknowledges them and hands out their stapled
  messages via `forwarded(headerDecrypted:)`.

  BREAKING for conformers and callers:

  - `Invitation.receive` returns `(Session, stapled: Session.MLSSenderMessage?)`
    instead of `(Session, plaintext: Data?)`: the staple decrypt CONSUMES its
    ratchet generation, so the full typed sender message is handed out exactly
    once — deliver it; it cannot be recovered from a re-delivered frame.
  - `createTwoMLSGroup` now attaches the app welcome to the session as its
    establishment-self-sufficient payload and returns the crate-composed
    envelope (the wrapper's own double-HPKE header frame is retired). CAPTURE
    ORDERING: persist-capture the session AFTER this call — the attached
    payload rides the archive; a capture taken between `reply` and the attach
    restores a replier whose frames carry no identity envelope.
  - `PrepareEncryptResult` gains `proposalMessage` (contract 14): the raw staged
    Upd(self) proposal, exposed so adopters digest the bytes themselves (sha256
    over it == `proposalHash` == the receiver's `QueuedRemoteProposal.digest`).
  - New `PQSession.receiveGroupId` (the receive group's classical id; nil before
    this side has joined one) — the post-join envelope check's counterpart to
    `shouldListenOn()`'s GroupID.
  - New `.appBindingMismatch` SessionError code (v15's AppBinding; this surface
    passes nil/unbound — threading a real binding through is its own follow-up).

  v0.4.1 fixes cross-endpoint handoff validation: the receiver's queued ordering
  context now equals the SENDER's `proposalContext` (the value the sender signs
  its handoff against), not a restatement of the receiver's own.

  Persisted state is NOT portable: contract 16 reset `SESSION_ARCHIVE_VERSION`
  and `INVITATION_VERSION` to 1 — regenerate ALL persisted sessions and
  invitations; v15's key-package wire cut also requires republishing key
  packages.

  germDM migration: deliver the `stapled` sender message from `receive` exactly
  once; capture-persist only after `createTwoMLSGroup`; regenerate persisted PQ
  state and republish key packages.

- [#8](https://github.com/germ-network/AbstractTwoMLS/pull/8) [`7b61f9a`](https://github.com/germ-network/AbstractTwoMLS/commit/7b61f9a9ab7b2526d0aae0d7ea395a442d2c5a61) Thanks [@germ-mark](https://github.com/germ-mark)! - Adopt TwoMLSPQ v0.1.0 (binding contract 13): push-based persistence

  `Archivable` is reshaped from pull to push. The old pull `archive` getter was
  a move, not a copy — using a live object after archiving, then restoring,
  rewound the sender ratchet into AEAD nonce reuse (security review H1). The
  live object is now the single writer and pushes its state to an installed sink.

  BREAKING for conformers and callers:

  - `Archivable`: `associatedtype Archive` → `Persisted`; `init(archive:)` →
    `init(persisted:)`; the pull `var archive` getter is REMOVED; new
    `func installSink(_:)` (once-only) and `var stateSeq: UInt64`.
  - New `AbstractTwoMLS.PersistenceSink` (`persist(seq:slot:bytes:)`, enqueue-only,
    called synchronously on the mutating thread) + `PersistedSlot{core, checkpoint}`.
  - `EncryptResultProtocol` gains `dependsOnSeq` (default `0`; the durability gate
    for key-material frames — routine frames impose no wait).
  - Session restore takes two slots (`PQSession.Persisted{core:checkpoint:}`);
    invitations stay monolithic and restore from bytes; `makeInvitation` still
    mints pull bytes (the object doesn't exist yet).

  Persisted state is NOT portable — regenerate all persisted sessions and
  invitations. (This adoption bumped `SESSION_ARCHIVE_VERSION` → 9 /
  `INVITATION_VERSION` → 3; contract 16 later reset both ladders to 1 — the
  §A.1 replier-first changeset carries the final pin, TwoMLSPQ v0.4.1.)

  germDM migration: implement `PersistenceSink` (two atomic slots, sealed);
  `installSink` after construction/restore; restore sessions via
  `init(persisted:)` and gate key-material-frame transmission on `dependsOnSeq` /
  `stateSeq` durability; regenerate persisted PQ state. The deprecated classical
  shim adapts with a one-shot baseline (its non-push limitation documented).

- [#8](https://github.com/germ-network/AbstractTwoMLS/pull/8) [`6b29476`](https://github.com/germ-network/AbstractTwoMLS/commit/6b29476d8aadaae7efaf47810a8ae60b27edaa7c) Thanks [@germ-mark](https://github.com/germ-mark)! - Single error contract: SessionError (review finding H2, M2, M4)

  Every throwing member of the abstract surface now throws exactly one type,
  `AbstractTwoMLS.SessionError` — no backend error (`TwoMlsPqError`,
  `UniffiInternalError`/`rustPanic`, `LinearEncodingError`) crosses the boundary.
  It carries a fine `code` (27 cases as of contract 16) and a derived `disposition` (8 values:
  `retryLater`, `discardFrame`, `reconnect`, `approveAndReprocess`,
  `discardArtifact`, `rejectEstablishment`, `callerBug`, `fatal`) so an app can
  drive recovery generically — the retry/reconnect/approve-and-reprocess
  semantics the crate documents are now reachable without importing the backend.

  The PQ wrapper's concrete members declare `throws(SessionError)` and route
  through one total translation that is exhaustive over the 22 `TwoMlsPqError`
  cases (a binding bump that adds a case fails compilation there); protocols stay
  untyped `throws`, so the deprecated classical conformance compiles unchanged
  and migrates on its own schedule (a `.staleFrame` code is reserved for its
  consumed-key string matching). `TwoMLSPQConformanceError` is removed.

  Also folds in two review conflations:

  - M2: `ingest` now distinguishes `.unopenableFrame` (no receive-window key
    opens it — a run of these is the documented reconnect signal) from
    `.misroutedFrame` (a message-path frame at the side-band door). The crate's
    overloaded `SessionNotReady` is likewise split by call-site.
  - M4: an identity mismatch is one `.identityMismatch` code whether the
    wrapper's key-package guard or the crate's `RemoteIdentityMismatch` raises it.

  germDM migration: catch `AbstractTwoMLS.SessionError` and switch on
  `code`/`disposition` (resolves the message-substring TODO in the incoming-loop
  handler); the classical conformance emits `SessionError` too once migrated.

- [#4](https://github.com/germ-network/AbstractTwoMLS/pull/4) [`cecb191`](https://github.com/germ-network/AbstractTwoMLS/commit/cecb1912d133aceb8a30e061e1ea41b49f37e4c3) Thanks [@germ-mark](https://github.com/germ-mark)! - TwoMLSPQ backend: routing (shouldListenOn/sendRendezvous), the APQ epoch pair on
  encrypt results, A.5 rekey, principal rotation (staging at receive, candidates
  proposed via prepareToEncrypt(proposing:) with the peer's approval —
  queueProposal — plus commit canonicalizing the handoff, and the PQ-leaf catch-up
  via begin(rotating:)), forward routing for replayed initial frames (spawn-token
  table + forwarded acknowledgment), and the raw-digest FFI convention. Binary
  pinned to the TwoMLSPQ v0.0.13 release (binding contract 12 —
  draft-ietf-mls-combiner-02 conformant: APQInfo, AppDataUpdate epoch attestation,
  SafeExportSecret application PSKs, event-driven cross-party injection; both
  halves run on Apple CryptoKit). Also in this pin: single-use vs last-resort
  invitations via `generateInvitation(lastResort:)` (AbstractTwoMLS mints
  last-resort invitations — reusable across many initiators, preserving
  forward-routing of replayed initial frames; a spent single-use invitation would
  fail `InvitationSpent`), the fixed/validated session cipher-suite binding
  (`CipherSuiteMismatch`), the id-based `stageRotation(newClientId:)`, and the
  Identity→Principal terminology rename (`TwoMlsPqPrincipal`, `myPrincipalState`).

  Platform floors stay `.iOS(.v17)/.macOS(.v15)`: the package imports and links on
  those OSes; the OS 26 requirement (CryptoKit ML-KEM-768) applies only at runtime
  to the PQ API paths.

- [#8](https://github.com/germ-network/AbstractTwoMLS/pull/8) [`33c3a6b`](https://github.com/germ-network/AbstractTwoMLS/commit/33c3a6bc1fe380a2b525a156aa67833943470ac6) Thanks [@germ-mark](https://github.com/germ-mark)! - Principal-state observability on the abstract Session surface (M6)

  `Session` gains the truth surface for credential state: `myPrincipalState` /
  `theirPrincipalState` (new `AbstractTwoMLS.PrincipalState`: `.sync(ClientID)` /
  `.pending(old:new:)`, shaped by the crate) and `queuedRemoteSuccessor` (the
  approval tally; protocol-extension default `nil` for tally-less backends).

  Why: rotation outcomes are one-shot events (`remoteCommit.newSender` /
  `newRecipient`) and can be LOST — a frame's staple applies before its app
  message decrypts, so a transient decrypt failure swallows the event (the
  retry's staple is an idempotent skip). State is truth, events are hints:
  after a retriable `processIncoming` failure, reconcile identity from
  `theirPrincipalState`.

  Breaking for external `Session` conformers: two new required getters. The
  deprecated classical backend (`MultiMLS.TwoMLS`) shims them in four lines by
  mapping its existing `myAgentState`/`theirAgentState`.

- [#8](https://github.com/germ-network/AbstractTwoMLS/pull/8) [`eab89e5`](https://github.com/germ-network/AbstractTwoMLS/commit/eab89e52b7ea482e5035ed47e1d1627c6d378408) Thanks [@germ-mark](https://github.com/germ-mark)! - Sessions are no longer Sendable

  `PQRatchet` (and with it `PQRatchetingSession` / `PQSession`) drops its
  `Sendable` requirement, and `PQSession` carries an unavailable `Sendable`
  conformance so it cannot be retroactively re-added. A session is a
  single-driver state machine (one parked reply slot, one pending-proposal
  slot): the wrapped FFI object is lock-serialized, so sharing was memory-safe,
  but concurrent drivers could interleave silently — a second
  `prepareToEncrypt` replaces the staged proposal with no signal to the first.
  Withholding `Sendable` turns that misuse into a compile error. The containing
  type — typically an actor that owns the session and serializes all driving —
  asserts its own `Sendable` conformance instead. Result/value types
  (`PQInbound`, `PQOutbound`, decrypt results, tokens, archives) remain
  `Sendable`.

- [#8](https://github.com/germ-network/AbstractTwoMLS/pull/8) [`36e08b5`](https://github.com/germ-network/AbstractTwoMLS/commit/36e08b516482613a5c1f6c4f685c2a5adbc492af) Thanks [@germ-mark](https://github.com/germ-mark)! - The library product vends only the `AbstractTwoMLS` module

  The concrete UniFFI wrapper module (`TwoMLSPQ`) is no longer importable by
  consumers (it still links transitively). UniFFI stamps its interface classes
  `@unchecked Sendable` — memory-safe sharing with no ordering guarantees — so
  exposing the module handed consumers a freely-shareable raw session handle
  that bypassed the deliberately non-Sendable wrapper types. The abstraction's
  public API is fully self-contained (verified: no binding type appears in any
  public signature). Consequence: concrete backend errors (`TwoMlsPqError`)
  are no longer catchable by type outside the package — catch generically
  until the planned `SessionError` contract lands.
