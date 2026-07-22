# API Reference

This is a narrative overview; the authoritative reference is rustdoc
(`cargo doc -p two-mls-pq --open`). All exported names are flat because UniFFI has no
module paths — hence the `TwoMlsPq*` / `Combiner*` / `Mls*` prefixes (`Combiner*` is
the code-name prefix for the APQ pieces — e.g. `CombinerKeyPackage`, an APQ group's
paired key packages).

## Binding contract

`binding_contract_version() -> u64` — a canary the Swift layer asserts at first
construction. UniFFI's own load-time checksums cover function signatures only; this
value is bumped on any shape change to an exported record or the error enum, so a
stale binding/binary pairing fails fast with an actionable message instead of
trapping mid-flow.

## References (Digests)

The FFI holds on to some state internally, e.g. queued Proposals,
and passes references across the FFI to the app to use in subsequent calls
to indicate the queued state.

The app can treat these references as opaque bytes-typed identifiers. They are in
practice **raw 32-byte values**: SHA-256 over the stated object.
That is this library's own wire convention; no app-layer type tags appear on this
surface.

The Swift wrapper applies the tag: everything it vends is `[kind][digest]` (33 bytes),
derived and compared by `PQDigest` (`Sources/TwoMLSPQ/PQDigest.swift`). The kind tag
belongs to the Swift package rather than to a shared identity type precisely because
the hash is a suite facet — `TwoMlsSuite::CURRENT.digest` — so it must version with
this crate. Since the crate carries no tags, the two sides restate the algorithm
independently; `DigestContractTests.digestDerivationMatchesTheCrate` is what holds
them together, and a suite whose digest is not SHA-256 must fail there.

## `TwoMlsPqPrincipal`

The principal and key-package/invitation mint — deliberately *not* an mls-rs-style
hub for group operations (see [Concepts](./concepts.md)).

- `new(client_id) -> Arc<TwoMlsPqPrincipal>` — build an identity for opaque `ClientId`
  bytes (carried as the Basic Credential); the MLS signing keys are generated
  internally and are independent of it.
- `client_id() -> ClientId` — the identity bytes.
- `generate_key_package(suite) -> Vec<u8>` — one MLS key package.
- `generate_combiner_key_package() -> CombinerKeyPackage` — paired classical +
  ML-KEM-768 key packages sharing one `ClientId`.
- `generate_invitation(last_resort) -> Vec<u8>` — capture a combiner key package's
  private material, with the signing identity, into a self-contained invitation archive,
  purging the identity's own copies. `last_resort` picks the key package's lifetime,
  which TwoMLS manages itself rather than via mls-rs's on-the-wire last-resort extension:
  `true` retains the key package so the invitation accepts many welcomes; `false` makes
  it single-use (consumed after the first accepted session).

## `TwoMlsPqInvitation`

The receiving side of a published key package — no live client required.

- `restore(archive)` — materialise from serialised bytes (from `generate_invitation` on
  first use, or a pushed blob on restore); they carry the signing identity, the key
  package's private material, the consumed-remote set, the spawned-group forward table,
  and the processed-welcome ledger. Named `restore`, not `new` — the state lives in the
  bytes.
- `install_sink(sink)` — attach the `ArchiveSink` this invitation pushes to after every
  state-advancing `receive` (once-only — a second call is `SinkAlreadyInstalled`; the
  first pushes a baseline `Checkpoint`). Persistence is push, not pull — the old
  `archive()` getter is off the FFI (see `TwoMlsPqSession` below for why). `state_seq()`
  reports the current push sequence.
- `client_id()`, `combiner_key_package()` — what to publish.
- `receive(welcome, their_classical_key_package, bootstrap_kp_commitment, spawn_token,
  new_client_id, expected_remote,
  expected_app_binding) -> TwoMlsPqSession` — establish from a remote initiator's welcome; rejects a
  re-delivered welcome (byte-identical, via the processed-welcome ledger) and a
  repeat remote (both `DuplicateWelcome`), and, for a single-use invitation whose key
  package has already been consumed, any further welcome (`InvitationSpent`).
  `their_classical_key_package` is the initiator's CLASSICAL return key package (a bare
  MLS KeyPackage message — §A.1: the return group starts classical-only).
  `bootstrap_kp_commitment` is `H(initiator's PQ keyPackage)` from the signed
  establishment payload, exactly 32 bytes: `pq_bootstrap_respond` refuses a bootstrap
  KP′ hashing to anything else (`BootstrapKpMismatch`).
  `spawn_token` is an opaque, replay-stable identifier for the initial frame, keying
  the forward table.
  `new_client_id` is an optional **dedicated per-session principal**: when `Some`, the
  spawned session's send group is created directly under a freshly-minted principal
  carrying that ClientId (signing keys minted internally) — so the acceptor runs as the
  dedicated agent from birth (its creator leaf carries `new_client_id`) and the
  initiator sees the dedicated principal from the very first frame, with no
  founding→dedicated rotation, so nothing can displace the welcome staple. The receive-group join still
  uses the invitation identity (the welcome was addressed to its key package), and
  the session id still derives from the founding pair, so both sides agree on it.
  `expected_remote` is the identity the caller already expects the welcome from
  (Germ validates it from the decrypted initial frame): a key package naming anyone
  else is rejected as `RemoteIdentityMismatch` **before any invitation state is
  claimed**, so the invitation stays fully reusable. Independently of it, the
  welcome's creator leaf must match the supplied key package (see
  [Group Rules](./group-rules.md)).
  `expected_app_binding` is the app-state binding the welcome must carry (the bytes
  the initiator passed to `initiate(app_binding:)`): an exact, symmetric match —
  `Some` requires byte-equality, `None` requires an unbound welcome; anything else
  (a stripped, unequal, or unexpected binding, or a PQ half smuggling one) is
  `AppBindingMismatch`, as is an empty expectation (empty is reserved — no group can
  carry an empty binding). Necessarily verified after the join (GroupContext rides
  the encrypted welcome) but still **before any invitation state is claimed** — a
  rejected welcome consumes nothing.
  The spawned session mirrors the verified binding onto its own send group.
- `forward_group_id(spawn_token) -> Option<MlsGroupId>` — resolve a replayed
  initial frame to the spawned session's receive group (its classical message-half id).
- `processed_welcome_group_id(welcome) -> Option<MlsGroupId>` — the content-keyed
  counterpart: resolve a re-delivered welcome by the digest of its exact bytes, no
  host token convention needed.
- `bootstrap_kp_group_id(kp_frame) -> Option<MlsGroupId>` — resolve a §A.1 bootstrap-KP
  frame (`[0x13][KP′]`, the `BootstrapKp` variant `open_initial` opens) to the session
  that owes A.3 for it, keyed on `H(KP′)` against the commitment `receive` pinned. Lets a
  KP′ delivered as an envelope (rather than a rendezvous side-band frame) self-route even
  when a reusable invitation has spawned many sessions; `None` for a KP′ no session
  pinned. (A KP′ whose session already finished A.3 still resolves — the table is not
  pruned — and the duplicate is caught at `pq_bootstrap_respond`.) Route the frame to
  that session's `pq_bootstrap_respond`.
- `open_initial(blob) -> OpenedInitial` — open the initiator's
  first frame (the §A.1 envelope `initiate` produced), dispatching on the plaintext's inner
  tag to `Establishment { frame }` (the app-layer welcome and the MLS `welcome` to pass to
  `receive`) or `BootstrapKp { frame }` (the parallel A.3 KP′). Decrypt-only and does
  **not** consume the
  invitation (validate before joining); `InvitationSpent` once a single-use invitation
  is consumed. The main receive path is `open_initial` → validate → `receive`.
- `hpke_open(kem_output, ciphertext, info, aad)` — the lower-level decrypt used by
  `open_initial`, kept exported for other stacks; the counterpart free function is
  `hpke_seal_to_key_package`.

## Parsing & routing helpers

- `parse_mls_key_package(bytes) -> MlsKeyPackage { client_id, cipher_suite }`
- `parse_combiner_key_package(kp) -> ParsedCombinerKeyPackage` — validates both halves
  share a `ClientId`.
- `encode_combiner_key_package` / `decode_combiner_key_package` — the pair as one
  opaque blob for layers that carry it as a single value.
- `MlsCipherSuite::is_combiner_pq()` / `is_combiner_classical()` — routing signals (true for
  the PQ `0xFDEA` and classical `0x0003` halves respectively).
- `derive_session_id(a, b) -> SessionId` — symmetric session identifier for a pair.

## `TwoMlsPqSession`

Constructors: `initiate(client, their_key_package, app_binding)` — the host's opaque
app-layer welcome is attached AFTER construction with `set_initial_app_payload` (it
typically signs over the welcome and the return key package, so it cannot exist before
`initiate` returns); the library composes it with the MLS welcome and HPKE-envelopes it to
the peer's KP′ so `pending_outbound` is one opaque blob the
peer opens with `TwoMlsPqInvitation::open_initial`; `app_binding` is the optional
app-state binding welded into the send group's GroupContext at this moment and immutable
for the session's lifetime — pass a **digest** of the app's immutable relationship
identity, not raw identifiers, and never empty (empty is reserved as invalid; `None` is
the unbound state) — the crate never interprets the bytes (see
[Group Rules](./group-rules.md) rule 8);
`accept(client, welcome, their_classical_key_package, bootstrap_kp_commitment,
expected_app_binding)` — the plaintext-welcome path (tests/embedded); `restore(core, checkpoint)` —
self-contained restore from the two pushed blobs: they carry the session's signing
identity, so restore rebuilds the exact client internally (no client argument),
byte-exact in ClientId and signing keys, and the restored groups still sign with the keys
embedded in their snapshots. It reconciles the pair (PQ halves from the checkpoint, the
rest by higher `state_seq`) and fails closed (`ArchiveInvalid`) on a PQ-epoch manifest
mismatch.

State: `is_established`, `is_fully_established`, `has_receive_group`,
`active_session_id`, `receive_group_id`, `my_principal_state`, `their_principal_state`,
`pending_outbound` (the standalone copy of the own welcome — not consumed by
`encrypt`; the welcome also rides every pre-commit frame as the staple), `epochs`,
`app_binding() -> Result<Option<Vec<u8>>>` (Swift `try appBinding() -> Data?`; the
app-state binding the session was created with, read from the send group's GroupContext —
it rides the persisted group state, so a restored session's owner re-verifies here;
errors only on a present-but-undecodable extension, so corruption can never read back as
"unbound").

Messaging: `prepare_to_encrypt(proposing)` — `Some(id)` proposes a rotation to that
ClientId on this round's Upd, admitting the candidate on the fly (minting the successor's
signing keys and authorizing it if `id` is not already staged — so a rotation can ride the
very first frame); `None` re-proposes the current identity and the commit path is
unchanged; its result carries the staged Upd both raw
(`proposal_message` — the exact message the paired `encrypt` staples) and digested
(`proposal_hash`), from one critical section, so a host binding a signature to the
proposal (the anchor agent handoff) applies its own digest to the returned bytes with
no staged-slot read a later prepare could have replaced; `encrypt`;
`process_incoming`; `proposal_context`;
`queue_proposal` — approve the peer's Upd (single-occupancy running tally,
latest-wins; validates then leaves the proposal cache untouched, so a rejected call is
a no-op and a replacement never doubles up; dropped when the send epoch advances via an
A.4 bind); `queued_remote_successor() -> Option<ClientId>` — the credential currently
queued, for the app's replace policy. Proposing another `Some(id)` adds a candidate,
never evicting one already sent, so several may be in flight (`my_principal_state` is
`Pending` while any are); overflow beyond the in-flight window defers to a single slot
proposed next round, and the peer's commit picks the winner. See
[Group Rules](./group-rules.md) for the Authentication Service semantics.

Header encryption: `open_incoming(blob) -> Option<OpenedFrame { kind, frame }>` removes
the outer seal from a rendezvous-channel blob and returns the plaintext `frame` plus a
routing `kind` (`OpenedFrameKind::Message` → `process_incoming`; `PqSideBand { kind }`
→ the named `pq_*` method); `None` means no key opened it (drop it). Every outbound
blob (`EncryptResult.cipher_text`, `pending_outbound`, `pq_take_pending_outbound`, the
`pq_*_begin` returns) is already sealed. `process_incoming` and the `pq_*` receivers
also accept a sealed blob directly (they open it transparently), so `open_incoming` is
strictly required only to *route* side-band frames. See
[Header Encryption](./header-encryption.md).

Transport routing: `should_listen_on() -> ListenChannels` (send-group ids + one
rendezvous address per retained epoch), `send_rendezvous()` (where to post),
`forwarded(spawn_token)` (acknowledge a replayed initial frame routed here by the
invitation's forward table).

PQ side-band (see [Session Lifecycle](./session-lifecycle.md)): `my_pq_turn`,
`pq_pending_outbound(sealing)` / `pq_take_pending_outbound`, `pq_bootstrap_begin(rotating)` /
`pq_bootstrap_respond` / `pq_bootstrap_bind`, and the ratchet/re-key *responder* and *bind/apply*
legs — `pq_ratchet_respond` / `pq_ratchet_bind` and `pq_rekey_respond` / `pq_rekey_apply`. **There
is no `pq_ratchet_begin` / `pq_rekey_begin`: the session self-drives A.4 and A.5.** On each
`encrypt`, when it is our turn and the side-band is idle, the session auto-stages the next round's
opening frame (A.5 on a credential lag — announcing the session's current principal as the handoff
— else A.4), and the host takes it from `pq_pending_outbound`/`pq_take_pending_outbound` to send
alongside the message. A.3 bootstrap stays host-driven (`pq_bootstrap_begin`, whose `rotating`
parameter carries the principal credential handoff and must name the session's current principal).
The A.4 ratchet and A.3 bootstrap have no separate `apply` call: the initiator ingests the
responder's reply and stages the owed bind with `pq_ratchet_bind` / `pq_bootstrap_bind`, and that
bind then rides the next message frame's staple, which the peer applies through `process_incoming`
(the v18 "a bind is the staple" model).

Side-band frame sizing (Feature B): `set_pad_target(target)` declares the frame-sizing intent.
`Some(n)` pads each side-band frame up to the co-stapled message's size, capped at the
push-payload budget `n` bytes, so the two co-stapled payloads are size-indistinguishable to an
on-path observer; `None` (the default) sends frames at their natural size. Like `install_sink`,
it is live plumbing outside the archive — set it right after restore, before use.

Persistence (push): attach an `ArchiveSink` with `install_sink` (once-only —
`SinkAlreadyInstalled` on a second call; the first pushes a baseline `Checkpoint`). The
session then PUSHES its new state after every state-advancing mutation via
`persist(seq, kind, bytes)`, where `kind` is **`Core`** (everything but the two ML-KEM
trees; written on classical mutations) or **`Checkpoint`** (the complete state incl. the
PQ trees; written on PQ-touching mutations and at baseline). The state is **total** — a
session is always encodable, in any state, so a push never refuses: it serialises the
current signing identity, both group snapshots, the cross-party PSK ledger, the per-epoch
listen map, the spawn token, a staged-but-uncommitted rotation, the full PQ round state
(including a mid-A.4 KEM round), and every parked one-shot frame. The bytes are
**plaintext secret material**: the sink must seal them before writing (the key belongs in
the platform keystore). Serializing a mid-A.4 round costs at most one round of PCS against
an archive thief who already holds the epoch secrets; discarding the round state instead
would permanently desync the side-band, so it is not an option.

Push replaced a pull `archive()` getter that was a *move, not a copy* — using the live
session after snapshotting it, then restoring, rewound the sender ratchet into AEAD nonce
reuse against a real transcript (security review finding H1). The getter survives only as
an in-crate test/fuzz helper, off the FFI. Every classical mutation pushes one `Core` and
every PQ op one `Checkpoint`, atomically and independently; the PQ trees never move
between checkpoints, so a `Core` is always consistent with the latest `Checkpoint`
(the `restore` constructor above reconciles the pair).

Transmit gating: `EncryptResult.depends_on_seq` is the `state_seq` at which the commit a
frame staples was persisted. A frame that publishes stored-private-key material (a fresh
commit) must not go out until the app has durably persisted that seq — otherwise a
crash-restore could rewind past keys the peer will rely on. A routine app message
re-staples an already-persisted commit, so its `depends_on_seq` is already durable and
imposes no wait; the durability gate covers only key-material frames (routine frames rely
on MLS's per-message `reuse_guard`, by design). `state_seq()` reports the current sequence
for the frames — the establishment envelope, PQ side-band — whose return type carries none.
In-library desync recovery is not planned — recovery is a re-establishment at the host layer.

## Errors

All failures map to the flat `TwoMlsPqError` enum (`Mls`, `InvalidKeyPackage`,
`MissingWelcome`, `PskBinding`, `PqNotAvailable`, `SessionNotEstablished`,
`SessionNotReady`, `ProposalRejected`, `DecryptionFailed`, `DuplicateWelcome`,
`InvitationSpent`, `ArchiveInvalid`, `UnsupportedCipherSuite`, `CipherSuiteMismatch`,
`EpochDesync`, `UnexpectedWelcome`, `InvalidClientId`, `RemoteIdentityMismatch`,
`CredentialRejected`, `ApqInfoMismatch`, `AppBindingMismatch`,
`SinkAlreadyInstalled`, `DuplicateSideBand`, `BootstrapKpMismatch`,
`BindDischargeFailed`, `BindApplyFailed`).
mls-rs error types never cross the FFI boundary. The two PQ-bind failures carry
recovery semantics a caller must branch on: `BindDischargeFailed` is fatal — the classical
commit discharging an owed bind failed, so the host re-establishes the session — while
`BindApplyFailed` (paired with the queryable `pq_receive_broken()`) marks receive-side PQ
state as broken but leaves sending intact, and a restore from the last persisted state
heals it. `DuplicateSideBand` is a benign no-op (a re-delivered side-band frame);
`BootstrapKpMismatch` rejects an A.3 bootstrap key package whose hash does not match the
commitment `receive` was given. `InvalidClientId` rejects an empty
principal id supplied to `receive(new_client_id:)` or `prepare_to_encrypt(Some(id))` — empty is
reserved (it is the ratchet-commit authenticated-data discriminator, so an empty id
could never be announced to the peer). `RemoteIdentityMismatch` is an establishment
identity-binding failure: an `expected_remote` the key package does not name, a
welcome whose creator leaf differs from the supplied key package, or an A.3
bootstrap key package naming a principal that is not the established peer (see
[Group Rules](./group-rules.md)). `CredentialRejected` is the Authentication
Service's refusal (an unauthorized credential succession) — retryable where it arises
from a staple: authorize (`queue_proposal` on a fresh delivery) and reprocess.
`EpochDesync` means a stapled commit is more than one epoch ahead of the receive group
(the bridging commit no longer rides any frame) — re-establish the session, distinct from the
transient `DecryptionFailed`. `UnexpectedWelcome` means a welcome differing from the one a
live session was joined from arrived (re-deliveries of the *same* welcome are silently
idempotent). `CipherSuiteMismatch` is raised when a peer key
package or welcome carries a cipher-suite pair that isn't the session's fixed suite
(`PqNotAvailable` when the peer offers no PQ half at all); `UnsupportedCipherSuite` is a local
provider-capability gap at construction. `AppBindingMismatch` is the app-state
binding's verification failure: a welcome that does not carry the caller's
`expected_app_binding` (absent or unequal), a binding-carrying welcome against no
expectation (never silently accepted), or a return welcome that fails to mirror the
initiator's own binding — on `receive` it is raised before any invitation state is
claimed, so the invitation stays fully reusable (see
[Group Rules](./group-rules.md)).
