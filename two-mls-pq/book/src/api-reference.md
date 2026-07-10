# API Reference

This is a narrative overview; the authoritative reference is rustdoc
(`cargo doc -p two-mls-pq --open`). All exported names are flat because UniFFI has no
module paths — hence the `TwoMlsPq*` / `Combiner*` / `Mls*` prefixes.

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
That is this library's own wire convention; the app layer wraps them in whatever
typed-digest encoding it uses — no app-layer type tags appear on this surface.

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

- `new(archive)` / `archive()` — restore/persist; the archive carries the signing
  identity, the key package's private material, the consumed-remote set, the
  spawned-group forward table, and the processed-welcome ledger.
- `client_id()`, `combiner_key_package()` — what to publish.
- `receive(welcome, their_key_package, spawn_token, new_client_id) -> TwoMlsPqSession`
  — establish from a remote initiator's welcome; rejects a re-delivered welcome
  (byte-identical, via the processed-welcome ledger) and a repeat remote (both
  `DuplicateWelcome`), and, for a single-use invitation whose key package has already
  been consumed, any further welcome (`InvitationSpent`). `spawn_token` is an opaque,
  replay-stable identifier for the initial frame, keying the forward table.
  `new_client_id` is an optional **dedicated per-session principal**: when `Some`, the
  spawned session's send group is created under a freshly-minted principal carrying
  that ClientId (signing keys minted internally, as with `stage_rotation`), so the
  initiator sees the dedicated principal from the very first frame — no rotation
  commit, so nothing can displace the welcome staple. The receive-group join still
  uses the invitation identity (the welcome was addressed to its key package), and
  the session id still derives from the founding pair, so both sides agree on it.
- `forward_group_id(spawn_token) -> Option<MlsGroupId>` — resolve a replayed
  initial frame to the spawned session's receive group (its classical message-half id).
- `processed_welcome_group_id(welcome) -> Option<MlsGroupId>` — the content-keyed
  counterpart: resolve a re-delivered welcome by the digest of its exact bytes, no
  host token convention needed.
- `open_initial(blob) -> InitialFrame { app_payload, welcome }` — open the initiator's
  first frame (the §A.1 envelope `initiate` produced), recovering the app-layer welcome
  and the MLS `welcome` to pass to `receive`. Decrypt-only and does **not** consume the
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

Constructors: `initiate(client, their_key_package, app_payload)` — `app_payload` is the
host's opaque app-layer welcome (or `None`), composed with the MLS welcome and
HPKE-enveloped to the peer's KP′ so `pending_outbound` is one opaque blob the peer opens
with `TwoMlsPqInvitation::open_initial`; `accept(client, welcome, their_key_package)` —
the plaintext-welcome path (tests/embedded); `from_archive(archive)` — self-contained:
the archive carries the session's signing identity, so restore rebuilds the exact client
internally (no client argument), byte-exact in ClientId and signing keys. The restored
groups still sign with the keys embedded in their snapshots.

State: `is_established`, `is_fully_established`, `has_receive_group`,
`active_session_id`, `receive_group_id`, `my_principal_state`, `their_principal_state`,
`pending_outbound` (the standalone copy of the own welcome — no longer consumed by
`encrypt`; the welcome also rides every pre-commit frame as the staple), `epochs`.

Messaging: `prepare_to_encrypt`, `encrypt`, `process_incoming`, `proposal_context`,
`queue_proposal`, `stage_rotation`.

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
`pq_take_pending_outbound`, `pq_bootstrap_begin(rotating)` / `pq_bootstrap_respond` /
`pq_bootstrap_apply`, and `pq_ratchet_begin` /
`pq_ratchet_respond` / `pq_ratchet_bind` / `pq_ratchet_apply` and
`pq_rekey_begin(rotating)` / `pq_rekey_respond` / `pq_rekey_apply`. The `rotating`
parameters carry the principal credential handoff and must name the session's current
principal.

Persistence: `archive() -> Archive` is **total** — a session is always archivable, in
any state, so it never refuses. It serialises the full session — the current signing
identity, both group snapshots, the cross-party PSK ledger, the per-epoch listen map,
the spawn token, a staged-but-uncommitted rotation, the full PQ round state (including
a mid-A.3 KEM round), and every parked one-shot frame. The bytes are **plaintext secret
material**: seal them before persisting (`apq::archive::seal` is the provided tool; the
key belongs in the platform keystore). An archive is **single-use** — any further use of
the live session (or a second restore) rewinds the sender ratchet into AEAD nonce reuse.
Serializing a mid-A.3 round costs at most one round of PCS against an archive thief who
already holds the epoch secrets; discarding the round state instead would permanently
desync the side-band, so it is not an option. Reconnect remains unimplemented — see
[Planned Features](./planned-features.md).

## Errors

All failures map to the flat `TwoMlsPqError` enum (`Mls`, `InvalidKeyPackage`,
`MissingWelcome`, `PskBinding`, `PqNotAvailable`, `SessionNotEstablished`,
`SessionNotReady`, `ProposalRejected`, `DecryptionFailed`, `DuplicateWelcome`,
`InvitationSpent`, `ArchiveInvalid`, `UnsupportedCipherSuite`, `CipherSuiteMismatch`,
`EpochDesync`, `UnexpectedWelcome`). mls-rs error types never cross the FFI boundary.
`EpochDesync` means a stapled commit is more than one epoch ahead of the receive group
(the bridging commit no longer rides any frame) — a reconnect condition, distinct from the
transient `DecryptionFailed`. `UnexpectedWelcome` means a welcome differing from the one a
live session was joined from arrived (re-deliveries of the *same* welcome are silently
idempotent). `CipherSuiteMismatch` is raised when a peer key
package or welcome carries a cipher-suite pair that isn't the session's fixed suite
(`PqNotAvailable` when the peer offers no PQ half at all); `UnsupportedCipherSuite` is a local
provider-capability gap at construction.
