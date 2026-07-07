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

## `TwoMlsPqClient`

- `new(client_id) -> Arc<TwoMlsPqClient>` — `client_id` is opaque identity bytes
  (carried as the Basic Credential); the MLS signing keys are generated internally
  and are independent of it.
- `client_id() -> ClientId` — those bytes back.
- `generate_key_package(suite) -> Vec<u8>` — one MLS key package.
- `generate_combiner_key_package() -> CombinerKeyPackage` — paired classical +
  ML-KEM-768 key packages sharing one `ClientId`.
- `generate_invitation() -> Vec<u8>` — capture a combiner key package's private
  material, with the signing identity, into a self-contained invitation archive; the
  client keeps none of it.

## `TwoMlsPqInvitation`

The receiving side of a published key package — no live client required.

- `new(archive)` / `archive()` — restore/persist; the archive carries the signing
  identity, the key package's private material, the consumed-remote set, and the
  spawned-group forward table.
- `client_id()`, `combiner_key_package()` — what to publish.
- `receive(welcome, their_key_package, spawn_token) -> TwoMlsPqSession` — establish
  from a remote initiator's welcome; rejects a repeat remote (`DuplicateWelcome`).
  `spawn_token` is an opaque, replay-stable identifier for the initial frame, keying
  the forward table.
- `forward_group_id(spawn_token) -> Option<CombinerGroupId>` — resolve a replayed
  initial frame to the spawned session's receive group.
- `hpke_open(kem_output, ciphertext, info, aad)` — decrypt data sealed to the
  invitation's key package (the initial routing-header pattern); the counterpart
  free function is `hpke_seal_to_key_package`.

## Parsing & routing helpers

- `parse_mls_key_package(bytes) -> MlsKeyPackage { client_id, cipher_suite }`
- `parse_combiner_key_package(kp) -> ParsedCombinerKeyPackage` — validates both halves
  share a `ClientId`.
- `encode_combiner_key_package` / `decode_combiner_key_package` — the pair as one
  opaque blob for layers that carry it as a single value.
- `MlsCipherSuite::is_supported()` / `is_combiner_classical()` — routing signals.
- `derive_session_id(a, b) -> SessionId` — symmetric session identifier for a pair.

## `TwoMlsPqSession`

Constructors: `initiate`, `accept`, `from_archive` (the last is not yet implemented).

State: `is_established`, `is_fully_established`, `has_receive_group`,
`active_session_id`, `receive_group_id`, `my_agent_state`, `their_agent_state`,
`pending_outbound`, `epochs`.

Messaging: `prepare_to_encrypt`, `encrypt`, `process_incoming`, `proposal_context`,
`queue_proposal`, `stage_rotation`.

Transport routing: `should_listen_on() -> ListenChannels` (send-group ids + one
rendezvous address per retained epoch), `send_rendezvous()` (where to post),
`forwarded(spawn_token)` (acknowledge a replayed initial frame routed here by the
invitation's forward table).

PQ side-band (see [Session Lifecycle](./session-lifecycle.md)): `my_pq_turn`,
`pq_take_pending_outbound`, `pq_bootstrap_begin(rotating)` / `pq_bootstrap_respond` /
`pq_bootstrap_apply`, and on `cryptokit` builds `pq_ratchet_begin` /
`pq_ratchet_respond` / `pq_ratchet_bind` / `pq_ratchet_apply` and
`pq_rekey_begin(rotating)` / `pq_rekey_respond` / `pq_rekey_apply`. The `rotating`
parameters carry the agent credential handoff and must name the session's current
agent.

Not yet implemented (return `Err`): `archive`, `from_archive`. See
[Planned Features](./planned-features.md).

## Errors

All failures map to the flat `TwoMlsPqError` enum (`Mls`, `InvalidKeyPackage`,
`MissingWelcome`, `PskBinding`, `PqNotAvailable`, `SessionNotEstablished`,
`SessionNotReady`, `ProposalRejected`, `DecryptionFailed`, `ArchiveInvalid`,
`DuplicateWelcome`). mls-rs error types never cross the FFI boundary.
