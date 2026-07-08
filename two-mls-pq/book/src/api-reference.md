# API Reference

This is a narrative overview; the authoritative reference is rustdoc
(`cargo doc -p two-mls-pq --open`). All exported names are flat because UniFFI has no
module paths — hence the `TwoMlsPq*` / `Combiner*` / `Mls*` prefixes.

## `TwoMlsPqIdentity`

The agent identity and key-package/invitation mint — deliberately *not* an mls-rs-style
hub for group operations (see [Concepts](./concepts.md)).

- `new(client_id) -> Arc<TwoMlsPqIdentity>` — build an identity for opaque `ClientId`
  bytes; the MLS signing key is generated internally.
- `client_id() -> ClientId` — the identity bytes.
- `generate_key_package(suite) -> Vec<u8>` — one MLS key package.
- `generate_combiner_key_package() -> CombinerKeyPackage` — paired classical +
  ML-KEM-768 key packages sharing one `ClientId`.
- `generate_invitation() -> Vec<u8>` — capture a combiner key package's private
  material (and the signing identity) into a self-contained invitation archive,
  purging the identity's own copies.

## `TwoMlsPqInvitation`

The receiving side of a published combiner key package; restored from an archive, no
live client needed.

- `new(archive) -> Arc<TwoMlsPqInvitation>` — restore from `generate_invitation` or
  `archive()` output.
- `archive() -> Vec<u8>` — re-serialise, including the consumed-remote replay guard.
- `client_id()` / `combiner_key_package()` — the identity and the published pair.
- `receive(welcome, their_key_package) -> Arc<TwoMlsPqSession>` — accept a remote
  initiator's welcome; rejects a replayed remote (`DuplicateWelcome`).
- `hpke_open(kem_output, ciphertext, info, aad) -> Vec<u8>` — decrypt data sealed to
  the invitation's key package init key (the initial routing-header pattern; the
  sender side is `hpke_seal_to_key_package`).

## Parsing & routing

- `parse_mls_key_package(bytes) -> MlsKeyPackage { client_id, cipher_suite }`
- `parse_combiner_key_package(kp) -> ParsedCombinerKeyPackage` — validates both halves
  share a `ClientId`.
- `MlsCipherSuite::is_supported()` / `is_combiner_classical()` — routing signals.
- `derive_session_id(a, b) -> SessionId` — symmetric session identifier for a pair.

## `TwoMlsPqSession`

Constructors: `initiate`, `accept`, `from_archive` (the last is not yet implemented).

State: `is_established`, `has_receive_group`, `active_session_id`, `receive_group_id`,
`my_agent_state`, `their_agent_state`, `pending_outbound`.

Messaging: `prepare_to_encrypt`, `encrypt`, `process_incoming`, `proposal_context`,
`queue_proposal`, `stage_rotation`.

Not yet implemented (return `Err`): `archive`, `send_rendezvous`, `should_listen_on`,
`forwarded`. See [Planned Features](./planned-features.md).

## Errors

All failures map to the flat `TwoMlsPqError` enum (`Mls`, `InvalidKeyPackage`,
`MissingWelcome`, `PskBinding`, `PqNotAvailable`, `SessionNotEstablished`,
`SessionNotReady`, `ProposalRejected`, `DecryptionFailed`, `DuplicateWelcome`,
`ArchiveInvalid`). mls-rs error types never cross the FFI boundary.
