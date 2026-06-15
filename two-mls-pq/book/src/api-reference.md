# API Reference

This is a narrative overview; the authoritative reference is rustdoc
(`cargo doc -p two-mls-pq --open`). All exported names are flat because UniFFI has no
module paths — hence the `TwoMlsPq*` / `Combiner*` / `Mls*` prefixes.

## `TwoMlsPqClient`

- `new(signing_key) -> Arc<TwoMlsPqClient>` — build a client from an agent signing key.
- `client_id() -> ClientId` — the public signing key bytes.
- `generate_key_package(suite) -> Vec<u8>` — one MLS key package.
- `generate_combiner_key_package() -> CombinerKeyPackage` — paired classical +
  ML-KEM-768 key packages sharing one `ClientId`.

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
`MissingWelcome`, `PskBinding`, `SessionNotEstablished`, `SessionNotReady`,
`ProposalRejected`, `DecryptionFailed`, `ArchiveInvalid`). mls-rs error types never
cross the FFI boundary.
