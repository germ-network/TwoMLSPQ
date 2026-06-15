# Session Lifecycle

## Establishment

1. **`TwoMlsPqSession::initiate(client, their_kp)`** — Alice builds her send group
   (Group_A): classical half, export a PSK, build the bound ML-KEM-768 half. The
   bundled `APQWelcome_A` is available via `pending_outbound()`.
2. **`TwoMlsPqSession::accept(client, welcome, their_kp)`** — Bob joins Group_A as his
   receive group, then builds his own bound send group (Group_B). `APQWelcome_B` is in
   `pending_outbound()`.
3. Alice calls **`process_incoming(APQWelcome_B)`** to join Group_B as her receive
   group. Now `is_established()` is true on both sides.

## Sending

Sending is two-phase so CommProtocol can bind a per-round proposal hash:

- **`prepare_to_encrypt(proposing)`** — stages key material and returns a
  `PrepareEncryptResult { proposal_hash, committed_remote_client_id, did_commit }`.
  - `proposing: None` → partial commit (refresh own receive-side key; send epoch
    unchanged) unless a remote proposal is queued, in which case a full commit runs.
  - `proposing: Some(new_client_id)` → agent key rotation (after `stage_rotation`).
- **`encrypt(app_message)`** — returns `EncryptResult { cipher_text, sender, recipient,
  epoch }`.

## Receiving

**`process_incoming(ciphertext)`** returns `Option<DecryptResult>`:

- `application_message` — a decrypted app message.
- `proposal` — a remote proposal to consider (then `queue_proposal(digest)`).
- `remote_commit` — a `CommitResult` (e.g. peer rotated → `new_sender`).
- `None` — message for an unknown epoch (reconnect path; see Planned Features).

## Remote proposals & full commit

When `process_incoming` surfaces a `proposal`, CommProtocol orders it against its own
sequence number and, if accepted, calls `queue_proposal(digest)`. The next
`prepare_to_encrypt(None)` then commits it (`did_commit: true`), advancing the send
epoch and refreshing the PSK binding.

## Agent key rotation

`stage_rotation(new_client)` then `prepare_to_encrypt(Some(new_id))` commits a new leaf
credential. The local state becomes `AgentState::Pending { old, new }` until the peer
replies, then resolves to `Sync { new }`. The peer observes the change as
`CommitResult.new_sender`.
