# Session Lifecycle

## Establishment

1. **`TwoMlsPqSession::initiate(client, their_kp)`** — Alice builds her send group
   (Group_A): the ML-KEM-768 half first, the APQ-PSK exported from it, then the
   classical half bound by that PSK. The bundled `APQWelcome_A` is available via
   `pending_outbound()`.
2. **`TwoMlsPqSession::accept(client, welcome, their_kp)`** — Bob joins Group_A as his
   receive group (PQ half first, re-deriving the APQ-PSK, then the classical half),
   and builds his own send group (Group_B) **classical half only**, bound by a
   cross-party PSK exported from Group_A's classical half — Group_B's PQ half is
   deferred to the bootstrap (below), so Bob can send immediately. `APQWelcome_B`
   (with an empty PQ slot) is in `pending_outbound()`.
3. Alice calls **`process_incoming(APQWelcome_B)`** to join Group_B as her receive
   group. Now `is_established()` is true on both sides.

## The PQ side-band

Two flows run beside the message path on their own tagged frames (see
[Wire Format](./wire-format.md)):

- **Bootstrap** (`0x11`/`0x13`) — stands up Group_B's deferred PQ half off the
  critical path: Alice sends her PQ key package; Bob creates Group_B.pq around it and
  returns its Welcome. Both send groups are then full APQ pairs.
- **PQ ratchet** (`0x0B`/`0x0D`/`0x0F`, `cryptokit` builds) — injects fresh ML-KEM
  entropy into a send group's PQ half via a pathless PSK commit and re-binds the
  exported APQ-PSK into the classical half in the same round.

## Sending

Sending is two-phase so CommProtocol can bind a per-round proposal hash:

- **`prepare_to_encrypt(proposing)`** — stages key material and returns a
  `PrepareEncryptResult { proposal_hash, committed_remote_client_id, did_commit }`.
  - `proposing: None` → routine round: stages an `Upd(self)` proposal addressed to
    the peer's send group (stapled onto the outgoing frame for the peer to approve).
    Our own send group commits only when a queued, app-approved remote proposal is
    pending — then `did_commit: true` and the cross-party PSK refreshes.
  - `proposing: Some(new_client_id)` → agent rotation (after `stage_rotation`).
- **`encrypt(app_message)`** — returns `EncryptResult { cipher_text, sender, recipient,
  epoch }`.

## Receiving

**`process_incoming(ciphertext)`** returns `Option<DecryptResult>`:

- `application_message` — a decrypted app message.
- `proposal` — the peer's stapled `Upd(sender)` proposal, offered for app approval
  (then `queue_proposal(digest)`).
- `remote_commit` — a `CommitResult` (e.g. peer rotated → `new_sender`).
- `None` — message for an unknown epoch (reconnect path; see Planned Features).

## Remote proposals & full commit

When `process_incoming` surfaces a `proposal`, CommProtocol orders it against its own
sequence number and, if accepted, calls `queue_proposal(digest)`. The next
`prepare_to_encrypt(None)` then commits it (`did_commit: true`), advancing the send
epoch and refreshing the PSK binding.

## Agent key rotation

`stage_rotation(new_client)` then `prepare_to_encrypt(Some(new_id))` commits the
handoff to the staged agent client, announcing the new `ClientId` in the commit's
authenticated data (the MLS leaf credential itself is unchanged). The local state
becomes `AgentState::Pending { old, new }` until the peer replies, then resolves to
`Sync { new }`. The peer observes the change as `CommitResult.new_sender`.
