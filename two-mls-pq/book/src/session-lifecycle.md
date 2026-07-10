# Session Lifecycle

## Establishment

1. **`TwoMlsPqSession::initiate(client, their_kp, app_payload)`** — Alice builds her
   send group (Group_A): the ML-KEM-768 half first, the APQ-PSK exported from it, then
   the classical half bound by that PSK. `pending_outbound()` returns the first frame as
   one opaque §A.1 envelope — `[app_payload ∥ APQWelcome_A]` HPKE-sealed to Bob's KP′ —
   so the app-layer welcome that identifies Alice is hidden on the invitation channel
   (see [Header Encryption](./header-encryption.md)).
2. **`TwoMlsPqInvitation::open_initial(envelope) -> { app_payload, welcome }`** then
   **`receive(welcome, their_kp, spawn_token)`** — Bob opens the envelope (the invitation
   holds the KP′ material), validates the app-layer welcome, and joins Group_A as his
   receive group (PQ half first, re-deriving the APQ-PSK, then the classical half),
   and builds his own send group (Group_B) **classical half only**, bound by a
   cross-party PSK exported from Group_A's classical half — Group_B's PQ half is
   deferred to the bootstrap (below), so Bob can send immediately. `APQWelcome_B`
   (with an empty PQ slot) rides as the **staple** on every frame Bob sends until his
   first commit (see [Wire Format](./wire-format.md)); a standalone copy is also in
   `pending_outbound()` for hosts that deliver it separately.
3. Alice joins Group_B as her receive group from whichever copy arrives first — the
   staple on Bob's first message frame, or a standalone `APQWelcome_B` via
   `process_incoming`. Re-deliveries are idempotent no-ops (the session records the
   digest of the welcome it joined from; a *different* welcome on a live session is
   `UnexpectedWelcome`). Now `is_established()` is true on both sides.

## The PQ side-band

Three flows run beside the message path on their own tagged frames (see
[Wire Format](./wire-format.md)). A single **turn** alternates between the parties:
the session initiator owes the bootstrap; completing an operation passes the turn to
the peer (`my_pq_turn()`), and only one operation may be in flight at a time.

- **Bootstrap** (`0x0B`/`0x0D`) — stands up Group_B's deferred PQ half off the
  critical path: Alice sends her PQ key package; Bob creates Group_B.pq around it and
  returns its Welcome. Both send groups are then complete APQ groups
  (`is_fully_established()`).
- **PQ ratchet** (`0x05`/`0x07`/`0x09`) — injects fresh ML-KEM
  entropy into a send group's PQ half via a pathless PSK commit and re-binds the
  exported APQ-PSK into the classical half in the same round.
- **PQ re-key** (`0x0F`/`0x11`) — updatePath commits run on the two send groups'
  PQ halves **alone**, so the classical ratchet is never blocked behind a large
  ML-KEM updatePath: the initiator proposes `Upd'(self)` into the PQ half of the
  peer's send group (`pq_rekey_begin`), the responder commits it and counter-proposes
  (`pq_rekey_respond`), and each `Commit'` cross-injects a PSK exported from the PQ
  half of the *opposite* send group (`pq_rekey_apply`). The bumped `pq_epoch`
  reconciles into the classical half at the next PQ ratchet bind.

## Routing

The session tells the transport where to listen and post; both derive from
`exportSecret(label="rendezvous", context="TwoMLS", len=32)` on a group's classical
half, so the two ends compute identical addresses:

- **`should_listen_on()`** — the send group's ids plus one rendezvous address per
  retained classical epoch. Listening works from birth; exporters are only derivable
  at their epoch, so each address is captured live, and the window follows mls-rs's
  own epoch retention (traffic posted at a recently prior epoch's address still
  lands).
- **`send_rendezvous()`** — where to post: the receive group's exporter at its
  current epoch. The receive group *is* the peer's send group, so this value appears
  verbatim in the peer's listen set. `None` until the receive group exists (the
  initiator's first frame travels via the invitation channel instead).

## Sending

Sending is two-phase so CommProtocol can bind a per-round proposal hash:

- **`prepare_to_encrypt(proposing)`** — stages key material and returns a
  `PrepareEncryptResult { proposal_hash, committed_remote_client_id, did_commit }`.
  `proposal_hash` is the raw 32-byte SHA-256 of the staged `Upd(self)` proposal —
  every round stages one, rotation rounds included — and the receiver independently
  derives the same value as `QueuedRemoteProposal.digest`.
  - `proposing: None` → routine round. Our own send group commits only when a
    queued, app-approved remote proposal is pending — then `did_commit: true` and
    the cross-party PSK refreshes.
  - `proposing: Some(new_client_id)` → principal rotation (after `stage_rotation`).
- **`encrypt(app_message)`** — binds the pending `proposal_hash` into the message's
  authenticated data and returns `EncryptResult { cipher_text, sender, recipient,
  epochs }`, where `epochs` is the send group's epoch pair — `pq_epoch` (0 while that
  half is deferred) and `classical_epoch` (the message epoch). The frame is always
  the `[staple][proposal][app]` triple: the staple (our latest send-group commit, or
  our APQWelcome until the first commit) rides every frame, so a peer that missed a
  frame is healed by the next one.

## Receiving

**`process_incoming(ciphertext)`** returns `Option<DecryptResult>`:

- `application_message` — a decrypted app message.
- `proposal` — the peer's stapled `Upd(sender)` proposal, offered for app approval
  (then `queue_proposal(digest)`).
- `remote_commit` — a `CommitResult`, surfaced on the frame whose staple was applied
  (e.g. peer rotated → `new_sender`); repeats of an already-applied staple are
  silent skips.
- `None` — a re-delivered welcome (standalone `0x01` already joined from), or a
  message for an unknown epoch (a reconnect condition — not recovered
  in-library; see Planned Features).

A stapled commit *ahead* of the receive group's next epoch fails with `EpochDesync`
before the app ciphertext is touched: the peer advanced more than one commit past us
and the bridging commit no longer rides any frame — reconnect territory,
distinguishable from a transient `DecryptionFailed` (e.g. a message frame that
overtook its A.3 BIND, which succeeds on retry once the BIND lands).

## Remote proposals & the folding commit

When `process_incoming` surfaces a `proposal`, CommProtocol orders it against its own
sequence number and, if accepted, calls `queue_proposal(digest)`. The next
`prepare_to_encrypt(None)` then commits it (`did_commit: true`), advancing the send
epoch and refreshing the PSK binding.

## Principal key rotation

`stage_rotation(new_client_id)` then `prepare_to_encrypt(Some(new_id))` commits the
handoff to the staged principal, announcing the new `ClientId` in the commit's
authenticated data (the classical leaf credential itself is unchanged; ratchet
commits have empty AD, which is the whole wire discriminator). A rotation round is
otherwise an ordinary round: it stages the routine `Upd(self)` proposal, and it
folds a queued, app-approved peer proposal into the same commit (with the
cross-party PSK refresh, reported via `committed_remote_client_id`). Rotation is
gated on having processed at least one peer message frame (`SessionNotReady`
otherwise) — a unilateral commit must never displace a welcome staple the peer may
still need. The app supplies
only the opaque `ClientId`; the successor's MLS signing keys are minted internally, as
session-owned state — staging the same id twice is a no-op, a different id replaces the
staged one. The local state becomes `AgentState::Pending { old, new }` until the peer
replies, then resolves to `Sync { new }`. The peer observes the change as
`CommitResult.new_sender`.

The **PQ leaves catch up on the next re-key**: `pq_rekey_begin(rotating: new_id)` —
which must name the session's *current* principal, i.e. the classical rotation above has
already happened — moves the initiator's leaf in both PQ groups to the new principal's
signing key (the `Upd'`, then the final `Commit'`'s updatePath). The `ClientId`
travels in the proposal's authenticated data, and the responder returns it from
`pq_rekey_respond`; leaf credential *bytes* stay fixed, as on the classical side.
`pq_bootstrap_begin(rotating:)` accepts the same id — its key package is generated by
the current principal, so the check alone suffices.

## Invitations & replayed initial frames

A published key package is backed by a self-contained **`TwoMlsPqInvitation`** (the
signing identity plus the key package's private material) rather than a live client;
one invitation services many welcomes, deduplicating repeats per remote
(`DuplicateWelcome`). `receive(welcome, their_kp, spawn_token)` takes an opaque,
caller-chosen, replay-stable token for the initial frame and records
`token → the spawned session's receive group` in a **forward table**:

- **`forward_group_id(spawn_token)`** — `Some` means this exact initial frame was
  already accepted; route the payload to the owning session instead of surfacing a
  fresh welcome.
- **`TwoMlsPqSession::forwarded(spawn_token)`** — the session acknowledges the replay
  (`Ok(None)`: an initiator cannot staple a private message pre-establishment, so a
  replay never carries an undelivered payload); a mismatched token is a mis-route.

- **`processed_welcome_group_id(welcome)`** — the content-keyed counterpart of the
  forward table: resolves a re-delivered welcome (by the digest of its exact bytes)
  to the spawned session's receive group, with no host token convention needed.
  `receive` consults the same ledger up front and rejects a re-delivery as
  `DuplicateWelcome` before claiming or reserving anything.

The invitation's `archive()` persists the consumed set, the forward table, and the
processed-welcome ledger, so all three guards survive a restore. The token is opaque
to this crate — the caller picks the convention (Germ's adapter uses the app-layer
digest of the decrypted frame).
