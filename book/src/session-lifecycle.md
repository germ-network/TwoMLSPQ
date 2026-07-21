# Session Lifecycle

## Establishment

1. **`TwoMlsPqSession::initiate(client, their_kp, app_binding)`** — Alice
   builds her send group (Group_A): the ML-KEM-768 half first, the APQ-PSK exported from
   it, then the classical half bound by that PSK — carrying the optional `app_binding`
   (the app-state binding, welded into the GroupContext here and immutable for the
   session's lifetime; see [Group Rules](./group-rules.md) rule 8). The app-layer welcome
   that identifies Alice is attached with `set_initial_app_payload`. `pending_outbound()`
   returns the first frame as
   one opaque §A.1 envelope — `[app_payload ∥ APQWelcome_A]` HPKE-sealed to Bob's KP′ —
   so that welcome is hidden on the invitation channel
   (see [Header Encryption](./header-encryption.md)).
2. **`TwoMlsPqInvitation::open_initial(envelope) -> OpenedInitial`** then
   **`receive(welcome, their_classical_kp, bootstrap_kp_commitment, spawn_token,
   new_client_id, expected_remote, expected_app_binding)`** — Bob
   opens the envelope
   (the invitation holds the KP′ material), validates the app-layer welcome, and joins
   Group_A as his receive group (PQ half first, re-deriving the APQ-PSK, then the
   classical half), and builds his own send group (Group_B) **classical half only**,
   bound by a cross-party PSK exported from Group_A's classical half — Group_B's PQ
   half is deferred to the bootstrap (below), so Bob can send immediately.
   `new_client_id` selects an optional **dedicated per-session principal** at
   establishment: Group_B (and later its A.3 PQ half) is created under a freshly-minted
   principal with that id, so Alice sees the dedicated principal as the creator leaf of
   the very welcome she joins from — no first-frame rotation is needed. Alice adopts the id
   on the joining frame, surfacing it as `remote_commit.new_sender`; authenticity rides
   the cross-party PSK — only the invitation holder can create a Group_B that Alice's
   join accepts. `APQWelcome_B`
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
[Wire Format](./wire-format.md)). This section is the caller's view;
[Protocol Flows](./protocol-flows.md) §A.3–A.5 is the protocol they implement, and why the
epochs must line up as they do. A single **turn** alternates between the parties: the session
initiator owes the bootstrap; completing an operation passes the turn to the peer
(`my_pq_turn()`), and only one operation may be in flight at a time.

**The host drives only the A.3 bootstrap and then ordinary sends — the SESSION self-drives A.4
and A.5.** There is no `begin(.ratchet/.rekey)` for the host to call: on each `encrypt`, when it
is our turn and the side-band is idle, the session opens the next round automatically — an **A.5**
re-key when our send-PQ leaf still lags the canonical (classically committed) identity, else an
**A.4** ratchet. "A.4 begins immediately" is just the first send after the turn becomes ours; the
ratchet then ping-pongs, turn-gated so the two sides never both open at once. Staging is
best-effort (a transient KEM/proposal failure simply retries on the next send) and the staged
frame rides that send's re-staple peek (`pq_pending_outbound`), so the host's role is
`.finishBootstrap` plus sending messages.

- **Bootstrap** (`0x13`/`0x15`, then a stapled bind) — stands up Group_B's deferred PQ half
  off the critical path: Alice sends her PQ key package (`0x13`) — the one PRE-COMMITTED at
  `initiate` (`bootstrap_kp_commitment()` put its hash inside the signed establishment
  payload, and Bob's `receive` pinned it) — Bob verifies the hash (`BootstrapKpMismatch`
  otherwise), creates Group_B.pq around it and returns its Welcome (`0x15`); Alice joins and
  binds. Both send groups are then complete APQ groups (`is_fully_established()`). The
  round's closing bind is not a side-band frame — it rides the next message frame's staple.
  The bind is structurally the PQ ratchet's (below), differing only in where its injected
  secret comes from — an exporter off the newly joined group rather than a KEM exchange —
  and it doubles as the round's receipt: that secret is derivable only from inside
  Group_B.pq, so a bind that applies at all proves Alice joined.
- **PQ ratchet** (`0x17`/`0x19`, then a stapled bind) — injects fresh ML-KEM
  entropy into a send group's PQ half via a pathless PSK commit and re-binds the
  exported APQ-PSK into the classical half in the same round. Opened automatically by the
  turn-holder's next send (no host call): it auto-stages the initiator's ML-KEM encapsulation
  key (`0x17`); the responder answers with its ciphertext plus the AEAD-sealed injected secret
  (`0x19`), and the closing bind rides the next message frame's staple.
- **PQ re-key** (`0x1B`/`0x1D`, then a stapled bind) — updatePath commits run on the two
  send groups' PQ halves **alone**, so the classical ratchet is never blocked behind a large
  ML-KEM updatePath. It is not a host call either: the session opens it in place of an A.4 when
  our send-PQ leaf still lags the canonical principal (a Phase 8 classical rotation moved the
  session client; the PQ leaf catches up here), announcing that principal as the handoff. The
  initiator's send auto-stages `Upd'(self)` into the PQ half of the peer's send group (`0x1B`);
  the responder commits it with its own `Commit'` (`pq_rekey_respond`, `0x1D`) — whose updatePath
  rotates the committer's leaf and cross-injects a PSK exported from the PQ half of the *opposite*
  send group. The round's third leg is not a side-band frame: the initiator acks with a pathless
  partial commit stapled onto its next classical commit (`pq_rekey_apply`), a FULL commit whose
  `AppDataUpdate` reconciles the bumped `pq_epoch` **in-round**. (One credential catch-up can defer
  a round when an A.4 is already in flight — a staged A.4 is not upgraded mid-flight; the A.5 fires
  on the next turn.)

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
  `PrepareEncryptResult { proposal_message, proposal_hash, committed_remote_client_id,
  did_commit }`. `proposal_message` is the staged `Upd(self)` proposal, raw — every
  round stages one, rotation rounds included — and `proposal_hash` its 32-byte
  SHA-256; the receiver independently derives the same value as
  `QueuedRemoteProposal.digest`. A host that must sign over the proposal (the anchor
  agent handoff binds the rotation Upd's digest) applies its own digest to
  `proposal_message`: bytes and hash come from the same critical section, so no later
  prepare can interpose a different Upd.
  - `proposing: None` → routine round. Our own send group commits in two cases, both
    gated on the peer having applied our previous commit: when a queued, app-approved
    remote proposal is pending (it folds the proposal — `did_commit: true`, and the
    cross-party PSK refreshes *if* the peer's send group has advanced since the last
    binding), **or** when an owed PQ bind must be discharged (a proposal-less,
    updatePath-only commit — `did_commit: true` with nothing folded, so PQ liveness never
    waits on app approval policy). A round with neither pending commits nothing.
  - `proposing: Some(new_client_id)` → this round's Upd proposes a rotation to that
    ClientId, admitting the candidate on the fly (see Principal key rotation below).
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
- `remote_commit` — a `CommitResult`, surfaced on the delivery that applied the staple
  or performed the welcome join (peer rotated, or established under a dedicated
  principal → `new_sender`); repeats of an already-applied staple are silent skips. A
  *standalone* welcome that adopts a dedicated peer principal returns a `DecryptResult`
  with only `remote_commit` set — the handoff is observable whichever copy of the
  welcome arrives first. `new_sender` is an event hint; `their_principal_state()` is
  the truth (the signal is lost if the same frame's app message fails).
- `None` — a welcome that changed nothing to announce (a re-delivery already joined
  from, or a first join under the peer's expected identity), or a message for an
  unknown epoch (re-establish the session — not recovered in-library).

A stapled commit *ahead* of the receive group's next epoch fails with `EpochDesync`
before the app ciphertext is touched: the peer advanced more than one commit past us
and the bridging commit no longer rides any frame — re-establish territory,
distinguishable from a transient `DecryptionFailed` (e.g. a message frame that
overtook its A.4 BIND, which succeeds on retry once the BIND lands).

## Remote proposals & the folding commit

When `process_incoming` surfaces a `proposal`, CommProtocol orders it against its own
sequence number and, if accepted, calls `queue_proposal(digest)`. The next
`prepare_to_encrypt(None)` then commits it (`did_commit: true`), advancing the send
epoch and refreshing the PSK binding.

## Principal key rotation

Rotation is **proposal-driven** (see [Group Rules](./group-rules.md) — the
Authentication Service) and **lazy** — there is no separate stage call:
`prepare_to_encrypt(Some(new_id))` makes this round's stapled Upd(self) carry the
successor's credential, minting the successor (the app supplies only the opaque
ClientId; signing keys are session-owned) and authorizing it on the fly if `new_id` is
not already a candidate. Admitting a candidate marks the session `Pending`. Different
rounds may propose different candidates — the app orders them. The peer surfaces each candidate as
`QueuedRemoteProposal.proposing`, approves one with `queue_proposal` (the running
tally), and its next commit **canonicalizes** it: `committed_remote_client_id` and
`their_principal_state` report the new identity on the committing side, and the
commit staple's return canonicalizes the proposer (`remote_commit.new_recipient`,
`my_principal_state` → `Sync { new }`, the session swaps to the winning principal).
Because rotation rides the proposal slot, it can be offered on the very first frame —
it can never displace the welcome staple. A candidate proposed on the wire is never
dropped (the peer may commit any of them); staging beyond the in-flight window parks
the request in a single deferred slot and proposes it on the next routine round once a
slot frees. On the receiver, `queue_proposal` is a single-occupancy latest-wins tally
(`queued_remote_successor()` reveals it), epoch-locked so it is dropped when the send
epoch advances by an A.4 bind.

The winner's other leaves **lag and catch up**: the proposer's own send-group leaf
moves at its next approved commit (the peer observes `new_sender` on that staple, and
message attribution follows); the PQ leaves catch up at the next A.3/A.5 handoff (the
session self-drives this — when a rotation leaves the send-PQ leaf lagging, the next A.5
it opens announces the session's *current*, already-canonical principal as the handoff,
and the handoff's new leaf carries that credential); the acceptor's recv-group leaf
converges from the invitation identity to the dedicated establishment principal via its
first committed Upd. Every catch-up is validated
against the AS history window.

For the common "dedicated agent per session" pattern, don't rotate at establishment
at all: pass the agent's id to `receive(…, new_client_id:)` and the session is born
under it (Establishment, above).

## Invitations & replayed initial frames

A published key package is backed by a self-contained **`TwoMlsPqInvitation`** (the
signing identity plus the key package's private material) rather than a live client;
one invitation services many welcomes, deduplicating repeats per remote
(`DuplicateWelcome`). `receive(welcome, their_classical_kp, bootstrap_kp_commitment,
spawn_token)` takes an opaque, caller-chosen, replay-stable token for the initial frame
and records
`token → the spawned session's receive group` in a **forward table**:

- **`forward_group_id(spawn_token)`** — `Some` means this exact initial frame was
  already accepted; route the payload to the owning session instead of surfacing a
  fresh welcome.
- **`TwoMlsPqSession::forwarded(spawn_token)`** — the session acknowledges the
  re-delivery (`Ok(None)` always: the call only validates the routing — a
  pre-establishment frame staples the sender's current app message §A.1-style, and
  the host delivers that staple by parsing the envelope
  (`decode_initial_plaintext`) and feeding it to `process_incoming`); a mismatched
  token is a mis-route.

- **`processed_welcome_group_id(welcome)`** — the content-keyed counterpart of the
  forward table: resolves a re-delivered welcome (by the digest of its exact bytes)
  to the spawned session's receive group, with no host token convention needed.
  `receive` consults the same ledger up front and rejects a re-delivery as
  `DuplicateWelcome` before claiming or reserving anything.

The invitation pushes these to its `ArchiveSink` after every `receive` — the consumed
set, the forward table, the processed-welcome ledger, and the bootstrap-commitment routing
table (contract 23) — so all four survive a restore. The token is opaque
to this crate — the caller picks the convention (Germ's adapter digests the envelope's
STABLE PREFIX — the app payload, else the bare welcome — so every pre-establishment
re-staple from the same initiator resolves to the same token).
