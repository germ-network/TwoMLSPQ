# @germ-network/two-mls-pq

## 0.11.0

### Minor Changes

- [#95](https://github.com/germ-network/TwoMLSPQ/pull/95) [`d400e7a`](https://github.com/germ-network/TwoMLSPQ/commit/d400e7ad4b32609bc5bf6f40e5d819859ad7cce8) Thanks [@germ-mark](https://github.com/germ-mark)! - Born-dedicated establishment now carries a signed identity delegation (binding contract 26). A `receive(new_client_id:)` acceptor whose dedicated credential differs from the invitation identity is non-emittable until `install_establishment_envelope` supplies the host's signed handoff, which wraps the unmodified `APQWelcome_A` in a new `0x0B` establishment-handoff staple. The initiator's `process_incoming` pauses on that frame (`DecryptResult.pending_establishment`) for out-of-band verification and completes via the stateless re-feed `process_incoming_approved(ciphertext, approved_envelope_digest:, approved_welcome_digest:, expected_creator:)`; a bare welcome whose creator differs from the invitation identity is refused at the join. `receive(new_client_id:)` equal to the invitation identity degenerates to the nil topology. New errors: `EstablishmentEnvelopeRequired`, `EstablishmentCreatorMismatch`, `EstablishmentEnvelopeConflict`.

## 0.10.0

### Minor Changes

- [#91](https://github.com/germ-network/TwoMLSPQ/pull/91) [`5ec39db`](https://github.com/germ-network/TwoMLSPQ/commit/5ec39db63ea162d04d560007b68a2165abe758b2) Thanks [@germ-mark](https://github.com/germ-mark)! - Session-driven PQ side-band advancement, optional side-band frame padding, lazy credential staging,
  and a rotated-party discharge fix (binding contract 23 → 25).

  The session now DRIVES its own A.3 ratchet and A.5 re-key rounds — the host no longer calls
  `pq_ratchet_begin` / `pq_rekey_begin` (both removed). On each `encrypt`, when it is our turn and the
  side-band is idle, the session opens the next round automatically: an A.5 credential catch-up when
  the send-PQ leaf still lags the canonical (classically committed) principal, else an A.3 ratchet.
  The host just takes the staged frame from `pq_pending_outbound` to send alongside the message, so
  its PQ role is now `.finishBootstrap` (A.4) plus ordinary sends. A staged A.5 is checkpointed with
  the send so a crash-restore cannot strand its pending update.

  Every header-sealed frame gains a 4-byte little-endian length prefix, and a new
  `set_pad_target(Option<u64>)` lets a host zero-pad each side-band frame up to the co-stapled
  message's size (capped at a push-payload budget), so the two co-stapled payloads are
  size-indistinguishable to an on-path observer. Absent the intent, frames go out at their natural
  size. The prefix is a hard wire change — a v23 seal mis-parses under a v24 open — so the binding
  contract bumps 23 → 24.

  Credential staging is now LAZY (contract 24 → 25). `prepare_to_encrypt(Some(id))` admits an unstaged
  candidate on the fly — minting its keys and authorizing it — so a rotation can ride the very first
  frame with no separate stage call; `stage_rotation` is removed from the FFI (a session advances state
  only by sending, so pre-staging bought nothing). Establishing a dedicated per-session principal is now
  "born-dedicated": `receive(new_client_id:)` creates the acceptor's send group directly under that
  principal (its creator leaf carries the id), retiring the old establish-under-founding → rotate dance.

  Also fixes a rotated party's owed-bind discharge: when it discharged via the bare evidence-gating
  license (no approved fold), the commit carried the credential handoff but no updatePath, so the new
  leaf never reached the peer and its next message failed to verify. A FULL (attestation-carrying)
  classical commit now always includes a path.

## 0.9.0

### Minor Changes

- [#88](https://github.com/germ-network/TwoMLSPQ/pull/88) [`516fe80`](https://github.com/germ-network/TwoMLSPQ/commit/516fe809a5393e6a945f6118fd0d1228601fcb4d) Thanks [@germ-mark](https://github.com/germ-mark)! - Split the backward-compat shim protocols out of the public TwoMLSPQ product.

  The Swift package is renamed `AbstractTwoMLS` → **`TwoMLSPQ`** and vends a `TwoMLSPQ` product
  containing only the concrete PQ types and their value/currency types, de-nested to top level
  (`PQSession`, `PQInvitation`, `PQClient`, `SessionError`, `HeaderDecryptResult`, `WelcomeToken`,
  `PrincipalState`, …), plus the UniFFI binding — isolated in an internal `TwoMLSPQBinding` target
  so its generated interface types stay off the public surface (and no longer collide with the
  wrapper's same-named currency types).

  The cross-backend shim **protocols** (`Session`, `Client`, `Invitation`, `Archivable`,
  `PQRatchet`, `PQRatchetingSession`, the `*Protocol` result protocols) move to the separate
  `AbstractTwoMLS` package, which depends on and re-exports this one and adds the conformances via
  extensions. `CommProtocol` is retained: `TypedDigest` is not an opaque token — the proposal
  digest's `.wireFormat` is signed into the cross-party agent handoff, so it is shared crypto
  vocabulary, and it's a type dependency rather than the shim protocol being quarantined.

  BREAKING: the module/product is now `TwoMLSPQ` and the types are top-level (not `AbstractTwoMLS.*`);
  consumers re-point their dependency and add `import AbstractTwoMLS` (which re-exports `TwoMLSPQ`).

## 0.8.0

### Minor Changes

- [#82](https://github.com/germ-network/TwoMLSPQ/pull/82) [`3fd6574`](https://github.com/germ-network/TwoMLSPQ/commit/3fd65741d4ea5bf599c6079cfda99e059eda7b6d) Thanks [@germ-mark](https://github.com/germ-mark)! - Route a parallel-delivered A.4 bootstrap KP′ to its session by content (contract 23).

  A KP′ shipped as a §A.1 bootstrap envelope (contract 21) carries no session id, and a
  reusable invitation spawns many sessions, so it cannot be routed by transport address.
  The invitation now keeps a commitment→group table — populated at `receive` from the
  `H(bootstrap KP)` commitment it was already given — and the new
  `bootstrap_kp_group_id(kp_frame)` resolves a framed `[0x13][KP′]` against it, the
  bootstrap-KP counterpart of `forward_group_id`/`processed_welcome_group_id`. The hash
  stays in Rust, so a frame that resolves can never fail `pq_bootstrap_respond`'s own
  commitment check. `pq_bootstrap_begin` (the rendezvous side-band path) is unchanged.

  Invitation archive layout changed (`INVITATION_VERSION` 1 → 2, pre-release hard cut): a
  stale invitation blob fails to decode and must be regenerated.

- [#84](https://github.com/germ-network/TwoMLSPQ/pull/84) [`9fd7d73`](https://github.com/germ-network/TwoMLSPQ/commit/9fd7d73607206a0273b4dce0db634b85382e2ebb) Thanks [@germ-mark](https://github.com/germ-mark)! - Consolidate the AbstractTwoMLS Swift package into this repository.

  The hand-written Swift wrapper that was maintained in a separate repo now lives here
  (`Package.swift`, `Sources/`, `Tests/`), with the Rust/UniFFI core relocated under `rust/`.
  A wire change and its Swift adapter land in one PR, tested against a LOCAL xcframework build:
  `Package.swift`'s `TwoMLSPQrs` binary target reads the local `buildIos/` build when
  `TWOMLSPQ_LOCAL_XCFRAMEWORK` is set and falls back to the pinned release url+checksum
  otherwise. The release tag `vX.Y.Z` remains the xcframework version the app resolves. The
  shipped packaging is unchanged (dynamic framework bundles); the legacy classical MLSrs target
  is dropped from this repo (the adopting app still links it on its own).

- [#85](https://github.com/germ-network/TwoMLSPQ/pull/85) [`c21369b`](https://github.com/germ-network/TwoMLSPQ/commit/c21369bfcc9cf9dd94506df50b77bf5d5979ecf3) Thanks [@germ-mark](https://github.com/germ-mark)! - Adopt the parallel A.4 bootstrap delivery in the Swift wrapper.

  An initiator now ships its pre-committed KP′ as a §A.1 bootstrap envelope via the new
  `PQRatchet.bootstrapEnvelope()` — alongside the establishment reply, so the acceptor can
  answer A.4 one round trip sooner off the invitation channel it already reads.
  `begin(.finishBootstrap)` stays valid and idempotent (both carry the same KP′, only the
  outer framing differs). The acceptor's `decodeHeader` self-routes an
  `OpenedInitial.bootstrapKp` to the owed session through the invitation's `bootstrapKpGroupId`
  table and answers it in `forwarded` via `pqBootstrapRespond` (a `DuplicateSideBand`, when the
  side-band won the race, is a benign no-op); the parked `Welcome'` rides the acceptor's next
  `pendingSideBand` hand-out. No crate or contract change — the binding stays at contract 23.

## 0.7.0

### Minor Changes

- [#79](https://github.com/germ-network/TwoMLSPQ/pull/79) [`1c8c068`](https://github.com/germ-network/TwoMLSPQ/commit/1c8c068f40eb8aed7540095bffc51d420132da08) Thanks [@germ-mark](https://github.com/germ-mark)! - Parallel A.4 KP′ delivery, and the §A.1 envelope drops its outer tag (contract 21).

  The initiator can now ship its pre-committed A.4 bootstrap key package IN PARALLEL with
  the establishment reply via `pq_bootstrap_envelope`, instead of waiting a full round trip
  for A.4's first side-band leg. Because the KP bytes are fixed at `initiate` (contract 20),
  an acceptor that already holds the KP′ when its return welcome goes out can respond and
  send `Welcome'` alongside it — A.4 completes ~one round trip sooner. The first emit
  registers the round exactly as `pq_bootstrap_begin` does; every later pre-establishment
  send re-seals the retained frame under a fresh HPKE ephemeral (unlinkable) without
  advancing state.

  To carry the KP frame and the reply under one indistinguishable shape, the §A.1 envelope
  loses its OUTER tag byte: the blob is now the raw `[u32-LE kem_output_len][kem_output]
[ciphertext]`, and discrimination moves INSIDE to the HPKE plaintext's authenticated
  leading tag — `ESTABLISHMENT_VECTOR_TAG` (0x07, repurposing the retired outer
  `INITIAL_ENVELOPE_TAG`) for the reply's four sections, `PQ_BOOTSTRAP_KP_TAG` (0x13) for
  the bootstrap KP. `open_initial` / `decode_initial_plaintext` now return `OpenedInitial`
  (`Establishment` / `BootstrapKp`); `initial_envelope_tag()` is retired (the host routes by
  transport channel, not first byte). Wire-format change — the outer tag is gone and the
  plaintext gained an inner tag — hence `BINDING_CONTRACT_VERSION` 20 → 21.

- [#80](https://github.com/germ-network/TwoMLSPQ/pull/80) [`06a5cd4`](https://github.com/germ-network/TwoMLSPQ/commit/06a5cd4e08a1d7647765f2d91c5bc44092b42720) Thanks [@germ-mark](https://github.com/germ-mark)! - One declared TwoMLS suite drives every crypto choice, and the §A.1 envelope binds it via
  untransmitted AAD (contract 22).

  The scattered suite constants collapse into one up-front declaration (the internal
  `TwoMlsSuite` enum): the group pair (`APQ_SUITE`), the §A.1/A.4 envelope HPKE (PQ half),
  the header-encryption AEAD (classical half's ChaCha20-Poly1305 — no longer an
  "independent variable"), and the protocol digest (classical half's SHA-256) are all
  facets read from `TwoMlsSuite::CURRENT`. Behavior-preserving: every facet equals the
  previously pinned value.

  The §A.1 envelope HPKE now BINDS the declared suite: both sides derive
  `[framing version (1)][classical u16 BE][pq u16 BE]` locally and pass it as the HPKE
  `aad` — it never travels the wire (the posted `APQKeyPackage` already names the pair
  publicly, and the opener's invitation defines the suite of every inbound envelope). The
  blob shape is byte-for-byte unchanged; the cut is cryptographic: a contract-21 seal
  (`aad = None`) fails a contract-22 open's AEAD tag and vice versa (`DecryptionFailed`,
  deliberately opaque). This downgrade-binds the CLASSICAL half too — which the HPKE
  operation alone never touches — at zero wire bytes. New export `envelope_framing_aad()`
  for hosts on the split `hpke_open` + `decode_initial_plaintext` path;
  `BINDING_CONTRACT_VERSION` 21 → 22.

## 0.6.0

### Minor Changes

- [#78](https://github.com/germ-network/TwoMLSPQ/pull/78) [`652c384`](https://github.com/germ-network/TwoMLSPQ/commit/652c384c1c06ec0d9e7b97ca96d6f14e72cb4b68) Thanks [@germ-mark](https://github.com/germ-mark)! - The establishment return key package is classical-only, and the A.4 bootstrap key
  package is pre-committed (contract 20).

  `receive`/`accept` now take the initiator's bare classical MLS KeyPackage message in
  place of the dual combiner blob — its PQ half fed nothing but a halves-agree check, and
  A.4 minted a fresh key package anyway (~2.6 KB of dead weight per establishment reply) —
  plus a required 32-byte `bootstrap_kp_commitment`: SHA-256 of the initiator's PQ
  keyPackage, which the host carries inside its SIGNED establishment payload. `initiate`
  mints that PQ key package up front with SESSION-OWNED custody — both halves ride the
  session archive, the private half injected just-in-time at the bind join — so neither a
  restore nor a Phase 8 rotation's client swap can strand the committed round
  (`bootstrap_kp_commitment()` exposes the hash for the host's envelope).
  `pq_bootstrap_begin` sends the retained pre-committed KP, and
  `pq_bootstrap_respond` rejects a KP′ hashing to anything else (`BootstrapKpMismatch`,
  new error variant, appended). This anchors the ML-KEM key material to the host's signed
  establishment rather than resting it on classical channel auth alone. When a commitment
  is pinned, the hash check replaces the names-the-established-peer equality (strictly
  stronger — it pins the exact committed bytes), so a KP′ under a since-rotated principal
  still lands (PQ leaves lag credentials by design; A.5 catches them up).

  Host worklist: `reply`-side flows mint a classical KP (`generate_key_package`, x25519)
  instead of `generate_combiner_key_package` for the return KP; the signed app welcome
  carries the classical KP + the 32-byte commitment; the receive flow threads the
  commitment into `receive`. `set_initial_return_key_package` takes the bare classical
  bytes. Archive layout changed (pre-release hard cut: old blobs fail to decode and are
  regenerated).

### Patch Changes

- [#74](https://github.com/germ-network/TwoMLSPQ/pull/74) [`d667923`](https://github.com/germ-network/TwoMLSPQ/commit/d6679230c8971b43b56009a1dde90f4d74ae8ba9) Thanks [@germ-mark](https://github.com/germ-mark)! - Retire "reconnect" from the session layer's vocabulary.

  There is no reconnect at this layer and never was: `EpochDesync` is not recovered
  in-library, restore cannot heal it (the persisted state is desynced too), and the
  recovery is out-of-session — the host re-establishes a fresh session. The word was
  inherited from classical TwoMLS, where "reconnect" names a real in-band rejoin
  mechanism with no PQ counterpart; using it here implied a capability this crate
  deliberately does not have.

  The one host-visible delta: `EpochDesync`'s Display string is now "stapled commit is
  ahead of the receive group; re-establish the session" (was "...reconnect required").
  Hosts should match the `EpochDesync` variant, never the string. Everything else is
  doc comments and book prose; "reconnect" survives only where it correctly names the
  classical mechanism, now labeled as such.

## 0.5.0

### Minor Changes

- [#73](https://github.com/germ-network/TwoMLSPQ/pull/73) [`bada78b`](https://github.com/germ-network/TwoMLSPQ/commit/bada78ba47574bc2bc9b4dd9ee3411425a274439) Thanks [@germ-mark](https://github.com/germ-mark)! - Retain the PQ side-band's in-flight frame so a host can re-send it.

  A side-band frame is the only carrier of its PQ half, and until now it was handed
  out once: `pq_take_pending_outbound` consumed the slot, and initiator frames
  (`pq_ratchet_begin` / `pq_bootstrap_begin` / `pq_rekey_begin`) were returned
  without being parked at all. A frame lost in transport therefore had nowhere to
  be re-sent from, and the round stalled with no way to heal — `pq_inflight` blocks
  a re-begin, and nothing can re-emit an ephemeral's public half.

  The A.3 bind is the sharp case, and `pq_ratchet_bind`'s own comment describes the
  hole without closing it: the bind's classical commit re-staples on message frames,
  but the peer cannot apply that staple without the PQ commit riding the bind, so
  the classical stream stalls retriably "until the BIND lands" — forever, if the
  bind is gone. A.4 is worse: a lost KP' means the session never reaches full
  establishment.

  Both roles' frames are now retained in `pending_side_band` (already archived,
  so retention survives restore), replaced when this side produces the round's next
  frame and cleared when the peer's answer proves it landed. This mirrors
  `current_staple`, which has always re-sent the classical commit on every frame so
  that any single received frame heals the peer.

  - **New `pq_pending_outbound(sealing)`** — the frame, sealed, without consuming it.
    Prefer it over `pq_take_pending_outbound` (retained, and still correct for hosts
    driving a strict request/response). Advances no protocol state: no `state_seq`
    bump, nothing to persist. The seal is under the current PQ header epoch, so a
    frame retained across a ratchet still opens.
  - **New `SideBandSealing`** — the frame is retained as plaintext and sealed per
    hand-out, so how repeated hand-outs look on the wire is the host's call, and only
    the host can make it. `Fresh` re-seals every time: repeated sends of one retained
    frame are distinct, so a passive observer cannot correlate the re-sends of a
    stalled round. `Stable` seals once and repeats the bytes while the frame is
    unchanged, which a host that CHUNKS requires — chunks are cut from the sealed
    bytes, and pieces cut from two different seals never reassemble. The trade is
    exactly the correlation `Fresh` avoids, and neither is safer in general.
    Stability is scoped to the frame: when the round advances, the next hand-out seals
    the new frame (the cache stores what it sealed and re-seals on a mismatch, so no
    set site has to remember to invalidate it). The cache is live-only, so a restore
    restarts a chunking pass with a fresh base — which a host must tolerate anyway,
    since a lost pass demands the same.
  - **New `DuplicateSideBand` error** — the PQ analogue of `DuplicateWelcome`.
    Re-sending makes duplicates steady-state traffic: an initiator's terminal frame
    has no inbound of its own to retire it, so it re-sends until the peer opens the
    next round. Receivers now classify a frame for a step already taken as a
    discardable duplicate rather than `SessionNotReady`, which a host must stay free
    to read as a routing signal. Raised only where the state proves the step is done;
    a merely ill-timed frame still reports `SessionNotReady`. These guards already
    sat above the persist choke point, so a duplicate remains a true no-op.
  - **Operation guards key on turn and `pq_inflight`, not slot occupancy** — under
    retention an occupied slot is the steady state, not "busy". The gates are
    unchanged in effect: `pq_inflight` already rejected a double-respond or a bind
    without the ephemeral.

  Hosts that keep using `pq_take_pending_outbound` are unaffected: initiator frames
  are still returned as before, and taking still consumes.

  ## A.4 is a well-formed round now, so one slot suffices

  Retention exposed that A.4 could be evicted: it was the only flow absent from
  `pq_inflight`, so a ratchet round could open beside a bootstrap and replace its frame —
  and a bootstrap frame is irreplaceable, so establishment stranded for good. Reachable in a
  NORMAL flow, because `pq_bootstrap_respond` took the turn at its own send: the responder
  was expected to open the next round while its own welcome was still unconfirmed.

  The cause was A.4's two-leg shape. A.3 and A.5 end with the initiator finalising, which is
  what lets the turn pass on a receipt; A.4 stopped at KP' → Welcome, so it had no finalising
  leg and handed the turn over early to compensate. It now has one:

  **KP' → Welcome' → bind.** The initiator joins the welcomed group, exports the cross-party
  secret from its birth epoch, injects it into its own send-PQ with a pathless commit, and
  OWES the classical half. The only difference from A.3's bind is where the secret comes
  from: a group exporter rather than a KEM exchange.

  Three things fall out:

  - **The receipt is free.** The secret is derivable only from INSIDE the welcomed group, so a
    bind that applies at all proves the initiator joined. The responder re-derives it from its
    own copy — same group, epoch and domain — so it never goes on the wire. An ack frame would
    have proved the same thing and done no work.
  - **The turn passes on the same rule as everything else** — the initiator relinquishes at its
    terminal send, the responder takes it on applying. The responder never holds the turn while
    its welcome is unconfirmed, so the collision cannot form.
  - **A.4 registers in `pq_inflight`**, joining the single-occupancy that already kept A.3 and
    A.5 apart. So `pq_pending_outbound` returns at most one frame, and the second slot the
    first cut of this change added is gone.

  The old `PQ_BOOTSTRAP_BIND` tag briefly named this leg's frame; the frame is gone (see the
  staple section below) and the tag with it.

  One consequence worth knowing: **A.4 is no longer PQ-groups-only.** Its bind carries a
  classical commit, so it advances the initiator's epochs (1/1 → 2/2) where the old bootstrap
  advanced nothing. Post-A.4 state is therefore asymmetric: the responder's send-PQ is born at
  A.4 and does not move until its own next bind. Classical never blocks on PQ — this defers
  freshness, not liveness.

  ## A bind is the staple, not a frame

  draft-ietf-mls-combiner-02 §7 defines the wire shapes, and it has **no `APQCommit`**: a
  FULL commit travels as `APQPrivateMessage { t_message; pq_message; }`. The old bind frame
  `[pq_commit][cl_commit][app]` was a Germ invention sitting exactly where the draft already
  had the shape — the book's claim that the Germ frames _enclose_ the draft-02 wire shapes
  rather than replacing them was false for the bind. So the bind is now that struct, riding
  where a classical commit already rides: the message-frame **staple**.

  The trigger (`pq_ratchet_bind` / `pq_bootstrap_bind`) commits the PQ half pathlessly and
  records the classical half as OWED; the next classical COMMIT discharges it — exports the
  `apq_psk` from the reserved epoch, folds it and the shared attestation into the commit it
  is already building, and staples both halves as one `APQPrivateMessage`. Nothing about the
  bind is parked on the side-band: the staple re-sends until superseded, so a lost bind heals
  by machinery that already existed, and `apply_bind` collapses into the ordinary staple path
  on the receiver. The binds lose their `app` parameter (the committing round's own message
  frame carries the app), and `pq_ratchet_apply` / `pq_bootstrap_apply` are deleted — the
  bind arrives via `process_incoming` like any staple.

  The owed state is two rules, enforced explicitly while it stands: **at most one owed bind**
  (a second PQ commit would move `pq_epoch` out from under the attestation the first one
  reserved), and **the next classical COMMIT is the bind** (not the next send — non-committing
  rounds flow freely, so PQ never holds up classical). `discharge_owed_bind` re-checks both
  against the live groups, because a violated reservation must fail loudly on our side, where
  nothing has been sent, not on the peer's with our PQ leaf already spent. The turn passes at
  discharge rather than at the trigger: one `EncryptResult` can then carry this round's bind
  in the staple and the next round's `begin` frame in the side-band slot — different paths,
  no contention — saving a round trip in async messaging.

  **A bind's classical half is an ordinary commit**, so the frame carrying a bind carries
  everything a plain commit frame does — including a credential rotation's canonical step,
  when the round folds an Upd naming a candidate. Hosts see no new case (the rotation surfaces
  on `remote_commit` exactly as it does off a plain commit); the wire shape that delivers it is
  the only difference, which is why the receiver's identity bookkeeping runs off what the
  applied commit MOVED rather than off which staple form carried it.

  ## Evidence-gating: a commit needs a license, not an approval

  Rule 3 makes an owed bind wait for a classical COMMIT — and while folding an app-approved Upd
  was the only way to commit, that made **PQ liveness hostage to app approval policy**: an app
  that receives offers and never approves them stranded every PQ round at 2/1 forever, peer
  parked in `Responding`, turn never passing. A round now commits when it folds an approved Upd
  (unchanged) **or** when it owes a bind and is licensed.

  The license is the property that was already there, unnamed. A sender may only commit once
  the peer has demonstrably applied its previous commit — **at most one commit outstanding, per
  direction** — and two things rest on it: any single frame heals the peer (a staple bridges a
  peer at most one commit behind), and a bind's staple provably survives until applied (a
  superseded staple never re-sends, and by then `owed_bind` is consumed and the PQ exporter leaf
  spent — no classical reconnect repairs that). Folding _was_ the evidence: the peer builds its
  `Upd(self)` in its recv group, which IS our send group, so the offer is bound to our epoch and
  `validate_offered_update` refuses a stale one against the live group. A proposal-less commit
  has no fold to infer it from, so the watermark is now explicit (`peer_applied_send_epoch`,
  archived). It is stamped only from an offer that passes the same `validate_offered_update` a
  fold runs: the epoch field of raw proposal bytes is unsigned, so a spliced high-epoch offer
  must not be trusted to advance it — a valid offer proves exactly our live send epoch, and the
  watermark is set to that.

  Why the proposal and not the peer's cross-injected PSK, which also proves application: the
  PSK rides **commits only**, so both directions would gate on each other and two concurrent
  commits would deadlock — neither able to produce the evidence releasing the other. The
  proposal rides every frame. (The header-key application receipt deleted above was the weaker
  version of the same idea: transport-window position, where the proposal proves MLS state
  incorporation.)

  Deliberately NOT offered: **empty commits on cadence.** Our commit invalidates whatever offer
  is in flight, so committing every licensed round would kill each offer inside the window the
  peer's app has to approve it — starving rotation (approval IS the AS authorization) for any
  host that deliberates across a round trip. Tying the empty commit to an owed bind bounds that
  churn to the PQ cadence, which the host already chooses. An empty commit still carries an
  updatePath (RFC 9420 forces one), so a discharge delivers both PCS sources — a fresh own leaf
  and the `apq_psk` chaining the PQ half's entropy in; it simply leaves the peer's leaf where it
  was, which is where it was staying anyway.

  Host-visible: `did_commit` can now be true with no `queue_proposal`, and
  `committed_remote_client_id` is `None` on such a round — it reports what the commit
  CANONICALIZED, and a proposal-less commit canonicalizes nothing of the peer's.

  The wrapper tag exists because the struct cannot self-discriminate: its first byte is its
  inner `MLSPrivateMessage`'s `0x00`, identical to a bare commit, and the staple slot tells
  its forms apart by first byte alone (`0x00` MLSMessage, `0x01` APQWelcome, `0x05`
  APQPrivateMessage).

  ## The bind's two failure paths are surfaced, not silent

  An owed bind consumes irreversible state — the reserved epoch, the PQ exporter leaf — so a
  failure while it is being spent cannot be retried away. Neither path is reachable from an
  honest flow (both take an internal MLS failure), but each now wears its own error instead of
  a misleadingly retriable one:

  - **`BindDischargeFailed` (fatal).** The classical commit discharging a bind failed after the
    reservation was consumed and the leaf spent. The round can never be rebuilt and the peer
    waits forever, so the host must re-establish rather than retry — which the dedicated variant
    makes unmistakable. The whole destructive tail is now one helper (`discharge_and_commit`),
    so the fatal mapping covers it by construction and a fallible line added there can't escape
    it.
  - **`BindApplyFailed` + `pq_receive_broken()`.** Applying a peer's bind staple failed after
    the round's secret was consumed, so RECEIVING is broken — the peer re-staples the same
    unappliable bind on every frame (evidence-gating forbids it committing past it), and every
    inbound frame fails before its app message. SENDING is unaffected. In-memory only (inbound
    processing persists on success), so restoring the last persisted state heals it; and it is a
    query, not only an error, because how urgent a receive-break is depends on what the session
    is for — a receive-critical role treats it as fatal, a send-mostly role can defer.

  ## The A.3 ciphertext seals a random secret, so a stale one is rejected cleanly

  ML-KEM decapsulation returns a garbage secret — not an error — for a ciphertext that answers
  a different ephemeral (implicit rejection). Under the bundling window a lagging peer's re-sent
  round-N ciphertext can reach the initiator while it holds round N+1's ephemeral; a bare
  decapsulate would inject that garbage, spend the PQ leaf, and strand the round on a secret the
  peer never shares — silently.

  So the A.3 secret is no longer the KEM output. The responder picks a **random** secret and
  **seals** it to the initiator's EK under a key derived from the KEM shared secret **and** a
  repeatable exporter of the group the secret is injected into, at its current epoch. The
  initiator **opens** it before injecting: a ciphertext answering the wrong ephemeral (garbage
  KEM secret) or built against a different epoch (wrong PSK) fails the AEAD tag **explicitly**,
  and is rejected in the bind's pre-persist guard with the ephemeral and PQ leaf untouched. The
  open is the receipt ML-KEM couldn't give.

  Two bonuses fall out. S is now **hybrid-secure** — `key = Extract(kem_ss, psk)` needs both, so
  it holds if _either_ ML-KEM or the group's epoch secret does. And the epoch export is the
  plain **repeatable** exporter, deliberately not `SafeExport`: a one-shot leaf could be burned
  by a stale ciphertext's failed open, re-introducing the very brick through a different door;
  each A.3 round is already at a distinct epoch, so the epoch is the round nonce with no new
  state. The 0x19 frame gains the sealed secret (`[u32 enc_len][enc][sealed]`) — a wire cut.

  ## A.5 becomes the same round shape: proposal, full commit, stapled ack

  A.5 was `Upd' → [Commit'][counter-Upd'] → Commit2`, rekeying both PQ groups in one round —
  and `Commit2` was both **terminal** (nothing answers it) and **large** (updatePath). Its
  last leg is now the same ack every round ends with: a small pathless partial commit riding
  the staple.

      leg 1  initiator: Upd'(self) into the peer's send-PQ     proposal — replaces the
                                                               PROPOSER's leaf
      leg 2  responder: Commit' folding it, with updatePath    the round's ONE large frame —
                                                               replaces the COMMITTER's leaf
      leg 3  initiator: applies it, ACKS with a partial        small, a STAPLE, and a
             commit exporting from the NEW epoch               conformant FULL commit

  All three rounds are now `X → Y → bind`, differing only in where the bind's secret comes
  from (KEM decapsulation; CrossParty export at the birth epoch; CrossParty export at the
  rekeyed epoch). The counter-proposal is gone, so one A.5 round re-keys ONE group — the same
  bytes per group as before (one updatePath commit each), across two rounds whose turn
  alternation the protocol already had. The ack's attestation reconciles the bumped `pq_epoch`
  into APQInfo **in-round**, where the old design deferred it to the next A.3 bind; the
  side-band `Commit'` itself still carries no attestation, preserving the A.5 isolation rule
  (the large PQ frame never rides the message path — "classical stapled commits carry no PQ
  keys").

  The credential handoff redistributes with the legs. The initiator's handoff rides its leg-1
  `Upd'` (a proposal replaces the proposer's leaf) — as it always did. The old counter-commit
  also moved the initiator's OWN send-PQ leaf; that updatePath is gone, so the committer
  replacement moves where the updatePath went: `pq_rekey_respond`'s Commit' now catches the
  RESPONDER's leaf up to the session's canonical identity whenever it lags (the PQ analogue of
  the classical commit's own-leaf catch-up, validated by the AS's already-canonical rule).
  Each party's send-PQ leaf hands off when it responds; the turn alternation brings that round
  around.

  ## The peer-application receipt existed, and nothing needs it

  An earlier cut of this work retired terminal frames on a receipt recovered from header
  encryption, and the finding behind it was real: we seal to the peer under OUR recv group, so
  the peer seals to us under ITS recv group — our SEND group — at the epoch it has actually
  applied, which makes the epoch of the key that opens a frame an unforgeable, free,
  already-on-the-wire proof of what the peer has applied. `try_open` was discarding it.

  It is not recovered any more, because nothing needs it: with every round ending in a stapled
  bind, **no frame is both terminal and unanswered**. Every large frame is answered by the
  round's next leg (an EK by a CT, a KP' by a Welcome', a Commit' by the stapled ack), and the
  answer is what clears the retained frame — the ordinary round-complete rule, no stamps, no
  watermarks, no `(family, epoch)` on the wire structs. Should a future frame genuinely need a
  terminal receipt, the mechanism is a matter of record: the window that opens a frame names
  the family, and the epoch within it is the receipt.

  ## The tag space is banded, and the bands are enforced

  Adding A.4's bind exposed that the tag space had no single record. The bytes are one global
  first-byte discriminator space, but they are declared in three places — `apq::APQ_TAG`, the
  envelope tag in `key_packages`, and the rest in `session::frames` — because each tag lives
  with the thing it tags. Ownership is local; allocation is global, so "take the next unused
  odd value" was not answerable from any one file. The new bind was duly allocated at 0x15,
  which `key_packages` already owned: a collision is a silent wire misclassification, not a
  compile error, and the only comment describing the space sat in the file a reader adding a
  session frame never opens.

  Tags are now RENUMBERED into bands, each packed from its start with its remaining room at
  the end:

  | Band              | Range     | Used                                                                                              |
  | ----------------- | --------- | ------------------------------------------------------------------------------------------------- |
  | Message path      | 0x01-0x05 | 3 / 3 — full, and closed by design: welcome, message frame, and the APQPrivateMessage staple form |
  | A.1 establishment | 0x07-0x11 | 2 / 6 — the hybrid nested envelope would land in the room                                         |
  | PQ side-band      | 0x13-0x31 | 6 / 16 — lifecycle order: bootstrap, ratchet, re-key; no binds (a bind is the staple)             |

  Allocation order had left the side-band non-contiguous and silently falsified five
  range shorthands across the code and book; a range in prose should at least not
  be a lie. Extending the protocol is no longer "take the next unused odd value" — it is
  "append at the end of the right band, into the room it already reserves". Only a band that
  FILLS moves anything below it — which happened once within this very change: the bind
  becoming the staple's third form FILLED the message path, and every band below shifted.

  The room is free in both directions that could have cost something. On the wire, header
  encryption seals every blob, so a tag is never observed and a sparse space fingerprints
  nothing. In the tests, `tag_space_holds` asserts density WITHIN a band and membership against
  that band's bounds, so room at a band's end is legal while appending past the end still
  fails. The reserve costs no enforcement — which is why the sizes are generous. They are
  reserves, not predictions: only the message path's fullness is a design claim.

  A band's reserved bytes are unallocated and MUST NOT classify, so the side-band's invariant
  is set equality against the registry (`side_band_band_matches_the_classifier`, over all 256
  bytes) rather than a range test — a reserved byte is _in_ 0x11-0x2F, so "in range iff
  classified" would wave through a reserve that quietly started routing.

  `frames::tests::BANDS` is the record, and the book's `wire-format.md` table is its prose
  half.

  **This is a wire cut** (`BINDING_CONTRACT_VERSION` 19; 17 was burned by an interim build of
  this same work). Hosts classify via `pq_frame_kind` and never match raw bytes, so no host
  code changes beyond the deleted bind cases; stale frames from older builds fail loudly in
  the decoders, as they already did across the previous renumber.

### Patch Changes

- [#68](https://github.com/germ-network/TwoMLSPQ/pull/68) [`4c136c5`](https://github.com/germ-network/TwoMLSPQ/commit/4c136c54852aff68ffb2344af0048c76295ec0b3) Thanks [@germ-mark](https://github.com/germ-mark)! - Doc truth fix: `forwarded` and contract 16's pre-establishment staples.

  The `forwarded(spawn_token)` doc (and the session-lifecycle book section) still
  justified the `Ok(None)` return with "an initiator cannot staple a private
  message pre-establishment" — false since §A.1 replier-first sends (contract 16),
  where every pre-establishment frame staples the sender's CURRENT app message.
  The return contract is unchanged; the reason is corrected: `forwarded` only
  validates the routing, and the staple rides the envelope itself — the host
  parses it out (`decode_initial_plaintext`) and delivers it through
  `process_incoming`. Also updates the book's spawn-token convention note to the
  stable-prefix digest Germ's adapter actually uses. Doc-only — no code change.

## 0.4.1

### Patch Changes

- [#66](https://github.com/germ-network/TwoMLSPQ/pull/66) [`0c526e0`](https://github.com/germ-network/TwoMLSPQ/commit/0c526e068404cc5df68a7508cdde52e72f517166) Thanks [@germ-mark](https://github.com/germ-mark)! - Fix the agent-handoff binding context so cross-endpoint handoffs validate.

  An agent handoff is signed by the sender against its `proposal_context`
  (SHA-256 of its recv group's classical id) and validated by the receiver against
  the `context` that `process_incoming` stamps on the `QueuedRemoteProposal`. That
  stamp used the receiver's _recv_ group id — but the two endpoints' recv groups
  are distinct MLS groups (A's recv is B's send), so the values never matched and
  every cross-endpoint handoff signature failed to validate. It stayed latent
  because the only prior consumer never read `proposal_context`; the first consumer
  that does could not complete its first agent rotation (a Signature-validation
  failure that cascaded to a dropped decrypt).

  Stamp the queued proposal's context from our send group's classical id — the
  reverse channel, which is the sender's recv group — so sign and validate agree.
  Also correct `test_proposal_hash_is_digest_of_the_staple_both_sides_agree_on`,
  which asserted the receiver's context equalled the receiver's _own_
  `proposal_context` (trivially true under the bug); it now asserts equality with
  the _sender's_, the contract that actually gates handoff validation.

## 0.4.0

### Minor Changes

- [#64](https://github.com/germ-network/TwoMLSPQ/pull/64) [`d3f33ef`](https://github.com/germ-network/TwoMLSPQ/commit/d3f33efa239e696151375b5e4a62d37b98e2ccab) Thanks [@germ-mark](https://github.com/germ-mark)! - §A.1 pre-establishment initiator sends (binding contract 16; archive versions reset to the
  pre-release floor).

  The initiator can now send app messages immediately after `initiate`, before the
  acceptor's return welcome exists (architecture-diagrams 08-twoMLSPQ-APQ §A.1) —
  previously `prepare_to_encrypt` returned `SessionNotReady` until both groups were
  established, on live and restored sessions alike. Pre-establishment,
  `prepare_to_encrypt` is a no-op round (`proposal_message` empty; `proposal_hash` is
  the WELCOME digest — the documented carve-out on the v14 guarantee) and `encrypt`
  emits a fresh §A.1 envelope per frame (contract 16 atop v0.3.0 AppBinding — `initiate` keeps `app_binding` and loses `app_payload`), HPKE-sealed to the retained peer KP′,
  re-stapling the establishment sections plus the app message — any single frame lets
  the invitation holder join and read it.

  Envelope wire v2: tagged `[0x15][u32 kem_len][kem][ct]`; plaintext is four optional
  u32-LE length-prefixed sections `[app_payload][welcome][return_kp][stapled_message]`
  under the either/or rule — a host `app_payload` is establishment-SELF-SUFFICIENT
  (carries the welcome + return key package inside) and replaces the bare sections.
  `initiate` lost its `app_payload` parameter (a payload that signs over the welcome
  cannot exist before `initiate` returns); attach with the new
  `set_initial_app_payload` / `set_initial_return_key_package` (initiator-only,
  pre-establishment-only; capture AFTER attaching — the retained state rides the
  archive, so a birth-captured replier restores send-ready). New read-only
  `initial_welcome()`; `InitialFrame` reshaped (all four sections, `welcome` now
  optional); new exported `decode_initial_plaintext`. Replay-stable token/dedup keying:
  the stable prefix (`app_payload` when present, else `welcome`); all consequential
  state keys off the signed, JOINED welcome — the other sections are unauthenticated
  routing hints. The stapled app message is `[0x13][classical PrivateMessage]`, handed
  to `process_incoming` after the join. Establishment clears the retained state.

  Archive layout versions reset to the pre-release floor (SESSION_ARCHIVE and INVITATION
  both → 1 — the accumulated ladders carried no compatibility value pre-release; history
  stays in git): ALL persisted sessions and invitations regenerate, fail-closed
  (`ArchiveInvalid`). The v0.3.0 key-package WIRE cut (KP v3, a published artifact) is
  untouched. Composes
  with v0.3.0 AppBinding: the binding rides the welcome every pre-establishment frame
  re-staples, so `receive(expected_app_binding:)` verifies it on a join from any frame.

## 0.3.0

### Minor Changes

- [#62](https://github.com/germ-network/TwoMLSPQ/pull/62) [`b319e26`](https://github.com/germ-network/TwoMLSPQ/commit/b319e2698a6aafa81e8892f10c7c896643fb1359) Thanks [@germ-mark](https://github.com/germ-mark)! - **AppBinding** — an optional app-state binding welded into a session at creation and immutable for its lifetime. A TwoMLS session is definitionally bound to its two agents, but agents are _mutable_ (the rotation/candidate lifecycle); the new `AppBinding` GroupContext extension (`0xF0A2`, the APQInfo mechanism) binds the session to the app's **immutable** relationship identity: `initiate` gains `app_binding: Option<Vec<u8>>` (Swift: `appBinding: Data?`), `receive`/`accept` gain `expected_app_binding` — verified on the joined welcome with an exact, symmetric match (a stripped or unequal binding is a wrong-relationship welcome or downgrade attempt; a binding the caller did not state is never silently accepted) **before any invitation state is claimed**, so a rejected welcome leaves the invitation fully reusable. The acceptor's return group mirrors the verified binding; the initiator requires the return welcome to carry its own binding back unchanged. The binding lives on the classical halves only — a PQ half smuggling one is rejected at every PQ join — and an **empty** binding is reserved as invalid (rejected at creation and as an expectation; `None` is the unbound state). New `app_binding()` getter reads it back (it rides the persisted group state, so a restored session's owner re-verifies); new error `AppBindingMismatch`. GroupContextExtensions proposals remain outside the TwoMLS operation whitelist — now a deliberately tested guarantee — so the binding can never be rewritten.

  **⚠️ Binding contract 14 → 15 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release (`TwoMlsPqError` gained a variant; a stale pairing mis-reads FFI buffers). **Key packages and invitations regenerate**: leaves now advertise the AppBinding extension type, so `COMBINER_KEY_PACKAGE_VERSION` 2 → 3 and `INVITATION_VERSION` 3 → 4 (prerelease hard cut — v2 published key-package blobs and v3 invitation archives are rejected outright; re-pair sessions). Session archives are unaffected: the binding is optional, and existing (unbound) sessions restore and keep working.

  Adopter guidance: pass a **digest**, not raw identifiers — the first adopter (germDM) binds `H(domain-tag ‖ role-ordered did:did)`, sharing its canonicalization with the companion CommProtocol relationship-scoped introduction context so the delegation binding and the session binding cannot drift. The crate never interprets the bytes.

## 0.2.0

### Minor Changes

- [#60](https://github.com/germ-network/TwoMLSPQ/pull/60) [`3478ceb`](https://github.com/germ-network/TwoMLSPQ/commit/3478ceb0dec6dec2fa16d08b28709009c489c5d7) Thanks [@germ-mark](https://github.com/germ-mark)! - `PrepareEncryptResult` gains `proposal_message: Vec<u8>` (Swift: `proposalMessage: Data`) — the raw staged Upd(self) proposal, the exact message the paired `encrypt` staples and the peer independently digests.

  **⚠️ Binding contract 13 → 14 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release (a Record shape change; a stale pairing mis-reads FFI buffers). No wire, archive, or semantic change — persisted state carries over.

  Unblocks the anchor "agent handoff" flow: the app signs over its own `sha256(proposal_message)`, which equals the same result's `proposal_hash` and the receiver's independently derived `QueuedRemoteProposal.digest` (cross-side coherence, covered by new tests — including at the establishment moment, before any peer frame). Bytes and digest come from the same critical section, so there is deliberately NO staged-slot getter: a decoupled read could return whatever Upd a later `prepare_to_encrypt` staged (routine self-refreshes included), and a signature input must not be exposed to that race.

## 0.1.0

### Minor Changes

- [#57](https://github.com/germ-network/TwoMLSPQ/pull/57) [`8115145`](https://github.com/germ-network/TwoMLSPQ/commit/81151459925770851569e7fac93f39e47a714c90) Thanks [@germ-mark](https://github.com/germ-mark)! - Push-based persistence; the pull `archive()` is removed from the FFI

  **⚠️ Binding contract 12 → 13 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release. **Persisted state is not portable**: `SESSION_ARCHIVE_VERSION` → 9, `INVITATION_VERSION` → 3 — regenerate all persisted sessions and invitations.

  The pull `archive()` on `TwoMlsPqSession` and `TwoMlsPqInvitation` is **removed from the exported surface**. Its contract was a _move, not a copy_ — using the live object after archiving, then restoring, rewound the sender ratchet and re-derived AEAD keys/nonces (security review finding H1: keystream reuse against a real transcript). The crate could not enforce the discipline while the app decided when to pull.

  The live object now **pushes** its state to a foreign persistence hook after every state-advancing mutation:

  - **`ArchiveSink`** (`with_foreign` trait) with `persist(seq, kind: BlobKind, archive)`. Attach one per object with the new **`install_sink`** (pushes a baseline `Checkpoint`). The contract: enqueue-only, non-blocking, atomically upsert the one blob named by `kind` (never a multi-object write), newest-`seq`-wins per slot, and seal the plaintext bytes before writing.
  - **Two-blob session model**: a **classical** mutation rewrites `Core` (identity + both classical halves + meta — the ML-KEM ratchet trees omitted); a **PQ** op (and the baseline) writes a full `Checkpoint`. Every mutation is one atomic single-blob push, so the sink needs no cross-object transaction. Restore is **`TwoMlsPqSession.restore(core, checkpoint)`** (reconciles PQ-from-checkpoint, rest by higher `state_seq`, fails closed on a manifest mismatch). The invitation is monolithic (no ML-KEM trees) and restores with **`TwoMlsPqInvitation.restore(archive:)`**. Both restore constructors are named **`restore`** (renamed from the session's `from_persisted` and the invitation's `new(archive:)`) — the name signals materialising from serialised bytes, not minting fresh state.
  - **`EncryptResult.depends_on_seq`** + read-only **`state_seq()`** on both objects: the app waits until it has durably persisted the frame's `depends_on_seq` before transmitting a frame that publishes stored-private-key material (a routine app message re-staples an already-persisted commit, so it imposes no wait). Transmission stays entirely the app's concern.

  Internals: the invitation's four mutexes are consolidated into one (removing a torn-archive class); `pq_bootstrap_begin` now persists its pending PQ key package (previously at risk of a restore-time strand). No protocol/wire changes to messages — only persistence and the removed pull surface.

## 0.0.13

### Patch Changes

- [#55](https://github.com/germ-network/TwoMLSPQ/pull/55) [`2324280`](https://github.com/germ-network/TwoMLSPQ/commit/232428094946b8871fa52edc3119dcdb5f7619f8) Thanks [@germ-mark](https://github.com/germ-mark)! - Fix the iOS XCFramework build (restore the CryptoKit iOS-build fixes)

  v0.0.12's artifact build panicked in mls-rs-crypto-cryptokit's build.rs ("Libraries require RPath!"). The `germ-shadow-safe-exporter` branch had never picked up the CryptoKit iOS-build fixes the previous pin (`3743c75`) carried: newer Xcode toolchains report `librariesRequireRPath` for varying deployment targets, and that guard is spurious for this artifact — the cdylib ships inside an `@rpath/…framework`, so rpath-based loading is exactly what is wanted. The bumped mls-rs pin restores those fixes (panic → warning; `MIN_IOS_DEPLOYMENT_TARGET` stays 17.0, so the bridge still compiles for iOS 17+ deployment). No library code changes; binding contract, session archive, and key package versions are unchanged from 0.0.12 (which shipped no artifacts).

## 0.0.12

### Patch Changes

- [#53](https://github.com/germ-network/TwoMLSPQ/pull/53) [`66d12fb`](https://github.com/germ-network/TwoMLSPQ/commit/66d12fbbde29e1b2d8f7c5716bd9b742532eb946) Thanks [@germ-mark](https://github.com/germ-mark)! - draft-ietf-mls-combiner-02 conformance ([#51](https://github.com/germ-network/TwoMLSPQ/issues/51)), session modularization ([#52](https://github.com/germ-network/TwoMLSPQ/issues/52))

  **⚠️ Binding contract 8 → 12 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release; uniffi's load-time checksum rejects a stale pairing. **Persisted state is not portable**: `SESSION_ARCHIVE_VERSION` → 8 and the combiner key package framing → v2 — regenerate all persisted sessions, invitations, and published key packages.

  The `apq` crate and session layer now conform to **draft-ietf-mls-combiner-02** (with mls-extensions-08 for the component framework):

  - **APQInfo** GroupContext extension (`0xF0A1`) in both halves of every APQ group and in Welcomes — written once at creation, verified by joiners (group ids, mode, suite pair).
  - **AppDataUpdate** (`0x0008`) on both commits of every FULL, attesting the new epochs of both halves; receivers verify both copies against the actual post-commit epochs before any app data is decrypted.
  - **Safe Extensions PSK recipe**: the APQ-PSK and cross-party TwoMLS-PSK derive via `SafeExportSecret(component_id)` + `DeriveSecret(exporter, "psk_id"/"psk")` and import as `psk_type = application(3)` (components `0xFF01`/`0xFF02`); the A.3 injected secret stays an external PSK. Requires the germ-network/mls-rs `germ-shadow-safe-exporter` build branch (`safe_extensions` feature).
  - **Event-driven cross-party binding**: a commit re-binds the peer's group only when it has advanced since the last binding; three epoch watermarks make each `(group, epoch, component)` export happen at most once, as the consuming exporter requires.
  - Combiner key package v2 encloses the -02 §7 `APQKeyPackage` TLS payload.

  Documented extensions beyond -02: A.3 substitutes the injected KEM secret for the PQ updatePath as the PQ-PCS source; A.5 re-keys on the PQ groups alone, reconciling `pq_epoch` at the next A.3 bind.

  A security and functional review (wire/versioning, downgrade, crypto/PSK, fork, state machine) found no correctness or security defect; its hardening fixes are included. `session.rs` is split into a `session/` module directory (pure moves; no API change). The book chapters (psk-binding, group-rules, wire-format, cipher-suites) match the shipped recipe.
