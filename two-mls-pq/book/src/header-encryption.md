# Header Encryption (design)

> **Status: design for review — not implemented.** Nothing in this chapter is on the
> wire today. The only shipped piece is the `hpke_seal_to_key_package` /
> `TwoMlsPqInvitation::hpke_open` pair (the §A.1 envelope primitive), which currently
> has no caller in either this crate or AbstractTwoMLS.

MLS PrivateMessage encrypts the message *content*, but its framing is plaintext:
`group_id`, `epoch`, `content_type`, and the entire `authenticated_data` field travel
in the clear (RFC 9420 §6.3). TwoMLSPQ's own frame layer adds a plaintext tag byte on
top. This chapter specifies an outer encryption layer — *header encryption* — that
makes every outbound blob a single opaque ciphertext, following the scheme the
classical stack (multiMLS-Swift `TwoMLS`) already ships.

**Sequencing:** the wire-format rework (always-staple the send-group commit; one
message-frame shape; retagging) **landed first** — tag values below refer to the
reworked [Wire Format](./wire-format.md). Header encryption applies on top of those
frames; its rules are per-*stream* (message path vs. PQ side-band), not per-tag.

## What leaks today

| Field | Where | What an observer learns |
|---|---|---|
| frame tag (`0x01`–`0x11`) | first byte of every tagged frame | frame kind: establishment vs. rotation vs. PQ side-band activity (bootstrap, ratchet, re-key) |
| `group_id` | every `MLSMessage` | a stable per-direction session identifier — links every message of a direction across epochs, undoing the per-epoch rendezvous rotation for anyone who stores ciphertexts |
| `epoch` | every `MLSMessage` | commit cadence, message ordering, session age |
| `content_type` | every PrivateMessage | application vs. proposal vs. commit |
| `authenticated_data` | every PrivateMessage | the 32-byte per-round proposal hash; on rotation frames and A.5 `Upd'` proposals, the announced `ClientId` |
| Welcome plaintext | APQWelcome (both halves) | cipher suites, `KeyPackageRef`s of the joiner — linkable to published key packages |
| MLS version / wire format | every `MLSMessage` | protocol fingerprint |

The rendezvous scheme already unlinks *routing* across epochs; header encryption
extends that to the ciphertexts themselves, so a stored frame is one uniform blob
with no protocol fingerprint, no session identifier, and no visible side-band
activity.

## The classical precedent, verified

What multiMLS-Swift `TwoMLS` actually does (verified against
`SendGroup.headerEncrypt`, `ReceiveGroup.headerDecrypt`, `prepareCommit`,
`processNewEpoch`, `expectWelcome`, and the invitation flow):

- **Steady state — the header key is an exporter of the *opposite* group, at that
  group's current epoch.** Frames I send on my send group are sealed with
  `ChaChaPoly` under `exportSecret(label = "germ.network.pairwiseKeyExport",
  context = group_id, len = 32)` evaluated on **my receive group** (= the peer's
  send group) at the newest epoch I have applied there. It is *not* derived from the
  previous epoch of the sending group.
- **Rotation points.** When I commit my own send group (epoch `n → n+1`) I export
  its new header key and file it in my *receive window*, keyed as "the key the peer
  will seal under once they process this commit". When I apply the peer's commit to
  my receive group (epoch `m → m+1`) I re-derive my *send* header key from the new
  epoch. The two groups alternate commits, so the header key protecting each
  direction always comes from the freshest secret both parties provably share.
- **Why the opposite group:** the frame that *carries* a commit for epoch `n+1` is
  itself encrypted at epoch `n+1` — a receiver cannot derive anything from `n+1`'s
  secrets before decrypting that very frame. The sender's receive group is the
  freshest state the receiver is guaranteed to already have. (The previous epoch
  `n` of the same group would also satisfy the availability constraint, but it is
  strictly staler, and the cross-group derivation additionally ties the two
  directions' metadata protection together, complementing the cross-party PSK.)
- **Receive side: trial decryption over a bounded window.** The receiver keeps up to
  3 epochs of expected header keys (`EpochHistory`, `maxPrevousEpochs`) plus the
  establishment-phase keys, and tries each against an incoming blob. There is no key
  id or epoch hint on the wire; the blob is fully oblivious. Frames that cross a
  commit in flight decrypt via the older window entries.
- **Establishment, first round (no shared group yet):** every initiator frame is
  HPKE-sealed (`Curve25519_SHA256_ChachaPoly`) to the **init key of the recipient's
  KeyPackage** (`getHpkeInitKey` — the Welcome-encryption key, *not* the leaf-node
  encryption key), with `info` = recipient ClientId. The sealed plaintext is the
  *composed* first frame: the app-layer welcome (`AppWelcome.Combined`) together
  with the MLS welcome — the app payload is a parameter of group creation, so the
  library envelopes the whole thing.
- **Establishment, second round:** the joiner's return frame (carrying Group_B's
  welcome) is sealed under the symmetric exporter of Group_A at the epoch the joiner
  joined; the initiator pre-computed that key at creation and holds it in
  `reconnectArchive` until the return frame arrives.

## Relation to the classical stapling construction

Classical TwoMLS staples the commit into the AD of a proposal and that proposal into
the AD of the app message, then header-encrypts the outermost message. Assessment:

- What it bought: no bespoke frame format (everything on the wire is one
  `MLSMessage`), atomic delivery, and mix-and-match resistance — the AD chain binds
  app message ↔ proposal ↔ commit, and the receiver *checks* each link (the
  proposal's AD must equal the commit bytes before the commit is applied; the app
  message's AD must hash to the proposal digest). Because AD is covered by
  PrivateMessage authentication, each link is authenticated once its carrier is
  processed, and MLS independently authenticates the commit itself during
  processing — nothing unauthenticated is ever *acted on*; "unchecked" refers only
  to the parse that extracts the nested bytes.
- What it costs: `authenticated_data` is **plaintext** in PrivateMessage, so the
  stapled messages are wire-visible metadata — stapling only works *because* the
  header layer hides it; parsing is a try-cascade over unauthenticated nested
  structure (`uncheckedAuthData`) with genuinely odd control flow; and the commit
  must still be applied before the app message riding with it can be decrypted, so a
  frame that fails late leaves the group advanced (the rejoin machinery exists
  largely to recover from this).
- TwoMLSPQ replaced stapling with explicit length-prefixed tagged frames. The
  sender still writes the 32-byte proposal hash into the app message's AD, but —
  unlike the Swift stack — nothing on the receive side of this crate reads it back:
  the message-frame handler applies the commit and surfaces the stapled proposal's digest
  without comparing either against the app message's AD, and the AD is not exposed
  across the FFI. Component-binding today rests on the digest CommProtocol binds
  *inside the encrypted app payload*, not on the AD. Header encryption incidentally
  restores frame-level splice resistance against network adversaries — the outer
  AEAD covers all sections of a frame as one unit — but peer-level mix-and-match
  hardening (checking the AD on receive, as classical does) remains a separate,
  worthwhile fix, orthogonal to this design.
- **Verdict: keep the frame format; do not import stapling.** Tagged frames keep
  the atomicity, parse cleanly, and their one real downside — a recognizable
  plaintext container — is exactly what header encryption removes.

## Design

### Sealed frame

Every blob that leaves the library is one of:

```
SealedFrame   = [12-byte random nonce][AEAD ct+tag]   ; steady state (symmetric)
EnvelopeFrame = [kem_output][AEAD ct+tag]             ; establishment only (HPKE)
```

- The AEAD is the **classical half's suite AEAD** (ChaCha20-Poly1305 for the pinned
  `0x0003`), invoked through the classical `CipherSuiteProvider` — cipher agility
  follows the pinned suite, consistent with the suite-binding work. Empty AAD. The
  plaintext is the entire existing frame (tag byte included), unchanged.
- The HPKE envelope is the shipped §A.1 primitive: `hpke_seal` under the
  `0xFDEA` suite to the **PQ init key in the recipient's published KP′**, `info` =
  recipient ClientId. The two forms carry no discriminator; they never share a
  channel (envelopes travel only on the invitation channel, symmetric frames only
  on rendezvous addresses), so the receiver always knows which opener to use.
- No version byte, tag, key id, or epoch hint outside the encryption. A sealed frame
  is indistinguishable from random to anyone without the session's keys.

### Key schedule

Two key families, one per stream — the **message path** keys from the classical
halves and rotates with the classical epoch; the **PQ side-band** keys from the PQ
halves and rotates with `pq_epoch`, so PQ operations stay aligned with the state
machine their frames advance:

```
HeaderKey(G, e)   = exportSecret(label = "germ.network.twomlspq.headerKey.v1",
                                 context = group_id(G.classical),
                                 len = 32)  on G's classical half at epoch e

HeaderKeyPQ(G, e) = exportSecret(label = "germ.network.twomlspq.headerKey.pq.v1",
                                 context = group_id(G.pq),
                                 len = 32)  on G's PQ half at pq_epoch e
```

- **New labels**, distinct from each other (insurance against any group-id
  coincidence), from the classical stack's (`germ.network.pairwiseKeyExport`), the
  rendezvous exporter, and the PSK exporter — none of the derivations may collide.
- **Message-path keys are hybrid.** Group_A's classical key schedule absorbs the
  ML-KEM-derived APQ-PSK at creation (and again at every A.3 bind). Group_B is
  created classical-only pre-A.4, but its key schedule absorbs the **cross-party
  TwoMLS-PSK exported from Group_A's classical half** — whose epoch secrets are
  already ML-KEM-seeded — so Group_B's hybridness (and hence its header keys') is
  *transitive* through that PSK until its own PQ half lands at the A.4 bootstrap.
  Either way, a quantum adversary who breaks X25519 alone cannot reconstruct the
  epoch secrets the exporters draw from.
- **Side-band keys are PQ-only — a deliberate, consistent failure domain.** No
  classical entropy ever enters the PQ groups (the A.1/A.3/A.5 PSKs are all
  ML-KEM-derived or PQ↔PQ), so `HeaderKeyPQ` lacks the classical half's hybrid
  cover. An adversary who breaks ML-KEM already breaks the PQ groups those frames
  service; the marginal loss is side-band *metadata* (PQ group ids, epochs,
  activity). The protocol-level remedy — a reverse (classical→PQ) PSK injection at
  A.3/A.5 commits, hybridizing the PQ groups' own key schedules — is noted as an
  open question, out of scope for the header layer.
- **Rotation.** Message-path keys refresh whenever the classical epoch advances
  (A.2 ratchet, rotation, A.3 bind). Side-band keys refresh whenever `pq_epoch`
  advances — so an A.5 re-key *immediately* rotates the keys protecting subsequent
  side-band metadata (side-band PCS), rather than waiting for the next bind; its
  effect reaches the *message-path* keys at the next A.3 bind, as elsewhere.
- A direction that never commits keeps one header key indefinitely; with 12-byte
  random nonces the birthday margin (~2⁴⁸ frames per key) is far beyond any
  realistic per-epoch volume, so no mid-epoch rotation is needed.

### Send rule

- **Message-path frames** (0x01 standalone welcomes and 0x03 message frames —
  `encrypt`'s output, welcome-or-commit staple included): seal under
  `HeaderKey(recv_group, current classical epoch)`.
- **PQ side-band frames** (0x05–0x11): seal under `HeaderKeyPQ(recv_group,
  current pq_epoch)` — the *opposite PQ group* (my receive-PQ = the peer's
  send-PQ), keeping side-band protection aligned with the PQ epoch. This covers
  both the responder frames surfaced by `pq_take_pending_outbound` (0x07, 0x0D,
  0x11) **and the initiator frames returned directly by `pq_ratchet_begin`
  (0x05), `pq_bootstrap_begin` (0x0B), and `pq_rekey_begin` (0x0F)** — the latter
  are easy to miss because they bypass `EncryptResult`; leaving them plaintext
  would fingerprint every PQ exchange by its first frame.
  - *No chicken-and-egg anywhere in the side-band:* the A.3 BIND carries a PQ
    commit for the *initiator's send-PQ* but seals under the *receive-PQ*
    exporter, which that exchange never advances; REKEY_UPD carries only a
    proposal; the responder's REKEY_COMMIT advances its *own* send-PQ, not the
    sealing group; and the initiator's final REKEY_COMMIT seals under the epoch
    the responder's Commit' just confirmed on both sides.
  - *Pre-A.4 fallback:* before the bootstrap completes, only one shared PQ group
    exists (Group_A.pq) — the initiator's BOOTSTRAP_KP (0x0B, and any resend)
    seals under `HeaderKeyPQ(Group_A.pq)`, my own *send*-PQ group in that
    direction. The turn-based side-band (one in-flight op) bounds how long the
    fallback lives.
- Both keys are recomputed live (exporters work at the current epoch, which is
  exactly where the recv group sits); no send-side storage.
- **Pre-establishment (initiator between `initiate` and the return welcome):** the
  only permitted outbound is the enveloped first frame (below). Operations that can
  emit other frames without a recv group today — `prepare_to_encrypt(Some(id))`
  (rotation) and `pq_ratchet_begin` currently have no recv-group guard — **must be
  guarded to return `SessionNotEstablished` pre-establishment**: there is no
  symmetric key to seal them under, and their semantics before the peer has even
  joined are dubious anyway. (The alternative — retaining the peer's KP′ on the
  session and enveloping arbitrary pre-establishment frames — buys nothing the app
  needs and complicates the invitation replay story.)
- The acceptor always has a recv group from `accept()` onward, so *every* acceptor
  frame — including the first, whose staple slot carries `APQWelcome_B` — is
  symmetric, sealed under `HeaderKey(Group_A, join epoch)`. The initiator can open
  it: see below.
- **Seal timing:** symmetric frames are sealed **on exit** — at the boundary where
  bytes leave the library — so the acceptor's welcome rides raw in the message
  frame's staple slot and the whole frame is sealed once (no double sealing). The
  initiator's first frame is the one sealed-at-rest value (enveloped when composed,
  stored sealed, `pending_outbound` returns it as-is).

### Receive rule

Maintain two **receive windows**, one per key family — because the peer seals under
*their* recv groups, which are my send groups:

- **Message-path window**: `HeaderKey(send_group, e)` for each retained recent
  classical epoch `e` of my own send group. Capture is live-at-epoch, exactly like
  `listen_rendezvous` (exporters cannot be derived retroactively), and at the same
  call sites: extend `record_listen_rendezvous` to capture
  `(epoch, rendezvous_addr, header_key)` together — group creation, the
  A.2/rotation commits in `prepare_to_encrypt`, the A.3 bind, and the
  `should_listen_on`/`archive` backstops already enumerate every classical
  send-epoch advance.
- **Side-band window**: `HeaderKeyPQ(send_group, e)` for recent `pq_epoch`s of my
  own send-PQ group, captured at every `pq_epoch` advance — bootstrap create/join,
  the A.3 bind's PQ commit, the A.5 respond/apply commits. Two entries per PQ
  group suffice (the side-band is turn-based with one in-flight op). Plus, until
  the A.4 bootstrap turn completes, the pre-A.4 fallback candidate:
  `HeaderKeyPQ(recv-PQ)` — the shared Group_A.pq — under which the peer's
  BOOTSTRAP_KP (and any resend that crosses the bootstrap reply) arrives.

Retention: header keys are session-owned 32-byte secrets with no mls-rs dependency,
so the window is a session constant. **Ship it ledger-sized
(`SEND_PSK_WINDOW = 8`)** rather than tied to mls-rs's epoch retention (currently
4): the peer seals under my send group's epoch *as they last applied it* — exactly
the lag the PSK ledger exists to absorb — and 8 keys cost 256 bytes. The routing
window (which does follow mls-rs retention) stays the effective delivery bound
today, giving the invariant:

> **A frame that can still be routed can still be opened** — the header window is a
> superset of the rendezvous listen window, and hosts with looser-than-per-epoch
> delivery get the full ledger-sized tolerance instead of a silent gap.

Opening an incoming blob = trial AEAD-open against both windows, newest first (the
common case is the newest or second-newest message-path key; each trial is one
ChaCha20-Poly1305 open — DoS cost is bounded and linear in the combined window).
**Which key family opens the blob doubles as the routing signal**: a side-band key
implies a PQ side-band frame, a message-path key implies `process_incoming`
territory — corroborated by the inner tag byte. On success, dispatch the plaintext
frame exactly as today. On exhaustion return `Ok(None)` — the same "unknown epoch"
semantics the planned reconnect path assigns, which trial decryption makes
literal: an out-of-window frame and garbage are indistinguishable, by
construction. **Observability caveat:** desyncs that today fail loudly
(`DecryptionFailed` from mls-rs) become silent `None`s at this layer; the
implementation should count trial-decrypt exhaustions (a debug counter or log
hook), or hosts lose their main desync diagnostic.

Frames that cross a commit in flight are covered by the window: if the peer sealed
under my send group's epoch `n` while my `n → n+1` commit was in transit to them,
the `n` entry still opens it (the same reasoning as the `send_psk_ledger`, and the
reason the window must be ≥ 2 even in the happy path).

### Establishment walkthrough

Alice initiates; Bob accepts (send groups per the [Session
Lifecycle](./session-lifecycle.md); this inverts the §A.1 diagram's roles, matching
the crate's constructor names).

1. **Alice `initiate`** — builds Group_A; captures `HeaderKey(Group_A, e₀)` into her
   receive window (piggybacked on the existing `record_listen_rendezvous` call).
   `initiate` gains an `app_payload: Option<Vec<u8>>` parameter (mirroring the
   classical stack, where the app welcome is a group-creation parameter):
   `pending_outbound` returns **one envelope over the composed first frame**
   `[app_payload ∥ APQWelcome_A]`, sealed to Bob's KP′. Without this, the host's
   app-layer welcome — the most linkable first-frame metadata (identity
   introduction, signed keys) — would ride outside the envelope, or the host would
   have to keep sealing the composed frame itself, making the internal envelope
   redundant.
2. **Bob's host calls `TwoMlsPqInvitation::open_initial(blob)`** — a new,
   state-free decrypt-only method (the envelope opener, replacing raw `hpke_open`
   in the main path): returns `{ app_payload, welcome }`. The host validates the
   app-layer welcome and computes the spawn token over the **decrypted** frame —
   the token must be replay-stable across *re-sends*, and a re-sent envelope has a
   fresh HPKE ephemeral (different outer bytes, identical plaintext), so sealed
   bytes cannot key the forward table. Then `receive(welcome, their_kp,
   spawn_token)` proceeds unchanged on plaintext, preserving the existing contract
   that the app decides *before* the library joins.
3. **Bob `receive`/`accept`** — joins Group_A, builds Group_B classical; captures
   `HeaderKey(Group_B, e₀)` into his window. His send key is
   `HeaderKey(Group_A, join epoch)` — derivable immediately.
4. **Bob's first frame** — a message frame with `APQWelcome_B` in its staple slot,
   sealed under
   `HeaderKey(Group_A, e₀)`. Alice's window (from step 1) opens it; she joins
   Group_B; her send key becomes `HeaderKey(Group_B, current)`. Both directions are
   now symmetric, and every subsequent frame — A.2 rounds, rotation, A.4 bootstrap
   (whose PQ Welcome now needs no envelope of its own), A.3, A.5 — follows the
   steady-state rules. Side-band keying starts on the same schedule: Group_A.pq is
   shared from step 3, carrying the bootstrap exchange (with the pre-A.4 fallback
   for BOOTSTRAP_KP), and Group_B.pq keys join the rotation once the bootstrap
   lands it.

Replays and re-sends: `forward_group_id(spawn_token)` remains a pure table lookup.
A **last-resort** invitation can always `open_initial` a replayed or re-sent first
frame, recompute the token, and forward. A **spent single-use** invitation has lost
the KP′ private material, cannot open, cannot compute the token — its replays are
dropped as undecryptable rather than forwarded. Hosts that need replay
acknowledgment after consumption must use last-resort invitations. (This is an
existing property of the §A.1 envelope, now explicit.)

Direct `accept()` keeps its plaintext-welcome signature and becomes a test/embedded
entry point: callers holding a sealed envelope must go through an invitation
(`open_initial` needs the KP′ private material, which only invitations hold).

### Host routing and the API

Today the host routes PQ side-band frames to `pq_*` entry points by the leading tag
byte, which header encryption hides. The wire boundary therefore moves one step:

- **`open_incoming(blob) -> OpenedFrame { kind, frame }`** — new session method: one
  trial-decrypt pass over both receive windows, returning the plaintext frame plus
  its kind. `kind` must classify the **full** tag set — standalone welcomes (0x01),
  message frames (0x03), and PQ side-band (0x05–0x11) — so the host can route to
  `process_incoming` / `pq_ratchet_*` / `pq_rekey_*` / `pq_bootstrap_*` as today;
  those entry points keep their plaintext-frame signatures. The key family that
  opened the blob pre-sorts side-band from message-path; the inner tag byte refines
  it. (The shipped `pq_frame_kind` classifier covers the side-band subset, 0x05–0x11;
  this needs the superset, applied *after* opening.) `forwarded(spawn_token)` is
  untouched — it already takes the token, not bytes.
- **Outbound is sealed inside the library** at every exit: `EncryptResult
  .cipher_text`, `pending_outbound()`, `pq_take_pending_outbound()`, **and the
  direct returns of `pq_ratchet_begin` / `pq_bootstrap_begin` / `pq_rekey_begin`**.
  The exported `hpke_seal_to_key_package` / `hpke_open` pair stays (other stacks
  use the pattern), but the main path no longer requires the host to touch either.
- **Archive**: both receive windows ride in the session archive next to
  `listen_rendezvous` (parallel `(epoch, key)` lists; entries validated to 32
  bytes on restore, like rendezvous addresses). Pre-release, so the layout change
  simply invalidates old archives per the existing `SESSION_ARCHIVE_VERSION`
  policy. The initiator's pre-return-welcome state needs no extra machinery: her
  window entry was captured at `initiate`, and her sealed first frame is already
  the persisted `pending_outbound` value.

### What this layer does and does not provide

Provides: metadata confidentiality (everything in the table above), unlinkability of
stored ciphertexts across epochs and across the two directions, uniform-looking
blobs, hybrid confidentiality for the metadata layer, whole-frame splice resistance
against network adversaries, and — because the outer keys are symmetric and shared —
the same deniability shape as the inner protocol.

Does not provide: length or timing obfuscation (padding stays a host concern);
third-party-verifiable authenticity (either key-holder can forge the outer layer —
by design; the inner MLS authentication is the arbiter); sender anonymity against
the rendezvous server within an epoch (routing already reveals the channel); and
protection of the very first envelope against a break of ML-KEM alone — see open
questions.

Non-committing AEAD note: trial decryption with ChaCha20-Poly1305 across the window
is safe here because every candidate key is honestly derived and secret; the
partitioning-oracle failure mode requires attacker-chosen keys, which this scheme
never has.

## Implementation sketch

1. `providers.rs`: add `classical_envelope_suite()` beside `pq_envelope_suite()`
   (classical `CipherSuiteProvider` for `aead_seal`/`aead_open`/`random_bytes`).
2. `session.rs`: `header_key(group)` and `header_key_pq(group)` beside
   `rendezvous_secret`; `seal_frame` / `try_open_frame` (both windows); extend
   `record_listen_rendezvous` to capture the classical header key per epoch into a
   ledger-sized window, and add the mirror capture for `HeaderKeyPQ` at every
   `pq_epoch` advance (bootstrap create/join, A.3 bind, A.5 respond/apply); seal
   at every outbound exit (`encrypt`, `pending_outbound`,
   `pq_take_pending_outbound`, `pq_ratchet_begin`, `pq_bootstrap_begin`,
   `pq_rekey_begin` — side-band exits use the PQ key); guard `prepare_rotation`
   and `pq_ratchet_begin` on an established recv group; add `open_incoming` with
   the full-tag `FrameKind`; add `app_payload` to `initiate` and envelope the
   composed first frame.
3. `invitation.rs` / `key_packages.rs`: add `open_initial`; fix the two stale
   comments claiming the envelope uses the *classical* init key (it seals to and
   opens with the **PQ** half's — `hpke_seal_to_key_package`, `hpke_open`).
4. Archive: parallel `(epoch, header_key)` entries for both windows; 32-byte
   validation on restore.
5. Tests: cross-commit frame crossing (both directions); multi-commit lag to the
   window edge; window eviction; restored sessions opening in-flight frames;
   re-sent (fresh-ephemeral) first frames deduplicating via the token;
   replay-after-spent behavior; sealed `pq_*_begin` outputs under the PQ key
   (including BOOTSTRAP_KP under the pre-A.4 fallback, and rekey frames opening
   across the pq_epoch bump); pre-establishment rotation/ratchet guards; a fixture
   asserting sealed frames carry no plaintext MLS bytes.

## Open questions

1. **Hybrid envelope for the very first frame?** The §A.1 envelope is PQ-only —
   the inverse of the classical stack's X25519-only envelope. A nested seal
   (classical HPKE inside the PQ envelope, both init keys are already in the
   published pair) would make first-frame *metadata* survive a break of either KEM,
   for ~one X25519 op and ~100 bytes. The payload's own secrecy is already hybrid at
   the MLS layer; this is purely about Welcome metadata (KeyPackageRefs, suites,
   and the app payload now inside the envelope). Recommended, but it changes the
   published-KP consumption contract, so it should ride the same release as the
   envelope's first real adoption.
2. **Hybridizing the PQ groups** (from the side-band trade-off): a reverse
   (classical→PQ) PSK injection at the A.3/A.5 PQ commits would give the PQ
   groups' key schedules — and hence `HeaderKeyPQ` — classical cover, closing the
   one non-hybrid derivation in the design. Protocol-level (changes commit
   contents on both sides), so it belongs to a Combiner revision, not to header
   encryption.
3. **Receive-side AD checking** (from the stapling assessment): should the PARTIAL
   handler verify the app message's AD against the stapled proposal's digest, and
   the rotation handler against the commit, restoring the classical stack's
   peer-level mix-and-match checks? Orthogonal to header encryption but adjacent —
   deciding it in the same review avoids re-opening the frame contract twice.
4. **Padding.** Out of scope here, but the uniform blob makes a future
   fixed-bucket padding scheme purely additive.
