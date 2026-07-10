# Header Encryption

> **Status: the symmetric steady-state layer is implemented**, with **two key
> families** — message-path frames sealed under the classical half (`HeaderKey`), PQ
> side-band frames under the PQ half (`HeaderKeyPQ`), each keyed by its own ratchet's
> epoch. Every rendezvous-channel frame leaves the library sealed; the host removes the
> seal with `open_incoming`. One piece remains design-only: the **first-frame envelope
> inside `initiate`** — the initiator's initial welcome is still enveloped host-side via
> the shipped `hpke_seal_to_key_package` / `TwoMlsPqInvitation::hpke_open` pair (see
> *Establishment walkthrough* and *Open questions*).

MLS PrivateMessage encrypts the message *content*, but its framing is plaintext:
`group_id`, `epoch`, `content_type`, and the entire `authenticated_data` field travel
in the clear (RFC 9420 §6.3). TwoMLSPQ's own frame layer adds a plaintext tag byte on
top. This chapter specifies the outer encryption layer — *header encryption* — that
makes every outbound blob a single opaque ciphertext, following the scheme the
classical stack (multiMLS-Swift `TwoMLS`) already ships.

**Sequencing:** the wire-format rework (always-staple the send-group commit; one
message-frame shape; retagging) landed first — tag values below refer to the reworked
[Wire Format](./wire-format.md). Header encryption is applied on top of those frames;
its rules are per-*stream* (message path vs. PQ side-band), not per-tag.

**As shipped, in one paragraph.** `TwoMlsPqSession::encrypt`, `pending_outbound` (once
a recv group exists), `pq_take_pending_outbound`, and the `pq_*_begin` returns all emit
`[12-byte random nonce][ChaCha20-Poly1305 ct+tag]` over the whole frame. Message-path
frames key on `exportSecret("germ.network.twomlspq.headerKey.v1", group_id, 32)` on the
recv group's **classical** half at its current classical epoch; PQ side-band frames key
on `exportSecret("germ.network.twomlspq.headerKey.pq.v1", group_id, 32)` on the recv
group's **PQ** half at its current `pq_epoch` (the pre-A.4 `BOOTSTRAP_KP`, whose recv-PQ
group doesn't exist yet, falls back to the classical key). The receiver's
`open_incoming(blob) -> Option<OpenedFrame { kind, frame }>` trial-decrypts over both
per-epoch windows of its own send group's header keys (the classical window captured
beside the listen addresses; the PQ window captured at each `pq_epoch` advance; both
archived), returns the plaintext `frame` plus a routing `kind` (`Message` or
`PqSideBand { PqFrameKind }`), and the host routes `frame` to the existing plaintext
entry points — which also transparently open a sealed blob passed straight through, so
a host may skip `open_incoming` for the message path. The initiator's initial welcome
(invitation channel, no symmetric key yet) is the one frame not sealed here.

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

- The AEAD is a **single configured choice for the whole header layer**
  (`providers::HEADER_AEAD_SUITE`, ChaCha20-Poly1305 today), *not* inherited from the
  group whose exporter produced the key. Both families — message-path (classical
  exporter) and PQ side-band (PQ exporter) — seal with this one AEAD; the two-family
  split only chooses which group half derives the key. The key length
  (`header_key_len` = the AEAD's `aead_key_size`) and the nonce length
  (`aead_nonce_size`) are both read from the chosen suite, so swapping the header AEAD
  is a one-line change with nothing downstream assuming a specific cipher or size.
  Empty AAD; the plaintext is the entire existing frame (tag byte included), unchanged.
  - *Why not the group's AEAD:* the PQ suite's AEAD is AES-128-GCM (128-bit key);
    sealing the side-band with the classical ChaCha20-Poly1305 (256-bit key) gives it
    the stronger primitive and better post-quantum headroom — matching the group's own
    AEAD there would be a downgrade. The header AEAD is a build-level constant (both
    parties must agree; there is no negotiation), so a per-deployment change is a
    recompile, and runtime negotiation would be a separate protocol addition.
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
halves and rotates with `pq_epoch`, so each header key tracks the clock of the frames
it protects. This matters because the classical and PQ ratchets run on **independent,
asynchronous cadences** — the classical ratchet is continuous (every message), the PQ
side-band is a slower turn-based exchange, and the two synchronize only at the A.3 bind
(partial PQ commit + full classical commit importing the exported PSK). A side-band
frame keyed by the classical epoch would have its outer-seal availability governed by
classical message volume: a frame in flight could be overtaken by classical epoch
advances unrelated to it and, past the classical retention window, become unopenable.
Keying it by `pq_epoch` decouples it — its small window covers any lag regardless of
classical traffic (see the *rejected simplification* below).

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

> **Rejected simplification — one classical family for both streams.** An earlier cut
> sealed the side-band under the classical family too (the classical recv-group key is
> always available post-establishment, so it needs no second window or pre-A.4
> fallback). It was replaced because it couples the side-band's outer-seal availability
> to the *async* classical cadence: a side-band frame in flight can be overtaken by
> classical epoch advances driven by unrelated message traffic and, once they exceed
> the classical retention window, become unopenable — a delivery-robustness dependency
> that shouldn't exist. The two-family scheme removes it (a side-band frame is keyed by
> `pq_epoch`, which only PQ commits advance) and additionally gives immediate side-band
> PCS at A.5. The one thing the classical family had going for it — a *hybrid* header
> key even for side-band frames — is the accepted trade-off below.

### Send rule

- **Message-path frames** (0x01 standalone welcomes and 0x03 message frames —
  `encrypt`'s output, welcome-or-commit staple included): seal under
  `HeaderKey(recv_group, current classical epoch)`.
- **PQ side-band frames** (0x05–0x11): seal under `HeaderKeyPQ(recv_group,
  current pq_epoch)` — the opposite PQ group at its `pq_epoch`. This covers both the
  responder frames surfaced by `pq_take_pending_outbound` (0x07, 0x0D, 0x11) **and
  the initiator frames returned directly by `pq_ratchet_begin` (0x05),
  `pq_bootstrap_begin` (0x0B), and `pq_rekey_begin` (0x0F)** — the latter are easy
  to miss because they bypass `EncryptResult`; leaving them plaintext would
  fingerprint every PQ exchange by its first frame. No chicken-and-egg blocks it: the
  A.3 BIND commits the *initiator's* send-PQ but seals under the never-advanced
  receive-PQ; REKEY_UPD carries only a proposal; each REKEY_COMMIT seals under the
  confirmed epoch.
  - *Pre-A.4 fallback:* the one side-band frame whose recv-PQ group doesn't exist yet
    is the initiator's `BOOTSTRAP_KP` — its recv-PQ (Group_B.pq) is the very group the
    bootstrap creates. `seal_side_band` falls back to the **classical** `HeaderKey`
    for exactly that frame (a one-time establishment frame whose cadence is
    irrelevant, and the classical recv group always exists); the receiver opens it
    from its classical window via the dual-window `try_open`. Every steady-state
    side-band frame has its recv-PQ live and uses `HeaderKeyPQ`.
- Both keys are recomputed live (exporters work at the current epoch, which is
  exactly where the recv group sits); no send-side storage.
- **Pre-establishment (initiator between `initiate` and the return welcome):** no
  frame is sealed here because there is no recv group and thus no symmetric key. The
  operations that could otherwise emit a frame are blocked: `prepare_to_encrypt`
  needs the recv group to stage its proposal, rotation is additionally gated on
  `peer_confirmed` (both from the wire-format rework), and `pq_ratchet_begin` now
  returns `SessionNotEstablished` without a recv group. The one thing the initiator
  *does* emit — its initial welcome — travels the invitation channel (below).
- The acceptor always has a recv group from `accept()` onward, so *every* acceptor
  frame — including the first, whose staple slot carries `APQWelcome_B` — is
  symmetric, sealed under `HeaderKey(Group_A, join epoch)`. The initiator opens it
  from its window: see below.
- **Seal timing:** frames are sealed **on exit** — at the boundary where bytes leave
  the library — so the acceptor's welcome rides raw in the message frame's staple
  slot and the whole frame is sealed once (no double sealing). `pending_outbound`
  seals only when a recv group exists, so the initiator's plaintext initial welcome
  passes through and the acceptor's return welcome is sealed.

### Receive rule

There are **two receive windows**, one per family (the peer seals under *their* recv
group, which is my send group):

- **`recv_header_keys`** — `HeaderKey(send_group, e)` for each retained *classical*
  epoch of my send group. Captured live-at-epoch beside the rendezvous address in
  `record_listen_rendezvous` (exporters can't be derived retroactively), same call
  sites (group creation, the A.2/rotation commits in `prepare_to_encrypt`, the A.3
  bind, the `should_listen_on`/`archive` backstops), same retention (the send-group
  storage probe). So for the message path, **a frame that can still be routed can
  still be opened**: this window is exactly the rendezvous listen window.
- **`recv_header_keys_pq`** — `HeaderKeyPQ(send_group.pq, e)` for recent `pq_epoch`s of
  my send-PQ group. Captured by `record_pq_header_key` wherever the send-PQ group is
  created or its `pq_epoch` advances (`initiate` / `pq_bootstrap_respond` create it;
  `pq_ratchet_bind`, `pq_rekey_respond`, `pq_rekey_apply` advance it). This window has
  **no rendezvous coupling** — the PQ side-band keeps no routing addresses of its own
  (routing stays classical). Retention is a plain keep-newest `PQ_HEADER_WINDOW = 4`;
  the side-band is turn-based with one op in flight, so `pq_epoch` moves slowly and a
  few keys cover any lag regardless of classical traffic — which is the whole point
  (see *rejected simplification*).

`open_incoming(blob)` / the receivers' `open_or_raw` trial-AEAD-open against **both**
windows (classical first, then PQ), newest epoch first in each. A message frame
authenticates only under a classical key and a side-band frame only under a PQ key
(the pre-A.4 `BOOTSTRAP_KP` under classical), so the family that opens it corroborates
the inner tag; there is no ambiguity. Each trial is one ChaCha20-Poly1305 open — DoS
cost is bounded and linear in the combined (small) window. On success it classifies
the opened frame's leading tag into `OpenedFrameKind` (`Message` for 0x01/0x03,
`PqSideBand { PqFrameKind }` for 0x05–0x11) and returns `OpenedFrame { kind, frame }`;
the host routes `frame` by `kind`. On exhaustion it returns `Ok(None)` — the same
"unknown, drop it" signal the reconnect path assigns, which trial decryption makes
literal: an out-of-window frame and garbage are indistinguishable, by construction. An
opened-but-unrecognized tag is `DecryptionFailed`.

**Convenience:** `process_incoming` and the `pq_*` receivers transparently remove the
seal if present (`open_or_raw`), so a host may pass the sealed blob straight through
for the message path and skip the explicit `open_incoming` (it still needs
`open_incoming` to *route* side-band frames). An already-opened frame passes through —
it fails AEAD auth under every window key. This is a receiver convenience only; the
metadata-hiding property is a sender guarantee (every outbound frame is sealed), so
accepting an opened frame downgrades nothing an observer sees.

**Observability caveat:** desyncs that mls-rs would once have surfaced loudly can read
as a silent `None` here; a host tracking liveness should treat a run of `None`s on a
live session as a reconnect signal.

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
   `pending_outbound` returns the plaintext `APQWelcome_A`. **As shipped, the
   initiator's initial welcome is enveloped host-side** with the exported
   `hpke_seal_to_key_package` (sealed to Bob's KP′), because it travels the
   invitation channel and there is no symmetric key yet.
   *Refinement (deferred):* moving the envelope inside `initiate` — with an
   `app_payload` parameter so the host's app-layer welcome (the most linkable
   first-frame metadata) is sealed *with* the MLS welcome — is the parity change the
   classical stack has; it changes the published-KP consumption contract, so it is
   left as a follow-up (see *Open questions*).
2. **Bob's host** opens the envelope with `TwoMlsPqInvitation::hpke_open` (the
   invitation holds the KP′ private material), validates the app-layer welcome, and
   computes the spawn token over the **decrypted** frame — the token must be
   replay-stable across re-sends, and a re-sent envelope has a fresh HPKE ephemeral
   (different outer bytes, identical plaintext), so sealed bytes cannot key the
   forward table. Then `receive(welcome, their_kp, spawn_token)` joins.
3. **Bob `receive`/`accept`** — joins Group_A, builds Group_B classical; captures
   `HeaderKey(Group_B, e₀)` into his window. His send key is
   `HeaderKey(Group_A, join epoch)` — derivable immediately.
4. **Bob's first frame** — a message frame with `APQWelcome_B` in its staple slot,
   sealed under `HeaderKey(Group_A, e₀)`. Alice's window (from step 1) opens it; she
   joins Group_B; her send key becomes `HeaderKey(Group_B, current)`. Both directions
   are now symmetric, and every subsequent frame — A.2 rounds, rotation, A.4
   bootstrap (whose PQ Welcome rides a sealed side-band frame, no envelope of its
   own), A.3, A.5 — follows the steady-state rules.

Replays and re-sends: `forward_group_id(spawn_token)` remains a pure table lookup,
and the content-keyed `processed_welcome_group_id` resolves a re-delivered welcome
directly. A **spent single-use** invitation has lost the KP′ private material and can
no longer `hpke_open` a replayed envelope; hosts that need replay acknowledgment after
consumption use last-resort invitations. (This is an existing property of the §A.1
envelope.)

Direct `accept()` keeps its plaintext-welcome signature (a test/embedded entry point);
the normal path is `TwoMlsPqInvitation::receive`.

### Host routing and the API

The host used to route PQ side-band frames to `pq_*` entry points by the leading tag
byte, which header encryption hides. The wire boundary moved one step:

- **`open_incoming(blob) -> Option<OpenedFrame { kind, frame }>`** — the session
  method: one trial-decrypt pass over the receive window, returning the plaintext
  frame plus its `kind` (`OpenedFrameKind::Message` for 0x01/0x03,
  `PqSideBand { PqFrameKind }` for 0x05–0x11), or `None` if no window key opens it.
  The host routes `frame` by `kind` to `process_incoming` / `pq_ratchet_*` /
  `pq_rekey_*` / `pq_bootstrap_*`; those entry points keep their plaintext-frame
  signatures (and additionally auto-open a sealed blob, per the receive rule).
  `forwarded(spawn_token)` is untouched — it takes the token, not bytes.
- **Outbound is sealed inside the library** at every exit: `EncryptResult
  .cipher_text`, `pending_outbound()` (once a recv group exists),
  `pq_take_pending_outbound()`, and the direct returns of `pq_ratchet_begin` /
  `pq_bootstrap_begin` / `pq_rekey_begin`. The exported `hpke_seal_to_key_package` /
  `hpke_open` pair stays for the initiator's initial welcome and other stacks.
- **Archive**: both receive windows (`recv_header_keys`, `recv_header_keys_pq`) ride
  in the session archive as parallel `(epoch, key)` lists, entries validated to 32
  bytes on restore. `SESSION_ARCHIVE_VERSION` bumped to 4; pre-release, so old
  archives simply fail to decode and regenerate.
- **Contract**: `BINDING_CONTRACT_VERSION` bumped to 7 — the FFI gains
  `open_incoming` and the `OpenedFrame` / `OpenedFrameKind` types, and every
  outbound blob is now sealed.

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

## What shipped (implementation)

1. `providers.rs`: `classical_aead_suite()` beside `pq_envelope_suite()` (classical
   `CipherSuiteProvider` for `aead_seal`/`aead_open`/`random_bytes`).
2. `session.rs`: `header_key(group)` and `header_key_pq(pq_group)` beside
   `rendezvous_secret`; `SessionInner::seal` / `seal_side_band` (PQ-or-classical
   fallback) / `try_open` (both windows) / `open_or_raw`; `record_listen_rendezvous`
   captures the classical header key into `recv_header_keys`, and `record_pq_header_key`
   captures the PQ header key into `recv_header_keys_pq` at each `pq_epoch` advance
   (`initiate`, `pq_bootstrap_respond`, `pq_ratchet_bind`, `pq_rekey_respond`,
   `pq_rekey_apply`); seal at every outbound exit (`encrypt` / `pending_outbound`
   classical; the `pq_*_begin` returns and `pq_take_pending_outbound` via
   `seal_side_band`); `pq_ratchet_begin` guarded on the recv group; `open_incoming`
   with `OpenedFrameKind`; `process_incoming` and the `pq_*` receivers `open_or_raw`
   their input.
3. Archive: `recv_header_keys` and `recv_header_keys_pq` as `(epoch, key)` entries,
   32-byte validated on restore; `SESSION_ARCHIVE_VERSION` → 4,
   `BINDING_CONTRACT_VERSION` → 7 (unchanged by the PQ-family follow-up — no FFI shape
   change).
4. Tests: sealed frames carry no plaintext framing; cross-commit crossing; restored
   session opens an in-flight frame (message *and* side-band); garbage → `None`;
   sealed side-band opens and classifies + full A.3/A.4/A.5 through sealed frames;
   the side-band survives classical churn that evicts the message window (proving the
   PQ family); the pre-A.4 `BOOTSTRAP_KP` opens via the classical fallback; initial
   welcome unsealed vs. return welcome sealed.

Not yet implemented (see *Open questions*): moving the initial-welcome envelope (with
`app_payload`) inside `initiate`.

## Open questions

1. **Initial-welcome envelope inside `initiate` (with `app_payload`).** The initial
   welcome is enveloped host-side today. Moving it into the library — sealing
   `[app_payload ∥ APQWelcome_A]` to Bob's KP′ so the host's app-layer welcome
   (identity introduction, signed keys) rides inside the envelope — matches the
   classical stack's parity and needs a new `open_initial` on the invitation. It
   changes the published-KP consumption contract, so it should ride the same release
   as its first real host adoption.
2. **Hybrid envelope for the very first frame?** The §A.1 envelope is PQ-only —
   the inverse of the classical stack's X25519-only envelope. A nested seal
   (classical HPKE inside the PQ envelope, both init keys are already in the
   published pair) would make first-frame *metadata* survive a break of either KEM,
   for ~one X25519 op and ~100 bytes. The payload's own secrecy is already hybrid at
   the MLS layer; this is purely about Welcome metadata (KeyPackageRefs, suites,
   and the app payload now inside the envelope). Recommended, but it changes the
   published-KP consumption contract, so it should ride the same release as the
   envelope's first real adoption.
3. **Hybridizing the PQ groups** (the side-band trade-off): `HeaderKeyPQ` is
   ML-KEM-only, so it falls to an ML-KEM-only break where the classical `HeaderKey`
   would not — accepted, because an ML-KEM break already exposes the side-band's
   *content*, leaving only its metadata. A reverse (classical→PQ) PSK injection at the
   A.3/A.5 PQ commits would give the PQ groups' key schedules — and hence
   `HeaderKeyPQ` — classical cover, closing the one non-hybrid derivation. It is
   protocol-level (changes commit contents on both sides), so it belongs to a Combiner
   revision, not the header layer.
4. **Receive-side AD checking** (from the stapling assessment): should the PARTIAL
   handler verify the app message's AD against the stapled proposal's digest, and
   the rotation handler against the commit, restoring the classical stack's
   peer-level mix-and-match checks? Orthogonal to header encryption but adjacent —
   deciding it in the same review avoids re-opening the frame contract twice.
5. **Padding.** Out of scope here, but the uniform blob makes a future
   fixed-bucket padding scheme purely additive.
