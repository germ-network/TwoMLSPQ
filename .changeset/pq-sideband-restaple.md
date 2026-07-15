---
"@germ-network/two-mls-pq": minor
---

Retain the PQ side-band's in-flight frame so a host can re-send it.

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

Both roles' frames are now retained in `pending_pq_outbound` (already archived,
so retention survives restore), replaced when this side produces the round's next
frame and cleared when its part in the round completes. This mirrors
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

**KP' → Welcome' → Bind.** The initiator joins the welcomed group, exports the cross-party
secret from its birth epoch, injects it into its own send-PQ with a pathless commit, and
chains the exported apq_psk into its classical half — `encode_bootstrap_bind`
(`[pq_commit][classical_commit][app]`), which is A.3's bind under its own tag.
The only difference from A.3 is where the secret comes from: a group exporter rather than a
KEM exchange.

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

`pq_bootstrap_apply` now means the RESPONDER's leg-4 apply and returns the stapled app, as
`pq_ratchet_apply` does; the initiator's join-and-bind is `pq_bootstrap_bind`. Like
`pq_ratchet_bind`, it refuses with `SessionNotReady` while a prepared-but-unsent classical
commit is staged — the bind's own commit would displace one that has never ridden a frame,
and the peer would then hit `EpochDesync` with nothing lost on the wire. Retriable: bind
after the round's `encrypt`. The exposure is sharper than A.3's, whose trigger the host asks
for: A.4's is an INBOUND welcome, so a host that prepares a round and then receives it before
its `encrypt` meets this without having done anything wrong. The old
`PQ_BOOTSTRAP_BIND` tag is renamed `PQ_BOOTSTRAP_WELCOME` — it has always carried a welcome,
and the bind name goes to the frame that earns it.

Two consequences worth knowing:

- **A.4 is no longer PQ-groups-only.** Its bind carries a classical commit, so it advances
  the initiator's epochs (1/1 → 2/2) where the old bootstrap advanced nothing. Post-A.4
  state is therefore asymmetric: the responder's send-PQ is born at A.4 and does not move
  until its own next bind. Classical never blocks on PQ — this defers freshness, not
  liveness.
- **A.4's terminal frame gets the FAST receipt.** Its classical commit means an ordinary peer
  message frame retires it, where the old PQ-only bootstrap could only be confirmed by a peer
  side-band frame.

## Terminal frames retire on the peer's application receipt

A round's last frame — A.3's bind, A.4's BootstrapBind, A.5's final Commit′ — has no reply,
so retention alone would re-send it forever, riding every message send.

The receipt was already on the wire and was being thrown away. We seal to the peer under
OUR recv group, so the peer seals to us under ITS recv group — which is our SEND group — at
the epoch it has actually applied. `recv_header_keys`' own doc said as much: "the peer seals
frames to me under my send group (their recv group) *as they last applied it*". `try_open`
iterated a map keyed by exactly that epoch and returned only the plaintext. It now returns
the epoch and the window that matched, and a terminal frame carries the `(family, epoch)`
that spends it.

Consequences worth knowing:

- **The A.3 bind retires fast.** It advances both epochs, so it stamps CLASSICAL and any
  ordinary message frame confirms it — and messages flow.
- **A.4 and A.5 retire on a peer SIDE-BAND frame**, because both are PQ-only. A.5 is
  deliberately so ("updatePath commits run on the PQ groups alone so the classical ratchet
  is never blocked behind a large ML-KEM updatePath"), and welding it to a classical round
  to get a faster receipt would reintroduce exactly that coupling. Accepted: the lingering
  is bounded by the host's PQ cadence, not by the protocol.
- **Unforgeable and free** — the key is derivable only inside the group at that epoch, and
  it already rides every frame. No new wire bytes, no protocol change, and nothing that
  could leak processing outcome.
- **Monotone**: old epochs are retained so a lagging peer still lands, so a frame opening at
  an older epoch is not evidence of regression — evidence only accrues.

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

| Band | Range | Used |
|------|-------|------|
| Message path | 0x01-0x03 | 2 / 2 — full, and closed by design: the message path has exactly one shape |
| A.1 establishment | 0x05-0x0F | 2 / 6 — the hybrid nested envelope would land in the room |
| PQ side-band | 0x11-0x2F | 8 / 16 — lifecycle order: bootstrap, ratchet, re-key |

Allocation order had left the side-band non-contiguous and silently falsified five
`0x05-0x11` range shorthands across the code and book; a range in prose should at least not
be a lie. Extending the protocol is no longer "take the next unused odd value" — it is
"append at the end of the right band, into the room it already reserves". Only a band that
FILLS moves anything below it.

The room is free in both directions that could have cost something. On the wire, header
encryption seals every blob, so a tag is never observed and a sparse space fingerprints
nothing. In the tests, `tag_space_holds` asserts density WITHIN a band and membership against
that band's bounds, so room at a band's end is legal while appending past the end still
fails. The reserve costs no enforcement — which is why the sizes are generous. They are
reserves, not predictions: only the message path's fullness is a design claim.

A band's reserved bytes are unallocated and MUST NOT classify, so the side-band's invariant
is set equality against the registry (`side_band_band_matches_the_classifier`, over all 256
bytes) rather than a range test — a reserved byte is *in* 0x11-0x2F, so "in range iff
classified" would wave through a reserve that quietly started routing.

`frames::tests::BANDS` is the record, and the book's `wire-format.md` table is its prose
half.

**This is a wire cut** (`BINDING_CONTRACT_VERSION` 17). Hosts classify via `pq_frame_kind`
and never match raw bytes, so no host code changes; stale frames from older builds fail
loudly in the decoders, as they already did across the previous renumber.
