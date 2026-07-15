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

## Two slots, because A.4 is concurrent

A.3 and A.5 are mutually exclusive — every entry point gates on `pq_inflight`, so one
round is open at a time and one slot serves both. A.4 does NOT gate on it and runs
alongside them, so it gets its own: `pq_bootstrap_respond` parks its bind AND takes the
turn, so the responder opening an A.3 round (its move, legitimately) shared the slot with
an unfinished A.4 and evicted it. A BootstrapBind is irreplaceable — the peer's deferred
PQ half is built from it and nothing else can re-emit it — so eviction stranded
establishment for good, in a normal flow.

`pq_pending_outbound` therefore returns a LIST: zero, one, or two frames, since a
bootstrap can be in flight while a ratchet round is open. Send them all; they are
independent. Bootstrap comes first, but the receiver's two doors are order-independent.

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
