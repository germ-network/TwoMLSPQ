---
"@germ-network/two-mls-pq": minor
---

**DO NOT RELEASE YET — one open defect, see "Slot collision" at the bottom.**

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

## Slot collision (open — needs a protocol decision before release)

A.4 and A.3 are separate flows sharing ONE retained slot, so retention lets an A.3
round evict an in-flight A.4's frame — and a bootstrap frame is irreplaceable, so
losing it strands establishment for good. Take-once had no such collision: the slot
only ever held responder frames and the host drained it immediately.

Reachable in a NORMAL flow, not just a misbehaving one:

1. Alice `pq_bootstrap_begin` → KP'.
2. Bob `pq_bootstrap_respond` → parks the BootstrapBind **and takes the turn**.
3. Bob, holding the turn, opens an A.3 round — legitimate; it is his move.
4. The EK replaces the BootstrapBind. Alice can never complete A.4
   (`pq_bootstrap_apply` fails `Mls`).

The existing suite cannot see this: `establish_full` drives A.4 with
`pq_take_pending_outbound`, which empties the slot, so no test drives A.4 through
the peek this change asks hosts to adopt.

The root cause is that a TERMINAL frame has no retirement rule — its sender never
learns it landed, so it lingers and collides. Three ways out, all protocol calls:

- **Give A.4 its own retained slot.** Honest (A.4 *is* a distinct one-time flow) and
  it rides the archive like the existing one. Costs an API shape: two frames can then
  be pending at once, so the peek must return a list rather than an `Option`.
- **Retire a terminal frame on positive evidence the peer advanced** (e.g. their
  post-bind epoch), rather than letting it linger. Fixes the general case, including
  the initiator's lingering bind noted below.
- **Order A.4 strictly before A.3.** Simplest, but it is a real protocol constraint
  and the guard cannot live on `pq_ratchet_begin`: A.3 needs only the initiator's
  send-PQ and the responder's recv-PQ, both of which predate A.4 (verified — eight
  tests ratchet before A.4 today).
