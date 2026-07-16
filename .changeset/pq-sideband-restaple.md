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
had the shape — the book's claim that the Germ frames *enclose* the draft-02 wire shapes
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
spent — no classical reconnect repairs that). Folding *was* the evidence: the peer builds its
`Upd(self)` in its recv group, which IS our send group, so the offer is bound to our epoch and
`validate_offered_update` refuses a stale one against the live group. A proposal-less commit
has no fold to infer it from, so the watermark is now explicit (`peer_applied_send_epoch`,
read off every inbound frame's proposal, archived).

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

| Band | Range | Used |
|------|-------|------|
| Message path | 0x01-0x05 | 3 / 3 — full, and closed by design: welcome, message frame, and the APQPrivateMessage staple form |
| A.1 establishment | 0x07-0x11 | 2 / 6 — the hybrid nested envelope would land in the room |
| PQ side-band | 0x13-0x31 | 6 / 16 — lifecycle order: bootstrap, ratchet, re-key; no binds (a bind is the staple) |

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
bytes) rather than a range test — a reserved byte is *in* 0x11-0x2F, so "in range iff
classified" would wave through a reserve that quietly started routing.

`frames::tests::BANDS` is the record, and the book's `wire-format.md` table is its prose
half.

**This is a wire cut** (`BINDING_CONTRACT_VERSION` 19; 17 was burned by an interim build of
this same work). Hosts classify via `pq_frame_kind` and never match raw bytes, so no host
code changes beyond the deleted bind cases; stale frames from older builds fail loudly in
the decoders, as they already did across the previous renumber.
