---
"@germ-network/abstract-two-mls": minor
---

Rename the `.reconnect` disposition to `.reestablish`.

There is no reconnect at this layer: the emitting backend (TwoMLSPQ) has no rejoin
path, the classical backend that HAS one is disarmed on every session driven through
this abstraction, and the recovery the disposition actually calls for is
out-of-session — tear the session down and re-exchange. The old name was inherited
from a wire-frame type in the deprecated classical backend and implied an in-session
capability that does not exist. `.reestablish` matches both the crate's own wording
("route to re-establishment") and what hosts actually do.

Mapped codes are unchanged: `.epochDesync` and `.bindDischargeFailed`. The
"reconnect signal" prose for `.unopenableFrame` runs is now the "re-establish
signal" (including the error's `detail` string).

**App adoption note** (add to the 0.5.0 worklist): `FrameExit.swift:80`'s pattern
label changes `.reconnect` → `.reestablish`; the app's `sessionRecovery` vocabulary
is already honest and keeps its name. The generated binding retains the crate's old
wording until the next binding regeneration picks up the paired TwoMLSPQ PR
(germ-network/TwoMLSPQ#74) — prose-only skew, no behavioral difference.
