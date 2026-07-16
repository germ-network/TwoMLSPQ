---
"@germ-network/two-mls-pq": patch
---

Retire "reconnect" from the session layer's vocabulary.

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
