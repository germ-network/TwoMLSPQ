---
"@germ-network/two-mls-pq": minor
---

Adopt the parallel A.4 bootstrap delivery in the Swift wrapper.

An initiator now ships its pre-committed KP′ as a §A.1 bootstrap envelope via the new
`PQRatchet.bootstrapEnvelope()` — alongside the establishment reply, so the acceptor can
answer A.4 one round trip sooner off the invitation channel it already reads.
`begin(.finishBootstrap)` stays valid and idempotent (both carry the same KP′, only the
outer framing differs). The acceptor's `decodeHeader` self-routes an
`OpenedInitial.bootstrapKp` to the owed session through the invitation's `bootstrapKpGroupId`
table and answers it in `forwarded` via `pqBootstrapRespond` (a `DuplicateSideBand`, when the
side-band won the race, is a benign no-op); the parked `Welcome'` rides the acceptor's next
`pendingSideBand` hand-out. No crate or contract change — the binding stays at contract 23.
