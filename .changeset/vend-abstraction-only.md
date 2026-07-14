---
"@germ-network/abstract-two-mls": minor
---

The library product vends only the `AbstractTwoMLS` module

The concrete UniFFI wrapper module (`TwoMLSPQ`) is no longer importable by
consumers (it still links transitively). UniFFI stamps its interface classes
`@unchecked Sendable` — memory-safe sharing with no ordering guarantees — so
exposing the module handed consumers a freely-shareable raw session handle
that bypassed the deliberately non-Sendable wrapper types. The abstraction's
public API is fully self-contained (verified: no binding type appears in any
public signature). Consequence: concrete backend errors (`TwoMlsPqError`)
are no longer catchable by type outside the package — catch generically
until the planned `SessionError` contract lands.
