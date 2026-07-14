---
"@germ-network/abstract-two-mls": minor
---

Sessions are no longer Sendable

`PQRatchet` (and with it `PQRatchetingSession` / `PQSession`) drops its
`Sendable` requirement, and `PQSession` carries an unavailable `Sendable`
conformance so it cannot be retroactively re-added. A session is a
single-driver state machine (one parked reply slot, one pending-proposal
slot): the wrapped FFI object is lock-serialized, so sharing was memory-safe,
but concurrent drivers could interleave silently — a second
`prepareToEncrypt` replaces the staged proposal with no signal to the first.
Withholding `Sendable` turns that misuse into a compile error. The containing
type — typically an actor that owns the session and serializes all driving —
asserts its own `Sendable` conformance instead. Result/value types
(`PQInbound`, `PQOutbound`, decrypt results, tokens, archives) remain
`Sendable`.
