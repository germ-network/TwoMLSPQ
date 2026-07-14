---
"@germ-network/abstract-two-mls": minor
---

Single error contract: SessionError (review finding H2, M2, M4)

Every throwing member of the abstract surface now throws exactly one type,
`AbstractTwoMLS.SessionError` — no backend error (`TwoMlsPqError`,
`UniffiInternalError`/`rustPanic`, `LinearEncodingError`) crosses the boundary.
It carries a fine `code` (27 cases as of contract 16) and a derived `disposition` (8 values:
`retryLater`, `discardFrame`, `reconnect`, `approveAndReprocess`,
`discardArtifact`, `rejectEstablishment`, `callerBug`, `fatal`) so an app can
drive recovery generically — the retry/reconnect/approve-and-reprocess
semantics the crate documents are now reachable without importing the backend.

The PQ wrapper's concrete members declare `throws(SessionError)` and route
through one total translation that is exhaustive over the 22 `TwoMlsPqError`
cases (a binding bump that adds a case fails compilation there); protocols stay
untyped `throws`, so the deprecated classical conformance compiles unchanged
and migrates on its own schedule (a `.staleFrame` code is reserved for its
consumed-key string matching). `TwoMLSPQConformanceError` is removed.

Also folds in two review conflations:
- M2: `ingest` now distinguishes `.unopenableFrame` (no receive-window key
  opens it — a run of these is the documented reconnect signal) from
  `.misroutedFrame` (a message-path frame at the side-band door). The crate's
  overloaded `SessionNotReady` is likewise split by call-site.
- M4: an identity mismatch is one `.identityMismatch` code whether the
  wrapper's key-package guard or the crate's `RemoteIdentityMismatch` raises it.

germDM migration: catch `AbstractTwoMLS.SessionError` and switch on
`code`/`disposition` (resolves the message-substring TODO in the incoming-loop
handler); the classical conformance emits `SessionError` too once migrated.
