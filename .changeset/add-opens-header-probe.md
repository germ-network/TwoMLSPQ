---
"@germ-network/two-mls-pq": minor
---

Add a public additive `PQSession.opensHeader(_:)` probe that reports whether one
of the session's header receive-window keys authenticates a blob — the engine's
ownership signal for a pooled session. It is a pure read over the existing
`openIncoming` path: no state mutation, no persistence push, and never throws.
