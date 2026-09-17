---
"@germ-network/two-mls-pq": minor
---

Add a Rust-free `TwoMLSPQTypes` product carrying the pure-Swift currency types (`ClientID`, `PrincipalState`, `SessionError`, `WelcomeToken`, …) for consumers that build all-Swift and cannot link the `TwoMLSPQrs` xcframework (e.g. Android). `TwoMLSPQ` re-exports the new target, so `import TwoMLSPQ` is unchanged for existing consumers.
