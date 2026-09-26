---
---

Test-only: add a randomized differential testing harness over the Swift and Rust engines (GER-2566 item 1) — seeded op sequences with drop/reorder/duplicate, legality-gated crash-restore, a behind-delivery negative op, and an engine-attributed divergence ledger. It runs against the deployed pin (`c501f9d`) via `just differential-deployed`, which swaps the pin binding in and restores after; the standard build, tests, and lint are unaffected. Nothing ships.
