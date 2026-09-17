---
"@germ-network/two-mls-pq": minor
---

Add the session migration export (GER-2433 C1) — the session-level analogue of the invitation migration export, completing the Rust engine's read-side bridge to the native twomlspq-swift engine.

`TwoMlsPqSession.migrationExport()` returns an established session's full migration payload: every group half (up to four: send/recv × classical/PQ) as a swift-mls format-2 snapshot via mls-rs's new `swift_export` feature, plus the session metadata (identity, AS sequences, PQ round state, PSK and attachment ledgers, proposal slots, epoch windows) as new UniFFI records. The export admits only established, quiescent sessions and refuses (rather than mis-maps) states the native archive cannot represent: pre-establishment initiators, mid-rotation sessions, installed born-dedicated envelopes, and wedged side-bands. The `TwoMLSPQMigrate` target gains `SessionMigrator`, mapping the payload onto twomlspq-swift's `SessionMigration.mintArchive`.

`BINDING_CONTRACT_VERSION` bumps 34 → 35 (new records and one new FFI method); the vendored binding and xcframework ship re-synced from the same build. The mls-rs pin moves to `llm/mlsrs-format2-export` (82b4dc1) with the `swift_export` feature, which extends mls-rs's serialized `EpochSecrets` — group state persisted by a build without `swift_export` no longer loads under this one, so persisted Rust session archives must be migrated, not carried, across this release. twomlspq-swift is pinned by revision to the `SessionMigration` merge (28807d6), the 0.1.0 tag predating it.
