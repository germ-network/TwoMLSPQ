---
"@germ-network/two-mls-pq": minor
---

Add the invitation migration export (GER-2484, GER-2372 R2/R3) — the Rust engine's read-side bridge to the native twomlspq-swift engine.

`TwoMlsPqInvitation.migrationExport()` returns the invitation's full migration payload (signing identity, both halves' HPKE secrets and bare RFC 9420 KeyPackages, the four routing tables, `stateSeq`) as new UniFFI records. The new `TwoMLSPQMigrate` Swift target maps that payload onto twomlspq-swift's `InvitationMigration.mintArchive`, minting a native invitation `SecretArchive` from a legacy Rust invitation (dual-read / single-write: the Rust engine is a read-only legacy decoder). A differential test suite proves the migrated invitation opens the same §A.1 envelope, carries populated routing tables, handles spent single-use invitations, and rejects perturbed secrets.

`BINDING_CONTRACT_VERSION` bumps 33 → 34 (new records and one new FFI method); the vendored binding and xcframework ship re-synced from the same build.
