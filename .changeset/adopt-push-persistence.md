---
"@germ-network/abstract-two-mls": minor
---

Adopt TwoMLSPQ v0.1.0 (binding contract 13): push-based persistence

`Archivable` is reshaped from pull to push. The old pull `archive` getter was
a move, not a copy — using a live object after archiving, then restoring,
rewound the sender ratchet into AEAD nonce reuse (security review H1). The
live object is now the single writer and pushes its state to an installed sink.

BREAKING for conformers and callers:

- `Archivable`: `associatedtype Archive` → `Persisted`; `init(archive:)` →
  `init(persisted:)`; the pull `var archive` getter is REMOVED; new
  `func installSink(_:)` (once-only) and `var stateSeq: UInt64`.
- New `AbstractTwoMLS.PersistenceSink` (`persist(seq:slot:bytes:)`, enqueue-only,
  called synchronously on the mutating thread) + `PersistedSlot{core, checkpoint}`.
- `EncryptResultProtocol` gains `dependsOnSeq` (default `0`; the durability gate
  for key-material frames — routine frames impose no wait).
- Session restore takes two slots (`PQSession.Persisted{core:checkpoint:}`);
  invitations stay monolithic and restore from bytes; `makeInvitation` still
  mints pull bytes (the object doesn't exist yet).

Persisted state is NOT portable — regenerate all persisted sessions and
invitations. (This adoption bumped `SESSION_ARCHIVE_VERSION` → 9 /
`INVITATION_VERSION` → 3; contract 16 later reset both ladders to 1 — the
§A.1 replier-first changeset carries the final pin, TwoMLSPQ v0.4.1.)

germDM migration: implement `PersistenceSink` (two atomic slots, sealed);
`installSink` after construction/restore; restore sessions via
`init(persisted:)` and gate key-material-frame transmission on `dependsOnSeq` /
`stateSeq` durability; regenerate persisted PQ state. The deprecated classical
shim adapts with a one-shot baseline (its non-push limitation documented).
