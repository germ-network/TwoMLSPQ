---
"@germ-network/two-mls-pq": minor
---

Push-based persistence; the pull `archive()` is removed from the FFI

**⚠️ Binding contract 12 → 13 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release. **Persisted state is not portable**: `SESSION_ARCHIVE_VERSION` → 9, `INVITATION_VERSION` → 3 — regenerate all persisted sessions and invitations.

The pull `archive()` on `TwoMlsPqSession` and `TwoMlsPqInvitation` is **removed from the exported surface**. Its contract was a *move, not a copy* — using the live object after archiving, then restoring, rewound the sender ratchet and re-derived AEAD keys/nonces (security review finding H1: keystream reuse against a real transcript). The crate could not enforce the discipline while the app decided when to pull.

The live object now **pushes** its state to a foreign persistence hook after every state-advancing mutation:

- **`ArchiveSink`** (`with_foreign` trait) with `persist(seq, kind: BlobKind, archive)`. Attach one per object with the new **`install_sink`** (pushes a baseline `Checkpoint`). The contract: enqueue-only, non-blocking, atomically upsert the one blob named by `kind` (never a multi-object write), newest-`seq`-wins per slot, and seal the plaintext bytes before writing.
- **Two-blob session model**: a **classical** mutation rewrites `Core` (identity + both classical halves + meta — the ML-KEM ratchet trees omitted); a **PQ** op (and the baseline) writes a full `Checkpoint`. Every mutation is one atomic single-blob push, so the sink needs no cross-object transaction. Restore is **`TwoMlsPqSession.from_persisted(core, checkpoint)`** (reconciles PQ-from-checkpoint, rest by higher `state_seq`, fails closed on a manifest mismatch). The invitation is monolithic (no ML-KEM trees) and restores with **`TwoMlsPqInvitation.restore(archive:)`** — the constructor was renamed from `new(archive:)`, which wrongly implied minting fresh state (the state lives in the bytes; mirrors the session's `from_persisted`).
- **`EncryptResult.depends_on_seq`** + read-only **`state_seq()`** on both objects: the app waits until it has durably persisted the frame's `depends_on_seq` before transmitting a frame that publishes stored-private-key material (a routine app message re-staples an already-persisted commit, so it imposes no wait). Transmission stays entirely the app's concern.

Internals: the invitation's four mutexes are consolidated into one (removing a torn-archive class); `pq_bootstrap_begin` now persists its pending PQ key package (previously at risk of a restore-time strand). No protocol/wire changes to messages — only persistence and the removed pull surface.
