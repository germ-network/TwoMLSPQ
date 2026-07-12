# @germ-network/two-mls-pq

## 0.1.0

### Minor Changes

- [#57](https://github.com/germ-network/TwoMLSPQ/pull/57) [`8115145`](https://github.com/germ-network/TwoMLSPQ/commit/81151459925770851569e7fac93f39e47a714c90) Thanks [@germ-mark](https://github.com/germ-mark)! - Push-based persistence; the pull `archive()` is removed from the FFI

  **⚠️ Binding contract 12 → 13 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release. **Persisted state is not portable**: `SESSION_ARCHIVE_VERSION` → 9, `INVITATION_VERSION` → 3 — regenerate all persisted sessions and invitations.

  The pull `archive()` on `TwoMlsPqSession` and `TwoMlsPqInvitation` is **removed from the exported surface**. Its contract was a _move, not a copy_ — using the live object after archiving, then restoring, rewound the sender ratchet and re-derived AEAD keys/nonces (security review finding H1: keystream reuse against a real transcript). The crate could not enforce the discipline while the app decided when to pull.

  The live object now **pushes** its state to a foreign persistence hook after every state-advancing mutation:

  - **`ArchiveSink`** (`with_foreign` trait) with `persist(seq, kind: BlobKind, archive)`. Attach one per object with the new **`install_sink`** (pushes a baseline `Checkpoint`). The contract: enqueue-only, non-blocking, atomically upsert the one blob named by `kind` (never a multi-object write), newest-`seq`-wins per slot, and seal the plaintext bytes before writing.
  - **Two-blob session model**: a **classical** mutation rewrites `Core` (identity + both classical halves + meta — the ML-KEM ratchet trees omitted); a **PQ** op (and the baseline) writes a full `Checkpoint`. Every mutation is one atomic single-blob push, so the sink needs no cross-object transaction. Restore is **`TwoMlsPqSession.restore(core, checkpoint)`** (reconciles PQ-from-checkpoint, rest by higher `state_seq`, fails closed on a manifest mismatch). The invitation is monolithic (no ML-KEM trees) and restores with **`TwoMlsPqInvitation.restore(archive:)`**. Both restore constructors are named **`restore`** (renamed from the session's `from_persisted` and the invitation's `new(archive:)`) — the name signals materialising from serialised bytes, not minting fresh state.
  - **`EncryptResult.depends_on_seq`** + read-only **`state_seq()`** on both objects: the app waits until it has durably persisted the frame's `depends_on_seq` before transmitting a frame that publishes stored-private-key material (a routine app message re-staples an already-persisted commit, so it imposes no wait). Transmission stays entirely the app's concern.

  Internals: the invitation's four mutexes are consolidated into one (removing a torn-archive class); `pq_bootstrap_begin` now persists its pending PQ key package (previously at risk of a restore-time strand). No protocol/wire changes to messages — only persistence and the removed pull surface.

## 0.0.13

### Patch Changes

- [#55](https://github.com/germ-network/TwoMLSPQ/pull/55) [`2324280`](https://github.com/germ-network/TwoMLSPQ/commit/232428094946b8871fa52edc3119dcdb5f7619f8) Thanks [@germ-mark](https://github.com/germ-mark)! - Fix the iOS XCFramework build (restore the CryptoKit iOS-build fixes)

  v0.0.12's artifact build panicked in mls-rs-crypto-cryptokit's build.rs ("Libraries require RPath!"). The `germ-shadow-safe-exporter` branch had never picked up the CryptoKit iOS-build fixes the previous pin (`3743c75`) carried: newer Xcode toolchains report `librariesRequireRPath` for varying deployment targets, and that guard is spurious for this artifact — the cdylib ships inside an `@rpath/…framework`, so rpath-based loading is exactly what is wanted. The bumped mls-rs pin restores those fixes (panic → warning; `MIN_IOS_DEPLOYMENT_TARGET` stays 17.0, so the bridge still compiles for iOS 17+ deployment). No library code changes; binding contract, session archive, and key package versions are unchanged from 0.0.12 (which shipped no artifacts).

## 0.0.12

### Patch Changes

- [#53](https://github.com/germ-network/TwoMLSPQ/pull/53) [`66d12fb`](https://github.com/germ-network/TwoMLSPQ/commit/66d12fbbde29e1b2d8f7c5716bd9b742532eb946) Thanks [@germ-mark](https://github.com/germ-mark)! - draft-ietf-mls-combiner-02 conformance ([#51](https://github.com/germ-network/TwoMLSPQ/issues/51)), session modularization ([#52](https://github.com/germ-network/TwoMLSPQ/issues/52))

  **⚠️ Binding contract 8 → 12 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release; uniffi's load-time checksum rejects a stale pairing. **Persisted state is not portable**: `SESSION_ARCHIVE_VERSION` → 8 and the combiner key package framing → v2 — regenerate all persisted sessions, invitations, and published key packages.

  The `apq` crate and session layer now conform to **draft-ietf-mls-combiner-02** (with mls-extensions-08 for the component framework):

  - **APQInfo** GroupContext extension (`0xF0A1`) in both halves of every APQ group and in Welcomes — written once at creation, verified by joiners (group ids, mode, suite pair).
  - **AppDataUpdate** (`0x0008`) on both commits of every FULL, attesting the new epochs of both halves; receivers verify both copies against the actual post-commit epochs before any app data is decrypted.
  - **Safe Extensions PSK recipe**: the APQ-PSK and cross-party TwoMLS-PSK derive via `SafeExportSecret(component_id)` + `DeriveSecret(exporter, "psk_id"/"psk")` and import as `psk_type = application(3)` (components `0xFF01`/`0xFF02`); the A.3 injected secret stays an external PSK. Requires the germ-network/mls-rs `germ-shadow-safe-exporter` build branch (`safe_extensions` feature).
  - **Event-driven cross-party binding**: a commit re-binds the peer's group only when it has advanced since the last binding; three epoch watermarks make each `(group, epoch, component)` export happen at most once, as the consuming exporter requires.
  - Combiner key package v2 encloses the -02 §7 `APQKeyPackage` TLS payload.

  Documented extensions beyond -02: A.3 substitutes the injected KEM secret for the PQ updatePath as the PQ-PCS source; A.5 re-keys on the PQ groups alone, reconciling `pq_epoch` at the next A.3 bind.

  A security and functional review (wire/versioning, downgrade, crypto/PSK, fork, state machine) found no correctness or security defect; its hardening fixes are included. `session.rs` is split into a `session/` module directory (pure moves; no API change). The book chapters (psk-binding, group-rules, wire-format, cipher-suites) match the shipped recipe.
