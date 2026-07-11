# @germ-network/two-mls-pq

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
