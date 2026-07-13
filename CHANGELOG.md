# @germ-network/two-mls-pq

## 0.4.0

### Minor Changes

- [#64](https://github.com/germ-network/TwoMLSPQ/pull/64) [`d3f33ef`](https://github.com/germ-network/TwoMLSPQ/commit/d3f33efa239e696151375b5e4a62d37b98e2ccab) Thanks [@germ-mark](https://github.com/germ-mark)! - §A.1 pre-establishment initiator sends (binding contract 16; archive versions reset to the
  pre-release floor).

  The initiator can now send app messages immediately after `initiate`, before the
  acceptor's return welcome exists (architecture-diagrams 08-twoMLSPQ-APQ §A.1) —
  previously `prepare_to_encrypt` returned `SessionNotReady` until both groups were
  established, on live and restored sessions alike. Pre-establishment,
  `prepare_to_encrypt` is a no-op round (`proposal_message` empty; `proposal_hash` is
  the WELCOME digest — the documented carve-out on the v14 guarantee) and `encrypt`
  emits a fresh §A.1 envelope per frame (contract 16 atop v0.3.0 AppBinding — `initiate` keeps `app_binding` and loses `app_payload`), HPKE-sealed to the retained peer KP′,
  re-stapling the establishment sections plus the app message — any single frame lets
  the invitation holder join and read it.

  Envelope wire v2: tagged `[0x15][u32 kem_len][kem][ct]`; plaintext is four optional
  u32-LE length-prefixed sections `[app_payload][welcome][return_kp][stapled_message]`
  under the either/or rule — a host `app_payload` is establishment-SELF-SUFFICIENT
  (carries the welcome + return key package inside) and replaces the bare sections.
  `initiate` lost its `app_payload` parameter (a payload that signs over the welcome
  cannot exist before `initiate` returns); attach with the new
  `set_initial_app_payload` / `set_initial_return_key_package` (initiator-only,
  pre-establishment-only; capture AFTER attaching — the retained state rides the
  archive, so a birth-captured replier restores send-ready). New read-only
  `initial_welcome()`; `InitialFrame` reshaped (all four sections, `welcome` now
  optional); new exported `decode_initial_plaintext`. Replay-stable token/dedup keying:
  the stable prefix (`app_payload` when present, else `welcome`); all consequential
  state keys off the signed, JOINED welcome — the other sections are unauthenticated
  routing hints. The stapled app message is `[0x13][classical PrivateMessage]`, handed
  to `process_incoming` after the join. Establishment clears the retained state.

  Archive layout versions reset to the pre-release floor (SESSION_ARCHIVE and INVITATION
  both → 1 — the accumulated ladders carried no compatibility value pre-release; history
  stays in git): ALL persisted sessions and invitations regenerate, fail-closed
  (`ArchiveInvalid`). The v0.3.0 key-package WIRE cut (KP v3, a published artifact) is
  untouched. Composes
  with v0.3.0 AppBinding: the binding rides the welcome every pre-establishment frame
  re-staples, so `receive(expected_app_binding:)` verifies it on a join from any frame.

## 0.3.0

### Minor Changes

- [#62](https://github.com/germ-network/TwoMLSPQ/pull/62) [`b319e26`](https://github.com/germ-network/TwoMLSPQ/commit/b319e2698a6aafa81e8892f10c7c896643fb1359) Thanks [@germ-mark](https://github.com/germ-mark)! - **AppBinding** — an optional app-state binding welded into a session at creation and immutable for its lifetime. A TwoMLS session is definitionally bound to its two agents, but agents are _mutable_ (the rotation/candidate lifecycle); the new `AppBinding` GroupContext extension (`0xF0A2`, the APQInfo mechanism) binds the session to the app's **immutable** relationship identity: `initiate` gains `app_binding: Option<Vec<u8>>` (Swift: `appBinding: Data?`), `receive`/`accept` gain `expected_app_binding` — verified on the joined welcome with an exact, symmetric match (a stripped or unequal binding is a wrong-relationship welcome or downgrade attempt; a binding the caller did not state is never silently accepted) **before any invitation state is claimed**, so a rejected welcome leaves the invitation fully reusable. The acceptor's return group mirrors the verified binding; the initiator requires the return welcome to carry its own binding back unchanged. The binding lives on the classical halves only — a PQ half smuggling one is rejected at every PQ join — and an **empty** binding is reserved as invalid (rejected at creation and as an expectation; `None` is the unbound state). New `app_binding()` getter reads it back (it rides the persisted group state, so a restored session's owner re-verifies); new error `AppBindingMismatch`. GroupContextExtensions proposals remain outside the TwoMLS operation whitelist — now a deliberately tested guarantee — so the binding can never be rewritten.

  **⚠️ Binding contract 14 → 15 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release (`TwoMlsPqError` gained a variant; a stale pairing mis-reads FFI buffers). **Key packages and invitations regenerate**: leaves now advertise the AppBinding extension type, so `COMBINER_KEY_PACKAGE_VERSION` 2 → 3 and `INVITATION_VERSION` 3 → 4 (prerelease hard cut — v2 published key-package blobs and v3 invitation archives are rejected outright; re-pair sessions). Session archives are unaffected: the binding is optional, and existing (unbound) sessions restore and keep working.

  Adopter guidance: pass a **digest**, not raw identifiers — the first adopter (germDM) binds `H(domain-tag ‖ role-ordered did:did)`, sharing its canonicalization with the companion CommProtocol relationship-scoped introduction context so the delegation binding and the session binding cannot drift. The crate never interprets the bytes.

## 0.2.0

### Minor Changes

- [#60](https://github.com/germ-network/TwoMLSPQ/pull/60) [`3478ceb`](https://github.com/germ-network/TwoMLSPQ/commit/3478ceb0dec6dec2fa16d08b28709009c489c5d7) Thanks [@germ-mark](https://github.com/germ-mark)! - `PrepareEncryptResult` gains `proposal_message: Vec<u8>` (Swift: `proposalMessage: Data`) — the raw staged Upd(self) proposal, the exact message the paired `encrypt` staples and the peer independently digests.

  **⚠️ Binding contract 13 → 14 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release (a Record shape change; a stale pairing mis-reads FFI buffers). No wire, archive, or semantic change — persisted state carries over.

  Unblocks the anchor "agent handoff" flow: the app signs over its own `sha256(proposal_message)`, which equals the same result's `proposal_hash` and the receiver's independently derived `QueuedRemoteProposal.digest` (cross-side coherence, covered by new tests — including at the establishment moment, before any peer frame). Bytes and digest come from the same critical section, so there is deliberately NO staged-slot getter: a decoupled read could return whatever Upd a later `prepare_to_encrypt` staged (routine self-refreshes included), and a signature input must not be exposed to that race.

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
