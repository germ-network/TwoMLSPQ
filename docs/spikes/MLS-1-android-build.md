# MLS-1 (GER-2036) + DEPS-1 — spike report

Run 2026-08-07. Revisions every claim is true of: TwoMLSPQ `main` `3c25a8a`, mls-rs fork
`b43703f`, `aws-lc-sys 0.40.0` / `aws-lc-rs 1.16.3`, NDK **r27d** (27.3.13750724),
Swift **6.3.3** host + `swift-6.3.3-RELEASE_android` SDK, emulator API 28 arm64-v8a.

## Exit criteria

| Criterion | Result |
|---|---|
| `cargo ndk` build, both ABIs | **PASS** (x86_64 needed a fix — below) |
| ML-KEM round-trip on an emulator | **PASS** — 11 tests, 0 failed, RC=0 |
| 16 KB page alignment | **PASS** — every `PT_LOAD` `0x4000`, both ABIs |
| Stripped `.so` size per ABI | arm64 **2,959,368 B** · x86_64 **4,117,976 B** |
| `cargo deny check licenses` | **PASS** — `licenses ok` |
| *(added)* DEPS-1 packaging seam | **PASS** — Swift package builds for both Android triples |

## Sizes

| Artifact | Bytes | Note |
|---|---|---|
| iOS device dylib (cryptokit) | 1,302,308 | existing shipped artifact, for scale |
| Android arm64-v8a `.so` (awslc) | **2,959,368** | +1,657,060 vs iOS |
| Android x86_64 `.so` (awslc) | **4,117,976** | x86-64 is less code-dense |
| Android arm64-v8a `.a` | 46,303,568 | archive, not link size |
| Android x86_64 `.a` | 44,740,638 | archive, not link size |

`strip = "symbols"` already strips at link on ELF: `.symtab` count 0, and an `llvm-strip`
pass moves the file by **−696 B**. No separate strip step is needed.

`NEEDED` is **`libdl.so`, `libc.so` only** — no `libc++_shared.so`, because aws-lc-sys's cc
path is pure C plus `.S`. One fewer file to package. `native-static-libs` reports
`-ldl -llog -lunwind -ldl -lm -lc`.

## The x86_64 blocker, and why my first fix was wrong

`aws-lc-sys 0.40.0` ships checked-in bindings for a fixed target list containing
`aarch64_linux_android_crypto.rs` but **no x86_64 twin**. Off that list it demands bindgen and
falls back to `CmakeBuilder`, which fails under the NDK:

```
CMake Error: Android: Neither the NDK or a standalone toolchain was found.
CMake Error: CMake was unable to find a build program corresponding to "Unix Makefiles".
```

**The `default-features = false` fix I proposed does not work.** It builds — a probe crate that
referenced nothing compiled fine, which is exactly the trap — but the universal bindings are
**half the size and drop the symbols this crate needs**:

| binding set | lines | `EVP_PKEY_keygen_deterministic` | `X509_new` |
|---|---|---|---|
| per-target (all 13) | ~27,200–27,450 | yes | yes |
| universal (all 4) | ~14,300 | **no** | **no** |

`EVP_PKEY_keygen_deterministic` is the ML-KEM deterministic-keygen entry point MLS
`DeriveKeyPair` depends on. Turning off `all-bindings` loses it plus the whole X.509 surface —
`mls-rs-crypto-awslc` fails with 5 unresolved-import errors. I created and then **deleted** the
fork branch carrying that change.

**What actually works** — target-scoped, landed in `rust/two-mls-pq/Cargo.toml`:

```toml
[target.x86_64-linux-android.dependencies]
aws-lc-sys = { version = "=0.40.0", features = ["bindgen"] }
```

plus `AWS_LC_SYS_CMAKE_BUILDER=0` (set by `scripts/buildAndroid.sh`) so the cc builder is used
and CMake is never consulted. This generates *correct* bindings for the real target. Requires
`bindgen-cli` at build time.

`AWS_LC_SYS_EFFECTIVE_TARGET=x86_64-unknown-linux-gnu` also works and needs no extra tooling —
it substitutes the glibc x86_64 binding set, same LP64 ABI. Corroborating evidence that the
substitution is sound: the `.so` built that way is **byte-identical** (4,117,976 B) to the
bindgen build. Recorded as the fallback; the upstream fix is to get `x86_64-linux-android` onto
aws-lc-sys's pregenerated list.

## What did NOT go wrong

- **aws-lc-rs #918** (macOS host → Android `CC`/`AR` leakage) never bit. cargo-ndk 4.1.2 sets
  the environment correctly. arm64 built clean in **57 s** cold — far under the 8–12 min estimate,
  because the cc path compiles a curated ~350-file subset, not the whole 66 MB tree.
- No cmake / go / ninja / nasm needed on the arm64 path.

## Emulator run

Both payloads on `emulator-5554` (arm64-v8a, API 28, Android 9), pushed to `/data/local/tmp`:

- `provider_interop` — 2 passed, 0 failed. `awslc_pq_group_end_to_end` establishes a real
  ML-KEM-768 MLS group: keygen, add-member commit (encap), welcome (decap), messages both ways.
  Only 2 tests ran, confirming `mod cryptokit_interop` cfg'd out on Android.
- `r1_mls_assumptions` — 9 passed, 0 failed, including `a4_leg_rewrapped_after_a_commit_still_opens`
  (the A.4 PQ ratchet) and `ml_kem_768_ek_is_1184_bytes`.

Both `RC=0`. arm64 pulls aws-lc's hand-written NEON ML-KEM assembly, so this is the optimized path.

## DEPS-1 — the packaging seam works

`swift build --swift-sdk aarch64-unknown-linux-android28 --product TwoMLSPQ` → **complete**.
Same for `x86_64-unknown-linux-android28`.

Shape: iOS keeps the dynamic xcframework; Android gets a **separate** SE-0482
`.artifactbundle` carrying the static `.a` plus headers and modulemap. `binaryTarget` cannot be
conditioned, so both are declared and the **dependency edge** carries `.when(platforms:)`.

Confirmed mechanics:
- An xcframework binaryTarget is **silently inert** on Android — no diagnostic. Proven by a
  negative test: without the artifactbundle the same build fails with `cannot find type
  'RustBuffer' in scope`, because `#if canImport(two_mls_pqFFI)` compiles away quietly. **The
  artifactbundle is load-bearing.**
- One `supportedTriples` entry per arch covers API 28–36 — SwiftPM matches the environment by
  prefix, so `…-android` matches `…-android28`.
- `.linkedLibrary(…, .when(platforms: [.android]))` is a *safe* setting. No `unsafeFlags`
  anywhere, which matters because `unsafeFlags` still poisons versioned consumption — verified
  live in SwiftPM `main` and `swift-6.3-RELEASE`, despite reports it was removed in 6.2.
- **The uniffi-generated modulemap is unusable on Android** — it carries `use "Darwin"`. The
  bundle ships a hand-written one.
- `RUSTFLAGS` must be **per-target** (`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`). Plain `RUSTFLAGS`
  leaks into the native host build used for header generation, and ld64 rejects `-z` outright.
- Only Apple-only import in the package was `import CryptoKit` in `PQDigest.swift`, one call
  (`SHA256.hash`). Now conditional on `canImport`, falling back to swift-crypto's `Crypto`.

Bonus result: the binding generated from an **awslc** build is **byte-identical** to the
vendored one generated from **cryptokit**. The FFI contract is provider-independent, so one
vendored `two_mls_pq.swift` serves both platforms.

## Blockers for productionising

1. **`release-artifacts.yml:201-205` will silently mis-pin.** The checksum rewrite is
   `re.subn(…, count=1)` guarded on `n2 != 1`. With two binaryTargets there are two `checksum:`
   literals — it rewrites the first in file order and `n2` is still 1, **so the guard does not
   fire**. Must be anchored to the target name before a second binary target ships. This is the
   exact failure mode the `RELEASE CONVENTION` comment exists to prevent.
2. The reuse comparator and idempotency guard have one slot each; both need per-artifact logic.
3. The pin/retag must become a third job that `needs:` both builds, so the tag moves once.
4. No `.artifactbundle` determinism machinery exists (the deterministic-zip work is
   xcframework-specific).
5. `bindgen-cli` becomes a build requirement for the x86_64 Android leg.

## Corrections to the planning docs

**To the brief I was given** (already fixed in the docs — my briefing was stale): "the Swift SDK
for Android ships no 32-bit targets" is **false**. It ships `{aarch64, armv7, x86_64}-unknown-linux-android{28…36}`.
minSdk 28 is real but forced by `posix_spawn`. Already corrected at `06:329-336` via CRYPTO-9.

**Still wrong in `docs/android/03-twomlspq-android-build.md`:**

1. §4 "there is no `[profile.release]` today" — **false**. It exists and is worth ~1.4 MB per
   slice (2,682,536 → 1,302,308 B). **MLS-10 rests entirely on this premise** and its advice
   contradicts the shipped profile on three of five knobs.
2. §4 "iOS release device dylib … 2.7 MB" — pre-optimization figure. Current: **1,302,308 B**.
   Propagated to `06:331` and used as the base for the Android per-ABI estimate, which this
   spike now supersedes with measurements.
3. §4 "12.9 MB ratchet" — the ratchet is seeded at **13,719,424 B**.
4. §3 and the key-format row at line 77 — the archive-portability conclusion. The 96/2400
   observation is right; the inference that archives are *permanently* non-portable is **not**.
   Load-bearing for **MLS-13 / Q-MLS-6**, which should be re-scoped.
5. MLS-1's own framing assumed cargo-ndk was the whole story. The Swift-side seam (DEPS-1) is
   the harder half and had no MLS work item.

**In TwoMLSPQ:** `scripts/buildIosDynamic.sh:43` comments "Real ML-KEM-768 (AWS-LC)" directly
above `--features cryptokit`.

## Safety finding

`mls-rs-crypto-awslc`'s `decap()` passes `self.secret_key_size()` (2400, unconditionally) to
`EVP_PKEY_kem_new_raw_secret_key` and **never checks `secret_key.len()`**. A 96-byte CryptoKit
key there is a 2,304-byte out-of-bounds read in `unsafe` code — UB, not a clean `Err`. The
archive header carries no key-format discriminator, so both providers decode each other's
archives structurally and fail only at first key use. Any change to the stored key encoding must
land the length check and the discriminator first.

## Changes made (branch `llm/elated-napier-0e89eb`, not pushed)

| File | Change |
|---|---|
| `rust/two-mls-pq/Cargo.toml` | `[target.x86_64-linux-android.dependencies]` with `aws-lc-sys/bindgen` |
| `Sources/TwoMLSPQ/PQDigest.swift` | conditional CryptoKit / swift-crypto import |
| `Package.swift` | Android binaryTarget, conditioned edges, Android linkerSettings, swift-crypto |
| `scripts/buildAndroid.sh` | new — builds both ABIs and assembles the artifactbundle |
| `book/src/crypto-providers.md` | new — Q1/Q2/Q3 written down |
| `book/src/SUMMARY.md`, `.gitignore` | one line each |

Not changed: `rust/rust-toolchain.toml` (adding Android triples would force every Linux-CI and
Apple dev to install them), `rust/Cargo.toml`, `rust/deny.toml`, the pinned mls-rs rev.

Verified clean: `cargo fmt --all -- --check`, `taplo fmt --check`, `cargo clippy` (both gates).
The macOS build failure seen in passing is **pre-existing** — reproduced with all changes
stashed — and is the pinned v0.10.0 xcframework against the contract-33 binding, which is what
`TWOMLSPQ_LOCAL_XCFRAMEWORK` exists for and what CI always sets.

---

## Appendix — raw emulator transcripts

`emulator-5554`, arm64-v8a, API 28 (Android 9). Binaries pushed to `/data/local/tmp`.

### provider_interop
```

running 2 tests
test awslc_classical_group_end_to_end ... ok
test awslc_pq_group_end_to_end ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s

RC=0
```

### r1_mls_assumptions
```

running 9 tests
test a4_leg_rewrapped_after_a_commit_still_opens ... ok
test assumption_a_foreign_group_frame_does_not_consume_a_generation ... ok
test assumption_a_holds_on_the_classical_carrier ... ok
test assumption_a_second_delivery_of_same_frame_fails_replay ... ok
test assumption_a_valid_senderdata_corrupt_content_consumes_the_generation ... ok
test assumption_b_own_application_message_is_rejected ... ok
test assumption_c_pq_group_round_trips_application_messages_both_directions ... ok
test assumption_d_restored_group_signs_with_snapshot_signer_not_loader_key ... ok
test ml_kem_768_ek_is_1184_bytes ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s

RC=0
```
