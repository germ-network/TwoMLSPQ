# TwoMLSPQ

Germ Network's implementation of 1:1 aysnc, end-to-end encrypted messaging sessions,
built on MLS. It implements a triple ratchet
(symmetric encryption, asymmetric classical encryption, asymmetric PQ encryption) for forward
secrecy and post-compromise security. It further bundles MLS handshake plane messages so that
there is no dependency among in-flight messages, and applies header encryption to the bundle.

This repository holds the whole stack: the Rust/UniFFI core under [`rust/`](rust/), and
the hand-written Swift wrapper (**AbstractTwoMLS**) that consumes it — `Package.swift`,
[`Sources/`](Sources/), and [`Tests/`](Tests/) — at the top level. A wire change and its
Swift adapter land in one PR, tested against a **local** xcframework build; there is no
publish-a-release-to-test-an-integration step.

## Documentation

The full guide — concepts, the Combiner construction, cipher suites, the session
lifecycle, wire format, PSK binding, and the API reference — is an mdBook under
[`book`](book/src/introduction.md). The chapters are plain Markdown, so you can read them
directly on GitHub, or build the rendered site locally:

```sh
cargo install mdbook   # once
just book              # build → book/book/
just book-serve        # serve at http://localhost:3000
```

## Structure

```
Package.swift            Swift package manifest (env-gated binaryTarget — see below)
Sources/AbstractTwoMLS/  Hand-written Swift wrapper (the vended library)
Sources/TwoMLSPQ/        Vendored UniFFI binding (two_mls_pq.swift) — re-synced from bindings/
Tests/                   Swift tests
book/                    mdBook guide + API reference
scripts/                 iOS build tooling (buildIosDynamic.sh)
rust/                    Cargo workspace (the terminal dependency):
  apq/                   APQ Combiner layer (the {classical, pq} group pair, APQ-PSK, establishment)
  two-mls-pq/            Core library (session orchestration, wire format, UniFFI surface)
  uniffi-bindgen/        UniFFI binding generator
  fuzz/                  Fuzz targets
bindings/                Generated Swift output (after a build; git-ignored)
buildIos/                XCFramework output (after a build; git-ignored)
```

## Building the Rust core

Cargo runs from the workspace at `rust/` (its `.cargo/config.toml` and `rust-toolchain.toml`
are discovered from the working directory). There is no default crypto provider — every
build must select exactly one provider feature, so a bare `cargo build` fails with a
`compile_error!`. Use `awslc` for portable development and CI: it runs the full suite,
including every real ML-KEM-768 path, on any platform. See the CryptoKit section below for
the shipped Apple configuration.

```sh
cd rust
cargo build  --features awslc                                          # compile
cargo test   --features awslc,benchmark_util                           # run tests
cargo clippy --all-targets --features awslc,benchmark_util -- -D warnings   # lint
cargo fmt --all -- --check                                             # format check
```

(The `just` recipes — `just check`, `just test`, `just lint` — wrap these and `cd rust`
for you.)

## Swift bindings (debug)

Generates the Swift source and header from the debug dylib. Useful for inspecting the
generated API without a full release build (writes to repo-root `bindings/`):

```sh
cd rust
cargo build --package two-mls-pq --features cryptokit
cargo run --package uniffi-bindgen -- generate \
    target/debug/libtwo_mls_pq.dylib \
    --library --language swift --out-dir ../bindings
```

Or via the justfile: `just bindgen`.

## CryptoKit / ML-KEM-768 tests (macOS 26+)

The crates are crypto-provider agnostic: `apq` compiles no provider at all, and
`two-mls-pq` pins one per build feature (see `rust/two-mls-pq/src/providers.rs`). Exactly
one provider feature must be selected — there is no default:

- `cryptokit` — Apple CryptoKit for both halves (classical suites + native `MLKEM768`
  via `mls-rs-crypto-cryptokit`, `post-quantum` feature). The shipped configuration.
  CryptoKit's ML-KEM primitives require **iOS 26 / macOS 26**, so this feature builds
  and runs only on a macOS 26+ host with the matching Xcode toolchain (it links a Swift
  bridge and is not cross-platform).
- `awslc` — aws-lc for both halves; portable (Linux CI runs the full suite, including
  every real ML-KEM-768 path, with it) and wire-compatible with `cryptokit` (`apq`'s
  macOS test run includes cross-provider interop tests).

```sh
cd rust
cargo test --features awslc,benchmark_util   # any platform
cargo test -p two-mls-pq --features cryptokit
```

This tests:
- ML-KEM-768 key package generation via `CryptoKitMlKemProvider`
- Full APQ/Combiner session establishment with PQ groups using the real ML-KEM-768 cipher suite (0xFDEA)
- Encrypt/decrypt through PQ groups
- PSK chaining between classical and PQ group halves
- Agent rotation through PQ groups

The CryptoKit ML-KEM provider lives in the `mls-rs-crypto-cryptokit` fork at
`mls-rs-crypto-cryptokit/src/ml_kem.rs`; deterministic key derivation (needed for MLS
TreeKEM commits) bridges to `MLKEM768.PrivateKey(seedRepresentation:)`.

## iOS XCFramework

The supported, tested build is the **dynamic** framework-bundle xcframework — a cdylib
packaged as `.framework` bundles so TwoMLSPQ can coexist in one app with the legacy
classical static MLSrs library. It builds all Apple targets (iOS device, iOS simulator
arm64 + x86_64, macOS), regenerates the Swift bindings under `bindings/`, and prints the
SwiftPM checksum as its last line:

```sh
bash scripts/buildIosDynamic.sh
```

The script runs cargo from `rust/` but writes its outputs — `buildIos/TwoMLSPQ.xcframework`
(and `.zip`) plus `bindings/two_mls_pq.swift` and `bindings/two_mls_pqFFI.h` — to the repo
root, where the Swift package consumes them. It builds with the `cryptokit` provider (real
ML-KEM-768), so it requires a **macOS 26+ host with a matching Xcode toolchain**; if
`xcodebuild` can't find a full Xcode, point `DEVELOPER_DIR` at your `Xcode.app`. The
required Rust targets are installed automatically via rustup.

## Swift package: local build-and-test loop

`Package.swift`'s `TwoMLSPQrs` binary target is environment-switched, so in-repo work never
waits on a release:

- **In-repo dev/CI** — set `TWOMLSPQ_LOCAL_XCFRAMEWORK=1` and the manifest consumes the
  **local** `buildIos/TwoMLSPQ.xcframework`.
- **External consumers** (the app resolving a git tag) — unset, and the manifest pins the
  released `url` + `checksum`, which the release workflow rewrites per release.

The loop that replaces release-to-test:

```sh
bash scripts/buildIosDynamic.sh                       # build the local xcframework + bindings
cp bindings/two_mls_pq.swift Sources/TwoMLSPQ/        # re-sync the vendored binding in-tree
TWOMLSPQ_LOCAL_XCFRAMEWORK=1 swift test               # build + test against the local build
```

Keep `Sources/TwoMLSPQ/two_mls_pq.swift` re-synced from the SAME build as the binary: uniffi
embeds a checksum contract verified at init, and the `binding_contract_version()` ↔
`expectedBindingContract` canary (in `Sources/AbstractTwoMLS/AbstractTwoMLS+TwoMLSPQ.swift`)
guards a stale-binding/fresh-binary mismatch.

## Release Process

Releases are Changesets-driven (one version for the whole repo; the tag `vX.Y.Z` is the
xcframework version the app resolves). Add a `.changeset/*.md` describing the change. When the
"Prepare next release" PR merges, changesets bumps the version and tags the release; the
finalize job then builds the xcframework, computes the checksum, **pins** `Package.swift`'s
fallback `url` + `checksum` and the vendored binding to that build on a commit reachable via
the tag, **repoints the tag** to it, and uploads the assets (`TwoMLSPQ.xcframework.zip`,
`two_mls_pq.swift`, `two_mls_pqFFI.h`, and the `.checksum`).

Because in-repo dev/CI build locally (the env override above), the checksum chicken-and-egg
never blocks development — only the tagged commit carries the pinned checksum, and the retag
lands before any asset is uploaded, so no consumer can resolve a half-finalized tag.

Releases: https://github.com/germ-network/TwoMLSPQ/releases
