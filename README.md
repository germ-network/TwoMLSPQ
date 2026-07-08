# TwoMLSPQ

Germ Network's implementation of 1:1 encrypted messaging sessions built on two asymmetric MLS send groups (Distributed MLS — draft-xue-distributed-mls).

## Documentation

The full guide — concepts, the Combiner construction, cipher suites, the session
lifecycle, wire format, PSK binding, and the API reference — is an mdBook under
[`two-mls-pq/book`](two-mls-pq/book/src/introduction.md). The chapters are plain Markdown,
so you can read them directly on GitHub, or build the rendered site locally:

```sh
cargo install mdbook   # once
just book              # build → two-mls-pq/book/book/
just book-serve        # serve at http://localhost:3000
```

## Structure

```
apq/              APQ Combiner layer (the {classical, pq} group pair, APQ-PSK, establishment)
two-mls-pq/       Core library (session orchestration, wire format, UniFFI surface)
uniffi-bindgen/   UniFFI binding generator
scripts/          iOS build tooling
bindings/         Generated Swift output (after build)
buildIos/         XCFramework output (after build)
```

## Building

There is no default crypto provider — every build must select exactly one provider
feature, so a bare `cargo build` fails with a `compile_error!`. Use `awslc` for portable
development and CI: it runs the full suite, including every real ML-KEM-768 path, on any
platform. See the CryptoKit section below for the shipped Apple configuration.

```sh
cargo build  --features awslc                                          # compile
cargo test   --features awslc,benchmark_util                           # run tests
cargo clippy --all-targets --features awslc,benchmark_util -- -D warnings   # lint
cargo fmt --all -- --check                                             # format check
```

## Swift Bindings (debug)

Generates the Swift source and header from the debug dylib. Useful for inspecting the generated API without a full release build.

```sh
cargo build --package two-mls-pq --features cryptokit
cargo run --package uniffi-bindgen -- generate \
    target/debug/libtwo_mls_pq.dylib \
    --library --language swift --out-dir bindings
```

Or via the justfile:

```sh
just bindgen
```

## CryptoKit / ML-KEM-768 tests (macOS 26+)

The crates are crypto-provider agnostic: `apq` compiles no provider at all, and
`two-mls-pq` pins one per build feature (see `two-mls-pq/src/providers.rs`). Exactly one
provider feature must be selected — there is no default:

- `cryptokit` — Apple CryptoKit for both halves (classical suites + native `MLKEM768`
  via `mls-rs-crypto-cryptokit`, `post-quantum` feature). The shipped configuration.
  CryptoKit's ML-KEM primitives require **iOS 26 / macOS 26**, so this feature builds
  and runs only on a macOS 26+ host with the matching Xcode toolchain (it links a Swift
  bridge and is not cross-platform).
- `awslc` — aws-lc for both halves; portable (Linux CI runs the full suite, including
  every real ML-KEM-768 path, with it) and wire-compatible with `cryptokit` (`apq`'s
  macOS test run includes cross-provider interop tests).

```sh
cargo test --features awslc,benchmark_util   # any platform
```

```sh
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

Outputs `buildIos/TwoMLSPQ.xcframework` (and `.zip`) plus `bindings/two_mls_pq.swift` and
`bindings/two_mls_pqFFI.h`. It builds with the `cryptokit` provider (real ML-KEM-768), so
it requires a **macOS 26+ host with a matching Xcode toolchain**; if `xcodebuild` can't
find a full Xcode, point `DEVELOPER_DIR` at your `Xcode.app`. The required Rust targets are
installed automatically via rustup.

> The older `scripts/buildIos.sh` (and `just build-ios`) produces a *static*
> `MLSrs.xcframework` via a `-library`/`-headers` xcframework. It predates the
> coexistence requirement and is **not** the supported release flow — it is retained only
> as a vestigial artifact.

## Release Process

1. Run the dynamic build script and note the checksum it prints last:
   ```sh
   bash scripts/buildIosDynamic.sh
   ```

2. Tag the commit the script was run from:
   ```sh
   git tag 0.x.y
   git push origin 0.x.y
   ```

3. Create a GitHub release from that tag and upload:
   - `buildIos/TwoMLSPQ.xcframework.zip`
   - `bindings/two_mls_pqFFI.h`
   - `bindings/two_mls_pq.swift`

   Include the checksum in the release notes, along with the binding↔binary pairing
   warning and the `binding_contract_version()` value (currently **3**): a Swift binding
   and the binary it was generated from must ship as a matched pair, or the app aborts at
   first use.

   Releases: https://github.com/germ-network/TwoMLSPQ/releases

## Integrating into the Demo App

The demo app is at https://github.com/germ-network/AbstractTwoMLS.

After publishing a release:

1. Copy the generated header and Swift binding into the app's `Sources/TwoMLSPQ/`:
   ```sh
   cp bindings/two_mls_pqFFI.h bindings/two_mls_pq.swift /path/to/AbstractTwoMLS/Sources/TwoMLSPQ/
   ```
   Then bump the app's `expectedBindingContract` to match `binding_contract_version()`, so
   a stale binding/binary pairing fails fast instead of misreading FFI buffers.

2. Update `Package.swift` in the app with the new release URL and checksum:
   ```swift
   .binaryTarget(
       name: "TwoMLSPQ",
       url: "https://github.com/germ-network/TwoMLSPQ/releases/download/0.x.y/TwoMLSPQ.xcframework.zip",
       checksum: "<checksum printed by build script>"
   )
   ```

For local development, point `Package.swift` directly at the built framework (add `buildIos/` to `.gitignore`):
   ```swift
   .binaryTarget(
       name: "TwoMLSPQ",
       path: "../TwoMLSPQ/buildIos/TwoMLSPQ.xcframework"
   )
   ```
