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

```sh
# Default build (RustCrypto, no ML-KEM-768; see the CryptoKit section for real ML-KEM)
cargo build                        # compile
cargo test                         # run tests
cargo clippy --all-targets         # lint
cargo fmt --all -- --check         # format check
```

## Swift Bindings (debug)

Generates the Swift source and header from the debug dylib. Useful for inspecting the generated API without a full release build.

```sh
cargo build --package two-mls-pq
cargo run --package uniffi-bindgen -- generate \
    target/debug/libtwo_mls_pq.dylib \
    --library --language swift --out-dir bindings
```

Or via the justfile:

```sh
just bindgen
```

## CryptoKit / ML-KEM-768 tests (macOS)

The `cryptokit` feature enables real ML-KEM-768 (FIPS 203) session tests backed by
`mls-rs-crypto-awslc` with the `post-quantum` feature. Run on macOS:

```sh
cargo test -p two-mls-pq --features cryptokit
```

This tests:
- ML-KEM-768 key package generation via `AwsLcCryptoProvider`
- Full APQ/Combiner session establishment with PQ groups using the real ML-KEM-768 cipher suite (0xFDEA)
- Encrypt/decrypt through PQ groups
- PSK chaining between classical and PQ group halves
- Agent rotation through PQ groups

The production iOS path (CryptoKit native `MLKEM768`) lives in the `mls-rs-crypto-cryptokit`
fork at `mls-rs-crypto-cryptokit/src/ml_kem.rs` and requires iOS 26 / macOS 26.

## iOS XCFramework

Builds a release XCFramework for all targets (iOS device, iOS simulator arm + x86_64, macOS).

Requires Xcode command-line tools and Rust via rustup — the script installs the required Rust targets automatically.

```sh
bash scripts/buildIos.sh
```

## Release Process

1. Run the build script and note the printed checksum:
   ```sh
   bash scripts/buildIos.sh
   ```

2. Tag the commit the script was run from:
   ```sh
   git tag 0.x.y
   git push origin 0.x.y
   ```

3. Create a GitHub release from that tag and upload:
   - `buildIos/MLSrs.xcframework.zip`
   - `bindings/two_mls_pqFFI.h`

   Include the checksum in the release notes.

   Example: https://github.com/germ-network/TwoMLS/releases/tag/0.0.1

## Integrating into the Demo App

The demo app is at https://github.com/germ-network/AbstractTwoMLS.

After publishing a release:

1. Copy the generated header into the app:
   ```sh
   cp bindings/two_mls_pqFFI.h /path/to/AbstractTwoMLS/
   ```

2. Update `Package.swift` in the app with the new release URL and checksum:
   ```swift
   .binaryTarget(
       name: "MLSrs",
       url: "https://github.com/germ-network/TwoMLS/releases/download/0.x.y/MLSrs.xcframework.zip",
       checksum: "<checksum printed by build script>"
   )
   ```

For local development, point `Package.swift` directly at the built framework (add `buildIos/` to `.gitignore`):
   ```swift
   .binaryTarget(
       name: "MLSrs",
       path: "../TwoMLS/buildIos/MLSrs.xcframework"
   )
   ```
