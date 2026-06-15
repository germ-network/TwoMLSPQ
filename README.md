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
two-mls-pq/          Core library
uniffi-bindgen/   UniFFI binding generator
scripts/          iOS build tooling
bindings/         Generated Swift output (after build)
buildIos/         XCFramework output (after build)
```

## Building

```sh
# Default build (RustCrypto, no ML-KEM-768)
cargo test

# With ML-KEM-768 via AWS-LC (macOS, for local testing)
cargo test -p two-mls-pq --features cryptokit

cargo clippy
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

```sh
bash scripts/buildIos.sh
```

Requires `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `x86_64-apple-ios` Rust targets installed, plus Xcode command-line tools.
