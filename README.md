# TwoMLS

Germ Network's implementation of 1:1 encrypted messaging sessions built on two asymmetric MLS send groups (Distributed MLS — draft-xue-distributed-mls).

## Structure

```
two-mls/          Core library
uniffi-bindgen/   UniFFI binding generator
scripts/          iOS build tooling
bindings/         Generated Swift output (after build)
buildIos/         XCFramework output (after build)
```

## Building

```sh
cargo test
cargo clippy
```

## iOS XCFramework

```sh
bash scripts/buildIos.sh
```

Requires `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `x86_64-apple-ios` Rust targets installed, plus Xcode command-line tools.
