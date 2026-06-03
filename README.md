# TwoMLSPQ

Germ Network's implementation of 1:1 encrypted messaging sessions built on two asymmetric MLS send groups (Distributed MLS — draft-xue-distributed-mls).

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
cargo build                        # compile
cargo test                         # run tests
cargo clippy --all-targets         # lint
cargo fmt --all -- --check         # format check
```

## UniFFI bindings (Swift)

```sh
cargo build --package two-mls-pq
cargo run --package uniffi-bindgen -- generate \
    target/debug/libtwo_mls_pq.dylib \
    --library --language swift --out-dir bindings
```

## iOS XCFramework

```sh
bash scripts/buildIos.sh
```

Requires `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `x86_64-apple-ios` Rust targets installed, plus Xcode command-line tools.
