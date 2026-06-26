default:
    @just --list

check:
    cargo check --all-targets --all-features

lint: lint-rust lint-toml

lint-rust:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo deny check

lint-toml:
    taplo fmt --check

format:
    cargo fmt --all
    taplo fmt

test:
    cargo test --all-features

bench:
    cargo bench -p two-mls-pq --features benchmark_util

bench-pq:
    cargo bench -p two-mls-pq --features "benchmark_util cryptokit"
bindgen:
    cargo build --package two-mls-pq
    cargo run --package uniffi-bindgen -- generate \
        target/debug/libtwo_mls_pq.dylib \
        --library --language swift --out-dir bindings

build-ios:
    bash scripts/buildIos.sh

# Requires `cargo install mdbook` (and optionally mdbook-mermaid; see book/book.toml).
book:
    mdbook build two-mls-pq/book

book-serve:
    mdbook serve two-mls-pq/book
