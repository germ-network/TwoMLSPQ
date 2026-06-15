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

build-ios:
    bash scripts/buildIos.sh

# Requires `cargo install mdbook` (and optionally mdbook-mermaid; see book/book.toml).
book:
    mdbook build two-mls-pq/book

book-serve:
    mdbook serve two-mls-pq/book
