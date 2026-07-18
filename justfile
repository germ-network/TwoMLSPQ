default:
    @just --list

# Cargo recipes run inside the workspace (rust/) so its .cargo/config.toml and
# rust-toolchain.toml — both discovered from the cwd, not the manifest — take effect.
check:
    cd rust && cargo check --all-targets --all-features

lint: lint-rust lint-toml

lint-rust:
    cd rust && cargo fmt --all -- --check
    cd rust && cargo clippy --all-targets --all-features -- -D warnings
    cd rust && cargo deny check

lint-toml:
    cd rust && taplo fmt --check

format:
    cd rust && cargo fmt --all
    cd rust && taplo fmt

test:
    cd rust && cargo test --all-features

# NB: the --all-features recipes above assume an Apple host (cryptokit is Apple-only and
# wins the provider precedence there); on Linux use explicit `--features awslc,…` instead.

bench:
    cd rust && cargo bench -p two-mls-pq --features "benchmark_util awslc"

bench-pq:
    cd rust && cargo bench -p two-mls-pq --features "benchmark_util cryptokit"

# Debug-build the binding into repo-root bindings/ (dev convenience; the released binding
# comes from scripts/buildIosDynamic.sh, not this).
bindgen:
    cd rust && cargo build --package two-mls-pq --features cryptokit
    cd rust && cargo run --package uniffi-bindgen -- generate \
        target/debug/libtwo_mls_pq.dylib \
        --library --language swift --out-dir ../bindings

# The supported iOS build: dynamic framework-bundle xcframework (writes buildIos/ + bindings/
# at the repo root, builds cargo from rust/). See scripts/buildIosDynamic.sh.
build-ios:
    bash scripts/buildIosDynamic.sh

# Local build-and-test loop (macOS 26): build the xcframework, re-sync the vendored binding,
# and run the Swift tests against the LOCAL build — no release needed. Extra args pass through
# to `swift test` (e.g. `just swift-test --filter LifecycleTests`).
swift-test *ARGS:
    bash scripts/swiftTestLocal.sh {{ARGS}}

# Requires `cargo install mdbook` (and optionally mdbook-mermaid; see book/book.toml).
book:
    mdbook build book

book-serve:
    mdbook serve book
