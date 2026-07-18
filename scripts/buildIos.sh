#!/usr/bin/env bash
set -euo pipefail

# Static-library xcframework build (the FUTURE static-packaging seed; NOT the shipped flow).
# The supported release is the dynamic framework bundle — scripts/buildIosDynamic.sh (+ its
# Swift twin scripts/buildIos.swift). This static `-library`/`-headers` xcframework is kept
# only as the starting point for once-the-app-drops-legacy static packaging; it predates the
# coexistence requirement and the cryptokit-bridge shim/purge, so it is not currently wired
# into CI or the justfile.
#
# Paths mirror the dynamic script: cargo runs in the workspace (rust/) so its
# .cargo/config.toml + rust-toolchain.toml resolve; bindings + xcframework land at the repo
# root. `target/…` below is relative to the workspace cwd (= rust/target).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="$ROOT/rust"

CARGO="$HOME/.cargo/bin/cargo"
RUSTUP="$HOME/.cargo/bin/rustup"
FRAMEWORK="MLSrs"
BINDINGS_DIR="$ROOT/bindings"
BUILD_DIR="$ROOT/buildIos"

cd "$WORKSPACE"

# Ensure all required targets are installed
"$RUSTUP" target add \
    aarch64-apple-ios-sim \
    aarch64-apple-ios \
    x86_64-apple-ios \
    aarch64-apple-darwin || true

# Clean previous artifacts
rm -rf "$BUILD_DIR/$FRAMEWORK.xcframework" || true
rm -f  "$BUILD_DIR/$FRAMEWORK.xcframework.zip" || true
rm -f  "$BUILD_DIR/libtwo_mls_pq_sim_combined.a" || true

"$CARGO" clean

mkdir -p "$BUILD_DIR"

# Debug build + generate Swift bindings. The shipped configuration is CryptoKit for
# both halves (see rust/two-mls-pq/src/providers.rs).
"$CARGO" build --features two-mls-pq/cryptokit
"$CARGO" run -p uniffi-bindgen --bin uniffi-bindgen \
    generate --library ./target/debug/libtwo_mls_pq.dylib \
    --language swift \
    --out-dir "$BINDINGS_DIR"

mv "$BINDINGS_DIR/two_mls_pqFFI.modulemap" "$BINDINGS_DIR/module.modulemap"

# Release builds
"$CARGO" build --release --features two-mls-pq/cryptokit --target=aarch64-apple-ios-sim
IPHONEOS_DEPLOYMENT_TARGET=17.0 "$CARGO" build --release --features two-mls-pq/cryptokit --target=aarch64-apple-ios
MACOS_DEPLOYMENT_TARGET=10_15   "$CARGO" build --release --features two-mls-pq/cryptokit --target=aarch64-apple-darwin
"$CARGO" build --release --features two-mls-pq/cryptokit --target=x86_64-apple-ios  # XCode Cloud runs x86_64

# Combine arm + x86_64 simulator slices (required for XCode Cloud)
# https://forums.developer.apple.com/forums/thread/711294?answerId=722588022#722588022
lipo -create \
    -output "$BUILD_DIR/libtwo_mls_pq_sim_combined.a" \
    ./target/aarch64-apple-ios-sim/release/libtwo_mls_pq.a \
    ./target/x86_64-apple-ios/release/libtwo_mls_pq.a

xcodebuild -create-xcframework \
    -library "$BUILD_DIR/libtwo_mls_pq_sim_combined.a" -headers "$BINDINGS_DIR" \
    -library ./target/aarch64-apple-ios/release/libtwo_mls_pq.a  -headers "$BINDINGS_DIR" \
    -library ./target/aarch64-apple-darwin/release/libtwo_mls_pq.a -headers "$BINDINGS_DIR" \
    -output "$BUILD_DIR/$FRAMEWORK.xcframework"

cd "$BUILD_DIR"
zip -r "$FRAMEWORK.xcframework.zip" "$FRAMEWORK.xcframework"
swift package compute-checksum "$FRAMEWORK.xcframework.zip"
