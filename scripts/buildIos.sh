#!/usr/bin/env bash
set -euo pipefail

CARGO="$HOME/.cargo/bin/cargo"
RUSTUP="$HOME/.cargo/bin/rustup"
FRAMEWORK="MLSrs"
BINDINGS_DIR="./bindings"
BUILD_DIR="./buildIos"

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

# Debug build + generate Swift bindings
"$CARGO" build
"$CARGO" run -p uniffi-bindgen --bin uniffi-bindgen \
    generate --library ./target/debug/libtwo_mls_pq.dylib \
    --language swift \
    --out-dir "$BINDINGS_DIR"

mv "$BINDINGS_DIR/two_mls_pqFFI.modulemap" "$BINDINGS_DIR/module.modulemap"

# Release builds
"$CARGO" build --release --target=aarch64-apple-ios-sim
IPHONEOS_DEPLOYMENT_TARGET=17.0 "$CARGO" build --release --target=aarch64-apple-ios
MACOS_DEPLOYMENT_TARGET=10_15   "$CARGO" build --release --target=aarch64-apple-darwin
"$CARGO" build --release --target=x86_64-apple-ios  # XCode Cloud runs x86_64

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
