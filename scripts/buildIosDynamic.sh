#!/usr/bin/env bash
#
# Dynamic-framework build (Phase 0.3). Produces a dynamic (cdylib) xcframework so TwoMLSPQ
# and the legacy classical lib can coexist in one app without the
# `duplicate symbol _rust_eh_personality` link error — a dynamic lib keeps std's symbols
# internal (verified: the cdylib exports 0 `rust_eh_personality`).
#
# Differs from buildIos.sh only in shipping the `.dylib` (cdylib) instead of the `.a`
# (staticlib), with an @rpath install-name so the consuming app can embed it. The clang
# module name stays `two_mls_pqFFI` (via the generated `bindings/`), so the generated Swift
# is unchanged. Only TwoMLSPQ needs to be dynamic; the legacy framework stays static.
#
# Full validation = consume this xcframework from AbstractTwoMLS and build a real
# device/archive (embedded-framework code-signing). See ROADMAP Phase 0.3/0.4.
set -euo pipefail

CARGO="$HOME/.cargo/bin/cargo"
RUSTUP="$HOME/.cargo/bin/rustup"
CRATE="two-mls-pq"
LIB_NAME="libtwo_mls_pq"          # cargo output: <LIB_NAME>.dylib
FRAMEWORK="TwoMLSPQ"
BINDINGS_DIR="./bindings"
BUILD_DIR="./buildIos"
INSTALL_NAME="@rpath/${LIB_NAME}.dylib"

# Real ML-KEM-768 (AWS-LC) — the PQ half the coexistence check exercises.
BUILD_FLAGS=(--release --package "$CRATE" --no-default-features --features cryptokit)

# Ensure all required targets are installed
"$RUSTUP" target add \
    aarch64-apple-ios-sim \
    aarch64-apple-ios \
    x86_64-apple-ios \
    aarch64-apple-darwin || true

# Clean previous artifacts
rm -rf "$BUILD_DIR/$FRAMEWORK.xcframework" || true
rm -f  "$BUILD_DIR/$FRAMEWORK.xcframework.zip" || true

mkdir -p "$BUILD_DIR"

# Release cdylib builds
"$CARGO" build "${BUILD_FLAGS[@]}" --target=aarch64-apple-ios-sim
IPHONEOS_DEPLOYMENT_TARGET=17.0 "$CARGO" build "${BUILD_FLAGS[@]}" --target=aarch64-apple-ios
"$CARGO" build "${BUILD_FLAGS[@]}" --target=x86_64-apple-ios  # XCode Cloud runs x86_64
MACOS_DEPLOYMENT_TARGET=10_15   "$CARGO" build "${BUILD_FLAGS[@]}" --target=aarch64-apple-darwin

# @rpath-relative install-name on every slice so the consuming app can embed + load it
for target in aarch64-apple-ios-sim aarch64-apple-ios x86_64-apple-ios aarch64-apple-darwin; do
    install_name_tool -id "$INSTALL_NAME" "target/$target/release/${LIB_NAME}.dylib"
done

# Generate Swift bindings from the device dylib
"$CARGO" run -p uniffi-bindgen --bin uniffi-bindgen \
    generate --library "target/aarch64-apple-ios/release/${LIB_NAME}.dylib" \
    --language swift \
    --out-dir "$BINDINGS_DIR"

mv "$BINDINGS_DIR/two_mls_pqFFI.modulemap" "$BINDINGS_DIR/module.modulemap"

# Combine arm + x86_64 simulator slices (required for XCode Cloud)
# https://forums.developer.apple.com/forums/thread/711294?answerId=722588022#722588022
SIM_DYLIB="$BUILD_DIR/${LIB_NAME}_sim_combined.dylib"
lipo -create \
    -output "$SIM_DYLIB" \
    "target/aarch64-apple-ios-sim/release/${LIB_NAME}.dylib" \
    "target/x86_64-apple-ios/release/${LIB_NAME}.dylib"
install_name_tool -id "$INSTALL_NAME" "$SIM_DYLIB"

xcodebuild -create-xcframework \
    -library "$SIM_DYLIB" -headers "$BINDINGS_DIR" \
    -library "target/aarch64-apple-ios/release/${LIB_NAME}.dylib"    -headers "$BINDINGS_DIR" \
    -library "target/aarch64-apple-darwin/release/${LIB_NAME}.dylib" -headers "$BINDINGS_DIR" \
    -output "$BUILD_DIR/$FRAMEWORK.xcframework"

cd "$BUILD_DIR"
zip -r "$FRAMEWORK.xcframework.zip" "$FRAMEWORK.xcframework"
swift package compute-checksum "$FRAMEWORK.xcframework.zip"
