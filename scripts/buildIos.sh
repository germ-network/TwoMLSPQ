#!/usr/bin/env bash
set -euo pipefail

CRATE="two-mls-pq"
LIB_NAME="libtwo_mls_pq"
FRAMEWORK_NAME="TwoMLSPQ"
OUT_DIR="buildIos"
BINDINGS_DIR="bindings"

TARGETS=(
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "x86_64-apple-ios"
)

for target in "${TARGETS[@]}"; do
    echo "Building $target..."
    cargo build --release --target "$target" --package "$CRATE" --no-default-features --features cryptokit
done

echo "Generating UniFFI bindings..."
cargo run --package uniffi-bindgen -- generate \
    "target/aarch64-apple-ios/release/${LIB_NAME}.a" \
    --library \
    --language swift \
    --out-dir "$BINDINGS_DIR"

echo "Running swift-format on generated bindings..."
if command -v swift-format &>/dev/null; then
    swift-format format --in-place "$BINDINGS_DIR"/*.swift
fi

echo "Assembling XCFramework..."
rm -rf "${OUT_DIR}/${FRAMEWORK_NAME}.xcframework"

xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/release/${LIB_NAME}.a" \
    -headers "$BINDINGS_DIR" \
    -library "target/aarch64-apple-ios-sim/release/${LIB_NAME}.a" \
    -headers "$BINDINGS_DIR" \
    -library "target/x86_64-apple-ios/release/${LIB_NAME}.a" \
    -headers "$BINDINGS_DIR" \
    -output "${OUT_DIR}/${FRAMEWORK_NAME}.xcframework"

echo "Done: ${OUT_DIR}/${FRAMEWORK_NAME}.xcframework"
