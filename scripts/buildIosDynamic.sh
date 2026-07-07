#!/usr/bin/env bash
#
# Dynamic framework-bundle build. Produces a dynamic (cdylib) xcframework packaged as
# `.framework` bundles so TwoMLSPQ can coexist in one app with the legacy classical
# static MLSrs lib. Two independent reasons both require this shape:
#
#   1. dynamic (cdylib) keeps Rust std's symbols internal — avoids the
#      `duplicate symbol _rust_eh_personality` link error (a cdylib exports 0).
#   2. framework packaging keeps the clang `module.modulemap` INSIDE the framework
#      (`two_mls_pqFFI.framework/Modules/`), not in the shared build `include/` dir.
#      A `-library … -headers …` xcframework dumps `module.modulemap` into `include/`,
#      which collides with the other uniffi xcframework:
#      "Multiple commands produce …/include/module.modulemap".
#
# The framework + clang module is named `two_mls_pqFFI` (matches the generated Swift's
# `import two_mls_pqFFI`); the xcframework wrapper is `TwoMLSPQ.xcframework`.
#
# Full validation = consume this xcframework from AbstractTwoMLS and build a real
# device/archive (embedded-framework code-signing). See ROADMAP Phase 0.3/0.4.
set -euo pipefail

CARGO="$HOME/.cargo/bin/cargo"
RUSTUP="$HOME/.cargo/bin/rustup"
CRATE="two-mls-pq"
LIB_NAME="libtwo_mls_pq"              # cargo output: <LIB_NAME>.dylib
MODULE="two_mls_pqFFI"               # framework + clang module name
FRAMEWORK="TwoMLSPQ"                 # xcframework name
BINDINGS_DIR="./bindings"
BUILD_DIR="./buildIos"
FW_DIR="$BUILD_DIR/frameworks"
INSTALL_NAME="@rpath/${MODULE}.framework/${MODULE}"

# Real ML-KEM-768 (AWS-LC) — the PQ half the coexistence check exercises.
BUILD_FLAGS=(--release --package "$CRATE" --no-default-features --features cryptokit)

# Swift build-system shim. mls-rs-crypto-cryptokit's build.rs runs a bare `swift build`
# and then links libcryptokit-bridge.a from the legacy SwiftPM layout
# (.build/<unversioned-triple>/<profile>/). Xcode 16.3+/Swift 6.4 changed the default
# engine to "swiftbuild", which instead emits to .build/out/Products/<Config>/ — so the
# link fails with `could not find native static library cryptokit-bridge`. We can't pass
# flags into that nested invocation, so shim `swift build` to force the legacy "native"
# engine, restoring the path build.rs expects. (native is deprecated but still present;
# this is a stopgap until the crate's build.rs learns the new layout.)
SHIM_DIR="$(mktemp -d)"
trap 'rm -rf "$SHIM_DIR"' EXIT
REAL_SWIFT="$(xcrun -f swift)"
cat > "$SHIM_DIR/swift" <<SHIM
#!/usr/bin/env bash
if [ "\${1:-}" = "build" ]; then
    shift
    exec "$REAL_SWIFT" build --build-system native "\$@"
fi
exec "$REAL_SWIFT" "\$@"
SHIM
chmod +x "$SHIM_DIR/swift"
export PATH="$SHIM_DIR:$PATH"

# Ensure all required targets are installed
"$RUSTUP" target add \
    aarch64-apple-ios-sim \
    aarch64-apple-ios \
    x86_64-apple-ios \
    aarch64-apple-darwin || true

# Clean previous artifacts
rm -rf "$BUILD_DIR/$FRAMEWORK.xcframework" "$BUILD_DIR/$FRAMEWORK.xcframework.zip" "$FW_DIR" || true
mkdir -p "$BUILD_DIR" "$FW_DIR"

# Release cdylib builds (iOS device + simulator + macOS).
"$CARGO" build "${BUILD_FLAGS[@]}" --target=aarch64-apple-ios-sim
IPHONEOS_DEPLOYMENT_TARGET=17.0 "$CARGO" build "${BUILD_FLAGS[@]}" --target=aarch64-apple-ios
"$CARGO" build "${BUILD_FLAGS[@]}" --target=x86_64-apple-ios  # XCode Cloud runs x86_64
MACOSX_DEPLOYMENT_TARGET=15.0   "$CARGO" build "${BUILD_FLAGS[@]}" --target=aarch64-apple-darwin

# Generate Swift bindings from the device dylib
"$CARGO" run -p uniffi-bindgen --bin uniffi-bindgen \
    generate --library "target/aarch64-apple-ios/release/${LIB_NAME}.dylib" \
    --language swift \
    --out-dir "$BINDINGS_DIR"

# framework-scoped module map — lives inside each framework's Modules/, never include/.
MODMAP="framework module ${MODULE} {
    header \"${MODULE}.h\"
    export *
}"

# $1 = MinimumOSVersion, $2 = platform (CFBundleSupportedPlatforms)
make_plist() {
cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleExecutable</key><string>${MODULE}</string>
<key>CFBundleIdentifier</key><string>network.germ.${FRAMEWORK}</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>${MODULE}</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>MinimumOSVersion</key><string>${1}</string>
<key>CFBundleSupportedPlatforms</key><array><string>${2}</string></array>
</dict></plist>
EOF
}

# Flat framework (iOS device / simulator).  $1 dylib  $2 dest-parent  $3 minOS  $4 platform
flat_fw() {
  local dylib="$1" dir="$2/${MODULE}.framework"
  mkdir -p "$dir/Headers" "$dir/Modules"
  cp "$dylib" "$dir/${MODULE}"
  install_name_tool -id "$INSTALL_NAME" "$dir/${MODULE}"
  cp "$BINDINGS_DIR/${MODULE}.h" "$dir/Headers/"
  printf '%s\n' "$MODMAP" > "$dir/Modules/module.modulemap"
  make_plist "$3" "$4" > "$dir/Info.plist"
}

# Versioned framework (macOS).  $1 dylib  $2 dest-parent
versioned_fw() {
  local dylib="$1" base="$2/${MODULE}.framework" V="$2/${MODULE}.framework/Versions/A"
  mkdir -p "$V/Headers" "$V/Modules" "$V/Resources"
  cp "$dylib" "$V/${MODULE}"
  install_name_tool -id "$INSTALL_NAME" "$V/${MODULE}"
  cp "$BINDINGS_DIR/${MODULE}.h" "$V/Headers/"
  printf '%s\n' "$MODMAP" > "$V/Modules/module.modulemap"
  make_plist "15.0" "MacOSX" > "$V/Resources/Info.plist"
  ln -sf A "$base/Versions/Current"
  ln -sf "Versions/Current/${MODULE}" "$base/${MODULE}"
  ln -sf Versions/Current/Headers "$base/Headers"
  ln -sf Versions/Current/Modules "$base/Modules"
  ln -sf Versions/Current/Resources "$base/Resources"
}

# iOS device
flat_fw "target/aarch64-apple-ios/release/${LIB_NAME}.dylib" "$FW_DIR/ios" "17.0" "iPhoneOS"

# iOS simulator (lipo arm64 + x86_64 — XCode Cloud runs x86_64)
# https://forums.developer.apple.com/forums/thread/711294?answerId=722588022#722588022
mkdir -p "$FW_DIR/sim-build"
lipo -create -output "$FW_DIR/sim-build/${LIB_NAME}.dylib" \
    "target/aarch64-apple-ios-sim/release/${LIB_NAME}.dylib" \
    "target/x86_64-apple-ios/release/${LIB_NAME}.dylib"
flat_fw "$FW_DIR/sim-build/${LIB_NAME}.dylib" "$FW_DIR/sim" "17.0" "iPhoneSimulator"

# macOS
versioned_fw "target/aarch64-apple-darwin/release/${LIB_NAME}.dylib" "$FW_DIR/macos"

xcodebuild -create-xcframework \
    -framework "$FW_DIR/ios/${MODULE}.framework" \
    -framework "$FW_DIR/sim/${MODULE}.framework" \
    -framework "$FW_DIR/macos/${MODULE}.framework" \
    -output "$BUILD_DIR/$FRAMEWORK.xcframework"

cd "$BUILD_DIR"
zip -r "$FRAMEWORK.xcframework.zip" "$FRAMEWORK.xcframework"
swift package compute-checksum "$FRAMEWORK.xcframework.zip"
