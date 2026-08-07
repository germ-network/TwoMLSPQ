#!/usr/bin/env bash
#
# Builds the Android half of TwoMLSPQ: `libtwo_mls_pq.a` per ABI, packaged as an SE-0482
# artifactbundle that `Package.swift` consumes as a binaryTarget.
#
# WHY STATIC, when iOS ships a dynamic xcframework. SwiftPM's `ArtifactsArchiveMetadata`
# has no `dynamicLibrary` artifact type — `staticLibrary` is the only library form a
# binaryTarget can vend off-Apple (SE-0482, Swift 6.2). xcframeworks are not an option
# either: SwiftPM maps the android environment to nil and resolves ZERO libraries from
# one, silently. So the two platforms ship separate products from the same crate.
#
# WHY A HAND-WRITTEN MODULEMAP. uniffi emits one, but it carries `use "Darwin"` — the
# module fails to build against the Android SDK. The one written below is the same module
# without the Apple-only `use` lines.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/buildAndroid"
BUNDLE="$OUT/TwoMLSPQ-android.artifactbundle"
API="${ANDROID_API:-28}"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME (r27d = 27.3.13750724 is what the Swift SDK pins)}"

# 16 KB page alignment: NDK r27 does NOT default to it (r28 does), and Android 15+ requires
# it. The Swift SDK passes -z max-page-size=16384 for the SWIFT link, which does not cover
# a cdylib cargo links itself, so pass it here too and verify below.
#
# Per-target, NOT plain RUSTFLAGS: the header-generation step below is a native macOS build,
# and ld64 rejects `-z` outright ("unknown options: -z -z").
ALIGN_FLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="$ALIGN_FLAGS"
export CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS="$ALIGN_FLAGS"

# aws-lc-sys has no checked-in bindings for x86_64-linux-android and falls back to CMake,
# which cannot find the NDK. two-mls-pq/Cargo.toml enables `bindgen` for that one target;
# this forces the cc builder so CMake is never consulted. Needs `cargo install bindgen-cli`.
export AWS_LC_SYS_CMAKE_BUILDER=0

declare -a ABIS=("arm64-v8a:aarch64-linux-android:aarch64-unknown-linux-android"
                 "x86_64:x86_64-linux-android:x86_64-unknown-linux-android")

echo "==> building $API for ${#ABIS[@]} ABIs"
cd "$REPO_ROOT/rust"
for entry in "${ABIS[@]}"; do
	abi="${entry%%:*}"
	cargo ndk -t "$abi" -P "$API" build --release -p two-mls-pq --features awslc
done

echo "==> generating the FFI header"
# Library mode cannot read an ELF cdylib, so generate from a host build. The FFI contract is
# target- AND provider-independent (an awslc build emits the same binding as a cryptokit one),
# so this header describes the Android libraries correctly.
cargo build -q -p two-mls-pq --features awslc
BINDINGS="$(mktemp -d)"
cargo run -q -p uniffi-bindgen --bin uniffi-bindgen -- generate \
	--library target/debug/libtwo_mls_pq.dylib --language swift --out-dir "$BINDINGS"

echo "==> assembling $BUNDLE"
rm -rf "$BUNDLE"
variants=""
for entry in "${ABIS[@]}"; do
	rust_triple="$(echo "$entry" | cut -d: -f2)"
	swift_triple="$(echo "$entry" | cut -d: -f3)"
	arch="${rust_triple%%-*}"
	mkdir -p "$BUNDLE/$arch/Headers"
	cp "target/$rust_triple/release/libtwo_mls_pq.a" "$BUNDLE/$arch/"
	cp "$BINDINGS/two_mls_pqFFI.h" "$BUNDLE/$arch/Headers/"
	cat > "$BUNDLE/$arch/Headers/module.modulemap" <<-MODULEMAP
		module two_mls_pqFFI {
		    header "two_mls_pqFFI.h"
		    export *
		}
	MODULEMAP
	# One entry per architecture covers every API level: SwiftPM compares the triple's
	# environment by prefix, so "…-android" matches "…-android28" through "…-android36".
	variants="$variants{\"path\":\"$arch/libtwo_mls_pq.a\",\"supportedTriples\":[\"$swift_triple\"],\"staticLibraryMetadata\":{\"headerPaths\":[\"$arch/Headers\"],\"moduleMapPath\":\"$arch/Headers/module.modulemap\"}},"
done

VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$REPO_ROOT/package.json" | head -1)"
cat > "$BUNDLE/info.json" <<-JSON
	{"schemaVersion":"1.0","artifacts":{"TwoMLSPQrsAndroid":{"version":"${VERSION:-0.0.0}","type":"staticLibrary","variants":[${variants%,}]}}}
JSON
python3 -m json.tool "$BUNDLE/info.json" > "$BUNDLE/info.json.tmp" && mv "$BUNDLE/info.json.tmp" "$BUNDLE/info.json"

echo "==> verifying"
READELF="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf"
for entry in "${ABIS[@]}"; do
	rust_triple="$(echo "$entry" | cut -d: -f2)"
	so="target/$rust_triple/release/libtwo_mls_pq.so"
	bad="$("$READELF" -lW "$so" | awk '$1=="LOAD"{print $NF}' | grep -cv '^0x4000$' || true)"
	[ "$bad" -eq 0 ] || { echo "FAIL: $rust_triple has PT_LOAD segments not 16 KB aligned"; exit 1; }
	printf '  %-24s .a %10d bytes   .so %9d bytes   16KB-aligned\n' \
		"$rust_triple" "$(stat -f%z "target/$rust_triple/release/libtwo_mls_pq.a")" "$(stat -f%z "$so")"
done

echo "==> done: $BUNDLE"
