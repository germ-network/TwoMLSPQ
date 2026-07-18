#!/usr/bin/env bash
set -euo pipefail

# Local build-and-test loop — the thing that REPLACES publish-a-release-to-test. Builds the
# dynamic xcframework from the in-repo Rust workspace, re-syncs the vendored Swift binding
# from that SAME build, and runs the Swift tests against the local framework (no release, no
# checksum wait). Requires a macOS 26 host + Xcode toolchain (cryptokit ML-KEM-768).
#
# Any extra args are forwarded to `swift test` (e.g. --filter LifecycleTests).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 1. Build the local xcframework (writes buildIos/ + bindings/ at the repo root; installs the
#    required rust targets itself).
bash scripts/buildIosDynamic.sh

# 2. Re-sync the vendored binding from the SAME build. uniffi embeds a checksum contract and
#    the binding_contract_version canary compares against the linked binary, so the binding
#    and the framework must come from one build.
cp bindings/two_mls_pq.swift Sources/TwoMLSPQ/two_mls_pq.swift

export TWOMLSPQ_LOCAL_XCFRAMEWORK=1

# 3. Build the tests, then run them.
swift build --build-tests

# SwiftPM does not copy a dynamic binaryTarget's framework into the test bundle's @rpath
# (PackageFrameworks/), so dlopen fails with "Library not loaded:
# @rpath/two_mls_pqFFI.framework/two_mls_pqFFI". Symlink the macOS framework slice in before
# running. (Remove this once SwiftPM stages dynamic binaryTarget frameworks itself.)
PF=".build/out/Products/Debug/PackageFrameworks"
mkdir -p "$PF"
ln -sf "$ROOT/buildIos/TwoMLSPQ.xcframework/macos-arm64/two_mls_pqFFI.framework" \
    "$PF/two_mls_pqFFI.framework"

swift test --skip-build "$@"
