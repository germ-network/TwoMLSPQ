#!/usr/bin/env bash
set -euo pipefail

# Local build loop — the thing that REPLACES publish-a-release-to-test. Builds the dynamic
# xcframework from the in-repo Rust workspace, re-syncs the vendored Swift binding from that
# SAME build, and compiles the library against the local framework (no release, no checksum
# wait). Requires a macOS 26 host + Xcode toolchain (cryptokit ML-KEM-768).
#
# This package vends the concrete TwoMLSPQ product and runs the concrete/FFI-level Swift tests
# (raw-FFI invitation flows + the TwoMlsPqError → SessionError mapping); the abstract-surface
# suite lives in the AbstractTwoMLS consumer package (with the conformances). Extra args pass
# to `swift test`.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 1. Build the local xcframework (writes buildIos/ + bindings/ at the repo root; installs the
#    required rust targets itself).
bash scripts/buildIosDynamic.sh

# 2. Re-sync the vendored binding from the SAME build. uniffi embeds a checksum contract and
#    the binding_contract_version canary compares against the linked binary, so the binding
#    and the framework must come from one build.
cp bindings/two_mls_pq.swift Sources/TwoMLSPQBinding/two_mls_pq.swift

export TWOMLSPQ_LOCAL_XCFRAMEWORK=1

# 3. Run the concrete/FFI-level suites against the local framework (SwiftPM resolves the
#    macOS binaryTarget framework's rpath for the test bundle — no dlopen dance needed).
swift test "$@"
