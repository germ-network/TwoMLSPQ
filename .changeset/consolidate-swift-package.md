---
"@germ-network/two-mls-pq": minor
---

Consolidate the AbstractTwoMLS Swift package into this repository.

The hand-written Swift wrapper that was maintained in a separate repo now lives here
(`Package.swift`, `Sources/`, `Tests/`), with the Rust/UniFFI core relocated under `rust/`.
A wire change and its Swift adapter land in one PR, tested against a LOCAL xcframework build:
`Package.swift`'s `TwoMLSPQrs` binary target reads the local `buildIos/` build when
`TWOMLSPQ_LOCAL_XCFRAMEWORK` is set and falls back to the pinned release url+checksum
otherwise. The release tag `vX.Y.Z` remains the xcframework version the app resolves. The
shipped packaging is unchanged (dynamic framework bundles); the legacy classical MLSrs target
is dropped from this repo (the adopting app still links it on its own).
