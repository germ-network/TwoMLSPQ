---
"@germ-network/two-mls-pq": minor
---

Move the MLS engine dependencies onto swift-crypto 5, as part of the org-wide
swift-crypto 5 migration. This package has no direct `swift-crypto`
requirement (its `swift-crypto` arrives through swift-mls / swift-secret-bytes);
the move is carried by revision-pinning those:

- `twomlspq-swift` → its swift-crypto-5 branch (germ-network/twomlspq-swift#60)
- `swift-mls` → its swift-crypto-5 branch (germ-network/swift-mls#103)
- `autonomous-comm-protocol` → its swift-crypto-5 branch
  (germ-network/autonomous-comm-protocol#59)
- `swift-secret-bytes` → `.upToNextMinor(from: "0.5.0")` (its swift-crypto-5
  release)

All revision pins are temporary; replace with released versions once each cuts.

No source changes were required. (Note: `swift build` on a macOS host fails in
`Sources/TwoMLSPQBinding` on a UniFFI-bindings/xcframework mismatch; that
failure is identical on `main` and predates this change.)
