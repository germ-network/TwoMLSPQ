---
"@germ-network/two-mls-pq": patch
---

Raise the package's iOS floor to 18.0 (was 17.0). `swift-secret-bytes` moved
to `from: "0.5.0"` (its own floor is iOS 18/macOS 15) without a matching bump
here, so `TwoMLSPQMigrate` failed to build for iOS: "the package product
'SecretBytes-product' requires minimum platform version 18.0 for the iOS
platform, but this target supports 17.0."
