---
"@germ-network/two-mls-pq": patch
---

Bump the exact twomlspq-swift pin to 0.1.3 (the deployed combiner-blob wire codec — `CombinerKeyPackage(publishedBlob:)`/`publishedBlob()`, byte-compatible with this repo's Rust `encode_combiner_key_package`) so Rust-free consumers (the reduced Android build) share one copy of the package; pins mirror so no resolution conflict arises.
