---
"@germ-network/two-mls-pq": patch
---

Renumber the protocol-flow sections into lifecycle order — a pure §A.3↔§A.4 swap so the bootstrap ("Finish PQ setup") precedes the KEM ratchet, matching the wire-format side-band tag order — and sweep every in-repo reference (book, Rust/Swift doc comments, test names, vendored binding) to match. Land the four surviving PR #78 cleanup findings: the bootstrap twin-field invariant and the 32-byte KP-commitment length are now validated on archive restore (existing `ArchiveInvalid`), the commitment gets an internal `[u8; 32]` newtype, and the per-push clone of the ~8 KB bootstrap KP secret is eliminated by holding it behind an `Arc`. No FFI-visible shape change (`BINDING_CONTRACT_VERSION` stays 26); `SESSION_ARCHIVE_VERSION` bumps 1→2 and now advances monotonically, so persisted v1 sessions hard-cut and regenerate.
