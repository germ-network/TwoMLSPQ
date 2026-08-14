---
"@germ-network/two-mls-pq": patch
---

Add the dual MIT/Apache-2.0 license and fill in package metadata.

The repository was public with no license file, while `rust/Cargo.toml` already declared
`license = "MIT OR Apache-2.0"`. This adds `LICENSE-MIT` and `LICENSE-APACHE` so that
declaration is backed by actual license text, and states the inbound contribution terms in
`CONTRIBUTING.md` and `README.md`.

Also corrects documentation that still referred to `Sources/AbstractTwoMLS/` (moved to a
separate package) and to the vendored binding's old location — including the path in the
binding-contract mismatch error, which pointed developers at the wrong file to re-sync.
