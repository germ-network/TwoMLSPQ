---
"@germ-network/two-mls-pq": patch
---

Loosen the twomlspq-swift requirement from `.exact("0.1.1")` to `.upToNextMinor(from: "0.1.1")`. Library deps stay ranged: the exact pin was what forced a coordinated release of this repo every time a dep patch landed (twomlspq-swift 0.1.3's additive combiner-blob wire codec, needed by the Rust-free reduced Android build, was unresolvable against it). Patches here are additive, so the minor range is safe; exactness belongs to the app-level repo.
