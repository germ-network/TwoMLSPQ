---
"@germ-network/abstract-two-mls": minor
---

Bump TwoMLSPQ to v0.7.0 (contract 22): the §A.1 envelope drops its outer tag and
binds the declared cipher suite via an untransmitted AAD.

The establishment envelope is now the raw HPKE blob `[u32-LE kem-len][kem_output]
[ciphertext]` — no outer tag — so the split-open path (`decodeEnvelopeFrame`) no
longer reads `initialEnvelopeTag()` (retired). Frame-kind discrimination moved
inside the HPKE plaintext: `decodeInitialPlaintext` / `openInitial` now return
`OpenedInitial` (`.establishment(frame:)` / `.bootstrapKp(frame:)`), and the header
path requires the establishment variant. The seal now binds `[framingVersion][suite
pair]` as authenticated data, derived locally on both sides, so `hpkeOpen` on the
envelope is passed `envelopeFramingAad()` or the AEAD tag fails.

No host API change: `TwoMlsSuite` is crate-internal, and the parallel
`pqBootstrapEnvelope` is not adopted (the sequential side-band bootstrap is kept).
