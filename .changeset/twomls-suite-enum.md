---
"@germ-network/two-mls-pq": minor
---

One declared TwoMLS suite drives every crypto choice, and the §A.1 envelope binds it via
untransmitted AAD (contract 22).

The scattered suite constants collapse into one up-front declaration (the internal
`TwoMlsSuite` enum): the group pair (`APQ_SUITE`), the §A.1/A.4 envelope HPKE (PQ half),
the header-encryption AEAD (classical half's ChaCha20-Poly1305 — no longer an
"independent variable"), and the protocol digest (classical half's SHA-256) are all
facets read from `TwoMlsSuite::CURRENT`. Behavior-preserving: every facet equals the
previously pinned value.

The §A.1 envelope HPKE now BINDS the declared suite: both sides derive
`[framing version (1)][classical u16 BE][pq u16 BE]` locally and pass it as the HPKE
`aad` — it never travels the wire (the posted `APQKeyPackage` already names the pair
publicly, and the opener's invitation defines the suite of every inbound envelope). The
blob shape is byte-for-byte unchanged; the cut is cryptographic: a contract-21 seal
(`aad = None`) fails a contract-22 open's AEAD tag and vice versa (`DecryptionFailed`,
deliberately opaque). This downgrade-binds the CLASSICAL half too — which the HPKE
operation alone never touches — at zero wire bytes. New export `envelope_framing_aad()`
for hosts on the split `hpke_open` + `decode_initial_plaintext` path;
`BINDING_CONTRACT_VERSION` 21 → 22.
