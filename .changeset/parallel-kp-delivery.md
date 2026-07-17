---
"@germ-network/two-mls-pq": minor
---

Parallel A.4 KP′ delivery, and the §A.1 envelope drops its outer tag (contract 21).

The initiator can now ship its pre-committed A.4 bootstrap key package IN PARALLEL with
the establishment reply via `pq_bootstrap_envelope`, instead of waiting a full round trip
for A.4's first side-band leg. Because the KP bytes are fixed at `initiate` (contract 20),
an acceptor that already holds the KP′ when its return welcome goes out can respond and
send `Welcome'` alongside it — A.4 completes ~one round trip sooner. The first emit
registers the round exactly as `pq_bootstrap_begin` does; every later pre-establishment
send re-seals the retained frame under a fresh HPKE ephemeral (unlinkable) without
advancing state.

To carry the KP frame and the reply under one indistinguishable shape, the §A.1 envelope
loses its OUTER tag byte: the blob is now the raw `[u32-LE kem_output_len][kem_output]
[ciphertext]`, and discrimination moves INSIDE to the HPKE plaintext's authenticated
leading tag — `ESTABLISHMENT_VECTOR_TAG` (0x07, repurposing the retired outer
`INITIAL_ENVELOPE_TAG`) for the reply's four sections, `PQ_BOOTSTRAP_KP_TAG` (0x13) for
the bootstrap KP. `open_initial` / `decode_initial_plaintext` now return `OpenedInitial`
(`Establishment` / `BootstrapKp`); `initial_envelope_tag()` is retired (the host routes by
transport channel, not first byte). Wire-format change — the outer tag is gone and the
plaintext gained an inner tag — hence `BINDING_CONTRACT_VERSION` 20 → 21.
