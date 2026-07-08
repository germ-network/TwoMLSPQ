# Concepts

## Two asymmetric send groups

A classical MLS group is symmetric: every member can commit. TwoMLSPQ instead gives
each party a group they alone send on:

- **Group_A** — Alice's send group. Alice commits and encrypts; Bob joins and decrypts.
- **Group_B** — Bob's send group. Bob commits and encrypts; Alice joins and decrypts.

This makes the two directions independent and lets each side advance its own key
material without coordinating a shared committer.

## The Combiner / APQ construction

Each "group" above is really a **Combiner group**: a classical half (`0x0003`) and an
ML-KEM-768 half (`0xFDEA`). The two halves are bound by injecting a PSK derived from
the PQ half into the classical half at creation; a second, cross-party PSK ties each
party's send group to the group it receives on. An attacker must
break *both* halves to break the session — so the classical half keeps protecting
traffic even if ML-KEM were to fail, and vice-versa. This is the hybrid property,
achieved at the group level. See [PSK Binding](./psk-binding.md).

## Basic credentials, no AS

The MLS leaf identity is the agent's public signing key, wrapped in a Basic
Credential. There is no Authentication Service. Because basic credentials carry no
external trust, **CommProtocol cooperates on every encrypt and decrypt** — it decides
which remote proposals to accept and binds a per-round proposal hash into the
plaintext. TwoMLSPQ stages proposals and reports state changes; it does not make
trust decisions.

## The CommProtocol boundary

TwoMLSPQ receives agent signing keys and returns key packages, ciphertexts, and
structured results (`DecryptResult`, `PrepareEncryptResult`, …). Everything above —
DIDs, anchor signatures, key discovery from a PDS, sequencing/ordering of proposals,
transport — belongs to CommProtocol. Keeping that line sharp is why the API is
deliberately small and stateless about identity.
