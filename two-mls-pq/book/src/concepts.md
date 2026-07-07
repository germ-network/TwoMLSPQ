# Concepts

## The object model: one mls-rs client vs. three TwoMLSPQ objects

mls-rs centralizes everything behind one long-lived `Client` per credential: it
generates key packages, creates and joins groups, and owns the storage providers
(key packages, group state, PSKs) that every operation reads and writes. Persisting
an mls-rs application means persisting that one client's providers, and all
operations for a credential funnel through the one object.

TwoMLSPQ deliberately breaks this up into three app-facing objects, each owning
exactly the state its job needs:

- **`TwoMlsPqClient`** — the agent identity. Its job is minting key packages and
  invitations and holding their private material only until it is captured into an
  invitation (`generate_invitation` purges the client's own copies). It is not a
  hub for group operations.
- **`TwoMlsPqInvitation`** — a self-contained receiving capability: one published
  combiner key package's private material, the signing identity, and the
  consumed-remote replay guard. It turns welcomes into sessions with no live client
  and survives restarts through its own archive.
- **`TwoMlsPqSession`** — one established pairwise channel: the two Combiner
  send/receive group pairs and the per-round state.

Internally the invitation and the session still drive mls-rs clients — the
invitation rebuilds a stateless one from its captured material on each `receive`,
and a session holds the client backing its groups (plus the successor client staged
by an agent rotation) — but those are hidden plumbing, never handed to the app.

The consequence is that persistence is **per-object, not per-client**: each object
serialises what it owns (`TwoMlsPqInvitation.archive()` today; session archives are
[planned work](./planned-features.md)). There is no mls-rs-style "restore the
client and find your groups again" path — you restore an invitation or a session.

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
the classical half into the PQ half (and into the peer's groups). An attacker must
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
