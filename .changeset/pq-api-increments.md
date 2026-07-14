---
"@germ-network/abstract-two-mls": minor
---

TwoMLSPQ backend: routing (shouldListenOn/sendRendezvous), the APQ epoch pair on
encrypt results, A.5 rekey, principal rotation (staging at receive, candidates
proposed via prepareToEncrypt(proposing:) with the peer's approval —
queueProposal — plus commit canonicalizing the handoff, and the PQ-leaf catch-up
via begin(rotating:)), forward routing for replayed initial frames (spawn-token
table + forwarded acknowledgment), and the raw-digest FFI convention. Binary
pinned to the TwoMLSPQ v0.0.13 release (binding contract 12 —
draft-ietf-mls-combiner-02 conformant: APQInfo, AppDataUpdate epoch attestation,
SafeExportSecret application PSKs, event-driven cross-party injection; both
halves run on Apple CryptoKit). Also in this pin: single-use vs last-resort
invitations via `generateInvitation(lastResort:)` (AbstractTwoMLS mints
last-resort invitations — reusable across many initiators, preserving
forward-routing of replayed initial frames; a spent single-use invitation would
fail `InvitationSpent`), the fixed/validated session cipher-suite binding
(`CipherSuiteMismatch`), the id-based `stageRotation(newClientId:)`, and the
Identity→Principal terminology rename (`TwoMlsPqPrincipal`, `myPrincipalState`).

Platform floors stay `.iOS(.v17)/.macOS(.v15)`: the package imports and links on
those OSes; the OS 26 requirement (CryptoKit ML-KEM-768) applies only at runtime
to the PQ API paths.
