---
"@{owner}/{packageName}": minor
---

TwoMLSPQ backend: routing (shouldListenOn/sendRendezvous), the APQ epoch pair on
encrypt results, A.5 rekey, agent rotation (staging at receive, Phase 8 via
prepareToEncrypt(proposing:), PQ-leaf handoff via begin(rotating:)), forward routing
for replayed initial frames (spawn-token table + forwarded acknowledgment), and the
raw-digest FFI convention. Binary pinned to the TwoMLSPQ 0.0.10 release (binding
contract 5; provider-agnostic core — both halves run on Apple CryptoKit). New in this
pin: single-use vs last-resort invitations via `generateInvitation(lastResort:)`
(AbstractTwoMLS mints last-resort invitations — reusable across many initiators,
preserving forward-routing of replayed initial frames; a spent single-use invitation
would fail `InvitationSpent`), the fixed/validated session cipher-suite binding
(`CipherSuiteMismatch`), the id-based `stageRotation(newClientId:)`, and the
Identity→Principal terminology rename (`TwoMlsPqPrincipal`, `myPrincipalState`).
