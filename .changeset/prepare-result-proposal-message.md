---
"@germ-network/two-mls-pq": minor
---

`PrepareEncryptResult` gains `proposal_message: Vec<u8>` (Swift: `proposalMessage: Data`) — the raw staged Upd(self) proposal, the exact message the paired `encrypt` staples and the peer independently digests.

**⚠️ Binding contract 13 → 14 — binding and binary MUST pair.** Take `two_mls_pq.swift` from this release (a Record shape change; a stale pairing mis-reads FFI buffers). No wire, archive, or semantic change — persisted state carries over.

Unblocks the anchor "agent handoff" flow: the app signs over its own `sha256(proposal_message)`, which equals the same result's `proposal_hash` and the receiver's independently derived `QueuedRemoteProposal.digest` (cross-side coherence, covered by new tests — including at the establishment moment, before any peer frame). Bytes and digest come from the same critical section, so there is deliberately NO staged-slot getter: a decoupled read could return whatever Upd a later `prepare_to_encrypt` staged (routine self-refreshes included), and a signature input must not be exposed to that race.
