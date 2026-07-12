---
"@germ-network/two-mls-pq": patch
---

New non-mutating getter `TwoMlsPqSession::staged_rotation_proposal() -> Option<Vec<u8>>` (Swift: `stagedRotationProposal() -> Data?`): the raw bytes of the staged outbound Upd(self) proposal — the exact message the next `encrypt` staples and the peer independently digests. `Some` between the `prepare_to_encrypt` that materializes the Upd and the `encrypt` that consumes it; `None` otherwise (`stage_rotation` alone does not materialize the proposal).

Unblocks the anchor "agent handoff" flow: the app signs over its own `sha256(bytes)`, which equals both the sender's `PrepareEncryptResult.proposal_hash` and the receiver's independently derived `QueuedRemoteProposal.digest` (cross-side coherence, covered by a new test). Binding rule for signers: assert `sha256(bytes)` equals the `proposal_hash` from your own `prepare_to_encrypt(Some(id))` — the slot holds whatever Upd the last prepare staged, including routine self-refreshes.

Additive only — no wire, archive, or binding-contract change (contract stays 13; uniffi's load-time checksum covers the new method).
