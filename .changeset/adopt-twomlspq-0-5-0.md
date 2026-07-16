---
"@germ-network/abstract-two-mls": minor
---

Adopt TwoMLSPQ v0.5.0 (binding contract 19; v17 was burned, v18 + v19 land together).

**A bind is the staple, not a frame.** A.3's and A.4's closing legs — and A.5's new
closing ACK — commit their PQ half eagerly and OWE the classical half, which rides the
binder's next classical COMMIT as the message-frame staple (draft-02 §7
`APQPrivateMessage`). Binds therefore arrive through `processIncoming` like any message
frame: `PqFrameKind` loses `ratchetBind`/`bootstrapBind` and gains `bootstrapWelcome`,
and the wrapper's `ingest` no longer has bind cases at all. `PQInbound.plaintext` is
REMOVED — it existed for an A.3 bind's stapled app, which now travels as the committing
round's own app message (the field was always nil through this backend).

**Retention replaces one-shot hand-out.** New `pendingSideBand(sealing:)` on `PQRatchet`
peeks the retained frame without consuming it (`.fresh` re-seals per hand-out; `.stable`
holds bytes still for chunking); `advance(after:)` remains the consuming take for strict
request/response drivers. New `.duplicateSideBand` SessionError code (discardFrame):
re-sent frames for a step already taken are steady-state traffic, never a routing signal.

**A.5 is a three-leg round of the same shape**: Upd' → Commit' (the round's ONE
updatePath commit; the counter-Upd' is gone) → a stapled ACK. One A.5 round re-keys ONE
group; turn alternation covers the other. `ingest(.rekeyCommit)` reports
`advancedGroup: .theirs` unconditionally.

**New failure surface**: `.bindApplyFailed` (peer bind staple failed after its secret was
consumed — receiving is poisoned, sending unaffected; poll the new `isReceiveBroken` to
decide urgency by role) and `.bindDischargeFailed` (our own owed bind failed mid-commit —
permanently broken; route to re-establishment). Both map to `.reconnect`.

**Driving note (v19 evidence-gating)**: a classical commit no longer requires an approved
proposal — a round also commits when it owes a bind and holds a peer offer built against
our current epoch. `didCommit` can be true with no `queueProposal`, and
`committedRemoteClientId` is nil on such a round. MEASURED CAVEAT: after a Phase 8
rotation + A.5 credential handoff, the ROTATED party's license-only discharge produced a
frame its peer fails on with retriable `DecryptionFailed`; discharging via an approved
fold works. Suspected v0.5.0 edge — file upstream before relying on license-only
discharge post-rotation (the test suite documents the repro).
