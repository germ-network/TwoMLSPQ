---
"@germ-network/abstract-two-mls": minor
---

Principal-state observability on the abstract Session surface (M6)

`Session` gains the truth surface for credential state: `myPrincipalState` /
`theirPrincipalState` (new `AbstractTwoMLS.PrincipalState`: `.sync(ClientID)` /
`.pending(old:new:)`, shaped by the crate) and `queuedRemoteSuccessor` (the
approval tally; protocol-extension default `nil` for tally-less backends).

Why: rotation outcomes are one-shot events (`remoteCommit.newSender` /
`newRecipient`) and can be LOST — a frame's staple applies before its app
message decrypts, so a transient decrypt failure swallows the event (the
retry's staple is an idempotent skip). State is truth, events are hints:
after a retriable `processIncoming` failure, reconcile identity from
`theirPrincipalState`.

Breaking for external `Session` conformers: two new required getters. The
deprecated classical backend (`MultiMLS.TwoMLS`) shims them in four lines by
mapping its existing `myAgentState`/`theirAgentState`.
