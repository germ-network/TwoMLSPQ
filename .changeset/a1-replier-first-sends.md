---
"@germ-network/abstract-two-mls": minor
---

Adopt TwoMLSPQ v0.4.1 (binding contracts 14–16): §A.1 replier-first sends

The initiator sends app messages immediately after `reply` — before the
acceptor's return welcome exists. Pre-establishment `prepareToEncrypt` is a
NO-OP round (`proposalMessage` empty; `proposalHash` is the WELCOME digest —
the one carve-out on the hash == sha256(proposalMessage) guarantee) and
`encrypt` emits a fresh §A.1 envelope re-stapling the attached app payload plus
the current message, so ANY single frame both establishes the acceptor and
delivers. Later pre-establishment frames from the same initiator route
`.forward`; the spawned session acknowledges them and hands out their stapled
messages via `forwarded(headerDecrypted:)`.

BREAKING for conformers and callers:

- `Invitation.receive` returns `(Session, stapled: Session.MLSSenderMessage?)`
  instead of `(Session, plaintext: Data?)`: the staple decrypt CONSUMES its
  ratchet generation, so the full typed sender message is handed out exactly
  once — deliver it; it cannot be recovered from a re-delivered frame.
- `createTwoMLSGroup` now attaches the app welcome to the session as its
  establishment-self-sufficient payload and returns the crate-composed
  envelope (the wrapper's own double-HPKE header frame is retired). CAPTURE
  ORDERING: persist-capture the session AFTER this call — the attached
  payload rides the archive; a capture taken between `reply` and the attach
  restores a replier whose frames carry no identity envelope.
- `PrepareEncryptResult` gains `proposalMessage` (contract 14): the raw staged
  Upd(self) proposal, exposed so adopters digest the bytes themselves (sha256
  over it == `proposalHash` == the receiver's `QueuedRemoteProposal.digest`).
- New `PQSession.receiveGroupId` (the receive group's classical id; nil before
  this side has joined one) — the post-join envelope check's counterpart to
  `shouldListenOn()`'s GroupID.
- New `.appBindingMismatch` SessionError code (v15's AppBinding; this surface
  passes nil/unbound — threading a real binding through is its own follow-up).

v0.4.1 fixes cross-endpoint handoff validation: the receiver's queued ordering
context now equals the SENDER's `proposalContext` (the value the sender signs
its handoff against), not a restatement of the receiver's own.

Persisted state is NOT portable: contract 16 reset `SESSION_ARCHIVE_VERSION`
and `INVITATION_VERSION` to 1 — regenerate ALL persisted sessions and
invitations; v15's key-package wire cut also requires republishing key
packages.

germDM migration: deliver the `stapled` sender message from `receive` exactly
once; capture-persist only after `createTwoMLSGroup`; regenerate persisted PQ
state and republish key packages.
