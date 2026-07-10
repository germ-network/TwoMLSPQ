# The Rules of a TwoMLS Group

Every MLS group in this protocol — the classical and PQ halves of both send groups —
is a 1:1 pair driving a deliberately tiny slice of MLS. This chapter is the normative
list of what a TwoMLS group may ever do, and the map of where each rule is enforced.
The legacy classical implementation enforced most of these ad hoc; here they are one
reusable layer: an `MlsRules` filter every client is built with
(`apq/src/rules.rs`), plus session-level checks at the protocol's own ingest points.

## The constraint set

1. **Exactly two members, fixed at creation.** The *creation commit* is the one
   permitted Add: the creator, alone in the group, adds the single peer and nothing
   else. That is how every half is born — the classical halves at establishment, the
   acceptor's PQ half at the A.4 bootstrap (`create_group_with_member`). Once the
   roster is two: no Add, Remove, ReInit, ExternalInit, GroupContextExtensions, or
   custom proposals, ever; no external commits; no external senders.
2. **At most one Update per commit, never the committer's own.** The only Update a
   commit legitimately folds is the *other* party's leaf update (the stapled
   `Upd(sender)` of the classical ratchet, or the A.5 `Upd'`). An MLS Update always
   covers its sender's leaf, so requiring a member sender other than the committer
   pins it to the peer.
3. **External PSKs only.** PSK proposals carry the APQ and cross-party TwoMLS
   bindings; resumption PSKs are never used (this protocol never resumes groups).
4. **Basic credentials only.** Each leaf's credential is the member's opaque
   ClientId. (Credential *succession* rules — the TwoMLS Authentication Service —
   land as the next layer on top of this chapter's structural rules.)
5. **Commit epoch must equal the receiver's current epoch.** Ahead is `EpochDesync`
   (reconnect territory); behind is an idempotent skip (the staple re-rides every
   frame).
6. **Establishment binds identities.** A combiner key package's two halves must name
   one ClientId; the welcome's creator leaf must equal the key package's identity at
   `receive`/`accept`; an A.4 bootstrap key package must name the established peer.
   The caller can additionally pin the whole exchange to an identity it already
   expects with `receive(expected_remote:)` — checked before any invitation state is
   claimed, so a mismatch consumes nothing. (The one deliberate adoption: the
   *initiator's* welcome join takes the creator leaf as the peer's principal — the
   acceptor may establish under a dedicated per-session principal, authenticated by
   the cross-party PSK.)

## Enforcement map

Defense in depth is deliberate: the rules filter, the join gates, and the session
checks each cover ingress the others cannot see.

| Rule | `TwoMlsRules` (`filter_proposals`) | Session / apq checks |
|---|---|---|
| Two members | roster gate on every commit, both directions | `ensure_two_party` at every welcome join (no commit runs there) and re-asserted after every applied commit |
| Creation-commit shape | roster == 1 ⇒ exactly one Add | groups only ever built via `create_group_with_member` |
| No Add/Remove/ReInit/GCE/… post-creation | rejected on build **and** on receive (a peer commit carrying one is vetoed before it applies) | post-commit `ensure_two_party` backstop |
| ≤ 1 Update, peer's own leaf only | sender ≠ committer on every folded Update | `require_peer_update` at ingest: the stapled proposal (`queue_proposal`), the A.5 opener (`pq_rekey_respond`), and the A.5 counter slot (`pq_rekey_apply`) reject anything that isn't the peer's own-leaf Update *before* it enters a cache |
| External PSKs only | resumption PSKs rejected | PSK ids are minted internally (`export_psk`) |
| No external commits/senders | `CommitSource::NewMember` rejected | external senders never configured |
| Epoch discipline | — | staple-epoch compare in `process_incoming` (`EpochDesync` / skip) |
| Identity binding at establishment | — | `expected_remote` pre-claim check; creator-leaf ≡ key-package check at join; A.4 bootstrap KP identity check (`RemoteIdentityMismatch`) |

Two properties worth naming:

- **A peer's rule-violating commit is rejected before it is applied** — the receive
  side of `filter_proposals` runs during commit processing, so the local group state
  never advances into the violating epoch; the session surfaces `Mls` and the group
  remains usable.
- **A poisoned proposal cache fails loudly at build.** `queue_proposal` is the only
  path into the send group's cache and pre-validates, so if a forbidden proposal
  ever reaches a commit build, the build errors rather than silently filtering it
  out — an invariant violation should be visible, and the round recovers because
  the peer re-staples.

## The Authentication Service

Credential-succession rules (each leaf's credential as an app-defined sequence,
candidates riding the classical ratchet's Upd proposals, the peer's commit defining
the canonical next credential, with the PQ halves lagging) build on these structural
rules — see the plan in this repository's tracking issue; the chapter section lands
with that change.
