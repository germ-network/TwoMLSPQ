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
   acceptor's PQ half at the A.3 bootstrap (`create_group_with_member`). Once the
   roster is two: no Add, Remove, ReInit, ExternalInit, or GroupContextExtensions,
   ever; no external commits; no external senders. The **only** custom proposal ever
   admitted is the draft-02 `AppDataUpdate` (type `0x0008`) that attests new epochs in a
   FULL commit (rule 7); every other custom proposal is rejected.
2. **At most one Update per commit, never the committer's own.** The only Update a
   commit legitimately folds is the *other* party's leaf update (the stapled
   `Upd(sender)` of the classical ratchet, or the A.5 `Upd'`). An MLS Update always
   covers its sender's leaf, so requiring a member sender other than the committer
   pins it to the peer.
3. **Application and external PSKs only, never resumption.** The APQ-PSK and
   cross-party TwoMLS-PSK are imported as `application(3)` PSKs (draft-02 §6.2); the
   A.4 injected secret rides an `external(1)` PSK. Resumption PSKs are never used (this
   protocol never resumes groups). See [PSK Binding](./psk-binding.md).
4. **Basic credentials only, evolving along the app-defined sequence.** Each leaf's
   credential is the member's opaque ClientId, and it may change only per the TwoMLS
   Authentication Service (below).
5. **Commit epoch must equal the receiver's current epoch.** Ahead is `EpochDesync`
   (re-establish territory — unrecoverable in-library); behind is an idempotent skip
   (the staple re-rides every frame).
6. **Establishment binds identities.** A combiner key package's two halves must name
   one ClientId; the welcome's creator leaf must equal the key package's identity at
   `receive`/`accept`; an A.3 bootstrap key package must match the hash commitment the
   initiator pinned at `initiate` and the acceptor recorded at `receive`
   (`BootstrapKpMismatch`) — which binds the exact KP′, stronger than a names-the-peer
   equality, while its leaf identity is still AS-validated at group creation.
   The caller can additionally pin the whole exchange to an identity it already
   expects with `receive(expected_remote:)` — checked before any invitation state is
   claimed, so a mismatch consumes nothing. (The one deliberate adoption: the
   *initiator's* welcome join takes the creator leaf as the peer's principal — the
   acceptor may establish under a dedicated per-session principal, authenticated by
   the cross-party PSK.)
7. **APQInfo is written once; epochs are attested per FULL.** Each half carries an
   `APQInfo` GroupContext extension (type `0xF0A1`) naming both group ids, the mode,
   both cipher suites, and the creation-time epochs — written at creation, riding the
   Welcome, and **never rewritten** (rewriting it would need a GroupContextExtensions
   proposal, which rule 1 forbids — and which would force an updatePath onto the
   otherwise-pathless A.4 bind). Epoch freshness rides the `AppDataUpdate` in each FULL
   commit instead: both halves carry it, the two copies must agree, and each must attest
   its group's *actual* new epoch. A.5 re-keys are PQ-only and their side-band `Commit'` carries no `AppDataUpdate`
   (an attestation smuggled into one is rejected); the bumped `pq_epoch` reconciles
   **in-round**, in the FULL commit the initiator staples as the round's ack. The deferred A.3 PQ group id is pre-allocated in the classical half's
   `APQInfo` with its epoch set to `EPOCH_UNBOUND` until the bootstrap lands.
8. **The AppBinding is written once and verified at every join.** A session is
   definitionally bound to its two agents, but agents are *mutable* (the rotation
   lifecycle); the optional `AppBinding` GroupContext extension (type `0xF0A2`, the
   `APQInfo` mechanism) binds the session to the app's **immutable** relationship
   identity instead. Written at group creation into both classical halves (the PQ
   halves inherit coverage through the `APQInfo` half-binding), riding the Welcome,
   and never rewritten — rule 1's GroupContextExtensions ban is what makes it
   immutable. Verification is an exact, symmetric match: `receive(expected_app_binding:)`
   requires the welcome to carry exactly the stated binding (a stripped or unequal
   binding is a wrong-relationship welcome or downgrade attempt; a binding the caller
   did not state is never silently accepted), the acceptor mirrors the verified binding
   onto its return group, and the initiator requires the return welcome to carry its
   own binding back unchanged — all `AppBindingMismatch`, and on the invitation path
   raised before any invitation state is claimed. PQ halves must carry **no** binding
   (they inherit coverage; a smuggled PQ-half copy is rejected at every PQ join), and
   an **empty** binding is reserved as invalid — rejected at creation and as an
   expectation — so an accidentally empty digest cannot mint a bound-to-nothing
   session (`None` is the deliberate unbound state). The payload should be a **digest**
   (the first adopter binds `H(domain-tag ‖ role-ordered did:did)`); the crate never
   interprets the bytes. Leaves advertise the extension type, so a binding-carrying
   group can only ever contain capability-bearing leaves.

## Enforcement map

Defense in depth is deliberate: the rules filter, the join gates, and the session
checks each cover ingress the others cannot see.

| Rule | `TwoMlsRules` (`filter_proposals`) | Session / apq checks |
|---|---|---|
| Two members | roster gate on every commit, both directions | `ensure_two_party` at every welcome join (no commit runs there) and re-asserted after every applied commit |
| Creation-commit shape | roster == 1 ⇒ exactly one Add | groups only ever built via `create_group_with_member` |
| No Add/Remove/ReInit/GCE post-creation | rejected on build **and** on receive (a peer commit carrying one is vetoed before it applies) | post-commit `ensure_two_party` backstop |
| Custom proposals: only `AppDataUpdate` (`0x0008`) | ≤ 1 custom proposal, correct type, committer-sent, strict-decoded, same-half epoch == `context.epoch + 1`; any other custom type rejected | presence/cross-half agreement and actual-epoch match verified in the session (`apply_bind`), before app decrypt |
| ≤ 1 Update, peer's own leaf only | sender ≠ committer on every folded Update | `require_peer_update` at ingest rejects anything that isn't the peer's own-leaf Update *before* it enters a cache — the stapled proposal (`queue_proposal`) and the A.5 opener (`pq_rekey_respond`); the A.5 ack (`pq_rekey_apply`) ingests a `Commit'`, not a proposal, so its folded Update is vetoed instead by the mls-rs rules filter (sender ≠ committer) |
| Application/external PSKs, never resumption | resumption rejected; external **or** application accepted | PSK ids are minted internally (`export_psk`); application PSKs carry the APQ/cross-party bindings, the A.4 injected secret stays external |
| No external commits/senders | `CommitSource::NewMember` rejected | external senders never configured |
| Epoch discipline | — | staple-epoch compare in `process_incoming` (`EpochDesync` / skip) |
| Identity binding at establishment | — | `expected_remote` pre-claim check; creator-leaf ≡ key-package check at join; A.3 bootstrap KP hash-commitment check (`BootstrapKpMismatch`) |
| App-state binding at establishment | GCE ban keeps it immutable post-creation | `verify_app_binding` against `expected_app_binding` at `receive`/`accept` (post-join, pre-claim) and against the session's own binding at the initiator's return-welcome join; `verify_pq_half_unbound` at every PQ-half join (the binding lives on the classical halves only); empty bindings rejected at creation and as expectations (all `AppBindingMismatch`); leaf capability advertisement keeps uncapable leaves out of bound groups |

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

Each party's leaf credential evolves along an **app-defined sequence**, and the
sequence is driven by the classical ratchet itself:

1. **Candidates ride the Upd proposals.** `prepare_to_encrypt(Some(id))` makes this
   frame's Upd(self) carry a successor credential (its new leaf bears the candidate's
   credential), minting the successor principal and authorizing it on the fly if `id` is
   not already a candidate — there is no separate stage call, so a rotation can ride the
   very first frame. Different frames may propose different candidates. A candidate that has
   been proposed on the wire is **never evicted** — the peer may commit any of them, and
   only the proposer holds the winner's signing key. Staging beyond the in-flight window
   parks the request in a single deferred slot (a newer stage replaces it) and it is
   proposed automatically on the next routine round once a canonicalization frees a slot.
   The frame's proposal section is self-describing — the receiver surfaces the candidate
   as `QueuedRemoteProposal.proposing` *before* the proposal touches any group, and
   `queue_proposal` verifies the declared identity against the Update's actual leaf.
2. **The app's approval is the authorization.** `queue_proposal` is the running tally:
   approving a proposal authorizes its credential as the peer's next; a later approval
   replaces the tally (single-occupancy, latest-wins — the app owns ordering).
   `queued_remote_successor()` returns the currently-queued credential so the app can
   decide whether to replace it or keep it. Approval validates the proposal and then
   leaves the group's proposal cache **untouched** (it re-applies the one approved
   proposal only at commit), so a rejected approval is a no-op and a replacement never
   accumulates a second Update. The tally is epoch-locked: it is dropped when our send
   epoch advances by an A.4 bind, and the app re-approves from the peer's fresh offer
   (the receiver may freely drop — the proposer re-sends every round).
3. **The commit defines the canonical next credential.** When the receiver's commit
   folds the chosen Upd, that credential becomes the sender's canonical identity
   (`committed_remote_client_id`, `their_principal_state`). The staple back
   canonicalizes the sender's own session onto the winning candidate
   (`remote_commit.new_recipient`, `my_principal_state` → `Sync`); losing candidates'
   authorizations expire.
4. **Everything else lags and catches up.** The sender's own send-group leaf moves at
   its next approved commit (the peer observes `new_sender`); the PQ leaves catch up
   at the next A.3/A.5 handoff; the acceptor's recv-group leaf converges from the
   invitation identity to the dedicated principal via its first committed Upd.
   The AS validates every catch-up against the sequence *history*
   (`CREDENTIAL_HISTORY_WINDOW = 8` canonical steps) — a lagging leaf may only
   fast-forward to an already-canonical credential; candidates are proposed and
   canonicalized exclusively in the classical ratchet.

Enforcement is the mls-rs `IdentityProvider` (`apq/src/authentication.rs`):
`valid_successor` implements same-id / authorized-step / catch-up; `validate_member`
whitelists known-or-authorized identities (with a one-shot adoption window strictly
around a welcome join whose creator cannot be known in advance — the dedicated
establishment principal, authenticated by the cross-party PSK); external senders are
always rejected. Every client a session drives — invitation-derived, dedicated,
staged candidates, restored — resolves to one session-canonical state through a
rebindable view, and the sequences ride the session archive.

A refusal surfaces as `CredentialRejected` and is **retryable** where it arises from
a staple: the staple re-rides every frame, so approve-and-reprocess recovers the
round. `new_sender` / `new_recipient` are event hints; 	zxvbbvsv=`their_principal_state()` /
`my_principal_state()` are the truth.
