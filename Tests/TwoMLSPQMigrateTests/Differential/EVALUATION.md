# Divergence evaluation matrix

Working record for the engine divergences surfaced by the differential harness
(GER-2583, PR #158). Each finding gets one row; a row is complete when every
cell is resolved with evidence, not judgment. Rows are updated as
investigations land — an empty cell is an open question, not an implied "no".

## The frame

A divergence between the engines is evaluated against four questions, in order:

0. **Spec status** — does the book define this behavior? (defined /
   underspecified / silent). If silent, the first resolution step is a book
   clarification, not an engine change.
1. **Sender-legality** — is a conforming sender permitted to *emit* this?
2. **Accept-legality** — is a conforming acceptor permitted to *accept* this?
   Permitted to reject it? Required to reject it?
3. **Sender-bug recoverability** — if the behavior is a sender bug, is it
   recoverable by fixing the sender? (i.e. does the fix coexist on the wire
   with unfixed peers, or does it strand old sessions?)
4. **Safe leniency** — is there leniency in the spec or the acceptor that
   makes the *consequence* recoverable — not accepting the bugged behavior,
   but healing from it? (e.g. re-staple healing, re-establish, fail-closed
   restore.)

The distinction between 3 and 4 is the point of the matrix: a bug can be
unfixable-in-place (3: no) yet harmless-in-consequence (4: yes), which changes
both the urgency and the fix venue.

The TwoMLS invariant that frames every row: **each party writes only its own
group, so a well-behaved peer's offer/commit is always fold-valid.** Any
accept-side rejection of a well-behaved peer's traffic is either a stale/mis-
sequenced delivery (host bug) or an acceptor defect.

## Matrix

| # | Finding | Spec status | 1. Sender-legal? | 2. Accept-legal? | 3. Fix-sender recovers? | 4. Safe leniency? | Status |
|---|---------|-------------|------------------|------------------|-------------------------|-------------------|--------|
| 1 | Fold-legality rejections (Swift rejecting offers Rust accepts) | defined (fold-is-evidence, `validate_offered_update`) | n/a — no engine emitted anything wrong | n/a — the acceptor was right; the "bug" was the harness folding stale/epoch-mismatched offers | n/a (harness bug, fixed) | the epoch check is itself the safe leniency: stale offers are cleanly rejected, never mis-applied | **Closed** — harness artifact; 0 rejections across 12 seeds after liveness gates |
| 2 | Offer surfacing asymmetry (Swift surfaces `queuedProposal` on every successful decrypt; pin Rust surfaces `proposal: Some` on the main path, `nil` on other outcomes) | defined in mechanism — duplicate delivery is expected protocol behavior, and duplicate rejection rides on **application-message consumption** (ratchet generation), not ciphertext-level duplicate detection. A true duplicate app frame fails to decrypt in both engines, so neither re-surfaces its offer; Swift's `generationAlreadyConsumed` (row 5) is this rejection path with a leaked error class | n/a | both engines accept-or-reject fresh vs duplicate frames identically in principle | open — hypothesis: no independent divergence; mismatch sites are fresh-decrypt failures post-restore (row 3 territory) | expected yes via the app-consumption mechanism | **Open** — correlation re-aimed at row 3: classify each mismatch site as duplicate-app (both reject, no offer either side), fresh-decrypt (both surface), or post-restore decrypt failure (row 3) |
| 3 | Post-restore frame handling (`remoteCommitApplied` 152, `errorClass` 92: Rust `DecryptionFailed`/`Mls`/`unsupportedFrameTag` after restore) | underspecified — restore fail-closed and the `dependsOnSeq` durability contract are pinned; what a restored session does with frames delivered before the restore point is implied, not stated | open | open | open | open — fail-closed restore → re-establish is the designed recovery; question is whether anything worse than re-establish occurs | **Open** — issue #2 |
| 4 | Concurrent rotation (Swift refuses `.rotationInFlight`; deployed Rust permits and emits) | defined — the book's one-outstanding-round framing; deployed Rust is the documented deviator (anomaly family, GER-2531) | **no** — deployed Rust is the non-conformant sender | yes — Swift's refusal is its own-send precondition, not an accept rejection; Swift still accepts Rust's wire frames | yes in principle (the Rust-side fix is tracked); until then the stall is real in mixed sessions | yes — a conforming peer's reciprocal §A.5 heals the one-sided stall (book-documented healing) | **Ledgered** — accommodation `rotation-in-flight-guard` |
| 5 | Error surface: Swift leaks unwrapped MLS `generationAlreadyConsumed`; Rust classifies `StaleFrame` | silent at this grain — the error taxonomy is not pinned per-class in the book | n/a | n/a (both reject the frame; classification only) | n/a | yes — the harness's error-class table equates them; hosts see one class | **Ledgered** — equated in error-class table; Swift-side mapping cleanup optional |
| 6 | Approved-handoff payload (Rust returns the stapled app payload from `processIncomingApproved`; Swift's `.joined` carries none) | silent — the book does not say what happens to the app payload stapled to an approved 0x0B handoff | n/a | open | open — if Swift drops it: app-layer message loss, fix is Swift-side and local | open | **Open, dormant** — surfaces when born-dedicated topology is generated |

## Resolved learnings (context for the rows)

- **Row 1 evidence:** every residual fold rejection bisected to swift-mls
  `verifying`'s epoch check (`wrongEpoch(actual = expected − 1)`) — the five
  Swift-only conformance guards (embedded-leaf signature, `validatePolicy`,
  APQ/AppBinding/profile adverts) were never reached, and all 152 surveyed
  deployed-Rust offered leaves carry `0xF0A1`/`0xF0A2`/`0x0008` (rule 8
  satisfied; `0xF0A3` correctly absent for `deployedCompatible`). Caveat: the
  advert survey is one-directional (Rust-emitted offers seen by a Swift
  folder).
- **Cascade rule:** side-band leg-presence and leg-openability signatures are
  downstream of any primary state divergence — never report them as
  independent findings before the primary is root-caused.
- **Ledger rule:** a ledger entry must be scoped to the exact call site where
  a documented behavior surfaces; a both-engines (field, call) match
  demonstrably swallowed row 2's signal for an entire run.
