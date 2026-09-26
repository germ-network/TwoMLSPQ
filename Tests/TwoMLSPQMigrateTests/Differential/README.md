# Randomized differential harness (GER-2566 item 1)

A seeded, randomized harness that drives operation sequences on Swift↔Rust session pairs,
checks convergence, and operationalizes "no state is ever unreceivable" as re-staple
healing. A failing run prints a reproducible op script (seed + script blob + binding
contract version + Rust crate sha).

It lives in this test target and drives both engines in-process: the Rust engine through
the UniFFI binding (`TwoMLSPQBinding`), the Swift engine through `TwoMLSSession` from the
`twomlspq-swift` package dependency that this repo already pins. Cross-delivery is live —
every frame either engine produces is decoded by the other.

## The deployed-pin swap

The differential reference is the **deployed production pin: `two-mls-pq@c501f9d`,
mls-rs `b43703f`** — the pin `RustWireVectors.swift` already compares golden vectors
against. Not origin/main Rust. Two bindings cannot coexist in one module, so the pin run
swaps the pin's binding + xcframework into the working tree and runs only the differential
suite:

```
just differential-deployed
```

which runs `scripts/differentialDeployed.sh`:

1. `git worktree add /tmp/ger-2566-pin c501f9d` (outside `~/tmp/worktrees/agent` — build scratch).
2. `scripts/buildIosDynamic.sh` there → the pin's `buildIos/` + `bindings/`.
3. Copy the pin's `two_mls_pq.swift` and `TwoMLSPQ.xcframework` into this tree, stashing
   main's.
4. `TWOMLSPQ_LOCAL_XCFRAMEWORK=1 TWOMLSPQ_PIN_BINDING=1 DIFFERENTIAL_DEPLOYED_PIN=1
   swift test --filter DifferentialHarnessTests`.
5. A trap restores main's binding + xcframework on exit, so an interrupted run never leaves
   the tree swapped.

`TWOMLSPQ_PIN_BINDING=1` is required because the pin's binding predates the
migration-export FFI: `TwoMLSPQMigrate` and every suite that imports it cannot compile
against the pin (they use `migrationExport()` / `SessionMigration*`, main-only). Under this
flag `Package.swift` drops those targets/suites, leaving the Rust-free `TwoMLSPQTests`
suites plus the differential harness — all the pin run needs. The stub source
`Sources/TwoMLSPQMigrate/PinStub.swift` keeps the migrate target non-empty.

Without `DIFFERENTIAL_DEPLOYED_PIN=1` every differential test is **skipped**, so the
standard `swift test` under main's binding stays green — the swap never breaks the main
suite. `DIFFERENTIAL_SEED_MAX` (default 60) widens the sweep.

## The API-intersection constraint (legal subset)

The harness facade (`EngineSession.swift`) compiles against BOTH the swapped pin binding
and main's. It may only use the API surface present in both.

**Verified by diffing the two bindings' public surfaces** (`git show c501f9d:Sources/
TwoMLSPQBinding/two_mls_pq.swift` vs main's vendored copy):

- The public method surface of `TwoMlsPqSession`, `TwoMlsPqInvitation`, and
  `TwoMlsPqPrincipal` is **identical** in both bindings — the pin's is a strict subset of
  main's, and every pin method exists in main.
- The only main-only additions are `migrationExport()` and the `SessionMigration*` record
  types + their `FfiConverterType…` helpers. **The facade never touches either.**
- The `binding_contract_version()` function returns **33 at the pin** and **36 at main**;
  the uniffi *scaffolding* version constant is `30` in both (unrelated to the contract
  function). The ledger records 33, and `bindingContractMatchesLedger` fail-fasts the pin
  run if the linked binary is not the pin build (e.g. the released v0.10.0 binary).

So the legal subset the facade uses is the entire session/invitation/principal surface
*except* `migrationExport` / `SessionMigration*`.

## Running

```
# Standard suite (differential tests skip without the env var):
TWOMLSPQ_LOCAL_XCFRAMEWORK=1 swift test

# Differential sweep against the deployed pin:
just differential-deployed
DIFFERENTIAL_SEED_MAX=250 just differential-deployed      # wider sweep

# Against a local main-binding build instead of the pin (expected-signal run; see below):
TWOMLSPQ_LOCAL_XCFRAMEWORK=1 DIFFERENTIAL_DEPLOYED_PIN=1 \
  DIFFERENTIAL_SEED_MAX=5 swift test --filter DifferentialHarnessTests
```

## Replaying a seed

A failing run prints:

```
Differential repro:
  seed=<N>
  contract=<binding contract version> rustSha=<pin sha>
  script=<compact JSON op-script blob>
```

Replay it exactly with:

```
DIFFERENTIAL_REPLAY_SEED=<N> \
DIFFERENTIAL_REPLAY_BLOB='<the script=… JSON>' \
TWOMLSPQ_LOCAL_XCFRAMEWORK=1 DIFFERENTIAL_DEPLOYED_PIN=1 \
  swift test --filter replayScript
```

The same script always reproduces the same op sequence. The *engines'* randomness (key
generation, ML-KEM) stays live, so comparison is semantic, never byte-level.

## Adding an op

1. Add a case to `DiffOp` (`DiffOp.swift`) carrying only what the op needs; use a negative
   `index` for "from the back" so the generator need not know lane lengths.
2. Handle it in `DifferentialRun.execute` and, if it touches an engine, drive it through
   an `EngineSession` method (never a raw binding call — see the API-intersection
   constraint).
3. **Check the API subset first:** the new op must be expressible through methods present
   in both bindings. If it needs a pin-missing accessor, drive around it or drop it from
   the op set.
4. Optionally weight it into `ScriptGenerator`'s phases.

## Ledgering a divergence

`DifferentialResources/DivergenceLedger.json` records the known engine divergences from
`book/src/session-lifecycle.md` (shipped anomalies 1/2/3/5) plus the C1/C2
deployed-compatible behaviors. A mixed-pair mismatch whose `field` + `engine` + `calls`
matches an entry is **recorded, not failed**; the entry states the healing condition.
Anything else is a finding and fails the test.

To ledger a newly-understood divergence, add an entry:

```json
{
  "id": "…", "anomaly": "…", "title": "…",
  "engines": ["rust", "swift"],
  "fields": ["remoteCommitApplied"],
  "calls": ["deliver", "sideBandSend"],
  "healing": "…"
}
```

`fields` are `ComparableOutcome` field names (`appPayloads`, `joined`,
`pendingEstablishment`, `offeredDigest`, `remoteCommitApplied`, `errorClass`); `calls` are
the transcript `call` labels in `DifferentialRun`; `engines` names the engine(s) whose
behavior the entry documents. Matching is narrow on all three axes, and a mixed-pair
mismatch is excused only when **both** engines involved are documented (AND). A
single-engine entry therefore documents a divergence without suppressing a two-engine
mismatch that could equally be a regression on the other engine. Do **not** let a ledger
entry absorb engine-behavior mismatches you have not actually root-caused — file a finding
instead.

## Design notes / current scope

- **Pair topologies:** mixed pairs (Swift↔Rust, both directions) at full seed count are the
  differential legs; the harness compares the two directions' transcripts. Pure pairs
  (Swift↔Swift, Rust↔Rust) on a 1-in-5 subset are oracles for attributing a mismatch to
  engine vs script.
- **Alignment:** transcripts are compared grouped by (op, role, call), not raw index, so an
  op that no-ops in one direction does not shift every later comparison.
- **Establishment** happens before the randomized script (plain §A.1 + the parallel A.3
  bootstrap, both directions, up to fully established), so the DSL is a steady-state op
  set. `Topology.bornDedicated` is carried in the DSL but the generator currently emits
  only `.plain`; born-dedicated establishment is deferred.
- **`prepareToEncrypt(proposing:)` is a parameter, not a separate op** — rotation is a
  mid-script randomizable parameter on both engines.
- **Side-band (A.4/A.5) opens inside `encrypt`** on both engines; the scheduler models it
  with a separate side-band lane, peeked via `pqPendingOutbound` and routed by
  `openIncoming` kind.
- **Healing invariant:** after any fault sequence a `probe` (a FULL quiescence drain — every
  outstanding offer folded, side-band and main lanes drained to empty, looped to a fixpoint —
  plus one round-trip each way) must succeed, or both sides classify identically; and no
  direction may have two distinct commit epochs in flight. On the double-commit invariant:
  the generator constructs the closest reachable window (a commit queued undelivered, then
  the peer proposes a *rotation* via `sendRotating` and the committing role folds it), but
  the invariant is a SAFETY property this harness cannot drive to violation — a second commit
  needs a second authorization change, and the peer cannot author one until it learns of the
  first commit, which must stay undelivered for the window to exist. It is therefore a
  scheduler assertion that holds, not an exercised path. `crashAndRestore` picks only legal
  restore points through `isLegalRestore` (`seq` ≥ every delivered frame's `dependsOnSeq`)
  and asserts the gate; `restoreBehindDelivery` is the negative test whose expectation is
  clean classification, checked by re-delivering the last-seen frame after the restore — a
  CLEAN re-apply or clean ignore is HEALING, not a violation (the plan's nil→ignored rule);
  only an error that is actually thrown and classifies `.other` (unrecognised) fails.
- **Durability watermark is engine-symmetric:** `FrameRecord.dependsOnSeq` is each engine's
  `lastStateSeq()` at emit, not Rust's raw `encrypt.dependsOnSeq` (an earlier persisted seq)
  nor Swift's `update.stateSeq` (the just-bumped one) — the two encode different points, so
  mixing them would make the legality gate asymmetric.

## Current status

Under the pin swap (`just differential-deployed`, verified locally against the c501f9d
xcframework, 12 seeds):

- `bindingContractMatchesLedger` **passes** — the linked binding reports contract 33.
- `purePairOracles` **passes** (never vacuous: it always runs at least the last seed).
- `mixedPairDifferential` **reports findings and fails** on the current seed range, and
  `replayScript` with the same blob **reproduces the identical findings** (it runs the full
  two-direction comparison, not just per-direction violations). The findings are real
  engine differences in what each engine exposes, **not** suppressed. Making the mixed legs
  a green gate requires root-causing and ledgering these or narrowing the op set.

Findings surfaced so far (the ledger holds the excused ones):

- **Offer surfacing (primary).** On a delivered frame Swift always surfaces a
  `queuedProposal` (its `DecryptResult.queuedProposal` is non-optional), while the deployed
  Rust engine surfaces `proposal` only sometimes (its field is optional) — so one direction
  has an offer to fold and the other does not. This surfaces both as `queueProposal` count
  differences AND as `offeredDigest` (`hadOffer`) mismatches on plain `deliver` /
  `probeRoundTrip` — the latter were previously swallowed by the over-broad `c1` entry and
  now **fail**, which is the point. (The pin Rust sets `proposal: Some` unconditionally on
  the main decrypt path, `messaging.rs:1655`; the divergence is on edge paths, still to be
  root-caused.)
- **Auto-staged side-band leg presence** and **side-band leg openability** — reported as
  *consequences* of the offer-surfacing primary divergence, not independent findings (fault
  injection shows their call-count signatures cascade from it). Still failing until
  root-caused.
- **Post-restore frame handling (fourth class).** After a restore, a `probeRoundTrip` /
  `deliver` can show `remoteCommitApplied` Swift=true vs Rust=false, or Rust surfacing
  `DecryptionFailed` / `unsupportedFrameTag(...)` where Swift applies cleanly. Surfaced by
  the now-wired restore dimension; un-ledgered and failing.
- **Rotation guard (fixed in the harness).** Swift `prepareToEncrypt(rotating:)` throws
  `.rotationInFlight` for a concurrent rotation where Rust accepts it; the harness now
  proposes rotations only from a clean slate, and the divergence is ledgered as
  `rotation-in-flight-guard`.
- **Stale-frame error surface (equated).** Swift can leak an underlying MLS
  `generationAlreadyConsumed` where Rust classifies `StaleFrame`; equated in the error
  table.
- **Proposal-fold rejection.** Swift `.proposalRejected` / Rust `ProposalRejected` fire on
  different ops when folding a catch-up Upd; ledgered under anomaly 3.

**Ledger matching is engine-attributed and conservative.** A mismatch is attributed to the
engine at that role in each direction, and it is excused only when **both** sides are
documented (AND, not OR). A single-engine entry therefore documents a known divergence but
does not suppress a two-engine mismatch that could equally be a regression on the other
engine.

## Running against main's binding (expected-signal, not a failure)

Without a pin build, running the differential legs under main's local binding is useful
signal: main's Rust/contract differ from the deployed pin the ledger describes. The
`bindingContractMatchesLedger` test fails (36 vs 33, expected) and the mixed-pair legs
report the seeds that diverge — those are main-era divergences, not harness bugs. The
reference result is the `just differential-deployed` run.
