# v0.15.0 session-row fixtures

Golden `PQSession.Persisted` rows written by TwoMLSPQ v0.15.0 (binding contract 32, session
archive layout 3), pinning that a pre-`swift_export` archive still restores and keeps
messaging under the current engine. `LegacyRowFixtureTests.swift`, in this same test target,
restores these through the raw binding and drives a liveness exchange + a committing round
each way.

Six capture points, each with `initiator.json` (alice) and `acceptor.json` (bob, a
born-dedicated acceptor):

- `p1-bob-sent-unfolded` — bob installed his establishment envelope and sent his first frame;
  alice paused on the handoff and resumed (joined), but has not yet folded bob's classical
  catch-up Upd.
- `p2-converged` — alice approved and committed bob's catch-up Upd (his recv-classical leaf has
  converged); bob has not made a committing round of his own yet.
- `p3-steady` — bob folded one of alice's Upds, the A.3 PQ bootstrap and bind discharge ran, a
  full A.4 ratchet leg (EK -> CT) was driven to completion, and a final message went each way.
- `p4-a3-stalled` — forked from p2's own persisted rows: alice began the A.3 bootstrap
  (`finishBootstrap`, the explicit host-triggered path) but her KP' leg was never delivered to
  bob. This is the stall a session with NO side-band transport at all reaches — it can never
  complete A.3, so it never reaches p3/p5/p6.
- `p5-a4-stalled` — forked from p3's own persisted rows (already fully established — side-band
  DID carry A.3's Welcome' to get here, since full establishment needs it). Side-band carried
  A.3, then stopped: the turn holder's next ordinary send auto-staged a new A.4 EK, and it is
  parked and never delivered.
- `p6-a3-responded-stalled` — the field shape: a fresh, standalone pair (not a fork) where alice
  piggybacked her pre-committed A.3 KP' as an ordinary queued `0x13` message
  (`bootstrapEnvelope()`, the real app path — verified in the app's shipped releases), not the
  explicit `finishBootstrap()` path p4 exercises. Bob's `decodeHeader` resolved it to `.forward`
  and his session's `forwarded(...)` answered A.3, parking HIS Welcome' response — the app never
  transmits it. Notably, this leaves alice with a leg of her own parked too (her registered KP'
  is retrievable the same way), and answering A.3 fully establishes BOB immediately (mirroring
  the explicit-delivery path) even though alice is not fully established until she receives his
  Welcome' back — see meta.json's recorded `isFullyEstablished`/`legParked` per side, which
  reflect exactly this and are not both `false`/one-sided the way a first guess might assume.

`meta.json` records the generator's tag/commit, the binding contract version, the xcframework
provenance, the harness path used (the app-shaped `createTwoMLSGroup` +
`PQInvitation.decodeHeader` route, not the bare plaintext handoff), and whether the p3 A.4 leg
was driven (`a4LegDriven`, always `true` — it is required, not conditional). Per point it records
the initiator/invitation/dedicated ids (base64) — PER POINT, not shared across all of them: p1-p5
share one identity pair (p4/p5 fork from p2's/p3's own persisted state), but p6 is an independent,
freshly-minted pair — and, per point per side: the `core`/`checkpoint` seq the recording sink
last saw (`coreSeq` is `null` when no core was ever pushed for that row), `isFullyEstablished`,
this side's own `turn`, and two fields the generator sets BY CONSTRUCTION rather than deriving —
`roundInFlight` (which PQ round, if any, this side's own state was deliberately left mid-round
for, e.g. `"A.3"`/`"A.4"`, absent when none) and `legParked` (whether it still owed an outbound
side-band leg at the moment of capture, cross-checked against `pendingSideBand(sealing:)` when
each point was built, not re-derived at test time). `LegacyRowFixtureTests.restoreAndVerify`
re-checks both live against the restored session, so a generator/consumer drift shows up as a
test failure. For p4/p5/p6 the parking is one-sided by design — only the side that owed the
round's next leg shows `legParked: true`; the peer never received it and is oblivious (p6's
acceptor is the exception worth noting above: it isn't oblivious, it fully answered — it's the
RESPONSE that never ships).

`xcframeworkProvenance` in `meta.json` explains the build precisely: it is a LOCAL build of the
tag's own source (session archive layout 3), not the released asset. `rust/Cargo.lock` is
gitignored and was not tracked at the tag, so crates.io dependencies were resolved fresh at
build time — but the archive encoding is still pinned because mls-rs (and its git-pinned
`mls-rs-core`/`mls-rs-crypto-awslc`/`mls-rs-crypto-cryptokit`/`mls-rs-crypto-traits`) is fixed by
git rev `ec69dc251db66ae6eb117079564814998bb55dec` in `rust/Cargo.toml`'s `[patch.crates-io]` and
`[workspace.dependencies]`, and the generated binding is byte-identical to the tag's vendored
`Sources/TwoMLSPQBinding/two_mls_pq.swift`.

`Generator.swift.txt` is the generator test source, kept here as a non-compiled reference (it
targets v0.15.0's API and does not build against this repo). It is a direct port of the final,
reviewed v0.16.0 generator: v0.15.0's app-shaped API surface (`createTwoMLSGroup`,
`decodeHeader`, `receive(newClientId:)`, `installMockEstablishmentEnvelope`,
`acceptEstablishment`, `bootstrapEnvelope`, `forwarded(headerDecrypted:)`,
`pendingSideBand(sealing:)`) is identical between the two tags, so no flow adaptation — including
p6's piggybacked-KP' shape — was needed beyond this file's own header comment and the
`meta.json` provenance fields. Regenerating reproduces the FLOW these fixtures encode, not their
exact bytes — every identity is randomly minted, so a fresh run produces different (but
equivalent) rows. To regenerate:

```
git worktree add <a new directory> v0.15.0    # any path outside this repo
cd <that directory>
bash scripts/buildIosDynamic.sh
cp <this directory>/Generator.swift.txt Tests/TwoMLSPQTests/FixtureGeneratorTests.swift
rm -rf .build/out/Products/Debug/two_mls_pqFFI.framework
FIXTURE_OUT=<this directory> TWOMLSPQ_LOCAL_XCFRAMEWORK=1 swift test --filter FixtureGenerator
```

**These fixtures carry PLAINTEXT key material — throwaway test identities only, never real
credentials.**
