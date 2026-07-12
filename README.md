# AbstractTwoMLS

A Swift abstraction over Germ's two-party MLS session backends. Apps program
against one protocol surface (`AbstractTwoMLS.Session` / `Invitation` /
`Client` / `PQRatchet`) and backends conform to it:

- **TwoMLSPQ** (in this package) — the post-quantum backend: two send groups,
  each a classical MLS group bound to an ML-KEM-768 group per
  draft-ietf-mls-combiner-02, vendored as a UniFFI binding over the
  [TwoMLSPQ](https://github.com/germ-network/TwoMLSPQ) XCFramework.
- **Classical** (out of tree) — apps conform their classical MLS session type
  retroactively; only the abstraction's protocols are needed.

## Module surface: import `AbstractTwoMLS` only

The library product vends a single module. The concrete UniFFI wrapper
targets (`TwoMLSPQ`, and the test-only `MLSrsClassic`) are internal — they
link transitively but cannot be imported by consumers. This is deliberate:

- UniFFI stamps its interface classes `@unchecked Sendable` (the Rust objects
  are `Send + Sync` behind a lock). That makes sharing **memory-safe** but
  says nothing about **ordering** — and a session is a strictly sequential,
  single-driver state machine (one pending-proposal slot, one parked reply
  slot). Concurrent drivers can interleave silently: a second
  `prepareToEncrypt` replaces the first's staged proposal with no signal.
- The abstraction's session types are therefore deliberately **not
  `Sendable`** (`PQSession` carries an unavailable `Sendable` conformance so
  it cannot be retroactively re-added). The compiler refuses to move a
  session across task boundaries; the **containing type** — typically an
  actor that owns the session and serializes all driving — asserts its own
  `Sendable` conformance instead.
- Every FFI call is synchronous, so an owning actor gives strict
  serialization: no suspension points inside a call, no interleaving between
  calls. Don't drive a session from the main actor — PQ operations do
  ML-KEM work on the calling thread.

Value/result types (`PQInbound`, decrypt results, epochs, tokens, archives)
are `Sendable` snapshots and move freely.

## State is truth, events are hints

Rotation outcomes surface twice: as one-shot **events**
(`remoteCommit.newSender`/`newRecipient`, on the frame where the transition
applied) and as queryable **state** (`myPrincipalState` /
`theirPrincipalState` / `queuedRemoteSuccessor`). Events can be lost — a
frame's staple (commit) applies before its app message decrypts, so a
transient decrypt failure swallows the event and the retry's staple is an
idempotent skip. After any retriable `processIncoming` failure, reconcile
identity from `theirPrincipalState`; never depend on an event you might have
missed.

## Platforms

`.iOS(.v17)` / `.macOS(.v15)` are **import/link floors** — the package builds
and links there. The PQ backend's ML-KEM paths additionally require **OS 26
(CryptoKit ML-KEM-768) at runtime**; that floor applies to *calling* the PQ
API, not to importing the package.

## Archives

Session and invitation archives are returned as plaintext bytes and contain
long-term signing keys: **seal before persisting** is the caller's contract.
Restore validates fully and fails closed (`ArchiveInvalid`).

## Releases

Releases are cut with [changesets](https://github.com/changesets/changesets):
PRs add a changeset; merging the auto-opened "Prepare next release" PR tags
`vX.Y.Z` and publishes the GitHub release.

## Contributing and Collaboration

We welcome contributions!

Please follow our [guidelines for contributing code](./CONTRIBUTING.md)

To give clarity of what is expected of our members, Germ has adopted the
code of conduct defined by the Contributor Covenant. This document is used
across many open source communities, and we think it articulates our values
well. For more, see the [Code of Conduct](./CODE_OF_CONDUCT.md)
