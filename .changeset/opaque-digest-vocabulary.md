---
"@germ-network/two-mls-pq": minor
---

Own the digest vocabulary: drop CommProtocol from the Swift product.

Digests and routing ids now cross the Swift API as self-describing tagged `Data`
that this package derives (`PQDigest.over(_:)`) and compares, instead of as
`CommProtocol.TypedDigest`/`DataIdentifier`. The bytes were always the real
contract — the 33-byte tagged form is what the cross-party agent handoff signs
over — while the shared Swift *type* bought only call-site convenience, at the
price of putting the digest kind namespace in another package's hands. Since the
hash is a facet of the crate's cipher suite (`TwoMlsSuite::CURRENT.digest`), a
future suite could not ship without a CommProtocol release first. It can now.

Every byte is unchanged: the digest tag stays `0x01` and routing ids stay `0x02`,
the values CommProtocol assigned, so spawn tokens (keys of the crate's archived
forward table) and adopter-persisted routing keys keep matching across the
upgrade. No FFI change — binding contract stays 27, no re-pairing.

Source-breaking for adopters: `proposalHash`, `QueuedRemoteProposal.digest`/
`.context`, `proposalContext`, `queueProposal(digest:)`, `WelcomeToken.digest`,
and `HeaderDecryptResult.forward`'s group id are now `Data`. Where a caller
previously built a `TypedDigest` to hand back, pass the bytes through; where it
derived one to match a value this library emitted, use `PQDigest.over(_:)`. The
retype moved a type-system guarantee to a runtime check, so malformed digests
now throw `SessionError(.internalError)` at the boundary rather than failing to
compile.

The Swift package now has no external Swift dependencies (CommProtocol remains a
test-only dependency, which mints client ids the way the app does).
