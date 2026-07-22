# Carried Encodings

TwoMLSPQ holds bytes it does not interpret: the principal's `ClientId`, the app-state
binding welded into a key package, the app payload riding an establishment envelope.
This chapter is about what that costs. Carrying a value opaquely is not the same as
being decoupled from it — some carried bytes get **persisted** in MLS group state or
**byte-compared** across a version boundary, and those two facts impose obligations on
whoever *produces* the encoding, in a repo that has no build-time edge to this one.

The principle the API is built on: **foreign facts are opaque, domestic facts are
typed.** This library types what it owns and takes everything else as `Data`. The
obligations below are the residue — they are small, but they are invisible, because
both sides of each one spell the value `Data`.

## Digests: owned, not carried

Digests used to be the counterexample. The Swift surface spoke
`CommProtocol.TypedDigest`, which meant the *kind tag* — the byte naming the hash
algorithm — lived in another package's enum. That inverted ownership: the digest
algorithm is a facet of this crate's cipher suite (`TwoMlsSuite::CURRENT.digest`), so
a new suite's digest could not be named without first releasing the package that owned
the tag namespace.

The bytes were always the real contract. The 33-byte tagged form is what a
cross-party agent handoff signs over, and the verifier never parses it out of a
message — it rebuilds its signature body from a locally derived reference digest and
checks the signature against that. Sharing the Swift *type* bought call-site
convenience and nothing else.

So digests are now derived, tagged, and compared here (`PQDigest`), and carried by
everyone else as `Data`. Suite agility follows: a new digest is a new tag in this
repo, and no other package needs a release to permit it. Consumers owe these bytes
nothing but carriage — hand them back verbatim, and derive anything that must
byte-match one with `PQDigest.over(_:)` rather than a hand-rolled hash.

## `ClientId` is an identifier format

The app hands in a `ClientId` and this library never looks inside it. But it does not
merely pass it along: the bytes are baked into the MLS Basic Credential, **persisted
in ratchet trees**, byte-compared for identity mapping and the credential-sequence
whitelist, and checked against a welcome's creator leaf at a born-dedicated
establishment. The app then parses the same bytes back out of a `DecryptResult` into
its own key type.

Once bytes you produce are persisted by someone else as a key, you have an identifier
format, and identifier formats evolve **append-only**. In the Germ stack a `ClientId`
is an agent public key's `wireFormat` — itself a tagged, self-describing encoding — so
this works without anyone coordinating: adding a key algorithm mints a new tag, those
become new `ClientId`s through ordinary credential rotation, and every previously
persisted id still parses under its old tag.

What is *not* safe is changing the layout of an existing tag in place. That does not
break a wire format — it breaks stored group state, for every live session, with no
migration path short of re-pairing. This library cannot detect such a change; it will
faithfully compare the new bytes against the old ones and report an identity mismatch.

## The app binding is a derived equality

The `AppBinding` extension (the `app_binding` threaded through `initiate` / `receive`,
see [API Reference](./api-reference.md)) is different in kind,
and the difference matters. It is **equality-compared, not parsed**, and it is
**derived independently on both ends** from shared inputs — in the Germ stack, the two
anchor DIDs in lexical order. Self-description does not protect a value like this:
there is nothing to read a tag off, only two byte strings that must come out identical
on two devices that may be running different builds.

So the obligation is a stable canonical derivation — the sort order, the DID normal
form, the separator — and it is stricter than the `ClientId` rule, because even an
append-only change to the producer breaks it if the derived bytes move. The
consolation is blast radius: nothing is persisted, and the value is re-derived fresh
at each establishment, so a mismatch is a version-skew window that closes when both
ends update, not a permanent wound in stored state. The crate rejects the welcome
before consuming the invitation (`AppBindingMismatch`), so a skewed pair fails safe
and retries cleanly.

## What carries no obligation

Most opaque payloads impose nothing. App-layer identity envelopes, signed handoffs,
and the establishment app payload ride through as bytes both parties see identically —
this library digests some of them, but it never needs to agree with the *producer*
about their internal encoding, only to hand the same bytes to both ends. Change those
formats freely: an encoding change moves both sides at once.

The distinction is durable state and independent derivation. Ask of any carried value:
*does someone persist it, and does anyone else recompute it?* If neither, it is pure
carriage.

## Summary

| Carried value | How it is used | Producer's obligation | If violated |
|---|---|---|---|
| Digests (`PQDigest`) | derived and compared here | none — this package owns the tags | — |
| `ClientId` | persisted in group state, compared, parsed back | append-only (never re-lay out an existing tag) | live sessions' stored state; re-pairing |
| `AppBinding` | equality-compared, derived on both ends | frozen canonical derivation | establishment skew window; fails safe |
| App payloads, envelopes | passed through | none | — |

None of these appear in a dependency graph. Both sides of every row spell the value
`Data` — which is the point, and the reason they are written down here.
