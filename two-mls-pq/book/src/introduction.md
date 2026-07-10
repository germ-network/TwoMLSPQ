# Introduction

TwoMLSPQ is a Rust + UniFFI library implementing 1:1 post-quantum end-to-end
encryption on top of **two asymmetric MLS send groups** — the Combiner / APQ
construction from `draft-ietf-mls-combiner-02`, instantiated with ML-KEM-768
(FIPS 203).

It does not replace the classical MLS stack; it sits alongside it and covers the
post-quantum gap for direct (1:1) conversations.

## Where it sits

```
iOS App
  └─ CommProtocol (Swift)        DIDs · Anchors · Agent keys · routing
       └─ TwoMLSPQ (this crate)  Combiner sessions · two send groups
            └─ mls-rs            MLS group state · key schedules
                 └─ crypto       X25519/ChaCha (classical) · ML-KEM-768 (PQ)
```

CommProtocol owns identity (DIDs, anchor keys) and hands TwoMLSPQ a signing key for one
of its **agents**. TwoMLSPQ has no notion of agents; it wraps that key as a
**`TwoMlsPqPrincipal`** — *principal* is this library's CommProtocol-agnostic name for the
credential-scoped signer CommProtocol calls an agent (the `Agent ↔ Principal` mapping is
documented at the AbstractTwoMLS boundary). That key's public component is the MLS
`ClientId` (a Basic Credential — there is no Authentication Service). Everything above that
key is outside this library's boundary.

## How a session is built

Each session holds **two** Combiner groups:

- **send group** — owned by this party; they commit and encrypt here.
- **receive group** — owned by the remote party; this party joins and decrypts here.

Each Combiner group is itself a pair of MLS groups — a classical half (`0x0003`)
and an ML-KEM-768 half (`0xFDEA`) — cryptographically bound by a PSK chain. The
hybrid (classical + post-quantum) guarantee comes from this two-group binding, not
from a hybrid cipher suite.

The rest of this book covers the cipher suites, the session lifecycle, the wire
format, header encryption (the outer seal that hides frame metadata), the PSK
binding contract, and the public API, finishing with an end-to-end walkthrough and
how to run the benchmarks.
