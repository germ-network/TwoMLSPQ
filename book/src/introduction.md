# Introduction

TwoMLSPQ is a Rust implementation of a PQ triple ratchet with header encryption.
Its interface is exported through UniFFI.
We provide a swift build script, and a swift package that wraps the FFI API in
Swift Concurrency-friendly types.

TwoMLSPQ is a Rust + UniFFI library implementing 1:1 post-quantum end-to-end
encryption on top of **two send groups**, one per party. Each send
group is implemented as an **APQ group** — a classical MLS group and a PQ MLS group
bound by a PSK chain, following `draft-ietf-mls-combiner-02` and instantiated with
ML-KEM-768 (FIPS 203).

## Where it sits

```
App
		TwoMLSPQ(Swift Package) Swift API
    		└─ TwoMLSPQ (rust crate)  sessions · two send groups (APQ groups)
        		└─ mls-rs            MLS group state · key schedules
              		└─ crypto       X25519/ChaCha (classical) · ML-KEM-768 (PQ)
        └─ CommProtocol (Swift)        TypedDigest

```

The Swift package does pull in CommProtocol for a TypedDigest to express hash digests in its
API without making them opaque bytes. It does not otherwise depend on CommProtocol's identities
and exposes an MLS client interface of basic credentials.

The app hands TwoMLSPQ the opaque **`ClientId`** of one of its **agents** — identity bytes.
TwoMLSPQ builds a **`TwoMlsPqPrincipal`** for that ClientId, minting a fresh MLS leaf signing key
internally. The ClientId is carried as the MLS Basic Credential — identity trust comes
from the app layer, not an
external Authentication Service — and the signing key that authenticates the leaf lives
inside this library and never crosses the boundary. Everything above the ClientId is outside
this library's boundary.

## How a session is built

Each session holds **two send groups**, one per party; locally they play two roles:

- **send group** — owned by this party; they commit and encrypt here.
- **receive group** — the remote party's send group; this party joins and decrypts here.

Each send group is an APQ group: a pair of MLS groups — a classical half (`0x0003`)
and an ML-KEM-768 half (`0xFDEA`) — cryptographically bound by a PSK chain. The
hybrid (classical + post-quantum) guarantee comes from this two-group binding, not
from a hybrid cipher suite.

The rest of this book covers the cipher suites, the session lifecycle, the wire
format, header encryption (the outer seal that hides frame metadata), the PSK
binding contract, and the public API, finishing with an end-to-end walkthrough and
how to run the benchmarks.
