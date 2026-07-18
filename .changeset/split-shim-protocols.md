---
"@germ-network/two-mls-pq": minor
---

Split the backward-compat shim protocols out of the public TwoMLSPQ product.

The Swift package is renamed `AbstractTwoMLS` → **`TwoMLSPQ`** and vends a `TwoMLSPQ` product
containing only the concrete PQ types and their value/currency types, de-nested to top level
(`PQSession`, `PQInvitation`, `PQClient`, `SessionError`, `HeaderDecryptResult`, `WelcomeToken`,
`PrincipalState`, …), plus the UniFFI binding — isolated in an internal `TwoMLSPQBinding` target
so its generated interface types stay off the public surface (and no longer collide with the
wrapper's same-named currency types).

The cross-backend shim **protocols** (`Session`, `Client`, `Invitation`, `Archivable`,
`PQRatchet`, `PQRatchetingSession`, the `*Protocol` result protocols) move to the separate
`AbstractTwoMLS` package, which depends on and re-exports this one and adds the conformances via
extensions. `CommProtocol` is retained: `TypedDigest` is not an opaque token — the proposal
digest's `.wireFormat` is signed into the cross-party agent handoff, so it is shared crypto
vocabulary, and it's a type dependency rather than the shim protocol being quarantined.

BREAKING: the module/product is now `TwoMLSPQ` and the types are top-level (not `AbstractTwoMLS.*`);
consumers re-point their dependency and add `import AbstractTwoMLS` (which re-exports `TwoMLSPQ`).
