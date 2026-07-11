# Cipher Suites & Feature Flags

## Suites

| Role | Value | Suite |
|------|-------|-------|
| Classical | `0x0003` | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (RFC 9420 §17.1) |
| Post-quantum | `0xFDEA` | `MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519` (FIPS 203, private range) |

`MlsCipherSuite::is_combiner_pq()` returns true **only** for `0xFDEA` — it is the
routing signal: true means "handle in TwoMLSPQ as the PQ half", false means "hand to the
classical library". `is_combiner_classical()` returns true **only** for `0x0003`; use it to
recognise the classical half of an APQ group so it is paired with the ML-KEM-768
half rather than routed to the classical library on its own.

TwoMLSPQ uses **pure ML-KEM-768** for the PQ half — there is no hybrid (XWing-style)
cipher suite. The hybrid property comes from the APQ group's two-half binding (the
classical group bound to the ML-KEM-768 group via PSK).

## Suites and the APQ mode

MLS cipher suites are **monolithic**: one id fixes the KEM, AEAD, hash, *and* signature
scheme together (RFC 9420 §17.1). A suite id alone therefore tells you its signature
scheme — both `0x0003` and `0xFDEA` end in `…_Ed25519`, i.e. **classical Ed25519
signatures**.

A session is locked to a concrete pair, `ApqCipherSuite { classical, pq }` — the source of
truth. The **APQ mode is derived from that pair**, not the other way around:

- `ConfidentialityOnly` — the shipped combination `(0x0003, 0xFDEA)`: ML-KEM-768
  confidentiality with classical Ed25519 authentication. Authentication is *not*
  post-quantum.
- A future confidentiality **+ authentication** mode would use a PQ *signature* scheme
  (ML-DSA / SLH-DSA). No such suite has an IANA assignment, so — exactly as ML-KEM-768 uses
  the private-range `0xFDEA` — it would be pinned to a hardcoded private-range value, added
  to the suite classifier, and given a new mode variant.

A small classifier (in `apq`) reads each half's KEM/signature nature off the §17.1 table.
`ApqCipherSuite::new` enforces the slot invariant — the classical half must be a classical
KEM and the PQ half a post-quantum (ML-KEM) KEM, both recognised — rejecting anything else
with `CipherSuiteMismatch`. Given a valid pair, `mode()` is total: it reads the PQ half's
signature scheme, yielding `ConfidentialityOnly` for a classical (Ed25519) signature and
`ConfidentialityAndAuthenticity` for a post-quantum one.

The suite pair is a **fixed, stored property** of a session: captured at construction,
persisted in the session and invitation archives, and validated up front. A peer key
package or welcome whose suites don't match fails early with `CipherSuiteMismatch` (or
`PqNotAvailable` when the peer offers no PQ half at all) rather than as a late, opaque
decrypt error, and a restored archive whose suite pair differs from the build's pinned
suite is rejected as `ArchiveInvalid`.

The same `(mode, classical_suite, pq_suite)` triple is recorded in each half's `APQInfo`
GroupContext extension (type `0xF0A1`) and carried in the Welcome, so a joiner
re-verifies the pair — and rejects an invalid or duplicate suite pairing, as
`draft-ietf-mls-combiner-02` requires — against that record, not only against its own
pinned suite. See [group rules](./group-rules.md) (rule 7) and
[wire format](./wire-format.md).

## Feature flags

| Flag | Meaning |
|------|---------|
| `cryptokit` | Apple CryptoKit backs **both halves** (classical suites + native ML-KEM-768, FIPS 203). macOS 26 / iOS 26+ only. The shipped configuration. |
| `awslc` | aws-lc backs both halves. Portable (Linux CI runs the full suite with it) and wire-compatible with `cryptokit`. |
| `benchmark_util` | Gates the `benches/*` targets and their fixtures. |

Exactly one provider feature must be selected — there is **no default**, and a build
with neither fails with an explicit `compile_error!`. When both are enabled
(`--all-features` on an Apple machine), `cryptokit` wins. The PQ half is always real
ML-KEM-768: the crypto provider is an implementation detail pinned in
`two-mls-pq/src/providers.rs`, and the `apq` crate compiles no provider at all — the
concrete providers are injected as generic parameters (`apq::CryptoConfig`).
