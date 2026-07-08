# Cipher Suites & Feature Flags

## Suites

| Role | Value | Suite |
|------|-------|-------|
| Classical | `0x0003` | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (RFC 9420 §17.1) |
| Post-quantum | `0xFDEA` | `MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519` (FIPS 203, private range) |

`MlsCipherSuite::is_supported()` returns true **only** for `0xFDEA` — it is the
routing signal: true means "handle in TwoMLSPQ", false means "hand to the classical
library". `is_combiner_classical()` returns true **only** for `0x0003`; use it to
recognise the classical half of a Combiner pair so it is paired with the ML-KEM-768
half rather than routed to the classical library on its own.

TwoMLSPQ uses **pure ML-KEM-768** for the PQ half — there is no hybrid (XWing-style)
cipher suite. The hybrid property comes from the Combiner construction (the classical
group bound to the ML-KEM-768 group via PSK).

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
