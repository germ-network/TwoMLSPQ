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
| `rustcrypto` (default) | Both halves use `mls-rs-crypto-rustcrypto` (X25519/ChaCha). The PQ half is **simulated** — no real ML-KEM. Good for fast cross-platform tests. |
| `cryptokit` | The PQ half uses real **ML-KEM-768** (FIPS 203). macOS/iOS. |
| `benchmark_util` | Gates the `benches/*` targets and their fixtures. |

The crypto provider is an implementation detail: TwoMLSPQ only requires ML-KEM-768
for the PQ half. Under the default build the PQ half is X25519/ChaCha so a normal test
run exercises the Combiner machinery without needing ML-KEM available; real ML-KEM-768
numbers require `--features cryptokit`.
