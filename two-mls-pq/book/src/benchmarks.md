# Benchmarks

Criterion benchmarks live in `benches/`, gated behind the `benchmark_util` feature.

```sh
# Simulated PQ half (RustCrypto) — measures Combiner-machinery overhead
just bench
# or: cargo bench -p two-mls-pq --features benchmark_util

# Real ML-KEM-768 (AWS-LC, macOS)
just bench-pq
# or: cargo bench -p two-mls-pq --features "benchmark_util cryptokit"
```

`BenchmarkId`s are labelled with the active suite (`simulated` vs `ml_kem_768`) so the
two runs are distinguishable in reports.

## Groups

| Bench file | Measures |
|------------|----------|
| `kp_generation` | single key-package and combiner-pair generation |
| `establishment` | `initiate`, and the full `initiate`/`accept`/join handshake |
| `messaging` | steady-state partial-commit send, and a send→decrypt round trip |

Sessions mutate on commit, so messaging benches use `iter_batched_ref` with a freshly
established session per iteration. Shared fixtures are in `benches/common.rs`
(`autobenches = false` keeps it from being treated as its own bench target).

Additional groups (full commit, rotation, parsing, and — once archive lands — archive
round-trips) follow the same pattern.
