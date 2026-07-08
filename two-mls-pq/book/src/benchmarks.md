# Benchmarks

Criterion benchmarks live in `benches/`, gated behind the `benchmark_util` feature.

```sh
# Real ML-KEM-768 on aws-lc (any platform)
just bench
# or: cargo bench -p two-mls-pq --features "benchmark_util awslc"

# Real ML-KEM-768 on Apple CryptoKit (macOS 26+)
just bench-pq
# or: cargo bench -p two-mls-pq --features "benchmark_util cryptokit"
```

## HTML reports

Each run writes an interactive HTML report (criterion with the pure-Rust `plotters`
backend — no external tools) to `target/criterion/report/index.html`: violin plots,
per-benchmark PDF/iteration charts, and, when a previous run exists, before/after
comparison plots. Open it after `just bench`:

```sh
open target/criterion/report/index.html   # macOS
```

`target/` is gitignored, so reports stay local.

`BenchmarkId`s are labelled with the active suite and provider (`ml_kem_768/awslc` vs
`ml_kem_768/cryptokit`) so the two runs are distinguishable in reports.

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
