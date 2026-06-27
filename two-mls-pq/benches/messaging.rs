#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

mod common;
use common::{established, suite_label};

fn bench_messaging(c: &mut Criterion) {
    let mut group = c.benchmark_group("messaging");

    // Steady-state send (partial-commit path). Commits mutate state, so each iteration
    // gets a freshly established session via `iter_batched_ref`.
    group.bench_function(format!("send_partial/{}", suite_label()), |b| {
        b.iter_batched_ref(
            established,
            |(alice, _bob)| {
                alice.prepare_to_encrypt(None).unwrap();
                alice.encrypt(b"hello".to_vec()).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(format!("roundtrip_partial/{}", suite_label()), |b| {
        b.iter_batched_ref(
            established,
            |(alice, bob)| {
                alice.prepare_to_encrypt(None).unwrap();
                let enc = alice.encrypt(b"hello".to_vec()).unwrap();
                bob.process_incoming(enc.cipher_text).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_messaging);
criterion_main!(benches);
