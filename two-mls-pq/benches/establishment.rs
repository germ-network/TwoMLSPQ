#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use two_mls_pq::session::TwoMlsPqSession;

mod common;
use common::{client, combiner_kp, suite_label};

fn bench_establishment(c: &mut Criterion) {
    let mut group = c.benchmark_group("establishment");

    group.bench_function(format!("initiate/{}", suite_label()), |b| {
        b.iter_batched(
            || {
                let alice = client();
                let bob = client();
                (alice, combiner_kp(&bob))
            },
            |(alice, bob_kp)| TwoMlsPqSession::initiate(alice, bob_kp).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(format!("full_handshake/{}", suite_label()), |b| {
        b.iter_batched(
            || {
                let alice = client();
                let bob = client();
                let alice_kp = combiner_kp(&alice);
                let bob_kp = combiner_kp(&bob);
                (alice, bob, alice_kp, bob_kp)
            },
            |(alice, bob, alice_kp, bob_kp)| {
                let alice_session = TwoMlsPqSession::initiate(alice, bob_kp).unwrap();
                let welcome_a = alice_session.pending_outbound().unwrap();
                let bob_session = TwoMlsPqSession::accept(bob, welcome_a, alice_kp).unwrap();
                let welcome_b = bob_session.pending_outbound().unwrap();
                alice_session.process_incoming(welcome_b).unwrap();
                (alice_session, bob_session)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_establishment);
criterion_main!(benches);
