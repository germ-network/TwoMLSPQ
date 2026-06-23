#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use two_mls_pq::MlsCipherSuite;

mod common;
use common::{client, combiner_kp, suite_label};

fn bench_kp_generation(c: &mut Criterion) {
    let cl = client();
    let mut group = c.benchmark_group("kp_generation");

    group.bench_function("generate_key_package/classical", |b| {
        b.iter(|| {
            cl.generate_key_package(MlsCipherSuite::x25519_chacha())
                .unwrap()
        })
    });

    group.bench_function(
        format!("generate_combiner_key_package/{}", suite_label()),
        |b| b.iter(|| combiner_kp(&cl)),
    );

    group.finish();
}

criterion_group!(benches, bench_kp_generation);
criterion_main!(benches);
