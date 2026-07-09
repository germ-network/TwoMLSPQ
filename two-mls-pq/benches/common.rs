// Shared bench fixtures. Pulled into each bench via `mod common;` (the package sets
// `autobenches = false`, so this file is not itself a bench target). Mirrors
// `src/test_utils.rs`, but uses only the public API plus the crate's own deps.
#![allow(dead_code, unused_imports, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use two_mls_pq::{
    key_packages::{CombinerKeyPackage, TwoMlsPqPrincipal},
    session::TwoMlsPqSession,
    MlsCipherSuite,
};

/// A fresh, unique ClientId for benches. The bytes are opaque — uniqueness is all that
/// matters, so a counter + timestamp avoids pulling a crypto provider in here.
pub fn client_id() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("bench-client-{n}-{t}").into_bytes()
}

pub fn client() -> Arc<TwoMlsPqPrincipal> {
    TwoMlsPqPrincipal::new(client_id()).unwrap()
}

pub fn combiner_kp(client: &TwoMlsPqPrincipal) -> CombinerKeyPackage {
    client.generate_combiner_key_package().unwrap()
}

pub fn established() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let alice = client();
    let bob = client();
    let alice_kp = combiner_kp(&alice);
    let bob_kp = combiner_kp(&bob);
    let alice_session = TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp).unwrap();
    let welcome_a = alice_session.pending_outbound().unwrap();
    let bob_session = TwoMlsPqSession::accept(Arc::clone(&bob), welcome_a, alice_kp).unwrap();
    let welcome_b = bob_session.pending_outbound().unwrap();
    alice_session.process_incoming(welcome_b).unwrap();
    (alice_session, bob_session)
}

/// Suite + provider label for `BenchmarkId`s so cryptokit and awslc runs are
/// distinguishable in reports.
pub fn suite_label() -> &'static str {
    if cfg!(feature = "cryptokit") {
        "ml_kem_768/cryptokit"
    } else {
        "ml_kem_768/awslc"
    }
}
