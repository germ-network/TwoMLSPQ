// Shared bench fixtures. Pulled into each bench via `mod common;` (the package sets
// `autobenches = false`, so this file is not itself a bench target). Mirrors
// `src/test_utils.rs`, but uses only the public API plus the crate's own deps.
#![allow(dead_code, unused_imports, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use two_mls_pq::{
    key_packages::{
        CombinerKeyPackage, InitialFrame, OpenedInitial, TwoMlsPqInvitation, TwoMlsPqPrincipal,
    },
    session::TwoMlsPqSession,
    MlsCipherSuite,
};

/// Bench-side mirror of the test-only `TwoMlsPqInvitation::open_establishment`: open a §A.1
/// envelope and require the establishment variant (benches only ever open the reply).
pub fn open_establishment(inv: &TwoMlsPqInvitation, blob: Vec<u8>) -> InitialFrame {
    match inv.open_initial(blob).unwrap() {
        OpenedInitial::Establishment { frame } => frame,
        OpenedInitial::BootstrapKp { .. } => unreachable!("establishment envelope expected"),
    }
}

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

/// The initiator's CLASSICAL return key package (§A.1: the return group starts
/// classical-only; the PQ KP travels in A.4, hash-bound).
pub fn classical_kp(client: &TwoMlsPqPrincipal) -> Vec<u8> {
    client
        .generate_key_package(MlsCipherSuite::x25519_chacha())
        .unwrap()
}

pub fn established() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let alice = client();
    let bob = client();
    let alice_kp = classical_kp(&alice);

    // Production establishment path (mirrors `src/test_utils.rs`): Bob publishes an
    // invitation; Alice's first frame is the §A.1 envelope, which Bob opens and joins.
    let bob_inv = TwoMlsPqInvitation::restore(bob.generate_invitation(true).unwrap()).unwrap();
    let bob_kp = bob_inv.combiner_key_package();

    let alice_session = TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None).unwrap();
    let envelope = alice_session.pending_outbound().unwrap();
    let opened = open_establishment(&bob_inv, envelope);
    let bob_session = bob_inv
        .receive(
            opened.welcome.unwrap(),
            alice_kp,
            alice_session.bootstrap_kp_commitment().unwrap(),
            b"bench-establish".to_vec(),
            None,
            None,
            None,
        )
        .unwrap();
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
