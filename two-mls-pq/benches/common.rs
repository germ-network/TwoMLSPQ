// Shared bench fixtures. Pulled into each bench via `mod common;` (the package sets
// `autobenches = false`, so this file is not itself a bench target). Mirrors
// `src/test_utils.rs`, but uses only the public API plus the crate's own deps.
#![allow(dead_code, unused_imports, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use two_mls_pq::{
    key_packages::{CombinerKeyPackage, TwoMlsPqClient},
    session::TwoMlsPqSession,
    MlsCipherSuite,
};

pub fn signing_key() -> Vec<u8> {
    let crypto = RustCryptoProvider::new();
    let cs = crypto
        .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
        .unwrap();
    let (secret, _) = cs.signature_key_generate().unwrap();
    secret.as_bytes().to_vec()
}

pub fn client() -> Arc<TwoMlsPqClient> {
    TwoMlsPqClient::new(signing_key()).unwrap()
}

pub fn combiner_kp(client: &TwoMlsPqClient) -> CombinerKeyPackage {
    #[cfg(feature = "cryptokit")]
    {
        client.generate_combiner_key_package().unwrap()
    }
    #[cfg(not(feature = "cryptokit"))]
    {
        let classical = client
            .generate_key_package(MlsCipherSuite::x25519_chacha())
            .unwrap();
        let pq = client
            .generate_key_package(MlsCipherSuite::x25519_chacha())
            .unwrap();
        CombinerKeyPackage { classical, pq }
    }
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

/// Suite label for `BenchmarkId`s so default (simulated) and `cryptokit` (real
/// ML-KEM-768) runs are distinguishable in reports.
pub fn suite_label() -> &'static str {
    if cfg!(feature = "cryptokit") {
        "ml_kem_768"
    } else {
        "simulated"
    }
}
