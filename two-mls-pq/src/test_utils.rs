use std::sync::Arc;

use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::{
    key_packages::{CombinerKeyPackage, TwoMlsPqClient},
    session::TwoMlsPqSession,
};

#[cfg(not(feature = "cryptokit"))]
use crate::MlsCipherSuite;

/// A fresh, unique ClientId for tests (random bytes, so distinct callers get distinct
/// identities). The bytes are opaque — they are no longer a signing key.
pub(crate) fn test_client_id() -> Vec<u8> {
    let crypto = RustCryptoProvider::new();
    let cs = assert_some!(crypto.cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));
    let (secret, _) = assert_ok!(cs.signature_key_generate());
    secret.as_bytes().to_vec()
}

pub(crate) fn make_client() -> Arc<TwoMlsPqClient> {
    assert_ok!(TwoMlsPqClient::new(test_client_id()))
}

pub(crate) fn make_combiner_kp(client: &TwoMlsPqClient) -> CombinerKeyPackage {
    #[cfg(feature = "cryptokit")]
    return assert_ok!(client.generate_combiner_key_package());
    #[cfg(not(feature = "cryptokit"))]
    {
        let classical = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        let pq = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        CombinerKeyPackage { classical, pq }
    }
}

pub(crate) fn establish_sessions() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
    let welcome_a = assert_some!(alice_session.pending_outbound());
    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp
    ));
    let welcome_b = assert_some!(bob_session.pending_outbound());
    assert_ok!(alice_session.process_incoming(welcome_b));
    (alice_session, bob_session)
}
