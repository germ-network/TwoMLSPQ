use std::sync::Arc;

use mls_rs::{CipherSuiteProvider, CryptoProvider};

use crate::{
    key_packages::{CombinerKeyPackage, TwoMlsPqInvitation, TwoMlsPqPrincipal},
    session::TwoMlsPqSession,
};

/// A fresh, unique ClientId for tests (random bytes, so distinct callers get distinct
/// identities). The bytes are opaque — they are no longer a signing key.
pub(crate) fn test_client_id() -> Vec<u8> {
    let crypto = crate::providers::classical();
    let cs = assert_some!(crypto.cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));
    let (secret, _) = assert_ok!(cs.signature_key_generate());
    secret.as_bytes().to_vec()
}

pub(crate) fn make_client() -> Arc<TwoMlsPqPrincipal> {
    assert_ok!(TwoMlsPqPrincipal::new(test_client_id()))
}

pub(crate) fn make_combiner_kp(client: &TwoMlsPqPrincipal) -> CombinerKeyPackage {
    assert_ok!(client.generate_combiner_key_package())
}

/// The initiator's CLASSICAL return key package (a bare MLS KeyPackage message) — what
/// `receive`/`accept` take since the return KP went classical-only (§A.1). Retaining,
/// like the combiner generate, so the return-group join can resolve its private key.
pub(crate) fn make_classical_kp(client: &TwoMlsPqPrincipal) -> Vec<u8> {
    assert_ok!(client.generate_key_package(crate::MlsCipherSuite::x25519_chacha()))
}

/// The initiator session's A.4 bootstrap KP commitment, as the host would carry it in
/// the signed establishment payload and the acceptor would thread it into `receive`.
pub(crate) fn commitment_of(session: &TwoMlsPqSession) -> Vec<u8> {
    assert_some!(session.bootstrap_kp_commitment())
}

pub(crate) fn establish_sessions() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);

    // The production establishment path: Bob publishes an invitation (whose KP Alice
    // initiates to and which opens the §A.1 envelope). Alice's first frame is the sealed
    // envelope; Bob opens it and joins.
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let envelope = assert_some!(alice_session.pending_outbound());
    let opened = assert_ok!(bob_inv.open_establishment(envelope));
    let bob_session = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_session),
        b"establish".to_vec(),
        None,
        None,
        None
    ));

    let welcome_b = assert_some!(bob_session.pending_outbound());
    assert_ok!(alice_session.process_incoming(welcome_b));
    (alice_session, bob_session)
}

/// `establish_sessions` plus one message-frame round-trip in each direction, so both
/// sides have processed a peer frame. That is the `peer_confirmed` precondition for a
/// unilateral rotation commit under the always-staple wire format (a rotation commit
/// must never displace a welcome staple the peer may still need). Neither side queues
/// the offered proposals, so no epochs advance here.
pub(crate) fn establish_confirmed_sessions() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let (alice_session, bob_session) = establish_sessions();
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"confirm-a".to_vec()));
    assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"confirm-b".to_vec()));
    assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    (alice_session, bob_session)
}
