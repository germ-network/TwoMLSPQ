//! Narrative end-to-end demonstration of a TwoMLSPQ session, expressed as tests so it
//! stays compiled and correct. Run with `-- --nocapture` to see the printed walkthrough
//! (see `DEMO.md`). The assertions double as a living spec of the public API.

use std::sync::Arc;

use crate::{
    key_packages::parse_mls_key_package,
    test_utils::{make_client, make_combiner_kp},
    AgentState, MlsCipherSuite, TwoMlsPqSession,
};

fn provider_label() -> &'static str {
    #[cfg(feature = "cryptokit")]
    {
        "cryptokit (AWS-LC, real ML-KEM-768)"
    }
    #[cfg(not(feature = "cryptokit"))]
    {
        "rustcrypto (PQ half simulated with X25519/ChaCha20)"
    }
}

#[test]
fn demo_cipher_suite_constants() {
    let classical = MlsCipherSuite::x25519_chacha();
    let pq = MlsCipherSuite::ml_kem_768();

    println!("\n=== TwoMLSPQ cipher suites ===");
    println!("active provider : {}", provider_label());
    println!(
        "classical       : 0x{:04X}  is_supported={}  is_combiner_classical={}",
        classical.value(),
        classical.is_supported(),
        classical.is_combiner_classical(),
    );
    println!(
        "post-quantum    : 0x{:04X}  is_supported={}  (ML-KEM-768, FIPS 203)",
        pq.value(),
        pq.is_supported(),
    );

    assert_eq!(classical.value(), 0x0003);
    assert_eq!(pq.value(), 0xFDEA);
    assert!(pq.is_supported());
    assert!(classical.is_combiner_classical());
}

#[test]
fn demo_e2e_full_session() {
    println!("\n=== TwoMLSPQ end-to-end walkthrough ===");
    println!("provider: {}\n", provider_label());

    // Step 1 — clients.
    let alice = make_client();
    let bob = make_client();
    println!("[1] clients created");
    println!(
        "    alice.clientId = {} bytes",
        alice.client_id().bytes.len()
    );
    println!("    bob.clientId   = {} bytes", bob.client_id().bytes.len());

    // Step 2 — combiner key packages (classical + ML-KEM-768 halves).
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    println!("[2] combiner key packages generated (classical + pq halves)");

    // Step 3 — parsing / routing signal.
    let bob_classical = assert_ok!(parse_mls_key_package(bob_kp.classical.clone()));
    let bob_pq = assert_ok!(parse_mls_key_package(bob_kp.pq.clone()));
    println!(
        "[3] parsed bob's halves: classical suite=0x{:04X}, pq suite=0x{:04X}",
        bob_classical.cipher_suite.value(),
        bob_pq.cipher_suite.value(),
    );
    assert_eq!(
        bob_classical.client_id, bob_pq.client_id,
        "halves share clientId"
    );

    // Step 4 — establishment (0x01 APQWelcome both directions).
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
    let welcome_a = assert_some!(alice_session.pending_outbound());
    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp
    ));
    let welcome_b = assert_some!(bob_session.pending_outbound());
    assert_ok!(alice_session.process_incoming(welcome_b));
    assert!(alice_session.is_established() && bob_session.is_established());
    println!("[4] session established (both send + receive groups live; PSK chain bound)");

    // Step 5 — partial commit (0x05): Alice -> Bob.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"hello bob".to_vec()));
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"hello bob"
    );
    println!(
        "[5] partial commit: alice -> bob \"hello bob\" (epoch {})",
        enc.epoch
    );

    // Step 6 — full commit (0x07): Bob proposes, Alice queues + commits with PSK refresh.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let proposal = assert_ok!(bob_session.encrypt(b"bob update".to_vec()));
    let result = assert_some!(assert_ok!(
        alice_session.process_incoming(proposal.cipher_text)
    ));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));
    let prep = assert_ok!(alice_session.prepare_to_encrypt(None));
    assert!(
        prep.did_commit,
        "queued remote proposal forces a full commit"
    );
    let enc = assert_ok!(alice_session.encrypt(b"committed".to_vec()));
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"committed"
    );
    println!(
        "[6] full commit: epoch advanced to {} + PSK refreshed",
        enc.epoch
    );

    // Step 7 — continued bidirectional messaging.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"reply".to_vec()));
    let got = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"reply"
    );
    println!("[7] bidirectional messaging continues post-refresh");

    // Step 8 — agent key rotation (0x03): Alice rotates to a new agent.
    let new_alice = make_client();
    let new_alice_id = new_alice.client_id();
    assert_ok!(alice_session.stage_rotation(Arc::clone(&new_alice)));
    let prep = assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone())));
    assert!(prep.did_commit);
    let enc = assert_ok!(alice_session.encrypt(b"rotated".to_vec()));
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(assert_some!(got.remote_commit).new_sender),
        new_alice_id
    );
    assert!(matches!(
        alice_session.my_agent_state(),
        AgentState::Pending { .. }
    ));
    println!("[8] agent rotation: bob observes alice's new identity; alice state = Pending");

    println!("\n=== walkthrough complete ===\n");
}
