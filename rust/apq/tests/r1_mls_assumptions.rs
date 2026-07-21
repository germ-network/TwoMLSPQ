//! R1 — verify the mls-rs behavioral assumptions the "A.4 legs as MLS app messages"
//! design rests on, against the pinned mls-rs rev, before the session-layer rework
//! relies on them. Each `assumption_*` maps to a lettered item in the spec review.
//!
//! Run: `cargo test -p apq --test r1_mls_assumptions`.

// Test-only crate: helper fns aren't `#[test]` items, so the workspace's unwrap/panic
// denies would fire despite clippy.toml's allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use apq::{
    create_combiner_send_group, join_combiner_group, load_combiner_group, ApqCipherSuite,
    CombinerClient, CombinerGroup, CryptoConfig,
};
use mls_rs::group::ReceivedMessage;
use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;
use mls_rs::{CipherSuiteProvider, CryptoProvider, MlsMessage};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

type TestClient =
    CombinerClient<InMemoryKeyPackageStorage, AwsLcCryptoProvider, AwsLcCryptoProvider>;

fn crypto() -> CryptoConfig<AwsLcCryptoProvider, AwsLcCryptoProvider> {
    CryptoConfig::default()
}

fn client_id() -> Vec<u8> {
    let cs = AwsLcCryptoProvider::new()
        .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
        .unwrap();
    let (secret, _) = cs.signature_key_generate().unwrap();
    secret.as_bytes().to_vec()
}

fn client() -> TestClient {
    CombinerClient::new(client_id(), crypto()).unwrap()
}

/// A two-party APQ pair whose PQ half is live: Alice's send group (she commits) and
/// Bob's mirror of it (he is a member). Returns `(alice_send, bob_recv)`; call `.pq`
/// on either for the ML-KEM half both A.4 legs live in.
fn live_pair() -> (
    CombinerGroup<InMemoryKeyPackageStorage, AwsLcCryptoProvider, AwsLcCryptoProvider>,
    CombinerGroup<InMemoryKeyPackageStorage, AwsLcCryptoProvider, AwsLcCryptoProvider>,
) {
    let alice = client();
    let bob = client();
    let (alice_send, welcome) = create_combiner_send_group(
        &bob.generate_classical_key_package().unwrap(),
        &bob.generate_pq_key_package().unwrap(),
        &alice,
        None,
    )
    .unwrap();
    let bob_recv = join_combiner_group(&welcome, &bob).unwrap();
    (alice_send, bob_recv)
}

fn app_data(m: ReceivedMessage) -> Vec<u8> {
    match m {
        ReceivedMessage::ApplicationMessage(m) => m.data().to_vec(),
        _ => panic!("expected an application message"),
    }
}

/// (c) — the ML-KEM group carries application messages at all, in BOTH directions:
/// committer→member (Alice's EK leg) and member→committer (Bob's CT leg). This is the
/// first use of the PQ group's application ratchet (only handshake messages ran through
/// it before), so it is the assumption most in need of a live check on each backend.
#[test]
fn assumption_c_pq_group_round_trips_application_messages_both_directions() {
    let (mut alice_send, mut bob_recv) = live_pair();

    // committer → member (the A.4 EK leg's direction)
    let ek_leg = alice_send
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x17ek-bytes", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let got = bob_recv
        .pq
        .as_mut()
        .unwrap()
        .process_incoming_message(MlsMessage::from_bytes(&ek_leg).unwrap())
        .unwrap();
    assert_eq!(app_data(got), b"\x17ek-bytes");

    // member → committer (the A.4 CT leg's direction)
    let ct_leg = bob_recv
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x19ct-bytes", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let got = alice_send
        .pq
        .as_mut()
        .unwrap()
        .process_incoming_message(MlsMessage::from_bytes(&ct_leg).unwrap())
        .unwrap();
    assert_eq!(app_data(got), b"\x19ct-bytes");
}

/// (a) — CORRECTED. The spec originally wanted "a re-delivered frame still decrypts."
/// mls-rs does the OPPOSITE, by design: the receive ratchet consumes the generation on
/// first decrypt and does not retain it, so a second delivery of the SAME generation fails.
/// (`out_of_order` is on here — it ships via mls-rs's default `rfc_compliant` feature — but
/// it only keeps a bounded history of SKIPPED generations for later out-of-order arrival, and
/// the generation actually returned to a caller is never one of those, so a replay of the
/// exact generation still fails regardless.) This is MLS replay protection, and it is why the
/// session layer MUST gate re-sends on `pq_inflight` state BEFORE decrypting — never on the
/// frame re-decrypting. This test pins that behavior so a future mls-rs bump can't silently
/// change it under the guard-ordering argument.
#[test]
fn assumption_a_second_delivery_of_same_frame_fails_replay() {
    let (mut alice_send, mut bob_recv) = live_pair();

    let frame = alice_send
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x17ek", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();

    // First delivery consumes generation 0.
    assert_eq!(
        app_data(
            bob_recv
                .pq
                .as_mut()
                .unwrap()
                .process_incoming_message(MlsMessage::from_bytes(&frame).unwrap())
                .unwrap()
        ),
        b"\x17ek"
    );

    // Second delivery of the identical bytes fails: the generation-0 key is gone. So the
    // re-send discipline cannot lean on decryption — the guard must catch it first.
    assert!(
        bob_recv
            .pq
            .as_mut()
            .unwrap()
            .process_incoming_message(MlsMessage::from_bytes(&frame).unwrap())
            .is_err(),
        "a replayed application frame must not re-decrypt (guards must gate re-sends)"
    );
}

/// (a, corollary 1) — a message that PARSES as a valid `MLSMessage` but does not authenticate
/// for this group (here, a well-formed application message from an UNRELATED group) is
/// rejected before the content ratchet is touched — `process_incoming_message` runs but errs
/// at the group/epoch check, so no generation is consumed and the honest frame still decrypts.
/// This is the case a NETWORK attacker is confined to: it can replay real ciphertext from
/// elsewhere but cannot forge sender data valid for THIS group, so it cannot strand a
/// generation. (Unparseable random bytes are a weaker case — they fail at `from_bytes` and
/// never reach the group at all — so this test deliberately uses a parseable foreign frame to
/// exercise the actual `process_incoming_message` path.)
#[test]
fn assumption_a_foreign_group_frame_does_not_consume_a_generation() {
    let (mut alice_send, mut bob_recv) = live_pair();
    // An entirely separate session — its PQ group has a different id and key schedule.
    let (mut foreign_send, _foreign_recv) = live_pair();

    // A well-formed application message, but in the FOREIGN group.
    let foreign = foreign_send
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x17foreign", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let parsed = MlsMessage::from_bytes(&foreign).unwrap(); // it DOES parse
    assert!(
        bob_recv
            .pq
            .as_mut()
            .unwrap()
            .process_incoming_message(parsed)
            .is_err(),
        "a valid frame from a foreign group must be rejected"
    );

    // Bob's receive ratchet for Alice's sender was never touched: her generation-0 frame
    // still decrypts.
    let g0 = alice_send
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x17g0", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        app_data(
            bob_recv
                .pq
                .as_mut()
                .unwrap()
                .process_incoming_message(MlsMessage::from_bytes(&g0).unwrap())
                .unwrap()
        ),
        b"\x17g0",
        "a rejected foreign frame must not consume the honest generation"
    );
}

/// (a, corollary 2) — THE SHARP FINDING. A frame with VALID sender data but CORRUPTED
/// content DOES consume its generation: mls-rs ratchets the receive tree to the frame's
/// generation (deriving+deleting that key) *before* running the content AEAD, so when the
/// AEAD then fails the generation is already spent, and the pristine frame is rejected
/// `KeyMissing`. Producing such a frame requires the epoch's `sender_data_secret` — i.e.
/// group membership — so on the wire the header seal (a group-keyed AEAD over the whole
/// frame) is what keeps this out of a network attacker's reach: any wire tamper breaks the
/// OUTER seal and is dropped before mls-rs is invoked. Pinned here as the exact reason the
/// session layer MUST treat the header seal as the receive gate for A.4 legs (route via
/// `open_incoming`, never hand-feed an unsealed inner MLS frame to the `pq_*` receivers).
#[test]
fn assumption_a_valid_senderdata_corrupt_content_consumes_the_generation() {
    let (mut alice_send, mut bob_recv) = live_pair();

    let g0 = alice_send
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x17g0", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();

    // Flip a content-body byte; the (separately-encrypted) sender data stays valid, so the
    // generation is read and consumed before the content open fails.
    let mut mangled = g0.clone();
    let last = mangled.len() - 1;
    mangled[last] ^= 0xFF;
    assert!(bob_recv
        .pq
        .as_mut()
        .unwrap()
        .process_incoming_message(MlsMessage::from_bytes(&mangled).unwrap())
        .is_err());

    // The pristine generation-0 frame is now UNRECOVERABLE — its key was spent by the
    // corrupt copy. This is the behavior the header seal exists to keep off the wire.
    assert!(
        bob_recv
            .pq
            .as_mut()
            .unwrap()
            .process_incoming_message(MlsMessage::from_bytes(&g0).unwrap())
            .is_err(),
        "documents that a valid-sender-data corrupt frame spends the generation"
    );
}

/// (b) — processing one's OWN application message fails cleanly (never mis-parsed as the
/// peer's), so the explicit sender-index check in the session layer is belt-and-braces
/// over an mls-rs guarantee, not the sole line of defense.
#[test]
fn assumption_b_own_application_message_is_rejected() {
    let (mut alice_send, _bob_recv) = live_pair();
    let mine = alice_send
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x17mine", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(
        alice_send
            .pq
            .as_mut()
            .unwrap()
            .process_incoming_message(MlsMessage::from_bytes(&mine).unwrap())
            .is_err(),
        "a group must reject its own application message (CantProcessMessageFromSelf)"
    );
}

/// (d) — a restored PQ group signs with the signer captured in its OWN snapshot, not with
/// whatever key the loading client currently holds. This is the property the CT leg's
/// authentication depends on across a Phase 8 rotation: the session's current client may
/// have a fresh signing key, but the PQ group must keep signing as the leaf it actually
/// occupies until an A.5 catch-up rotates that leaf. Modeled by loading Alice's group onto
/// a DIFFERENT-keyed client and checking the peer still verifies the app message — a
/// mismatch would surface as an `InvalidSignature` rejection at Bob.
#[test]
fn assumption_d_restored_group_signs_with_snapshot_signer_not_loader_key() {
    let (mut alice_send, mut bob_recv) = live_pair();
    let state = alice_send.export_state().unwrap();

    // A brand-new client with an unrelated signing identity — stands in for the session's
    // post-rotation `self.client`.
    let loader = client();
    let mut restored: CombinerGroup<_, _, _> =
        load_combiner_group(&loader, &state).expect("load onto a different client");

    let msg = restored
        .pq
        .as_mut()
        .unwrap()
        .encrypt_application_message(b"\x19signed-as-alice", vec![])
        .unwrap()
        .to_bytes()
        .unwrap();

    // Bob verifies the leaf signature against Alice's leaf in his roster. Decrypting proves
    // the restored group signed with Alice's snapshot signer, not the loader's key.
    assert_eq!(
        app_data(
            bob_recv
                .pq
                .as_mut()
                .unwrap()
                .process_incoming_message(MlsMessage::from_bytes(&msg).unwrap())
                .unwrap()
        ),
        b"\x19signed-as-alice"
    );
}

/// Sanity: the ML-KEM-768 EK on the wire is the size the framing budget assumes, so the
/// doc's "~64 bytes of signature over an ~1184-byte payload" cost note stays honest.
#[test]
fn ml_kem_768_ek_is_1184_bytes() {
    let kem = mls_rs_crypto_awslc::MlKemKem::new(ApqCipherSuite::default().pq).unwrap();
    use mls_rs_crypto_traits::KemType;
    let (_dk, ek) = kem.generate().unwrap();
    assert_eq!(ek.as_ref().len(), 1184);
}
