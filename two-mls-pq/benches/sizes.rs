// Ciphertext-size report (not a timing benchmark — prints a table and exits).
//   cargo bench -p two-mls-pq --features "benchmark_util awslc" --bench sizes
//   cargo bench -p two-mls-pq --features "benchmark_util cryptokit" --bench sizes
// Captures the on-wire size of each frame type for a fixed payload, so we can track the
// effect of the APQ↔TwoMLS rework (dropping per-round PQ) and by-ref proposals.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

mod common;
use common::{client, combiner_kp, suite_label};
use two_mls_pq::{key_packages::TwoMlsPqInvitation, session::TwoMlsPqSession};

fn main() {
    let payload: &[u8] = b"the quick brown fox jumps over the lazy dog";

    // Establishment — Alice's first frame is the §A.1 envelope (sealed to Bob's KP′);
    // Bob's return is a sealed APQ welcome.
    let alice = client();
    let bob = client();
    let alice_kp = combiner_kp(&alice);

    let bob_inv = TwoMlsPqInvitation::new(bob.generate_invitation(true).unwrap()).unwrap();
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None).unwrap();
    let envelope_a = alice_s.pending_outbound().unwrap();
    let opened = bob_inv.open_initial(envelope_a.clone()).unwrap();
    let bob_s = bob_inv
        .receive(opened.welcome, alice_kp, b"sizes".to_vec(), None, None)
        .unwrap();
    let welcome_b = bob_s.pending_outbound().unwrap();
    alice_s.process_incoming(welcome_b.clone()).unwrap();

    // No-commit round (steady state, no queued proposal) — message frame 0x03.
    alice_s.prepare_to_encrypt(None).unwrap();
    let no_commit = alice_s.encrypt(payload.to_vec()).unwrap().cipher_text;
    bob_s.process_incoming(no_commit.clone()).unwrap();

    // Folding commit (epoch advance + PSK refresh) — still an A.2 message frame, 0x03.
    bob_s.prepare_to_encrypt(None).unwrap();
    let prop = bob_s.encrypt(b"proposal".to_vec()).unwrap();
    let res = alice_s.process_incoming(prop.cipher_text).unwrap().unwrap();
    alice_s
        .queue_proposal(res.proposal.unwrap().digest)
        .unwrap();
    alice_s.prepare_to_encrypt(None).unwrap();
    let folding = alice_s.encrypt(payload.to_vec()).unwrap().cipher_text;
    bob_s.process_incoming(folding.clone()).unwrap();

    // Principal rotation — message frame 0x03.
    let new_id = client().client_id();
    alice_s.stage_rotation(new_id.bytes.clone()).unwrap();
    alice_s.prepare_to_encrypt(Some(new_id)).unwrap();
    let rotation = alice_s.encrypt(payload.to_vec()).unwrap().cipher_text;

    // PQ ratchet (architecture-diagrams PR #2 §A.3) — fresh session pair.
    let (pq_ek, pq_ct, pq_bind, pq_commit_len, cl_commit_len, pq_app_len) = {
        let a = client();
        let b = client();
        let a_kp = combiner_kp(&a);
        let b_inv = TwoMlsPqInvitation::new(b.generate_invitation(true).unwrap()).unwrap();
        let b_kp = b_inv.combiner_key_package();
        let a_s = TwoMlsPqSession::initiate(Arc::clone(&a), b_kp, None).unwrap();
        let envelope = a_s.pending_outbound().unwrap();
        let opened = b_inv.open_initial(envelope).unwrap();
        let b_s = b_inv
            .receive(opened.welcome, a_kp, b"sizes-pq".to_vec(), None, None)
            .unwrap();
        let wb = b_s.pending_outbound().unwrap();
        a_s.process_incoming(wb).unwrap();

        let ek = a_s.pq_ratchet_begin().unwrap();
        b_s.pq_ratchet_respond(ek.clone()).unwrap();
        let ct = b_s.pq_take_pending_outbound().unwrap();
        a_s.pq_ratchet_bind(ct.clone(), payload.to_vec()).unwrap();
        let bind = a_s.pq_take_pending_outbound().unwrap();
        // `bind` is sealed on the wire; open it on the receiver to read the plaintext
        // `[tag ∥ pq_commit ∥ classical ∥ app]` layout the outer seal hides.
        let plain_bind = b_s.open_incoming(bind.clone()).unwrap().unwrap().frame;
        b_s.pq_ratchet_apply(bind.clone()).unwrap();

        let rdlen = |buf: &[u8], at: usize| {
            u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize
        };
        let pq_commit = rdlen(&plain_bind, 1);
        let cl_at = 1 + 4 + pq_commit;
        let cl = rdlen(&plain_bind, cl_at);
        let app_at = cl_at + 4 + cl;
        let app = rdlen(&plain_bind, app_at);
        (ek.len(), ct.len(), bind.len(), pq_commit, cl, app)
    };

    println!("\n=== TwoMLSPQ ciphertext sizes ({}) ===", suite_label());
    println!("payload (plaintext)          : {:>6} B", payload.len());
    println!("initial envelope A (§A.1)    : {:>6} B", envelope_a.len());
    println!("APQ welcome B (0x01, sealed) : {:>6} B", welcome_b.len());
    println!("no-commit frame + app (0x03) : {:>6} B", no_commit.len());
    println!("folding commit + app (0x03)  : {:>6} B", folding.len());
    println!("rotation commit + app (0x03) : {:>6} B", rotation.len());
    println!(
        "overhead: no-commit={} B, folding={} B, rotation={} B (over payload)\n",
        no_commit.len() - payload.len(),
        folding.len() - payload.len(),
        rotation.len() - payload.len(),
    );

    {
        println!("--- PQ ratchet (architecture-diagrams PR #2 §A.3) ---");
        println!("PQ EK message (0x05, sealed) : {:>6} B", pq_ek);
        println!("PQ ct message (0x07, sealed) : {:>6} B", pq_ct);
        println!("PQ bind frame (0x09, sealed) : {:>6} B", pq_bind);
        println!("  PQ partial-commit (no path): {:>6} B", pq_commit_len);
        println!("  classical commit           : {:>6} B", cl_commit_len);
        println!("  app                        : {:>6} B", pq_app_len);

        #[cfg(feature = "cryptokit")]
        let old_full = apq::pq_ratchet::full_pq_updatepath_commit_size(
            mls_rs_crypto_cryptokit::CryptoKitMlKemProvider,
            mls_rs::CipherSuite::from(0xFDEA),
        );
        #[cfg(all(feature = "awslc", not(feature = "cryptokit")))]
        let old_full = apq::pq_ratchet::full_pq_updatepath_commit_size(
            mls_rs_crypto_awslc::AwsLcCryptoProvider::new(),
            mls_rs::CipherSuite::from(0xFDEA),
        );
        println!("--- per-round PQ commit: OLD (APQ-faithful) vs NEW (ratchet) ---");
        println!("OLD full PQ updatePath commit: {:>6} B", old_full);
        println!(
            "NEW pathless PSK commit      : {:>6} B   ({}x smaller)",
            pq_commit_len,
            old_full / pq_commit_len.max(1)
        );
    }
}
