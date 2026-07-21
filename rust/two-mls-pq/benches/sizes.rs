// Ciphertext-size report (not a timing benchmark — prints a table and exits).
//   cargo bench -p two-mls-pq --features "benchmark_util awslc" --bench sizes
//   cargo bench -p two-mls-pq --features "benchmark_util cryptokit" --bench sizes
// Captures the on-wire size of each frame type for a fixed payload, so we can track the
// effect of the APQ↔TwoMLS rework (dropping per-round PQ) and by-ref proposals.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

mod common;
use common::{classical_kp, client, open_establishment, suite_label};
use two_mls_pq::{key_packages::TwoMlsPqInvitation, session::TwoMlsPqSession};

fn main() {
    let payload: &[u8] = b"the quick brown fox jumps over the lazy dog";

    // Establishment — Alice's first frame is the §A.1 envelope (sealed to Bob's KP′);
    // Bob's return is a sealed APQ welcome.
    let alice = client();
    let bob = client();
    let alice_kp = classical_kp(&alice);

    let bob_inv = TwoMlsPqInvitation::restore(bob.generate_invitation(true).unwrap()).unwrap();
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None).unwrap();
    let envelope_a = alice_s.pending_outbound().unwrap();
    let opened = open_establishment(&bob_inv, envelope_a.clone());

    // §A.1 pre-establishment app frames (v15): each send is a fresh envelope
    // re-stapling the establishment sections plus the app message. Bare shape
    // (welcome + CLASSICAL return-KP sections — v20: the PQ KP travels in A.3,
    // hash-bound) vs self-sufficient host payload (which replaces the bare sections —
    // here a thin wrapper over the welcome; a real identity envelope also carries the
    // return KP + the bootstrap KP commitment + signatures).
    alice_s
        .set_initial_return_key_package(classical_kp(&alice))
        .unwrap();
    alice_s.prepare_to_encrypt(None).unwrap();
    let pre_est_bare = alice_s.encrypt(payload.to_vec()).unwrap().cipher_text;
    let mut identity_payload = b"identity-envelope:".to_vec();
    identity_payload.extend_from_slice(&alice_s.initial_welcome().unwrap());
    alice_s.set_initial_app_payload(identity_payload).unwrap();
    alice_s.prepare_to_encrypt(None).unwrap();
    let pre_est_payload = alice_s.encrypt(payload.to_vec()).unwrap().cipher_text;
    let bob_s = bob_inv
        .receive(
            opened.welcome.unwrap(),
            alice_kp,
            alice_s.bootstrap_kp_commitment().unwrap(),
            b"sizes".to_vec(),
            None,
            None,
            None,
        )
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

    // Principal rotation — message frame 0x03. Proposing the id lazily stages it (no separate
    // stage call — that is the contract-25 lazy-staging path).
    let new_id = client().client_id();
    alice_s.prepare_to_encrypt(Some(new_id)).unwrap();
    let rotation = alice_s.encrypt(payload.to_vec()).unwrap().cipher_text;

    // Section split of the steady-state frame. Open the seal on the receiver and
    // read the `[0x03][u32 staple][staple][u32 proposal][proposal][u32 app][app]`
    // sections; the whole staple section is the commit `MLSMessage` (a
    // `PublicMessage`). GUARD: the commit must fold a peer proposal by REFERENCE —
    // its only by-value proposal is the small APQ PSK; a leaf-sized `Upd` inlined
    // here (instead of referenced) would blow past the threshold.
    let (rot_staple, rot_proposal, rot_app, rot_bv_n, rot_bv_bytes) = {
        use mls_rs::mls_rs_codec::MlsSize;
        use mls_rs::MlsMessage;
        let plain = bob_s
            .open_incoming(rotation.clone())
            .unwrap()
            .unwrap()
            .frame;
        let rd = |b: &[u8], at: usize| {
            u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
        };
        let staple_len = rd(&plain, 1);
        let prop_at = 5 + staple_len;
        let prop_len = rd(&plain, prop_at);
        let app_len = rd(&plain, prop_at + 4 + prop_len);
        let commit = MlsMessage::from_bytes(&plain[5..5 + staple_len]).unwrap();
        let bv = commit.proposals_by_value();
        let bv_bytes: usize = bv.iter().map(|p| p.mls_encoded_len()).sum();
        assert!(
            bv_bytes < 200,
            "commit inlined a leaf-sized proposal ({bv_bytes} B) — the fold must be by reference"
        );
        (staple_len, prop_len, app_len, bv.len(), bv_bytes)
    };

    // PQ ratchet (book: Protocol Flows §A.4) — fresh session pair.
    let (pq_ek, pq_ct, pq_bind, pq_commit_len, cl_commit_len, staple_len) = {
        let a = client();
        let b = client();
        let a_kp = classical_kp(&a);
        let b_inv = TwoMlsPqInvitation::restore(b.generate_invitation(true).unwrap()).unwrap();
        let b_kp = b_inv.combiner_key_package();
        let a_s = TwoMlsPqSession::initiate(Arc::clone(&a), b_kp, None).unwrap();
        let envelope = a_s.pending_outbound().unwrap();
        let opened = open_establishment(&b_inv, envelope);
        let b_s = b_inv
            .receive(
                opened.welcome.unwrap(),
                a_kp,
                a_s.bootstrap_kp_commitment().unwrap(),
                b"sizes-pq".to_vec(),
                None,
                None,
                None,
            )
            .unwrap();
        let wb = b_s.pending_outbound().unwrap();
        a_s.process_incoming(wb).unwrap();

        // A.3 bootstrap so both PQ halves are live — send-driven A.4 opens only post-A.3.
        let kp = a_s.pq_bootstrap_begin(None).unwrap();
        b_s.pq_bootstrap_respond(kp).unwrap();
        let welcome = b_s.pq_take_pending_outbound().unwrap();
        a_s.pq_bootstrap_bind(welcome).unwrap();
        // Discharge the bootstrap bind: Bob offers an Upd, Alice folds+commits, Bob applies —
        // which passes the PQ turn to Bob.
        b_s.prepare_to_encrypt(None).unwrap();
        let boot_upd = b_s.encrypt(b"boot-upd".to_vec()).unwrap();
        let g = a_s.process_incoming(boot_upd.cipher_text).unwrap().unwrap();
        a_s.queue_proposal(g.proposal.unwrap().digest).unwrap();
        a_s.prepare_to_encrypt(None).unwrap();
        let boot_disc = a_s.encrypt(b"boot-disc".to_vec()).unwrap();
        b_s.process_incoming(boot_disc.cipher_text).unwrap();

        // A.4 is session-driven now: Bob (the turn holder) opens the round by SENDING an ordinary
        // message, which auto-stages the EK; Alice responds, Bob binds.
        b_s.prepare_to_encrypt(None).unwrap();
        let opener = b_s.encrypt(b"a3-open".to_vec()).unwrap();
        a_s.process_incoming(opener.cipher_text).unwrap();
        let ek = b_s.pq_take_pending_outbound().unwrap();
        a_s.pq_ratchet_respond(ek.clone()).unwrap();
        let ct = a_s.pq_take_pending_outbound().unwrap();
        b_s.pq_ratchet_bind(ct.clone()).unwrap();
        // The bind rides Bob's next committing round as its staple (a draft-02 §7
        // APQPrivateMessage): drive the fold that discharges it and capture the one
        // message frame carrying both commits and the app.
        a_s.prepare_to_encrypt(None).unwrap();
        let upd = a_s.encrypt(b"upd".to_vec()).unwrap();
        let res = b_s.process_incoming(upd.cipher_text).unwrap().unwrap();
        b_s.queue_proposal(res.proposal.unwrap().digest).unwrap();
        b_s.prepare_to_encrypt(None).unwrap();
        let bind_frame = b_s.encrypt(payload.to_vec()).unwrap().cipher_text;
        // Sealed on the wire; open on the receiver to dissect the plaintext
        // `[0x03][staple][proposal][app]` whose staple is
        // `[0x05][u32 t-len][t_message][u32 pq-len][pq_message]`.
        let plain = a_s
            .open_incoming(bind_frame.clone())
            .unwrap()
            .unwrap()
            .frame;
        a_s.process_incoming(bind_frame.clone()).unwrap();

        let rdlen = |buf: &[u8], at: usize| {
            u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize
        };
        let staple = rdlen(&plain, 1);
        let cl = rdlen(&plain, 1 + 4 + 1);
        let pq_at = 1 + 4 + 1 + 4 + cl;
        let pq_commit = rdlen(&plain, pq_at);
        (ek.len(), ct.len(), bind_frame.len(), pq_commit, cl, staple)
    };

    println!("\n=== TwoMLSPQ ciphertext sizes ({}) ===", suite_label());
    println!("payload (plaintext)          : {:>6} B", payload.len());
    println!("initial envelope A (§A.1)    : {:>6} B", envelope_a.len());
    println!("pre-est app frame (bare)     : {:>6} B", pre_est_bare.len());
    println!(
        "pre-est app frame (payload)  : {:>6} B",
        pre_est_payload.len()
    );
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
    println!("--- rotation frame (0x03) section split ---");
    println!(
        "  staple(commit) : {:>4} B  ({} proposal(s) by value = {} B; peer Upd folded by reference)",
        rot_staple, rot_bv_n, rot_bv_bytes
    );
    println!(
        "  proposal(Upd)  : {:>4} B  (by value once; peer folds it by reference next round)",
        rot_proposal
    );
    println!("  app            : {:>4} B", rot_app);
    println!(
        "  framing        : {:>4} B\n",
        rotation.len() - rot_staple - rot_proposal - rot_app
    );

    {
        println!("--- PQ ratchet (book: Protocol Flows §A.4) ---");
        println!("PQ EK message (0x17, sealed) : {:>6} B", pq_ek);
        println!("PQ ct message (0x19, sealed) : {:>6} B", pq_ct);
        println!("bind frame (0x03 + staple)   : {:>6} B", pq_bind);
        println!("  APQPrivateMessage staple   : {:>6} B", staple_len);
        println!("  classical commit           : {:>6} B", cl_commit_len);
        println!("  PQ partial-commit (no path): {:>6} B", pq_commit_len);

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
