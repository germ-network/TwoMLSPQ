use std::sync::Arc;

use super::TwoMlsPqSession;
use crate::{
    assert_err, assert_ok, assert_some,
    test_utils::{establish_confirmed_sessions, establish_sessions, make_client, make_combiner_kp},
    PrincipalState, TwoMlsPqError,
};

#[test]
fn test_pq_bootstrap_completes_deferred_halves() {
    let (alice, bob) = establish_sessions();

    // Establishment is classical-complete but the acceptor's send-group PQ half
    // (and the initiator's recv mirror) is deferred.
    assert!(alice.is_established());
    assert!(bob.is_established());
    assert!(!alice.is_fully_established());
    assert!(!bob.is_fully_established());
    // The initiator holds the turn and owes the bootstrap.
    assert!(alice.my_pq_turn());
    assert!(!bob.my_pq_turn());

    let kp_msg = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp_msg));
    let bind = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_apply(bind));

    assert!(alice.is_fully_established());
    assert!(bob.is_fully_established());
    // Completing the operation passes the turn.
    assert!(!alice.my_pq_turn());
    assert!(bob.my_pq_turn());
    assert!(bob.epochs().pq_epoch > 0);

    // Both directions still message after the bind commits.
    assert_ok!(alice.prepare_to_encrypt(None));
    let a2b = assert_ok!(alice.encrypt(b"post-bootstrap a".to_vec()));
    let got = assert_ok!(bob.process_incoming(a2b.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-bootstrap a".to_vec()
    );
    assert_ok!(bob.prepare_to_encrypt(None));
    let b2a = assert_ok!(bob.encrypt(b"post-bootstrap b".to_vec()));
    let got = assert_ok!(alice.process_incoming(b2a.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-bootstrap b".to_vec()
    );
}

#[test]
fn test_pq_bootstrap_begin_requires_turn() {
    let (_alice, bob) = establish_sessions();
    // The acceptor does not hold the turn and cannot begin the bootstrap.
    assert_err!(
        bob.pq_bootstrap_begin(None),
        crate::TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_pq_bootstrap_respond_rejects_wrong_suite_key_package() {
    use crate::MlsCipherSuite;

    let (_alice, bob) = establish_sessions();
    // A bootstrap KP must be the PQ suite (0xFDEA). Forge a bootstrap frame carrying a
    // classical-suite KP instead: the suite check rejects it before any group is stood up,
    // rather than surfacing later as an opaque mls-rs error.
    let stranger = make_client();
    let classical_kp = assert_ok!(stranger.generate_key_package(MlsCipherSuite::x25519_chacha()));
    let mut kp_msg = vec![super::PQ_BOOTSTRAP_KP_TAG];
    kp_msg.extend_from_slice(&classical_kp);
    assert_err!(
        bob.pq_bootstrap_respond(kp_msg),
        TwoMlsPqError::CipherSuiteMismatch
    );
}

#[test]
fn test_initiate_stores_outbound_welcome() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(session.pending_outbound().is_some());
}

#[test]
fn test_pending_outbound_returns_none_after_take() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    let first = session.pending_outbound();
    let second = session.pending_outbound();
    assert!(first.is_some());
    assert!(second.is_none());
}

#[test]
fn test_is_established_false_before_both_groups_ready() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(!session.is_established());
}

#[test]
fn test_accept_stores_outbound_welcome() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let apq_welcome_a = alice_session.test_initial_welcome();

    let bob_session = assert_ok!(TwoMlsPqSession::accept(bob, apq_welcome_a, alice_kp));
    assert!(bob_session.pending_outbound().is_some());
}

#[test]
fn test_full_establishment_sequence_combiner() {
    let (alice_session, bob_session) = establish_sessions();
    assert!(bob_session.is_established(), "bob should be established");
    assert!(
        alice_session.is_established(),
        "alice should be established"
    );
}

#[test]
fn test_routing_available_from_birth_post_after_establishment() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    // Initiator: listening works immediately (send group @ classical epoch 1);
    // nowhere to post until the return welcome stands up the recv group.
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let listen_a = assert_ok!(alice_s.should_listen_on());
    assert!(!listen_a.send_group.classical.bytes.is_empty());
    assert!(!listen_a.send_group.pq.bytes.is_empty());
    assert_eq!(listen_a.rendezvous_by_epoch.len(), 1);
    assert_eq!(listen_a.rendezvous_by_epoch[0].epoch, 1);
    assert_eq!(
        listen_a.rendezvous_by_epoch[0].rendezvous_id.bytes.len(),
        32
    );
    assert!(assert_ok!(alice_s.send_rendezvous()).is_none());

    // Acceptor: posts immediately — its recv group is the initiator's send
    // group, so its post address is the initiator's listen address verbatim.
    let welcome_a = alice_s.test_initial_welcome();
    let bob_s = assert_ok!(TwoMlsPqSession::accept(bob, welcome_a, alice_kp));
    let bob_post = assert_some!(assert_ok!(bob_s.send_rendezvous()));
    assert_eq!(
        bob_post.bytes,
        listen_a.rendezvous_by_epoch[0].rendezvous_id.bytes
    );
    // The acceptor's own send group listens too — classical-only pre-A.4.
    let listen_b = assert_ok!(bob_s.should_listen_on());
    assert!(!listen_b.send_group.classical.bytes.is_empty());
    assert!(listen_b.send_group.pq.bytes.is_empty());
    assert_eq!(listen_b.rendezvous_by_epoch.len(), 1);

    // Initiator joins in-band from the stapled return welcome and can post;
    // its address is in the acceptor's listen set.
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(welcome_b));
    let alice_post = assert_some!(assert_ok!(alice_s.send_rendezvous()));
    assert!(listen_b
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == alice_post.bytes));
}

/// One approved A.2 round: `peer` staples an Upd(self); `committer` approves it and
/// its next send commits — advancing the committer's send-group classical epoch.
fn approved_commit_round(committer: &Arc<TwoMlsPqSession>, peer: &Arc<TwoMlsPqSession>) {
    assert_ok!(peer.prepare_to_encrypt(None));
    let upd = assert_ok!(peer.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(committer.process_incoming(upd.cipher_text)));
    let offered = assert_some!(got.proposal);
    assert_ok!(committer.queue_proposal(offered.digest));
    let prepared = assert_ok!(committer.prepare_to_encrypt(None));
    assert!(prepared.did_commit);
    let frame = assert_ok!(committer.encrypt(b"commit".to_vec()));
    assert_some!(assert_ok!(peer.process_incoming(frame.cipher_text)));
}

/// One full credential-rotation round under the AS model: `party` stages `new_id`
/// and proposes it on a frame; `peer`'s app approves and commits it (the canonical
/// step — the committed credential defines `party`'s next identity); the commit
/// staple returns and `party` swaps to the winning principal. `party`'s own
/// send-group leaf and the PQ leaves still lag until their next commits.
fn rotate_round(
    party: &Arc<TwoMlsPqSession>,
    peer: &Arc<TwoMlsPqSession>,
    new_id: crate::ClientId,
) {
    assert_ok!(party.stage_rotation(new_id.bytes.clone()));
    assert!(matches!(
        party.my_principal_state(),
        PrincipalState::Pending { .. }
    ));
    assert_ok!(party.prepare_to_encrypt(Some(new_id.clone())));
    let enc = assert_ok!(party.encrypt(b"rotate".to_vec()));
    let got = assert_some!(assert_ok!(peer.process_incoming(enc.cipher_text)));
    let offered = assert_some!(got.proposal);
    assert_eq!(offered.proposing.bytes, new_id.bytes);
    assert_ok!(peer.queue_proposal(offered.digest));
    let prepared = assert_ok!(peer.prepare_to_encrypt(None));
    assert!(prepared.did_commit);
    assert_eq!(
        assert_some!(prepared.committed_remote_client_id).bytes,
        new_id.bytes
    );
    assert_eq!(peer.their_principal_state().client_id().bytes, new_id.bytes);
    let frame = assert_ok!(peer.encrypt(b"canonicalize".to_vec()));
    let got = assert_some!(assert_ok!(party.process_incoming(frame.cipher_text)));
    let commit = assert_some!(got.remote_commit);
    assert_eq!(commit.new_recipient.bytes, new_id.bytes);
    assert_eq!(party.my_principal_state().client_id().bytes, new_id.bytes);
    assert!(matches!(
        party.my_principal_state(),
        PrincipalState::Sync { .. }
    ));
}

/// Approving a proposal, then approving a different one before committing, folds
/// only the second (no two-Update `BadUpdate`): `queue_proposal` un-caches, so the
/// replaced tally leaves nothing in the send-group cache. `queued_remote_successor`
/// reflects the replacement.
#[test]
fn test_queue_proposal_replace_tally() {
    let (alice, bob) = establish_confirmed_sessions();
    // Alice stages two candidates and proposes each on its own frame.
    let id1 = make_client().client_id();
    let id2 = make_client().client_id();
    assert_ok!(alice.stage_rotation(id1.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id1.clone())));
    let f1 = assert_ok!(alice.encrypt(b"c1".to_vec()));
    assert_ok!(alice.stage_rotation(id2.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id2.clone())));
    let f2 = assert_ok!(alice.encrypt(b"c2".to_vec()));

    // Bob approves c1, then c2 (replace) before committing.
    let g1 = assert_some!(assert_ok!(bob.process_incoming(f1.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(g1.proposal).digest));
    assert_eq!(bob.queued_remote_successor(), Some(id1.clone()));
    let g2 = assert_some!(assert_ok!(bob.process_incoming(f2.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(g2.proposal).digest));
    assert_eq!(bob.queued_remote_successor(), Some(id2.clone()));

    // The commit folds only c2 (no BadUpdate) and canonicalizes c2.
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    assert_eq!(bob.their_principal_state().client_id(), id2);
    assert!(bob.queued_remote_successor().is_none());
    let staple = assert_ok!(bob.encrypt(b"commit".to_vec()));
    let res = assert_some!(assert_ok!(alice.process_incoming(staple.cipher_text)));
    assert_eq!(assert_some!(res.remote_commit).new_recipient, id2);
    assert_eq!(alice.my_principal_state().client_id(), id2);
}

/// A proposal whose self-describing candidate id does not match the Update's actual
/// leaf is rejected, and the rejection is a **no-op**: nothing is authorized, nothing
/// is cached, and a subsequent honest approval + commit still succeeds.
#[test]
fn test_queue_proposal_declared_mismatch_is_noop() {
    let (alice, bob) = establish_confirmed_sessions();
    // Craft a frame whose declared `proposing` differs from the Upd's leaf: stage a
    // real candidate (leaf carries id_real) but relabel the section as id_fake.
    let id_real = make_client().client_id();
    assert_ok!(alice.stage_rotation(id_real.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id_real.clone())));
    let frame = assert_ok!(alice.encrypt(b"real".to_vec()));

    // Open Alice's frame on Bob, decode the proposal section, relabel `proposing`,
    // re-encode, re-seal — a hostile/buggy sender.
    let opened = assert_some!(assert_ok!(bob.open_incoming(frame.cipher_text.clone())));
    let (staple, section, app) = super::decode_message_frame(&opened.frame).unwrap();
    let (_declared, proposal_msg) = super::decode_proposal_section(&section).unwrap();
    let id_fake = make_client().client_id().bytes;
    let bad_section = super::encode_proposal_section(&id_fake, &proposal_msg);
    let bad_frame = super::encode_message_frame(&staple, bad_section, app);
    let bad_sealed = alice.lock().seal(&bad_frame).unwrap();

    let got = assert_some!(assert_ok!(bob.process_incoming(bad_sealed)));
    let offered = assert_some!(got.proposal);
    assert_eq!(offered.proposing.bytes, id_fake);
    // Approving the mismatched offer is rejected, and leaves NO state behind.
    assert_err!(
        bob.queue_proposal(offered.digest),
        TwoMlsPqError::ProposalRejected
    );
    assert!(bob.queued_remote_successor().is_none());

    // An honest round still commits cleanly afterward (no poisoned cache / auth):
    // Alice re-proposes id_real on a FRESH frame (the mislabelled one's app message
    // was already consumed).
    assert_ok!(alice.prepare_to_encrypt(Some(id_real.clone())));
    let honest = assert_ok!(alice.encrypt(b"honest".to_vec()));
    let g2 = assert_some!(assert_ok!(bob.process_incoming(honest.cipher_text)));
    let real = assert_some!(g2.proposal);
    assert_eq!(real.proposing, id_real);
    assert_ok!(bob.queue_proposal(real.digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    assert_eq!(bob.their_principal_state().client_id(), id_real);
}

/// The queued tally is epoch-scoped: an A.3 bind advances our send epoch, so the
/// queued peer proposal (bound to the prior epoch) is dropped rather than committed
/// stale on the next fold.
#[test]
fn test_queued_proposal_cleared_on_bind() {
    let (alice, bob) = establish_full();
    // Bob proposes a candidate; Alice approves it (the running tally).
    let id_b = make_client().client_id();
    assert_ok!(bob.stage_rotation(id_b.bytes.clone()));
    assert_ok!(bob.prepare_to_encrypt(Some(id_b.clone())));
    let f = assert_ok!(bob.encrypt(b"propose".to_vec()));
    let got = assert_some!(assert_ok!(alice.process_incoming(f.cipher_text)));
    assert_ok!(alice.queue_proposal(assert_some!(got.proposal).digest));
    assert_eq!(alice.queued_remote_successor(), Some(id_b));

    // Alice (the PQ initiator after A.4) runs an A.3 ratchet: the bind commits on her
    // send group, advancing its epoch and clearing the now-stale tally.
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"app".to_vec()));
    assert!(alice.queued_remote_successor().is_none());
}

/// A candidate that was proposed on the wire is never evicted: staging beyond the
/// in-flight window defers overflow rather than dropping a sent candidate, so the
/// peer can commit the very first one and the proposer still holds its principal.
/// (This is the adversarial-review repro, now resolved.)
#[test]
fn test_sent_candidate_not_evicted() {
    let (alice, bob) = establish_confirmed_sessions();
    let mut ids = Vec::new();
    let mut first_frame = None;
    // Stage super::CANDIDATE_WINDOW + 2 candidates. Only the first super::CANDIDATE_WINDOW are in
    // flight (proposable); the rest defer.
    for i in 0..(super::CANDIDATE_WINDOW + 2) {
        let id = make_client().client_id();
        assert_ok!(alice.stage_rotation(id.bytes.clone()));
        if i < super::CANDIDATE_WINDOW {
            assert_ok!(alice.prepare_to_encrypt(Some(id.clone())));
            let frame = assert_ok!(alice.encrypt(format!("cand{i}").into_bytes()));
            if i == 0 {
                first_frame = Some(frame);
            }
        }
        ids.push(id);
    }
    // The peer commits the FIRST candidate — not evicted despite two later stages.
    let got = assert_some!(assert_ok!(
        bob.process_incoming(assert_some!(first_frame).cipher_text)
    ));
    let offered = assert_some!(got.proposal);
    assert_eq!(offered.proposing, ids[0]);
    assert_ok!(bob.queue_proposal(offered.digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let staple = assert_ok!(bob.encrypt(b"commit".to_vec()));
    // Alice canonicalizes onto ids[0] cleanly — no CredentialRejected, no desync.
    let res = assert_some!(assert_ok!(alice.process_incoming(staple.cipher_text)));
    assert_eq!(assert_some!(res.remote_commit).new_recipient, ids[0]);
    assert_eq!(alice.my_principal_state().client_id(), ids[0]);
}

/// After a canonicalization frees a window slot, a deferred candidate is promoted
/// and proposed on the next routine round without an explicit selection.
#[test]
fn test_deferred_candidate_promoted_next_round() {
    let (alice, bob) = establish_confirmed_sessions();
    // Fill the window and defer one more.
    let mut ids = Vec::new();
    for _ in 0..(super::CANDIDATE_WINDOW + 1) {
        ids.push(make_client().client_id());
    }
    for id in &ids {
        assert_ok!(alice.stage_rotation(id.bytes.clone()));
    }
    let deferred = ids.last().unwrap().clone();
    // Propose + commit the first in-flight candidate to clear the pool.
    assert_ok!(alice.prepare_to_encrypt(Some(ids[0].clone())));
    let f = assert_ok!(alice.encrypt(b"c0".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(f.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let staple = assert_ok!(bob.encrypt(b"commit".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(staple.cipher_text)));
    assert_eq!(alice.my_principal_state().client_id(), ids[0]);

    // The window is now clear. A plain routine round auto-proposes the deferred id.
    assert_ok!(alice.prepare_to_encrypt(None));
    // The promoted rotation is now in flight, so the state reports Pending targeting
    // the deferred id — not the Sync the prior canonicalization set (else the
    // rotation would be invisible in `my_principal_state`).
    assert!(matches!(
        alice.my_principal_state(),
        PrincipalState::Pending { new, .. } if new == deferred
    ));
    let f2 = assert_ok!(alice.encrypt(b"routine".to_vec()));
    let got2 = assert_some!(assert_ok!(bob.process_incoming(f2.cipher_text)));
    assert_eq!(assert_some!(got2.proposal).proposing, deferred);
}

/// A session archived with a queued (approved-but-uncommitted) peer proposal
/// restores and re-applies it: the queued proposal bytes ride the archive
/// (`WireQueuedProposal.proposal`), so `prepare_to_encrypt(None)` commits it after
/// restore and canonicalizes the peer's credential.
#[test]
fn test_archive_round_trips_queued_proposal() {
    let (alice, bob) = establish_confirmed_sessions();
    // Alice proposes a rotation candidate; Bob approves it but does NOT commit.
    let id_a = make_client().client_id();
    assert_ok!(alice.stage_rotation(id_a.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id_a.clone())));
    let f = assert_ok!(alice.encrypt(b"propose".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(f.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert_eq!(bob.queued_remote_successor(), Some(id_a.clone()));

    // Archive Bob mid-approval and restore. The queued proposal must survive.
    let restored = round_trip(&bob);
    assert_eq!(restored.queued_remote_successor(), Some(id_a.clone()));

    // The restored session re-applies + commits the queued proposal, canonicalizing
    // Alice's credential; Alice sees it on her leaf's catch-up next round.
    assert!(assert_ok!(restored.prepare_to_encrypt(None)).did_commit);
    assert_eq!(restored.their_principal_state().client_id(), id_a);
    let staple = assert_ok!(restored.encrypt(b"commit".to_vec()));
    let res = assert_some!(assert_ok!(alice.process_incoming(staple.cipher_text)));
    assert_eq!(assert_some!(res.remote_commit).new_recipient, id_a);
    assert_eq!(alice.my_principal_state().client_id(), id_a);
}

/// A parked deferred rotation survives archive/restore and is still promoted +
/// proposed on the next routine round.
#[test]
fn test_archive_round_trips_deferred_candidate() {
    let (alice, bob) = establish_confirmed_sessions();
    // Fill the window and defer one more.
    let mut ids = Vec::new();
    for _ in 0..(super::CANDIDATE_WINDOW + 1) {
        ids.push(make_client().client_id());
    }
    for id in &ids {
        assert_ok!(alice.stage_rotation(id.bytes.clone()));
    }
    let deferred = ids.last().unwrap().clone();
    // Clear the pool by committing the first in-flight candidate.
    assert_ok!(alice.prepare_to_encrypt(Some(ids[0].clone())));
    let f = assert_ok!(alice.encrypt(b"c0".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(f.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let staple = assert_ok!(bob.encrypt(b"commit".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(staple.cipher_text)));

    // Archive Alice with the deferred candidate parked; restore.
    let restored = round_trip(&alice);
    // The restored session promotes + proposes the deferred candidate next round.
    assert_ok!(restored.prepare_to_encrypt(None));
    let f2 = assert_ok!(restored.encrypt(b"routine".to_vec()));
    let got2 = assert_some!(assert_ok!(bob.process_incoming(f2.cipher_text)));
    assert_eq!(assert_some!(got2.proposal).proposing, deferred);
}

/// Different frames may propose different candidates; the peer's commit picks the
/// winner — including an OLDER candidate whose frame it processed first. The loser's
/// authorization expires with the commit.
#[test]
fn test_peer_commit_picks_among_candidates() {
    let (alice, bob) = establish_confirmed_sessions();
    let id1 = make_client().client_id();
    let id2 = make_client().client_id();

    assert_ok!(alice.stage_rotation(id1.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id1.clone())));
    let frame1 = assert_ok!(alice.encrypt(b"candidate-1".to_vec()));

    assert_ok!(alice.stage_rotation(id2.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id2.clone())));
    let _frame2 = assert_ok!(alice.encrypt(b"candidate-2".to_vec()));

    // Bob processes only the FIRST frame and commits id1 — the canonical next
    // credential is the one committed, not the one most recently proposed.
    let got = assert_some!(assert_ok!(bob.process_incoming(frame1.cipher_text)));
    let offered = assert_some!(got.proposal);
    assert_eq!(offered.proposing, id1);
    assert_ok!(bob.queue_proposal(offered.digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let frame = assert_ok!(bob.encrypt(b"canonicalize".to_vec()));
    let got = assert_some!(assert_ok!(alice.process_incoming(frame.cipher_text)));
    assert_eq!(assert_some!(got.remote_commit).new_recipient, id1);
    assert_eq!(alice.my_principal_state().client_id(), id1);

    // Round trips continue under the winner.
    assert_ok!(alice.prepare_to_encrypt(None));
    let enc = assert_ok!(alice.encrypt(b"after".to_vec()));
    assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));
}

#[test]
fn test_rotation_commit_mints_new_listen_address() {
    let (alice, bob) = establish_confirmed_sessions();
    let before = assert_ok!(alice.should_listen_on());
    let bob_post_before = assert_some!(assert_ok!(bob.send_rendezvous()));

    // Rotation is proposal-driven: the round itself does not advance alice's send
    // epoch (bob commits, on HIS group). Her next approved commit — which also
    // carries the own-leaf catch-up — advances it and must mint the address.
    let new_client = make_client();
    rotate_round(&alice, &bob, new_client.client_id());
    assert_eq!(
        assert_ok!(alice.should_listen_on())
            .rendezvous_by_epoch
            .len(),
        before.rendezvous_by_epoch.len()
    );

    approved_commit_round(&alice, &bob);
    let after = assert_ok!(alice.should_listen_on());
    assert_eq!(
        after.rendezvous_by_epoch.len(),
        before.rendezvous_by_epoch.len() + 1
    );

    // Bob's post address migrated to the new epoch's channel, present in
    // alice's listen set.
    let bob_post_after = assert_some!(assert_ok!(bob.send_rendezvous()));
    assert_ne!(bob_post_after.bytes, bob_post_before.bytes);
    assert!(after
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == bob_post_after.bytes));
}

#[test]
fn test_rotation_preserves_listen_window_across_epochs() {
    // Regression check for the rotation × listen-window collapse: before
    // per-group persistence, `prepare_rotation`'s client swap left
    // `record_listen_rendezvous` probing the new client's empty storage, so
    // the window collapsed to the current epoch on every later commit
    // ([1,2] → rotate → [3] → [5], never recovering). With storage pulled
    // through the group objects, the swap must not touch the window.
    let epochs = |s: &Arc<TwoMlsPqSession>| -> Vec<u64> {
        assert_ok!(s.should_listen_on())
            .rendezvous_by_epoch
            .iter()
            .map(|e| e.epoch)
            .collect()
    };
    let (alice, bob) = establish_sessions();
    approved_commit_round(&alice, &bob);
    assert_eq!(epochs(&alice), vec![1, 2]);

    // Credential rotation: canonicalization swaps alice's session client. The
    // prior epochs must survive the swap (the regression this test pins), and
    // the catch-up commit on the next approved round advances the window.
    let new_client = make_client();
    rotate_round(&alice, &bob, new_client.client_id());
    assert_eq!(epochs(&alice), vec![1, 2]);
    approved_commit_round(&alice, &bob);
    assert_eq!(epochs(&alice), vec![1, 2, 3]);

    // And the window keeps growing on later rounds, up to mls-rs's
    // retention cap (current + 3 retained priors).
    approved_commit_round(&alice, &bob);
    assert_eq!(epochs(&alice), vec![1, 2, 3, 4]);
    approved_commit_round(&alice, &bob);
    assert_eq!(epochs(&alice), vec![2, 3, 4, 5]);
}

#[test]
fn test_listen_window_follows_mls_rs_epoch_retention() {
    let (alice, bob) = establish_sessions();
    // Five committed rounds: alice's send group moves from epoch 1 to epoch 6.
    for _ in 0..5 {
        approved_commit_round(&alice, &bob);
    }
    let listen = assert_ok!(alice.should_listen_on());
    let epochs: Vec<u64> = listen.rendezvous_by_epoch.iter().map(|e| e.epoch).collect();
    // The window is NOT all six epochs — it follows the injected group-state
    // storage's retention: current + mls-rs's retained prior epochs (mls-rs
    // in-memory default max_epoch_retention = 3).
    assert_eq!(epochs, vec![3, 4, 5, 6]);
    // Bob's post address still lands inside the retained window.
    let post = assert_some!(assert_ok!(bob.send_rendezvous()));
    assert!(listen
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == post.bytes));
}

#[test]
fn test_encrypt_result_reports_apq_epoch_pair() {
    let (alice, bob) = establish_sessions();

    // Acceptor pre-A.4: classical-only send group — pq epoch 0, not a
    // duplicate of the classical epoch.
    assert_ok!(bob.prepare_to_encrypt(None));
    let upd = assert_ok!(bob.encrypt(b"upd".to_vec()));
    assert_eq!(upd.epochs.pq_epoch, 0);
    assert_eq!(upd.epochs.classical_epoch, 1);

    // Initiator commit round: full APQ pair from birth — pq stays 1 while
    // the commit advances classical to 2 — matching the session's own view.
    let got = assert_some!(assert_ok!(alice.process_incoming(upd.cipher_text)));
    assert_ok!(alice.queue_proposal(assert_some!(got.proposal).digest));
    assert_ok!(alice.prepare_to_encrypt(None));
    let committed = assert_ok!(alice.encrypt(b"commit".to_vec()));
    assert_eq!(committed.epochs.pq_epoch, 1);
    assert_eq!(committed.epochs.classical_epoch, 2);
    let session_view = alice.epochs();
    assert_eq!(committed.epochs.pq_epoch, session_view.pq_epoch);
    assert_eq!(
        committed.epochs.classical_epoch,
        session_view.classical_epoch
    );
}

#[test]
fn test_encrypt_epochs_diverge_post_bootstrap() {
    let (alice, bob) = establish_full();
    // Post-A.4 the acceptor's send group has its PQ half (epoch 1); a commit
    // round moves classical to 2 while pq stays 1 — the pair diverges and
    // encrypt reports it faithfully.
    assert_ok!(alice.prepare_to_encrypt(None));
    let upd = assert_ok!(alice.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(upd.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert_ok!(bob.prepare_to_encrypt(None));
    let committed = assert_ok!(bob.encrypt(b"pq-live".to_vec()));
    assert_eq!(committed.epochs.pq_epoch, 1);
    assert_eq!(committed.epochs.classical_epoch, 2);
}

#[test]
fn test_commit_round_mints_new_listen_address_and_retains_old() {
    let (alice, bob) = establish_sessions();
    let listen_a0 = assert_ok!(alice.should_listen_on());
    let bob_post0 = assert_some!(assert_ok!(bob.send_rendezvous()));

    // Routine (non-committing) rounds don't move epochs or addresses.
    assert_ok!(bob.prepare_to_encrypt(None));
    let upd_frame = assert_ok!(bob.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(alice.process_incoming(upd_frame.cipher_text)));
    assert_eq!(
        assert_ok!(alice.should_listen_on())
            .rendezvous_by_epoch
            .len(),
        listen_a0.rendezvous_by_epoch.len()
    );

    // Full A.2 round: alice approves bob's stapled Upd; her next send commits
    // it, advancing her send group's classical epoch and minting a new address.
    let offered = assert_some!(got.proposal);
    assert_ok!(alice.queue_proposal(offered.digest));
    let prepared = assert_ok!(alice.prepare_to_encrypt(None));
    assert!(prepared.did_commit);
    let commit_frame = assert_ok!(alice.encrypt(b"commit".to_vec()));

    let listen_a1 = assert_ok!(alice.should_listen_on());
    assert_eq!(
        listen_a1.rendezvous_by_epoch.len(),
        listen_a0.rendezvous_by_epoch.len() + 1
    );

    // Bob applies the commit: his post address migrates to the new epoch's
    // channel — present in alice's set — while the old address stays listed.
    assert_some!(assert_ok!(bob.process_incoming(commit_frame.cipher_text)));
    let bob_post1 = assert_some!(assert_ok!(bob.send_rendezvous()));
    assert_ne!(bob_post1.bytes, bob_post0.bytes);
    assert!(listen_a1
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == bob_post1.bytes));
    assert!(listen_a1
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == bob_post0.bytes));
}

#[test]
fn test_pq_ratchet_bind_mints_new_listen_address() {
    let (alice, bob) = establish_sessions();
    let before = assert_ok!(alice.should_listen_on())
        .rendezvous_by_epoch
        .len();

    // A.3: the bind's classical commit advances alice's send-group epoch.
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"bind".to_vec()));
    let listen_a = assert_ok!(alice.should_listen_on());
    assert_eq!(listen_a.rendezvous_by_epoch.len(), before + 1);

    // Bob applies the bind; his post address lands on the new epoch's channel.
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"bind");
    let bob_post = assert_some!(assert_ok!(bob.send_rendezvous()));
    assert!(listen_a
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == bob_post.bytes));
}

/// Drive one full A.5 rekey with `initiator` holding the turn. Returns after the
/// responder applies the final commit (turn flipped to the responder).
fn rekey_round(initiator: &Arc<TwoMlsPqSession>, responder: &Arc<TwoMlsPqSession>) {
    let upd = assert_ok!(initiator.pq_rekey_begin(None));
    // The frame is sealed on the wire; opened, it classifies as the rekey Upd'.
    assert_eq!(
        assert_some!(assert_ok!(responder.open_incoming(upd.clone()))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RekeyUpdate
        }
    );
    // A rotation-less rekey announces no credential.
    assert!(assert_ok!(responder.pq_rekey_respond(upd)).is_none());
    let reply = assert_some!(responder.pq_take_pending_outbound());
    assert!(assert_ok!(initiator.pq_rekey_apply(reply)));
    let fin = assert_some!(initiator.pq_take_pending_outbound());
    assert!(!assert_ok!(responder.pq_rekey_apply(fin)));
}

#[test]
fn test_pq_rekey_full_round() {
    let (alice, bob) = establish_full();
    // Bob holds the turn after Alice's bootstrap completed.
    assert!(bob.my_pq_turn());
    let alice_classical = alice.epochs().classical_epoch;
    let alice_listen = assert_ok!(alice.should_listen_on())
        .rendezvous_by_epoch
        .len();

    rekey_round(&bob, &alice);

    // Both send groups' PQ epochs advanced; classical and the listen map are
    // untouched (A.5 is PQ-groups-only); the turn flipped back to Alice.
    assert_eq!(alice.epochs().pq_epoch, 2);
    assert_eq!(bob.epochs().pq_epoch, 2);
    assert_eq!(alice.epochs().classical_epoch, alice_classical);
    assert_eq!(
        assert_ok!(alice.should_listen_on())
            .rendezvous_by_epoch
            .len(),
        alice_listen
    );
    assert!(alice.my_pq_turn());
    assert!(!bob.my_pq_turn());

    // Messaging still flows both ways on the rekeyed groups, and the next
    // encrypt reports the bumped pq epoch.
    assert_ok!(alice.prepare_to_encrypt(None));
    let a2b = assert_ok!(alice.encrypt(b"post-rekey".to_vec()));
    assert_eq!(a2b.epochs.pq_epoch, 2);
    let got = assert_ok!(bob.process_incoming(a2b.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-rekey".to_vec()
    );

    // Consecutive rekeys work: the turn machine supports Alice going next.
    rekey_round(&alice, &bob);
    assert_eq!(alice.epochs().pq_epoch, 3);
    assert_eq!(bob.epochs().pq_epoch, 3);
}

/// Regression: two consecutive A.5 rekeys with an archive/restore of BOTH parties
/// *between* the rounds. This exercises the send-PQ export watermark
/// (`last_send_pq_exported`) against an ephemeral PQ secret store emptied by the jump —
/// the store that holds the A.5 cross-party PSKs is not archived, so the second round
/// must stand up entirely on restored watermark + epoch state. The lockstep invariant
/// (a party pre-registers its send-PQ leaf iff the peer will reference it) is what keeps
/// the empty store safe. Complements `test_pq_rekey_full_round` (two rekeys, no restore)
/// and `test_archive_mid_rekey_round_completes_after_restore` (restore mid-round).
#[test]
fn test_two_rekeys_with_archive_between_rounds() {
    let (alice, bob) = establish_full();
    // Round 1: Bob holds the turn after the bootstrap, so he initiates.
    assert!(bob.my_pq_turn());
    rekey_round(&bob, &alice);
    assert_eq!(alice.epochs().pq_epoch, 2);
    assert_eq!(bob.epochs().pq_epoch, 2);
    // The turn flipped to Alice.
    assert!(alice.my_pq_turn());
    assert!(!bob.my_pq_turn());

    // Archive + restore both parties between the rounds. The A.5 cross-party PSKs live
    // only in the ephemeral store, which does not ride the archive.
    let alice = round_trip(&alice);
    let bob = round_trip(&bob);
    assert!(alice.my_pq_turn());
    assert!(!bob.my_pq_turn());

    // Round 2: Alice initiates on the restored sessions. If the second round tried to
    // re-export a send-PQ leaf the first round consumed, or the peer referenced a PSK
    // the empty store could not resolve, this would fail here.
    rekey_round(&alice, &bob);
    assert_eq!(alice.epochs().pq_epoch, 3);
    assert_eq!(bob.epochs().pq_epoch, 3);
    assert!(bob.my_pq_turn());

    // Messaging still flows on the twice-rekeyed, once-restored groups.
    assert_ok!(alice.prepare_to_encrypt(None));
    let a2b = assert_ok!(alice.encrypt(b"after-two-rekeys".to_vec()));
    assert_eq!(a2b.epochs.pq_epoch, 3);
    let got = assert_ok!(bob.process_incoming(a2b.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"after-two-rekeys".to_vec()
    );
}

#[test]
fn test_pq_rekey_then_ratchet_still_works() {
    let (alice, bob) = establish_full();
    rekey_round(&bob, &alice);
    // A.3 ratchet after a rekey: Alice holds the turn.
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"post-rekey-ratchet".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(
        assert_ok!(bob.pq_ratchet_apply(bind)),
        b"post-rekey-ratchet"
    );
}

#[test]
fn test_pq_rekey_requires_full_establishment() {
    // Pre-A.4 the acceptor's send-PQ (and the initiator's recv mirror) is missing.
    let (alice, _bob) = establish_sessions();
    assert!(alice.my_pq_turn());
    assert_err!(alice.pq_rekey_begin(None), TwoMlsPqError::SessionNotReady);
}

#[test]
fn test_pq_rekey_requires_turn_and_rejects_unsolicited() {
    let (alice, bob) = establish_full();
    // Alice's bootstrap completion passed the turn to Bob.
    assert_err!(alice.pq_rekey_begin(None), TwoMlsPqError::SessionNotReady);
    // An unsolicited final commit (no rekey in flight) is rejected.
    let bogus = super::encode_pq_rekey_commit(vec![0u8; 8], Vec::new());
    assert_err!(bob.pq_rekey_apply(bogus), TwoMlsPqError::SessionNotReady);
    // A second begin while one is in flight is rejected (single slot).
    let _upd = assert_ok!(bob.pq_rekey_begin(None));
    assert_err!(bob.pq_rekey_begin(None), TwoMlsPqError::SessionNotReady);
}

/// The session's own leaf signature public keys in (send-PQ, recv-PQ) — the two
/// leaves an A.5 credential handoff must move to the new principal.
fn own_pq_leaf_signature_keys(session: &Arc<TwoMlsPqSession>) -> (Vec<u8>, Vec<u8>) {
    let inner = session.lock();
    let send = inner
        .send_group
        .as_ref()
        .and_then(|g| g.pq.as_ref())
        .expect("send-PQ live")
        .current_member_signing_identity()
        .expect("send-PQ leaf")
        .signature_key
        .as_bytes()
        .to_vec();
    let recv = inner
        .recv_group
        .as_ref()
        .and_then(|g| g.pq.as_ref())
        .expect("recv-PQ live")
        .current_member_signing_identity()
        .expect("recv-PQ leaf")
        .signature_key
        .as_bytes()
        .to_vec();
    (send, recv)
}

#[test]
fn test_pq_rekey_rotation_hands_pq_leaves_to_new_principal() {
    let (alice, bob) = establish_full();

    // Phase 8 first: the classical rotation swaps the session client to the new
    // principal (whose signing keys `stage_rotation` minted internally) and announces the
    // ClientId to the peer.
    let new_bob_id = make_client().client_id();
    rotate_round(&bob, &alice, new_bob_id.clone());

    // The successor's PQ signing key is now the session's current client — that is
    // what the A.5 handoff must install into both leaves.
    let new_key = {
        let inner = bob.lock();
        inner
            .client
            .combiner()
            .pq_signature_keypair()
            .1
            .as_bytes()
            .to_vec()
    };
    // The PQ leaves still sign as the old principal until the A.5 handoff.
    let before = own_pq_leaf_signature_keys(&bob);
    assert_ne!(before.0, new_key);
    assert_ne!(before.1, new_key);

    // A.5 with the credential handoff; the responder learns the announced id.
    let upd = assert_ok!(bob.pq_rekey_begin(Some(new_bob_id.clone())));
    assert_eq!(
        assert_some!(assert_ok!(alice.pq_rekey_respond(upd))),
        new_bob_id
    );
    let reply = assert_some!(alice.pq_take_pending_outbound());
    assert!(assert_ok!(bob.pq_rekey_apply(reply)));
    let fin = assert_some!(bob.pq_take_pending_outbound());
    assert!(!assert_ok!(alice.pq_rekey_apply(fin)));

    // Both of Bob's PQ leaves now sign with the new principal's key.
    let after = own_pq_leaf_signature_keys(&bob);
    assert_eq!(after.0, new_key);
    assert_eq!(after.1, new_key);

    // The rekeyed, rotated groups keep working: messaging flows and the next
    // rekey round (Alice's turn) proceeds — the new signer owns the leaves.
    assert_ok!(bob.prepare_to_encrypt(None));
    let msg = assert_ok!(bob.encrypt(b"post-handoff".to_vec()));
    let got = assert_ok!(alice.process_incoming(msg.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-handoff".to_vec()
    );
    rekey_round(&alice, &bob);
}

/// Phase 8 swaps the session client, but the existing groups keep resolving
/// external PSKs from the stores of the clients that created them. Every
/// PSK-carrying flow must still work after a rotation — this pins the
/// psk_stores registry (a plain rekey, an A.3 ratchet, and a full classical
/// commit round, all post-rotation, no credential handoff involved).
#[test]
fn test_psk_flows_survive_rotation_without_handoff() {
    let (alice, bob) = establish_full();

    let new_bob = make_client();
    assert_ok!(bob.stage_rotation(new_bob.client_id().bytes));
    assert_ok!(bob.prepare_to_encrypt(Some(new_bob.client_id())));
    let enc = assert_ok!(bob.encrypt(b"rotate".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(enc.cipher_text)));

    // A.5 plain rekey, initiated by the rotated side (Bob holds the turn).
    rekey_round(&bob, &alice);

    // A.3 ratchet with the rotated side responding (Alice's turn now).
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"post-rotation-ratchet".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(
        assert_ok!(bob.pq_ratchet_apply(bind)),
        b"post-rotation-ratchet"
    );

    // Full classical commit round from the rotated side: Alice staples an Upd
    // that Bob approves and commits with a cross-party PSK refresh.
    assert_ok!(alice.prepare_to_encrypt(None));
    let a2b = assert_ok!(alice.encrypt(b"staple".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(a2b.cipher_text)));
    let offered = assert_some!(got.proposal);
    assert_ok!(bob.queue_proposal(offered.digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let b2a = assert_ok!(bob.encrypt(b"folding-commit".to_vec()));
    assert_eq!(
        assert_some!(
            assert_some!(assert_ok!(alice.process_incoming(b2a.cipher_text))).application_message
        )
        .app_message_data,
        b"folding-commit"
    );
}

#[test]
fn test_pq_rekey_begin_rotating_requires_current_agent() {
    let (_alice, bob) = establish_full();
    // Bob holds the turn, but no Phase 8 rotation has run: a handoff to an
    // arbitrary principal is refused, and the slot stays free for a plain rekey.
    let stranger = make_client();
    assert_err!(
        bob.pq_rekey_begin(Some(stranger.client_id())),
        TwoMlsPqError::SessionNotReady
    );
    assert_ok!(bob.pq_rekey_begin(None));
}

#[test]
fn test_pq_bootstrap_begin_rotating_requires_current_agent() {
    let (alice, bob) = establish_confirmed_sessions();
    let stranger = make_client();
    assert_err!(
        alice.pq_bootstrap_begin(Some(stranger.client_id())),
        TwoMlsPqError::SessionNotReady
    );

    // After a Phase 8 rotation the bootstrap accepts the handoff id, and the
    // KP' it emits — generated by the new principal — completes A.4 as usual.
    let new_alice = make_client();
    let new_alice_id = new_alice.client_id();
    rotate_round(&alice, &bob, new_alice_id.clone());

    let kp = assert_ok!(alice.pq_bootstrap_begin(Some(new_alice_id)));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_apply(bind));
    assert!(bob.my_pq_turn());
}

#[test]
fn test_a4_bootstrap_mints_no_listen_addresses_but_advertises_pq_id() {
    let (alice, bob) = establish_sessions();
    let bob_before = assert_ok!(bob.should_listen_on());
    assert!(bob_before.send_group.pq.bytes.is_empty());

    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_apply(bind));

    // A.4 is PQ-groups-only: no classical commit, no new listen addresses —
    // but the acceptor's send group now advertises its PQ half.
    let bob_after = assert_ok!(bob.should_listen_on());
    assert_eq!(
        bob_after.rendezvous_by_epoch.len(),
        bob_before.rendezvous_by_epoch.len()
    );
    assert!(!bob_after.send_group.pq.bytes.is_empty());
}

#[test]
fn test_pq_ratchet_round_trip_delivers_app_message() {
    let (alice, bob) = establish_sessions();
    // Alice initiates a PQ ratchet on her send group; Bob responds and applies.
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"hello-pq".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    let got = assert_ok!(bob.pq_ratchet_apply(bind));
    assert_eq!(got, b"hello-pq");
}

/// The PQ side-band must survive a principal rotation: the injected-secret and apq PSKs
/// have to land in the stores the group halves actually resolve from (captured at
/// group creation), not the rotated-in client's stores — otherwise Alice's bind and
/// Bob's apply both fail to find their PSKs after the client swap.
#[test]
fn test_pq_ratchet_completes_after_principal_rotation() {
    let (alice, bob) = establish_confirmed_sessions();

    // Rotate both agents, delivering each rotation commit so the peer's recv group
    // tracks the new epoch.
    let new_alice = make_client();
    assert_ok!(alice.stage_rotation(new_alice.client_id().bytes));
    assert_ok!(alice.prepare_to_encrypt(Some(new_alice.client_id())));
    let enc = assert_ok!(alice.encrypt(b"alice-rotated".to_vec()));
    assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));

    let new_bob = make_client();
    assert_ok!(bob.stage_rotation(new_bob.client_id().bytes));
    assert_ok!(bob.prepare_to_encrypt(Some(new_bob.client_id())));
    let enc = assert_ok!(bob.encrypt(b"bob-rotated".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(enc.cipher_text)));

    // A full A.3 round after both rotations: Alice injects on her send group's PQ half
    // and binds into its classical half; Bob applies on his recv halves.
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"pq-after-rotation".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"pq-after-rotation");
}

/// Complete the A.4 bootstrap after establishment so both directions are full
/// APQ — required before the deferred acceptor side can ratchet.
fn establish_full() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let (alice, bob) = establish_confirmed_sessions();
    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_apply(bind));
    (alice, bob)
}

/// A bootstrap key package naming a principal other than the established peer is
/// rejected before any PQ group is stood up around it: the new half's added leaf
/// becomes a sender identity this library reports, so it must be the peer's.
#[test]
fn test_bootstrap_kp_from_unknown_principal_rejected() {
    let (_alice, bob) = establish_confirmed_sessions();
    let mallory = make_client();
    let mallory_pq_kp = make_combiner_kp(&mallory).pq;
    let mut frame = vec![super::PQ_BOOTSTRAP_KP_TAG];
    frame.extend_from_slice(&mallory_pq_kp);
    assert_err!(
        bob.pq_bootstrap_respond(frame),
        TwoMlsPqError::RemoteIdentityMismatch
    );
    // The turn state is untouched — the peer's real bootstrap still works.
    assert!(!bob.my_pq_turn());
}

#[test]
fn test_pq_ratchet_turn_flips_to_responder() {
    let (alice, bob) = establish_full();
    // Round 1: Alice initiates.
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"a1".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"a1");
    // Round 2: turn flips — Bob initiates on his send group, Alice applies.
    let ek2 = assert_ok!(bob.pq_ratchet_begin());
    assert_ok!(alice.pq_ratchet_respond(ek2));
    let ct2 = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct2, b"b1".to_vec()));
    let bind2 = assert_some!(bob.pq_take_pending_outbound());
    assert_eq!(assert_ok!(alice.pq_ratchet_apply(bind2)), b"b1");
}

#[test]
fn test_pq_ratchet_bind_guarded_while_commit_staged() {
    let (alice, bob) = establish_full();
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());

    // A prepared-but-unsent round holds the staple slot: the bind's classical
    // commit must not displace a commit that has never ridden a frame (the peer
    // would hit EpochDesync with zero loss on the wire).
    assert_ok!(alice.prepare_to_encrypt(None));
    assert_err!(
        alice.pq_ratchet_bind(ct.clone(), b"app".to_vec()),
        TwoMlsPqError::SessionNotReady
    );

    // Retriable: once the round's encrypt has gone out, the bind proceeds.
    let enc = assert_ok!(alice.encrypt(b"round".to_vec()));
    assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));
    assert_ok!(alice.pq_ratchet_bind(ct, b"app".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"app");
}

#[test]
fn test_message_frame_overtaking_bind_fails_retriably() {
    let (alice, bob) = establish_full();
    // Alice's A.3 round: EK → CT → bind (staged, not yet delivered).
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"bound".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());

    // A message frame sent after the bind overtakes it in transit: its staple is
    // the bind's classical commit, whose APQ-PSK Bob cannot resolve until the
    // BIND itself lands.
    assert_ok!(alice.prepare_to_encrypt(None));
    let overtaking = assert_ok!(alice.encrypt(b"overtook".to_vec()));
    assert_err!(
        bob.process_incoming(overtaking.cipher_text.clone()),
        TwoMlsPqError::DecryptionFailed
    );

    // The failed staple apply did not corrupt state: the BIND still applies…
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"bound");
    // …and the retried frame decrypts (its staple is now an already-applied
    // commit, skipped idempotently).
    let res = assert_some!(assert_ok!(bob.process_incoming(overtaking.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"overtook"
    );
}

#[test]
fn test_pq_ratchet_bind_without_begin_is_rejected() {
    let (alice, _bob) = establish_sessions();
    let mut ct = vec![super::PQ_CT_TAG];
    ct.extend_from_slice(&[0u8; 1088]);
    assert_err!(
        alice.pq_ratchet_bind(ct, b"x".to_vec()),
        TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_classical_round_still_works_after_pq_ratchet() {
    let (alice, bob) = establish_sessions();
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"pq".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"pq");

    // The classical ratchet must continue normally after a PQ bind.
    assert_ok!(alice.prepare_to_encrypt(None));
    let enc = assert_ok!(alice.encrypt(b"classical-after-pq".to_vec()));
    let result = assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"classical-after-pq"
    );
}

#[test]
fn test_three_sequential_pq_ratchets_alternate_and_deliver() {
    let (alice, bob) = establish_full();
    for (i, (initiator, responder)) in [(&alice, &bob), (&bob, &alice), (&alice, &bob)]
        .iter()
        .enumerate()
    {
        let payload = vec![i as u8; 8];
        let ek = assert_ok!(initiator.pq_ratchet_begin());
        assert_ok!(responder.pq_ratchet_respond(ek));
        let ct = assert_some!(responder.pq_take_pending_outbound());
        assert_ok!(initiator.pq_ratchet_bind(ct, payload.clone()));
        let bind = assert_some!(initiator.pq_take_pending_outbound());
        assert_eq!(assert_ok!(responder.pq_ratchet_apply(bind)), payload);
    }
}

#[test]
fn test_pq_ratchet_respond_rejects_wrong_tag() {
    let (_alice, bob) = establish_sessions();
    assert_err!(
        bob.pq_ratchet_respond(vec![0xAB, 1, 2, 3]),
        TwoMlsPqError::Mls
    );
}

#[test]
fn test_pq_frame_routed_to_process_incoming_is_rejected() {
    let (_alice, bob) = establish_sessions();
    // A PQ-ratchet EK frame must never be silently swallowed as an MLS ciphertext.
    let mut ek = vec![super::PQ_EK_TAG];
    ek.extend_from_slice(&[0u8; 8]);
    assert_err!(bob.process_incoming(ek), TwoMlsPqError::SessionNotReady);
}

#[test]
fn test_pq_ratchet_apply_from_stranger_is_rejected() {
    let (alice, bob) = establish_sessions();
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"x".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    // A different session cannot open the sealed bind (its header window holds none
    // of this session's keys), so it is rejected at the seal — `Mls` on the
    // passed-through, unparseable blob — before any KEM state is consulted.
    let (_a2, b2) = establish_sessions();
    assert_err!(b2.pq_ratchet_apply(bind), TwoMlsPqError::Mls);
}

#[test]
fn test_pq_ratchet_double_begin_is_rejected() {
    let (alice, _bob) = establish_sessions();
    assert_ok!(alice.pq_ratchet_begin());
    assert_err!(alice.pq_ratchet_begin(), TwoMlsPqError::SessionNotReady);
}

#[test]
fn test_pq_ratchet_tampered_frame_fails_to_bind() {
    let (alice, bob) = establish_sessions();
    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let mut ct = assert_some!(bob.pq_take_pending_outbound());
    // Flip a byte of the sealed ciphertext frame: the header AEAD tag no longer
    // verifies, so Alice cannot open it and the bind is rejected at the seal (the
    // passed-through blob's nonce byte is not `PQ_CT_TAG`). Header encryption makes
    // any wire-level tamper a seal failure before the ML-KEM layer is reached.
    // (ML-KEM implicit rejection itself is exercised at the `apq` layer, below the
    // seal.)
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    assert_err!(alice.pq_ratchet_bind(ct, b"x".to_vec()), TwoMlsPqError::Mls);
}

#[test]
fn test_decode_pq_bind_rejects_truncated_and_trailing() {
    let frame = super::encode_pq_bind(b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec());
    assert_ok!(super::decode_pq_bind(&frame));
    let mut trailing = frame.clone();
    trailing.push(0xFF);
    assert_err!(super::decode_pq_bind(&trailing), TwoMlsPqError::Mls);
    assert_err!(
        super::decode_pq_bind(&[super::PQ_BIND_TAG]),
        TwoMlsPqError::Mls
    );
}

#[test]
fn test_initiate_fails_when_both_suites_classical() {
    let alice = make_client();
    let bob = make_client();
    let classical = assert_ok!(bob.generate_key_package(crate::MlsCipherSuite::x25519_chacha()));
    let pq = assert_ok!(bob.generate_key_package(crate::MlsCipherSuite::x25519_chacha()));
    let bad_kp = crate::key_packages::CombinerKeyPackage { classical, pq };
    assert_err!(
        TwoMlsPqSession::initiate(alice, bad_kp, None),
        TwoMlsPqError::PqNotAvailable
    );
}

#[test]
fn test_accept_with_invalid_welcome_bytes_returns_error() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    assert_err!(
        TwoMlsPqSession::accept(bob, vec![0xFF; 32], alice_kp),
        TwoMlsPqError::Mls
    );
}

#[test]
fn test_session_id_is_same_from_both_sides() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let apq_welcome_a = alice_session.test_initial_welcome();

    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        apq_welcome_a,
        alice_kp
    ));

    assert_eq!(
        alice_session.active_session_id().bytes,
        bob_session.active_session_id().bytes,
        "session IDs must match"
    );
}

#[test]
fn test_prepare_to_encrypt_returns_proposal_hash() {
    let (alice_session, _bob_session) = establish_sessions();
    let result = assert_ok!(alice_session.prepare_to_encrypt(None));
    assert!(!result.proposal_hash.is_empty());
    assert!(!result.did_commit);
}

#[test]
fn test_encrypt_after_prepare_succeeds() {
    let (alice_session, _bob_session) = establish_sessions();
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let result = assert_ok!(alice_session.encrypt(b"hello world".to_vec()));
    assert!(!result.cipher_text.is_empty());
    assert_eq!(
        result.sender,
        alice_session.my_principal_state().client_id()
    );
}

#[test]
fn test_encrypt_double_call_after_single_prepare_returns_error() {
    let (alice_session, _) = establish_sessions();
    assert_ok!(alice_session.prepare_to_encrypt(None));
    assert_ok!(alice_session.encrypt(b"first".to_vec()));
    assert_err!(
        alice_session.encrypt(b"second".to_vec()),
        TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_process_incoming_app_message_returns_decrypt_result() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"secret".to_vec()));

    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    let app_msg = assert_some!(result.application_message);
    assert_eq!(app_msg.app_message_data, b"secret");
    assert_eq!(
        app_msg.sender_client_id,
        alice_session.my_principal_state().client_id()
    );
}

#[test]
fn test_process_incoming_garbage_bytes_returns_error() {
    let (_, bob_session) = establish_sessions();
    assert_err!(
        bob_session.process_incoming(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        TwoMlsPqError::DecryptionFailed
    );
}

#[test]
fn test_process_incoming_empty_bytes_returns_error() {
    let (_, bob_session) = establish_sessions();
    assert_err!(
        bob_session.process_incoming(vec![]),
        TwoMlsPqError::DecryptionFailed
    );
}

#[test]
fn test_create_send_group_with_valid_keypackage_succeeds() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = alice_session.test_initial_welcome();
    assert_ok!(TwoMlsPqSession::accept(bob, welcome, alice_kp));
}

#[test]
fn test_join_send_group_with_my_principal_succeeds() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = alice_session.test_initial_welcome();
    let bob_session = assert_ok!(TwoMlsPqSession::accept(Arc::clone(&bob), welcome, alice_kp));
    assert!(bob_session.has_receive_group());
    assert!(bob_session.is_established());
}

#[test]
fn test_create_bound_send_group_classical_with_psk_succeeds() {
    let (alice_session, bob_session) = establish_sessions();
    assert!(alice_session.receive_group_id().is_some());
    assert!(bob_session.receive_group_id().is_some());
}

#[test]
fn test_create_bound_send_group_ml_kem_768_with_psk_succeeds() {
    let (alice_session, bob_session) = establish_sessions();
    assert!(alice_session.is_established());
    assert!(bob_session.is_established());
}

#[test]
fn test_from_archive_returns_archive_invalid() {
    assert_err!(
        TwoMlsPqSession::from_archive(crate::Archive { bytes: vec![] }),
        TwoMlsPqError::ArchiveInvalid
    );
}

/// One plain application round: `sender` encrypts, `receiver` decrypts, payload matches.
fn message_round(sender: &Arc<TwoMlsPqSession>, receiver: &Arc<TwoMlsPqSession>, payload: &[u8]) {
    assert_ok!(sender.prepare_to_encrypt(None));
    let enc = assert_ok!(sender.encrypt(payload.to_vec()));
    let got = assert_some!(assert_ok!(receiver.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        payload
    );
}

/// Restore `session` through the PUSH path: attach a recording sink (whose `install_sink`
/// pushes a baseline checkpoint of the current state), then rebuild from the pushed blobs.
/// The whole archive/restore corpus therefore flows through `ArchiveSink` + `from_persisted`,
/// not just the legacy whole-blob `archive()`. (Equivalent outcome — the baseline checkpoint
/// is the full state — while exercising install_sink/encode_checkpoint/reconcile.)
fn round_trip(session: &Arc<TwoMlsPqSession>) -> Arc<TwoMlsPqSession> {
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(session.install_sink(sink.clone()));
    assert_ok!(TwoMlsPqSession::from_persisted(
        sink.latest(crate::BlobKind::Core),
        sink.latest(crate::BlobKind::Checkpoint),
    ))
}

/// A push-persistence sink that records every blob (the test analogue of a persistence
/// layer). `latest` returns the newest blob of a kind — exactly the newest-per-slot the
/// `ArchiveSink` contract asks a real sink to keep.
#[derive(Default)]
struct RecordingSink {
    pushes: std::sync::Mutex<Vec<(u64, crate::BlobKind, Vec<u8>)>>,
}

impl RecordingSink {
    fn kinds(&self) -> Vec<crate::BlobKind> {
        self.pushes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(_, k, _)| *k)
            .collect()
    }

    fn latest(&self, kind: crate::BlobKind) -> Option<crate::Archive> {
        self.pushes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, k, _)| *k == kind)
            .max_by_key(|(seq, _, _)| *seq)
            .map(|(_, _, bytes)| crate::Archive {
                bytes: bytes.clone(),
            })
    }
}

impl crate::ArchiveSink for RecordingSink {
    fn persist(&self, seq: u64, kind: crate::BlobKind, archive: Vec<u8>) {
        self.pushes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((seq, kind, archive));
    }
}

/// End-to-end smoke test of the push path: install a sink, drive classical + PQ ops, and
/// confirm the blob kinds, then restore from the pushed blobs and keep messaging.
#[test]
fn test_push_persistence_smoke() {
    let (alice, bob) = establish_full();

    let sink = Arc::new(RecordingSink::default());
    // `install_sink` pushes exactly one baseline checkpoint.
    assert_ok!(alice.install_sink(sink.clone()));
    assert_eq!(sink.kinds(), vec![crate::BlobKind::Checkpoint]);

    // Classical message rounds push ONLY Core — never re-encode the ML-KEM trees.
    message_round(&alice, &bob, b"one");
    message_round(&bob, &alice, b"two");
    assert!(
        sink.kinds()
            .iter()
            .skip(1)
            .all(|k| *k == crate::BlobKind::Core),
        "classical ops must push only Core, got {:?}",
        sink.kinds()
    );

    // A PQ side-band round (A.5 rekey) pushes Checkpoint(s).
    rekey_round(&bob, &alice);
    assert!(
        sink.kinds()
            .iter()
            .any(|k| *k == crate::BlobKind::Checkpoint && sink.kinds().len() > 1),
        "a PQ op must push a Checkpoint"
    );

    // Restore from the newest pushed blobs and keep going.
    let restored = assert_ok!(TwoMlsPqSession::from_persisted(
        sink.latest(crate::BlobKind::Core),
        sink.latest(crate::BlobKind::Checkpoint),
    ));
    message_round(&bob, &restored, b"after-restore");
    message_round(&restored, &bob, b"restore->bob");
}

/// `install_sink` is once-only: a second call is rejected rather than silently orphaning the
/// first sink (whose store would then go stale with no error).
#[test]
fn test_install_sink_rejects_second_call() {
    let (alice, _bob) = establish_full();
    let first = Arc::new(RecordingSink::default());
    assert_ok!(alice.install_sink(first.clone()));
    let second = Arc::new(RecordingSink::default());
    assert_err!(
        alice.install_sink(second.clone()),
        TwoMlsPqError::SinkAlreadyInstalled
    );
    // The rejected sink received nothing; the first stays the live one.
    assert_eq!(second.kinds().len(), 0);
    assert_eq!(first.kinds(), vec![crate::BlobKind::Checkpoint]);
}

/// Fail-closed restore: a `core` whose PQ-epoch manifest does not match the reconciling
/// `checkpoint` (a PQ op advanced without emitting a checkpoint — impossible normally, but
/// the manifest guards a lost/torn checkpoint) is rejected rather than restored spliced.
#[test]
fn test_from_persisted_fails_closed_on_stale_checkpoint() {
    let (alice, bob) = establish_full();
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(alice.install_sink(sink.clone()));
    // The baseline checkpoint carries the pre-rekey PQ epochs.
    let stale_checkpoint = sink.latest(crate::BlobKind::Checkpoint);
    assert!(stale_checkpoint.is_some());

    // A PQ rekey advances alice's PQ halves (and pushes a fresh checkpoint we deliberately
    // ignore); a classical message then pushes a Core whose manifest names the NEW PQ epochs.
    rekey_round(&bob, &alice);
    message_round(&alice, &bob, b"post-rekey");
    let core = sink.latest(crate::BlobKind::Core);
    assert!(core.is_some());

    // Splicing that newer Core onto the pre-rekey checkpoint would pair classical state with a
    // stale PQ tree — the manifest catches it.
    assert_err!(
        TwoMlsPqSession::from_persisted(core, stale_checkpoint),
        TwoMlsPqError::ArchiveInvalid
    );
}

/// `depends_on_seq`: a routine app message re-staples an already-committed staple, so its
/// `depends_on_seq` does not advance and never exceeds the live `state_seq`.
#[test]
fn test_depends_on_seq_stable_across_routine_messages() {
    let (alice, bob) = establish_full();
    assert_ok!(alice.prepare_to_encrypt(None));
    let first = assert_ok!(alice.encrypt(b"one".to_vec()));
    let _ = bob.process_incoming(first.cipher_text);
    assert_ok!(alice.prepare_to_encrypt(None));
    let second = assert_ok!(alice.encrypt(b"two".to_vec()));

    // Neither routine round committed, so the stapled commit — hence depends_on_seq — is
    // unchanged, and it can never point past the current state.
    assert_eq!(first.depends_on_seq, second.depends_on_seq);
    assert!(second.depends_on_seq <= alice.state_seq());
}

#[test]
fn test_archive_round_trips_session_state() {
    let (alice_session, bob_session) = establish_sessions();
    message_round(&alice_session, &bob_session, b"before");

    let session_id = alice_session.active_session_id();
    let restored = round_trip(&alice_session);
    assert_eq!(restored.active_session_id(), session_id);

    // Both directions keep flowing across the restore.
    message_round(&restored, &bob_session, b"restored->bob");
    message_round(&bob_session, &restored, b"bob->restored");
}

#[test]
fn test_archive_before_return_welcome_join_restores_and_joins() {
    // The initiator archives right after `initiate` — before the peer's return welcome
    // exists — so its return-group key package is still pending in the client store and
    // the recv group is not yet joined. A self-contained restore must carry that key
    // package, or the return-welcome join below fails (an empty-store restore cannot
    // find the private material the welcome addresses). This is the archive-returning
    // `reply` path the Swift adapter drives.
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = alice_session.test_initial_welcome();

    // Archive and restore the initiator BEFORE it has joined the return welcome.
    let restored_alice = round_trip(&alice_session);
    assert!(restored_alice.receive_group_id().is_none());

    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp
    ));
    let welcome_b = assert_some!(bob_session.pending_outbound());
    // The restored initiator joins the return welcome using its carried key package.
    assert_ok!(restored_alice.process_incoming(welcome_b));
    assert!(restored_alice.receive_group_id().is_some());

    // Both directions flow on the restored, now-established session.
    message_round(&restored_alice, &bob_session, b"restored-join");
    message_round(&bob_session, &restored_alice, b"back");
}

#[test]
fn test_archive_round_trips_fully_established_session() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_apply(bind));
    assert!(alice_session.is_fully_established());

    let restored = round_trip(&alice_session);
    assert!(restored.is_fully_established());

    // The PQ side-band still runs: a full A.3 ratchet round initiated by the
    // restored side (Bob holds the turn after the bootstrap, so pass it back first).
    let ek = assert_ok!(bob_session.pq_ratchet_begin());
    assert_ok!(restored.pq_ratchet_respond(ek));
    let ct = assert_some!(restored.pq_take_pending_outbound());
    assert_ok!(bob_session.pq_ratchet_bind(ct, b"pq-after-restore".to_vec()));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_eq!(
        assert_ok!(restored.pq_ratchet_apply(bind)),
        b"pq-after-restore"
    );
    message_round(&restored, &bob_session, b"classical-after-pq");
}

#[test]
fn test_archive_preserves_listen_map() {
    let (alice_session, bob_session) = establish_sessions();
    // Advance the send epoch (folding-commit round) so the map holds several epochs.
    message_round(&alice_session, &bob_session, b"staple");
    message_round(&bob_session, &alice_session, b"staple-back");
    let offered = {
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"upd".to_vec()));
        let got = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
        assert_some!(got.proposal)
    };
    assert_ok!(alice_session.queue_proposal(offered.digest));
    assert!(assert_ok!(alice_session.prepare_to_encrypt(None)).did_commit);
    let enc = assert_ok!(alice_session.encrypt(b"commit".to_vec()));
    assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    let before = assert_ok!(alice_session.should_listen_on());
    assert!(before.rendezvous_by_epoch.len() > 1);

    let restored = round_trip(&alice_session);
    let after = assert_ok!(restored.should_listen_on());
    assert_eq!(
        before.send_group.classical.bytes,
        after.send_group.classical.bytes
    );
    let pairs = |chans: &crate::ListenChannels| {
        chans
            .rendezvous_by_epoch
            .iter()
            .map(|e| (e.epoch, e.rendezvous_id.bytes.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(pairs(&before), pairs(&after));
}

#[test]
fn test_archive_preserves_spawn_token() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(crate::key_packages::TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = alice_session.test_initial_welcome();
    let token = b"spawn-token".to_vec();
    let bob_session = assert_ok!(bob_inv.receive(welcome_a, alice_kp, token.clone(), None, None));

    let restored = round_trip(&bob_session);
    assert!(assert_ok!(restored.forwarded(token)).is_none());
    assert_err!(
        restored.forwarded(b"other".to_vec()),
        TwoMlsPqError::DecryptionFailed
    );
}

/// The restored PSK ledger — not the (empty) stores of the rebuilt client — must
/// resolve the cross-party PSK a peer commit references: Bob's folding commit binds the
/// PSK of Alice's send group at the epoch he last observed, and the restored Alice
/// runs on a rebuilt identity whose mls-rs secret stores hold nothing.
#[test]
fn test_archive_preserves_psk_ledger_for_peer_commit() {
    let (alice_session, bob_session) = establish_sessions();
    // Alice staples an Upd for Bob to approve.
    message_round(&alice_session, &bob_session, b"staple");
    let offered = {
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"upd".to_vec()));
        let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
        assert_some!(got.proposal)
    };
    assert_ok!(bob_session.queue_proposal(offered.digest));
    assert!(assert_ok!(bob_session.prepare_to_encrypt(None)).did_commit);
    let crossing = assert_ok!(bob_session.encrypt(b"bound-commit".to_vec()));

    // Alice archives before Bob's bound frame arrives; the restore rebuilds her
    // client with empty PSK stores.
    let restored = round_trip(&alice_session);
    let got = assert_some!(assert_ok!(restored.process_incoming(crossing.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"bound-commit"
    );
}

/// Prepared-but-unsent state survives: the staged proposal/commit emit after restore
/// and the peer accepts the frame.
#[test]
fn test_archive_preserves_prepared_encrypt_state() {
    let (alice_session, bob_session) = establish_sessions();
    assert_ok!(alice_session.prepare_to_encrypt(None));

    let restored = round_trip(&alice_session);
    let enc = assert_ok!(restored.encrypt(b"prepared-before-archive".to_vec()));
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"prepared-before-archive"
    );
}

/// A committed-but-unconfirmed rotation (`my_state == Pending`) archives, restores
/// self-contained (the archive rebuilds the NEW principal's client — parameterless
/// restore), and resolves to `Sync` once the peer's traffic confirms.
#[test]
fn test_archive_mid_rotation_restores_onto_new_client() {
    let (alice_session, bob_session) = establish_confirmed_sessions();
    message_round(&alice_session, &bob_session, b"before");

    // A fresh opaque ClientId for the successor principal (the app owns only the id; the
    // signing keys are minted internally by `stage_rotation`). The rotation is
    // in flight as a PROPOSAL when the archive is cut — the candidate's minted
    // principal must ride the archive, or the restored session could never
    // resolve the peer's commit of it.
    let new_id = make_client().client_id();
    assert_ok!(alice_session.stage_rotation(new_id.bytes.clone()));
    assert_ok!(alice_session.prepare_to_encrypt(Some(new_id.clone())));
    let rotation = assert_ok!(alice_session.encrypt(b"rotate".to_vec()));
    assert!(matches!(
        alice_session.my_principal_state(),
        PrincipalState::Pending { .. }
    ));

    let restored = round_trip(&alice_session);
    assert!(matches!(
        restored.my_principal_state(),
        PrincipalState::Pending { .. }
    ));

    // The peer approves and commits the candidate; the staple back canonicalizes
    // the RESTORED session onto the successor principal.
    let got = assert_some!(assert_ok!(
        bob_session.process_incoming(rotation.cipher_text)
    ));
    assert_ok!(bob_session.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob_session.prepare_to_encrypt(None)).did_commit);
    let frame = assert_ok!(bob_session.encrypt(b"canonicalize".to_vec()));
    assert_some!(assert_ok!(restored.process_incoming(frame.cipher_text)));
    assert!(matches!(
        restored.my_principal_state(),
        PrincipalState::Sync { .. }
    ));
    assert_eq!(restored.my_principal_state().client_id(), new_id);
}

/// A parked responder side-band frame (turn already flipped) survives the round trip;
/// dropping it would desync the side-band permanently.
#[test]
fn test_archive_preserves_parked_pq_frame() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_apply(bind));

    // Bob initiates a ratchet round; Alice responds and parks the ct frame.
    let ek = assert_ok!(bob_session.pq_ratchet_begin());
    assert_ok!(alice_session.pq_ratchet_respond(ek));
    let ct = assert_some!(alice_session.pq_take_pending_outbound());
    assert_ok!(bob_session.pq_ratchet_bind(ct.clone(), b"pq-msg".to_vec()));

    // Bob's bind is parked with his turn already flipped: archive him and make sure
    // the frame is still deliverable from the restored session.
    let restored_bob = round_trip(&bob_session);
    let bind = assert_some!(restored_bob.pq_take_pending_outbound());
    assert_eq!(assert_ok!(alice_session.pq_ratchet_apply(bind)), b"pq-msg");
}

/// A.5 rekey markers hold no secrets and archive on both sides mid-round.
#[test]
fn test_archive_mid_rekey_round_completes_after_restore() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_apply(bind));

    // Bob holds the turn: he initiates the rekey, then archives mid-round.
    let upd = assert_ok!(bob_session.pq_rekey_begin(None));
    let restored_bob = round_trip(&bob_session);

    assert!(assert_ok!(alice_session.pq_rekey_respond(upd)).is_none());
    // Alice archives mid-round too (RekeyResponded, parked reply survives).
    let restored_alice = round_trip(&alice_session);

    let reply = assert_some!(restored_alice.pq_take_pending_outbound());
    assert!(assert_ok!(restored_bob.pq_rekey_apply(reply)));
    let fin = assert_some!(restored_bob.pq_take_pending_outbound());
    assert!(!assert_ok!(restored_alice.pq_rekey_apply(fin)));
}

/// Total archive #1: a staged-but-uncommitted rotation rides in the archive; after a
/// self-contained restore, `prepare_to_encrypt(Some(new_id))` commits the rotation and
/// the peer observes the new sender. (This path used to refuse `SessionNotReady`.)
#[test]
fn test_archive_with_staged_rotation_restores_and_commits() {
    let (alice_session, bob_session) = establish_confirmed_sessions();
    message_round(&alice_session, &bob_session, b"before");

    // Stage a rotation but do NOT commit it — the archive must carry the staged
    // successor identity (minted internally by `stage_rotation`).
    let new_id = make_client().client_id();
    assert_ok!(alice_session.stage_rotation(new_id.bytes.clone()));
    assert!(matches!(
        alice_session.my_principal_state(),
        PrincipalState::Pending { .. }
    ));

    let restored = round_trip(&alice_session);
    // The restored session still holds the staged candidate: proposing it succeeds
    // and the peer observes the candidate identity on the offered proposal.
    assert_ok!(restored.prepare_to_encrypt(Some(new_id.clone())));
    let rotation = assert_ok!(restored.encrypt(b"rotate-after-restore".to_vec()));

    let got = assert_some!(assert_ok!(
        bob_session.process_incoming(rotation.cipher_text)
    ));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"rotate-after-restore"
    );
    let offered = assert_some!(got.proposal);
    assert_eq!(offered.proposing, new_id);
    // Approve + commit: the canonical step completes against the restored session.
    assert_ok!(bob_session.queue_proposal(offered.digest));
    assert!(assert_ok!(bob_session.prepare_to_encrypt(None)).did_commit);
    let frame = assert_ok!(bob_session.encrypt(b"canonicalize".to_vec()));
    assert_some!(assert_ok!(restored.process_incoming(frame.cipher_text)));
    assert_eq!(restored.my_principal_state().client_id(), new_id);
}

/// `stage_rotation` is idempotent-ish (matching classical `propose`): staging the same
/// id twice keeps the existing staged identity; a different id replaces it.
#[test]
fn test_stage_rotation_same_id_is_idempotent() {
    let (alice_session, _bob_session) = establish_confirmed_sessions();
    let id = make_client().client_id();
    assert_ok!(alice_session.stage_rotation(id.bytes.clone()));
    // Staging the same id again is a no-op and does not error.
    assert_ok!(alice_session.stage_rotation(id.bytes.clone()));
    // A different id becomes a SECOND live candidate (the peer's commit picks the
    // winner); either may ride a frame's proposal.
    let other = make_client().client_id();
    assert_ok!(alice_session.stage_rotation(other.bytes.clone()));
    assert_ok!(alice_session.prepare_to_encrypt(Some(id)));
    assert_ok!(alice_session.encrypt(b"candidate-one".to_vec()));
    assert_ok!(alice_session.prepare_to_encrypt(Some(other)));
    assert_ok!(alice_session.encrypt(b"candidate-two".to_vec()));
}

/// Total archive #2: archive mid-A.3 as the INITIATOR (after `pq_ratchet_begin`,
/// before the ciphertext arrives). The held ephemeral survives the jump, so the
/// restored initiator binds the responder's ciphertext and the round completes.
#[test]
fn test_archive_mid_a3_as_initiator_completes_after_restore() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_apply(bind));

    // Bob holds the turn after the bootstrap: he is the A.3 initiator.
    let ek = assert_ok!(bob_session.pq_ratchet_begin());
    // Archive Bob mid-round (Initiating, holding the ephemeral) before the ct arrives.
    let restored_bob = round_trip(&bob_session);

    // Alice responds; the restored Bob binds across the jump with his rebuilt ephemeral.
    assert_ok!(alice_session.pq_ratchet_respond(ek));
    let ct = assert_some!(alice_session.pq_take_pending_outbound());
    assert_ok!(restored_bob.pq_ratchet_bind(ct, b"initiator-jump".to_vec()));
    let bind = assert_some!(restored_bob.pq_take_pending_outbound());
    assert_eq!(
        assert_ok!(alice_session.pq_ratchet_apply(bind)),
        b"initiator-jump"
    );
    message_round(&restored_bob, &alice_session, b"classical-after-jump");
}

/// Total archive #3: archive mid-A.3 as the RESPONDER (after `pq_ratchet_respond`,
/// holding the shared secret S). S survives the jump, so the restored responder
/// applies the initiator's bind (0x09) cleanly — the desync that discarding S would
/// cause is exactly why S must be serialized.
#[test]
fn test_archive_mid_a3_as_responder_completes_after_restore() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_apply(bind));

    // Bob initiates; Alice responds and holds S (having emitted the ciphertext).
    let ek = assert_ok!(bob_session.pq_ratchet_begin());
    assert_ok!(alice_session.pq_ratchet_respond(ek));
    let ct = assert_some!(alice_session.pq_take_pending_outbound());
    // Archive Alice mid-round (Responding, holding S).
    let restored_alice = round_trip(&alice_session);

    // Bob binds; the restored Alice applies the incoming bind across the jump.
    assert_ok!(bob_session.pq_ratchet_bind(ct, b"responder-jump".to_vec()));
    let bind = assert_some!(bob_session.pq_take_pending_outbound());
    assert_eq!(
        assert_ok!(restored_alice.pq_ratchet_apply(bind)),
        b"responder-jump"
    );
    message_round(&restored_alice, &bob_session, b"classical-after-jump");
}

#[test]
fn test_from_archive_rejects_malformed_bytes() {
    let (alice_session, _bob_session) = establish_sessions();
    let archive = assert_ok!(alice_session.archive());

    // Wrong version byte.
    let mut wrong_version = archive.bytes.clone();
    wrong_version[0] ^= 0xFF;
    assert_err!(
        TwoMlsPqSession::from_archive(crate::Archive {
            bytes: wrong_version
        }),
        TwoMlsPqError::ArchiveInvalid
    );

    // Truncated body.
    let truncated = archive.bytes[..archive.bytes.len() - 1].to_vec();
    assert_err!(
        TwoMlsPqSession::from_archive(crate::Archive { bytes: truncated }),
        TwoMlsPqError::ArchiveInvalid
    );

    // Trailing garbage.
    let mut trailing = archive.bytes.clone();
    trailing.push(0);
    assert_err!(
        TwoMlsPqSession::from_archive(crate::Archive { bytes: trailing }),
        TwoMlsPqError::ArchiveInvalid
    );
}

#[test]
fn test_send_rendezvous_none_without_recv_group() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    // Initiator pre-return-welcome: no recv group, nowhere to post.
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(assert_ok!(session.send_rendezvous()).is_none());
}

#[test]
fn test_should_listen_on_derivation_is_shared_not_random() {
    // Both members of the same group derive the same address independently:
    // alice's listen address at epoch 1 equals bob's post address, computed
    // from each side's own group state.
    let (alice_session, bob_session) = establish_sessions();
    let listen = assert_ok!(alice_session.should_listen_on());
    let post = assert_some!(assert_ok!(bob_session.send_rendezvous()));
    assert_eq!(
        listen.rendezvous_by_epoch[0].rendezvous_id.bytes,
        post.bytes
    );
}

#[test]
fn test_forwarded_refused_without_spawn_token() {
    // An initiator session carries no spawn token — nothing to match replays against —
    // so `forwarded` refuses. (An acceptor built through `TwoMlsPqInvitation::receive`
    // does have one, keyed by the invitation; that path is covered by the forward-table
    // tests.)
    let (alice_session, _bob_session) = establish_sessions();
    assert_err!(
        alice_session.forwarded(vec![]),
        TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_queue_proposal_stages_for_next_ratchet() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"hello from bob".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    let proposal = assert_some!(result.proposal);

    assert_ok!(alice_session.queue_proposal(proposal.digest));
    let prep = assert_ok!(alice_session.prepare_to_encrypt(None));

    assert!(prep.did_commit, "should commit after queued proposal");
    assert!(prep.committed_remote_client_id.is_some());
}

/// The binding values are honest digests with cross-side coherence: the sender's
/// `proposal_hash` is the SHA-256 of the staged Upd(self) proposal, so the
/// receiver's `QueuedRemoteProposal.digest` — derived independently from the
/// received bytes — equals it; and the receiver's ordering `context` equals its own
/// `proposal_context` (SHA-256 of its recv group's classical group id).
#[test]
fn test_proposal_hash_is_digest_of_the_staple_both_sides_agree_on() {
    let (alice_session, bob_session) = establish_sessions();

    let prep = assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"hello from bob".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    let proposal = assert_some!(result.proposal);

    // Sender's binding value == receiver's independently derived digest.
    assert_eq!(prep.proposal_hash, proposal.digest);
    assert_eq!(prep.proposal_hash.len(), 32);
    // Self-consistent across the receiver's two surfaces.
    assert_eq!(
        proposal.context,
        assert_some!(alice_session.proposal_context())
    );
}

#[test]
fn test_prepare_to_encrypt_did_commit_true_when_remote_proposal_staged() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"proposal msg".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"reply".to_vec()));

    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    let app = assert_some!(result.application_message);
    assert_eq!(app.app_message_data, b"reply");
    let commit = assert_some!(result.remote_commit);
    assert!(
        commit.new_sender.is_none(),
        "no rotation, new_sender should be None"
    );
}

#[test]
fn test_process_incoming_proposal_returns_none_until_queued() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"proposal".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    let proposal = assert_some!(result.proposal);

    let prep = assert_ok!(bob_session.prepare_to_encrypt(None));
    assert!(!prep.did_commit, "no commit before queue_proposal");

    let frame = assert_ok!(bob_session.encrypt(b"no-commit".to_vec()));
    assert_some!(assert_ok!(alice_session.process_incoming(frame.cipher_text)));

    assert_ok!(bob_session.queue_proposal(proposal.digest));
    let prep2 = assert_ok!(bob_session.prepare_to_encrypt(None));
    assert!(prep2.did_commit, "must commit after queue_proposal");
}

#[test]
fn test_session_id_differs_for_different_pairs() {
    let alice = make_client();
    let bob = make_client();
    let carol = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let carol_kp = make_combiner_kp(&carol);

    let alice_bob = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let alice_carol = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        carol_kp,
        None
    ));

    assert_ne!(
        alice_bob.active_session_id().bytes,
        alice_carol.active_session_id().bytes,
        "different peer pairs must produce different session IDs"
    );
}

#[test]
fn test_full_establishment_sequence_ml_kem_768() {
    let (alice_session, bob_session) = establish_sessions();
    assert!(alice_session.is_established());
    assert!(bob_session.is_established());

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"pq hello".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    let app = assert_some!(result.application_message);
    assert_eq!(app.app_message_data, b"pq hello");
    assert_eq!(
        app.sender_client_id,
        alice_session.my_principal_state().client_id()
    );
}

#[test]
fn test_principal_rotation_migrates_session_to_new_principal() {
    let (alice_session, bob_session) = establish_confirmed_sessions();

    let new_alice = make_client();
    let new_alice_id = new_alice.client_id();

    // The full round: propose → approve → commit → canonicalize (the helper
    // asserts Bob's their-state and Alice's Sync{new} along the way).
    rotate_round(&alice_session, &bob_session, new_alice_id.clone());

    // Alice's own send-group leaf catches up on her next approved commit; Bob
    // observes the leaf move as `new_sender`, and message attribution follows.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let upd = assert_ok!(bob_session.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(alice_session.process_incoming(upd.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(alice_session.prepare_to_encrypt(None)).did_commit);
    let enc = assert_ok!(alice_session.encrypt(b"rotated".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    let commit = assert_some!(result.remote_commit);
    assert_eq!(
        assert_some!(commit.new_sender),
        new_alice_id,
        "Bob must observe Alice's caught-up leaf"
    );
    let msg = assert_some!(result.application_message);
    assert_eq!(msg.app_message_data, b"rotated");
    assert_eq!(msg.sender_client_id, new_alice_id);
    assert_eq!(
        bob_session.their_principal_state().client_id(),
        new_alice_id
    );
}

#[test]
fn test_principal_rotation_resolves_pending_state_after_peer_reply() {
    let (alice_session, bob_session) = establish_confirmed_sessions();

    let new_alice = make_client();
    let new_alice_id = new_alice.client_id();

    assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
    assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone())));
    let enc = assert_ok!(alice_session.encrypt(b"rotation".to_vec()));
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    // Alice stays Pending until the peer COMMITS a candidate — a mere reply
    // (without committing) resolves nothing.
    assert!(matches!(
        alice_session.my_principal_state(),
        PrincipalState::Pending { .. }
    ));
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let reply = assert_ok!(bob_session.encrypt(b"ack".to_vec()));
    assert_some!(assert_ok!(alice_session.process_incoming(reply.cipher_text)));
    assert!(matches!(
        alice_session.my_principal_state(),
        PrincipalState::Pending { .. }
    ));

    // Bob approves and commits: the staple back canonicalizes Alice onto the
    // successor — Pending resolves to Sync { new }.
    assert_ok!(bob_session.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob_session.prepare_to_encrypt(None)).did_commit);
    let frame = assert_ok!(bob_session.encrypt(b"canonicalize".to_vec()));
    assert_some!(assert_ok!(alice_session.process_incoming(frame.cipher_text)));
    assert!(
        matches!(
            alice_session.my_principal_state(),
            PrincipalState::Sync { .. }
        ),
        "Pending must resolve to Sync after the peer commits the candidate"
    );
    assert_eq!(alice_session.my_principal_state().client_id(), new_alice_id);
}

#[test]
fn test_prepare_to_encrypt_rotation_without_stage_rotation_returns_error() {
    let (alice_session, _) = establish_sessions();
    let new_alice = make_client();
    assert_err!(
        alice_session.prepare_to_encrypt(Some(new_alice.client_id())),
        TwoMlsPqError::SessionNotReady
    );
}

/// A frame that crossed one of our commits references our send group's *previous*
/// epoch. The session's PSK ledger must still resolve it — live derivation cannot,
/// because mls-rs only exports the current epoch. Choreography: alice's folding-commit
/// frame binds the PSK of bob's send group at epoch E; bob rotates (E → E+1) before
/// processing alice's frame.
#[test]
fn test_psk_ledger_resolves_frame_that_crossed_a_commit() {
    let (alice_session, bob_session) = establish_confirmed_sessions();

    // Bob opens a routine round whose stapled Upd alice approves.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"proposal".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));

    // Alice's folding commit binds the PSK of bob's send group at its current epoch.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let crossing = assert_ok!(alice_session.encrypt(b"crossed".to_vec()));

    // Before processing alice's frame, bob rotates — his send group leaves the epoch
    // alice's commit references.
    let new_bob = make_client();
    assert_ok!(bob_session.stage_rotation(new_bob.client_id().bytes));
    assert_ok!(bob_session.prepare_to_encrypt(Some(new_bob.client_id())));

    // The crossed frame still processes: the ledger held the departed epoch's PSK.
    let result = assert_some!(assert_ok!(
        bob_session.process_incoming(crossing.cipher_text)
    ));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"crossed"
    );
}

/// One-shot PSKs (the recv-group export a folding commit binds) are removed from the
/// mls-rs secret stores once the commit is applied — the stores hold nothing the
/// session doesn't currently vouch for.
#[test]
fn test_consumed_one_shot_psk_is_forgotten_from_stores() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = alice_session.test_initial_welcome();
    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp
    ));
    let welcome_b = assert_some!(bob_session.pending_outbound());
    assert_ok!(alice_session.process_incoming(welcome_b));

    // Full-commit round: bob proposes, alice queues and commits. Alice's commit binds
    // the one-shot PSK exported from her recv group (bob's send group) at its current
    // epoch (1: established, no commits on it yet).
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"proposal".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));
    let recv_gid = assert_some!(alice_session.receive_group_id())
        .classical
        .bytes;
    assert_ok!(alice_session.prepare_to_encrypt(None));

    let mut id_bytes = 1u64.to_le_bytes().to_vec();
    id_bytes.extend_from_slice(&recv_gid);
    let one_shot = mls_rs::psk::ExternalPskId::new(id_bytes);
    assert!(
        alice
            .combiner()
            .classical()
            .secret_store()
            .get(&one_shot)
            .is_none(),
        "one-shot recv-group PSK must be dropped after the commit is applied"
    );
}

#[test]
fn test_full_commit_advances_send_group_epoch() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"proposal".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"after commit".to_vec()));

    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    let app = assert_some!(result.application_message);
    assert_eq!(app.app_message_data, b"after commit");
    assert!(
        app.epoch > 1,
        "send epoch must advance after the folding commit"
    );
}

#[test]
fn test_full_commit_enables_continued_messaging_after_psk_refresh() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"proposal".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"msg1".to_vec()));
    assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"msg2".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"msg2"
    );

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"reply".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"reply"
    );
}

#[test]
fn test_no_commit_round_delivers_app_message() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"no-commit".to_vec()));

    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"no-commit"
    );
}

#[test]
fn test_no_commit_round_followed_by_bob_send_still_decrypts() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"step1".to_vec()));
    assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"step2".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"step2"
    );
}

/// Remove the header seal from a frame `receiver` would open (test-side peek — the
/// wire is sealed, so inspecting a frame's plaintext structure goes through the
/// receiver's header window, exactly as `open_incoming` does for the host).
fn open_frame(receiver: &TwoMlsPqSession, blob: &[u8]) -> Vec<u8> {
    assert_some!(assert_ok!(receiver.open_incoming(blob.to_vec()))).frame
}

/// Extract the staple section of a message frame `receiver` opens.
fn frame_staple(receiver: &TwoMlsPqSession, blob: &[u8]) -> Vec<u8> {
    let (staple, _, _) = assert_ok!(super::decode_message_frame(&open_frame(receiver, blob)));
    staple
}

#[test]
fn test_welcome_staple_rides_until_first_commit_and_repeats_skip() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    // Alice initiates; her welcome_a is delivered separately so Bob can accept.
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = alice_s.test_initial_welcome();
    let bob_s = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp
    ));

    // Bob does NOT deliver welcome_b separately — every pre-commit frame staples it.
    assert!(
        !alice_s.is_established(),
        "alice has no recv group before welcome_b"
    );
    assert_ok!(bob_s.prepare_to_encrypt(None));
    let first = assert_ok!(bob_s.encrypt(b"hello".to_vec())).cipher_text;
    assert_eq!(
        open_frame(&alice_s, &first).first(),
        Some(&super::MESSAGE_FRAME_TAG)
    );
    let welcome_b = frame_staple(&alice_s, &first);
    assert_eq!(
        welcome_b.first(),
        Some(&super::APQ_TAG),
        "pre-commit staple must be the welcome"
    );

    // Alice joins (from the stapled welcome) and decrypts in one shot.
    let result = assert_some!(assert_ok!(alice_s.process_incoming(first)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"hello"
    );
    assert!(
        alice_s.is_established(),
        "alice should be established after the stapled welcome"
    );
    // The welcome is NOT consumed by stapling: the standalone copy stays available
    // for hosts that also deliver it separately…
    let standalone = assert_some!(bob_s.pending_outbound());
    // …and a late standalone delivery after the staple-join is an idempotent no-op.
    assert!(assert_ok!(alice_s.process_incoming(standalone)).is_none());

    // Until Bob commits, every frame re-staples the same welcome — and the repeat
    // skips idempotently on Alice's side.
    assert_ok!(bob_s.prepare_to_encrypt(None));
    let second = assert_ok!(bob_s.encrypt(b"world".to_vec())).cipher_text;
    assert_eq!(
        frame_staple(&alice_s, &second),
        welcome_b,
        "welcome staple repeats until the first commit"
    );
    let result2 = assert_some!(assert_ok!(alice_s.process_incoming(second)));
    assert_eq!(
        assert_some!(result2.application_message).app_message_data,
        b"world"
    );

    // Once Alice's stapled proposal is approved and Bob commits, the staple
    // switches from the welcome to the commit.
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let from_alice = assert_ok!(alice_s.encrypt(b"per-round".to_vec()));
    let res = assert_some!(assert_ok!(bob_s.process_incoming(from_alice.cipher_text)));
    assert_ok!(bob_s.queue_proposal(assert_some!(res.proposal).digest));
    let prep = assert_ok!(bob_s.prepare_to_encrypt(None));
    assert!(prep.did_commit);
    let committed = assert_ok!(bob_s.encrypt(b"committed".to_vec())).cipher_text;
    let staple = frame_staple(&alice_s, &committed);
    assert_eq!(
        staple.first(),
        Some(&0x00),
        "post-commit staple must be an MLS commit message"
    );
    let result3 = assert_some!(assert_ok!(alice_s.process_incoming(committed)));
    assert_some!(result3.remote_commit);
}

// ---- Header encryption ----

/// No plaintext MLS/TwoMLSPQ framing survives the seal: a sealed frame must not begin
/// with an MLS version byte (0x00) or any TwoMLSPQ tag, and must not contain the
/// recognizable APQWelcome framing of its own staple.
#[test]
fn test_sealed_frames_carry_no_plaintext_framing() {
    let (alice_session, bob_session) = establish_sessions();
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let sealed = assert_ok!(bob_session.encrypt(b"secret".to_vec())).cipher_text;

    // The plaintext frame is a welcome-stapled message frame; its bytes must not
    // appear verbatim in the sealed blob.
    let plaintext = open_frame(&alice_session, &sealed);
    assert_eq!(plaintext.first(), Some(&super::MESSAGE_FRAME_TAG));
    assert!(
        !sealed
            .windows(plaintext.len().min(16))
            .any(|w| w == &plaintext[..plaintext.len().min(16)]),
        "sealed blob leaks a prefix of the plaintext frame"
    );
    // First byte is a random nonce, never a tag or the MLS 0x00 version byte (with
    // overwhelming probability; a fixed seed would make this exact, but the point is
    // that nothing structural is guaranteed to be there).
    assert_ne!(sealed.first(), Some(&super::MESSAGE_FRAME_TAG));
}

/// A frame sealed under an epoch still in the receive window opens after the receiver
/// has advanced its own send group past it — the cross-commit crossing the window
/// exists for.
#[test]
fn test_sealed_frame_crossing_a_commit_still_opens() {
    let (alice_session, bob_session) = establish_sessions();

    // Alice seals a frame under Bob's send group (her recv group) at its current
    // epoch; hold it unopened.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let early = assert_ok!(alice_session.encrypt(b"early".to_vec())).cipher_text;

    // A full round now advances BOB's send group past that epoch: Alice proposes,
    // Bob approves and commits (Bob's send group is the one Bob's header window — and
    // Alice's seal of `early` — key off).
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let a2 = assert_ok!(alice_session.encrypt(b"a2".to_vec()));
    let r = assert_some!(assert_ok!(bob_session.process_incoming(a2.cipher_text)));
    assert_ok!(bob_session.queue_proposal(assert_some!(r.proposal).digest));
    assert!(assert_ok!(bob_session.prepare_to_encrypt(None)).did_commit);
    let _c = assert_ok!(bob_session.encrypt(b"c".to_vec()));

    // Bob's window now spans both his pre- and post-commit epochs, so the `early`
    // frame (sealed under the older epoch) still opens.
    let opened = assert_some!(assert_ok!(bob_session.open_incoming(early)));
    assert_eq!(opened.kind, super::OpenedFrameKind::Message);
}

/// A restored session still opens frames sealed under a recent epoch — the header
/// window rides the archive.
#[test]
fn test_restored_session_opens_in_flight_frame() {
    let (alice_session, bob_session) = establish_sessions();
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let sealed = assert_ok!(alice_session.encrypt(b"in flight".to_vec())).cipher_text;

    // Bob archives and restores BEFORE opening the frame.
    let archive = assert_ok!(bob_session.archive());
    let restored = assert_ok!(TwoMlsPqSession::from_archive(archive));
    let result = assert_some!(assert_ok!(restored.process_incoming(sealed)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"in flight"
    );
}

/// A garbage blob (no window key opens it) is a silent `None`, not an error.
#[test]
fn test_open_incoming_garbage_is_none() {
    let (alice_session, _bob) = establish_sessions();
    assert!(assert_ok!(alice_session.open_incoming(vec![0xAB; 64])).is_none());
    assert!(assert_ok!(alice_session.open_incoming(vec![])).is_none());
}

/// A sealed PQ side-band frame opens and classifies to the right `pq_*` kind, and the
/// The header key length tracks the configured header AEAD's key size — so a future
/// change of `HEADER_AEAD_SUITE` to a different-key-length cipher can't silently
/// desync key derivation from the seal. (Sanity for the crypto-agility wiring; today
/// both are 32 for ChaCha20-Poly1305.)
#[test]
fn test_header_key_len_matches_aead() {
    use mls_rs::CipherSuiteProvider;
    let aead_key_size = assert_ok!(crate::providers::header_aead_suite()).aead_key_size();
    assert_eq!(assert_ok!(super::header_key_len()), aead_key_size);

    // A derived header key is exactly that length.
    let (alice, _bob) = establish_sessions();
    assert_ok!(alice.prepare_to_encrypt(None));
    let sealed = assert_ok!(alice.encrypt(b"x".to_vec())).cipher_text;
    // Sealed length = nonce + plaintext + tag; nonce size also tracks the suite.
    let cs = assert_ok!(crate::providers::header_aead_suite());
    assert!(sealed.len() > cs.aead_nonce_size());
}

/// full A.3 round drives end-to-end through sealed frames.
#[test]
fn test_sealed_side_band_opens_and_classifies() {
    let (alice, bob) = establish_full();
    let ek = assert_ok!(alice.pq_ratchet_begin());
    // Sealed on the wire; opens on Bob's window as the ratchet EK frame.
    assert_eq!(
        assert_some!(assert_ok!(bob.open_incoming(ek.clone()))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RatchetEphemeralKey
        }
    );
    // And the round completes through the sealed frames (receivers auto-open).
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"a".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"a");
}

/// The point of the PQ family: a side-band frame is keyed by `pq_epoch`, so it
/// survives classical churn that evicts the message-path window — proving it does not
/// ride the (async) classical key. Contrast: a message frame from the same pre-churn
/// moment is evicted and no longer opens.
#[test]
fn test_side_band_survives_classical_churn() {
    let (alice, bob) = establish_full();

    // Capture two pre-churn frames Bob will try to open later: a message frame
    // (classical-keyed) and a side-band EK (PQ-keyed).
    assert_ok!(alice.prepare_to_encrypt(None));
    let early_message = assert_ok!(alice.encrypt(b"early".to_vec())).cipher_text;
    let ek = assert_ok!(alice.pq_ratchet_begin());

    // Churn ONLY the classical ratchet, well past mls-rs epoch retention: Alice
    // proposes, Bob commits Bob's send group each round, both stay in lockstep. No PQ
    // activity, so `pq_epoch` — and Bob's PQ window — is untouched.
    for _ in 0..10 {
        assert_ok!(alice.prepare_to_encrypt(None));
        let a = assert_ok!(alice.encrypt(b"churn".to_vec()));
        let r = assert_some!(assert_ok!(bob.process_incoming(a.cipher_text)));
        assert_ok!(bob.queue_proposal(assert_some!(r.proposal).digest));
        assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
        let bc = assert_ok!(bob.encrypt(b"c".to_vec()));
        assert_some!(assert_ok!(alice.process_incoming(bc.cipher_text)));
    }

    // The classical window has churned past the early message's epoch — it no longer
    // opens…
    assert!(
        assert_ok!(bob.open_incoming(early_message)).is_none(),
        "message-path window should have evicted the pre-churn epoch"
    );
    // …but the EK, keyed by the (unchanged) pq_epoch, still opens. If it rode the
    // classical key it would have been evicted alongside the message frame.
    assert_eq!(
        assert_some!(assert_ok!(bob.open_incoming(ek))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RatchetEphemeralKey
        }
    );
}

/// The pre-A.4 BOOTSTRAP_KP has no recv-PQ group yet, so it falls back to the
/// classical seal and opens via the classical window — still classifying as the
/// bootstrap side-band frame.
#[test]
fn test_bootstrap_kp_opens_via_classical_fallback() {
    let (alice, bob) = establish_sessions();
    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_eq!(
        assert_some!(assert_ok!(bob.open_incoming(kp.clone()))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::BootstrapKeyPackage
        }
    );
    // And the bootstrap completes through the sealed frames.
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_apply(bind));
    assert!(alice.is_fully_established() && bob.is_fully_established());
}

/// A restored session opens an in-flight side-band frame — the PQ window rides the
/// archive.
#[test]
fn test_restored_session_opens_in_flight_side_band() {
    let (alice, bob) = establish_full();
    let ek = assert_ok!(alice.pq_ratchet_begin());

    // Bob archives and restores before opening the EK.
    let restored = assert_ok!(TwoMlsPqSession::from_archive(assert_ok!(bob.archive())));
    assert_eq!(
        assert_some!(assert_ok!(restored.open_incoming(ek))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RatchetEphemeralKey
        }
    );
}

/// The initiator's initial welcome (invitation channel) is NOT sealed — it has no
/// symmetric key yet; the acceptor's return welcome (recv group live) IS sealed.
#[test]
fn test_initial_envelope_roundtrip_return_welcome_sealed() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // Alice's initial welcome is the §A.1 envelope over `[app_payload ∥ APQWelcome_A]`,
    // sealed to Bob's KP′ inside `initiate` — an opaque blob, NOT the plaintext welcome.
    let app = b"app-layer-welcome".to_vec();
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp,
        Some(app.clone())
    ));
    let envelope = assert_some!(alice_s.pending_outbound());
    assert_ne!(
        envelope.first(),
        Some(&super::APQ_TAG),
        "the initial frame is the opaque envelope, not the plaintext welcome"
    );
    assert!(
        !envelope
            .windows(4)
            .any(|w| w == &alice_s.test_initial_welcome()[..4]),
        "the plaintext welcome must not appear in the envelope"
    );

    // Bob opens the envelope: app_payload round-trips, welcome is the plaintext APQWelcome.
    let opened = assert_ok!(bob_inv.open_initial(envelope));
    assert_eq!(opened.app_payload, Some(app));
    assert_eq!(opened.welcome.first(), Some(&super::APQ_TAG));

    let bob_s = assert_ok!(bob_inv.receive(opened.welcome, alice_kp, b"tok".to_vec(), None, None));
    // Bob's return welcome is symmetric-sealed (Bob has the recv group) and opens on
    // Alice's window to the APQWelcome.
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ne!(welcome_b.first(), Some(&super::APQ_TAG));
    assert_eq!(
        open_frame(&alice_s, &welcome_b).first(),
        Some(&super::APQ_TAG)
    );
}

/// `app_payload: None` round-trips as `None` (empty section), and the welcome still
/// recovers.
#[test]
fn test_initial_envelope_no_app_payload() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_initial(assert_some!(alice_s.pending_outbound())));
    assert_eq!(opened.app_payload, None);
    assert_ok!(bob_inv.receive(opened.welcome, alice_kp, b"tok".to_vec(), None, None));
}

/// Establishment-time principal selection: `receive(new_client_id: Some)` creates the
/// acceptor's send group under a freshly-minted dedicated principal — its ClientId is
/// the creator leaf the initiator reads out of the return welcome. No rotation commit
/// is involved, so the `peer_confirmed` gate never fires; the initiator observes the
/// dedicated principal on the very frame whose welcome staple performed the join.
#[test]
fn test_receive_under_dedicated_principal() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_initial(assert_some!(alice_s.pending_outbound())));

    let dedicated = crate::test_utils::test_client_id();
    let bob_s = assert_ok!(bob_inv.receive(
        opened.welcome,
        alice_kp,
        b"tok".to_vec(),
        Some(dedicated.clone()),
        None
    ));

    // The acceptor's principal is the dedicated agent from birth — no Pending state,
    // nothing staged. The session id still derives from the FOUNDING pair (the
    // invitation identity Alice initiated toward), so both sides agree on it.
    assert_eq!(bob_s.my_principal_state().client_id().bytes, dedicated);
    assert_eq!(
        alice_s.active_session_id().bytes,
        bob_s.active_session_id().bytes
    );
    // Pre-join, Alice still knows the peer as the invitation identity.
    assert_eq!(
        alice_s.their_principal_state().client_id().bytes,
        bob_inv.client_id().bytes
    );

    // Bob's first frame staples APQWelcome_B, whose creator leaf carries the
    // dedicated id: the joining frame surfaces the handoff like a rotation
    // (remote_commit.new_sender) and message attribution carries it from the start.
    assert_ok!(bob_s.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_s.encrypt(b"hello".to_vec()));
    let res = assert_some!(assert_ok!(alice_s.process_incoming(enc.cipher_text)));
    let commit = assert_some!(res.remote_commit);
    assert_eq!(assert_some!(commit.new_sender).bytes, dedicated);
    let msg = assert_some!(res.application_message);
    assert_eq!(msg.sender_client_id.bytes, dedicated);
    assert_eq!(msg.app_message_data, b"hello".to_vec());
    assert_eq!(alice_s.their_principal_state().client_id().bytes, dedicated);

    // A repeat of the same welcome staple is an idempotent skip — the handoff is
    // surfaced exactly once.
    assert_ok!(bob_s.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_s.encrypt(b"again".to_vec()));
    let res = assert_some!(assert_ok!(alice_s.process_incoming(enc.cipher_text)));
    assert!(res.remote_commit.is_none());

    // The reverse direction flows too.
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_s.encrypt(b"back".to_vec()));
    let res = assert_some!(assert_ok!(bob_s.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"back".to_vec()
    );
}

/// Empty principal ids are reserved — the rotation-commit discriminator is "empty
/// authenticated_data = ratchet commit", so an empty id could never be announced —
/// and both entry points reject them up front. A rejected `receive` consumes
/// nothing: the same invitation immediately accepts a valid retry.
#[test]
fn test_empty_principal_id_rejected() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_initial(assert_some!(alice_s.pending_outbound())));
    assert!(matches!(
        bob_inv.receive(
            opened.welcome.clone(),
            alice_kp.clone(),
            b"tok".to_vec(),
            Some(Vec::new()),
            None
        ),
        Err(TwoMlsPqError::InvalidClientId)
    ));
    assert_ok!(bob_inv.receive(opened.welcome, alice_kp, b"tok".to_vec(), None, None));

    let (alice_c, _bob_c) = establish_confirmed_sessions();
    assert!(matches!(
        alice_c.stage_rotation(Vec::new()),
        Err(TwoMlsPqError::InvalidClientId)
    ));
}

/// A standalone welcome delivery that adopts a dedicated peer principal surfaces the
/// handoff exactly like the stapled delivery — which copy of the welcome arrives
/// first must not decide whether the app sees the signal. A re-delivery is the
/// idempotent `None`.
#[test]
fn test_standalone_welcome_surfaces_dedicated_principal() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_initial(assert_some!(alice_s.pending_outbound())));
    let dedicated = crate::test_utils::test_client_id();
    let bob_s = assert_ok!(bob_inv.receive(
        opened.welcome,
        alice_kp,
        b"tok".to_vec(),
        Some(dedicated.clone()),
        None
    ));

    let welcome_b = assert_some!(bob_s.pending_outbound());
    let res = assert_some!(assert_ok!(alice_s.process_incoming(welcome_b.clone())));
    assert!(res.application_message.is_none());
    assert!(res.proposal.is_none());
    let commit = assert_some!(res.remote_commit);
    assert_eq!(assert_some!(commit.new_sender).bytes, dedicated);
    assert_eq!(alice_s.their_principal_state().client_id().bytes, dedicated);
    // Re-delivery of the same (sealed) welcome: idempotent, silent.
    assert!(assert_ok!(alice_s.process_incoming(welcome_b)).is_none());
}

/// The dedicated-principal session drives the full lifecycle: cross-party PSK
/// refreshes (folding commits in both directions — the acceptor's recv group lives on
/// the invitation-derived client's stores while its send group lives on the
/// dedicated client's, so this proves `register_psk` reaches both), the A.4
/// bootstrap (the PQ half is created under the dedicated principal too — no
/// credential catch-up rekey needed), an A.3 ratchet round, and archive/restore.
#[test]
fn test_dedicated_principal_full_lifecycle() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_initial(assert_some!(alice_s.pending_outbound())));
    let dedicated = crate::test_utils::test_client_id();
    let bob_s = assert_ok!(bob_inv.receive(
        opened.welcome,
        alice_kp,
        b"tok".to_vec(),
        Some(dedicated.clone()),
        None
    ));

    // Confirm both directions (each side processes a peer frame).
    assert_ok!(bob_s.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_s.encrypt(b"confirm-b".to_vec()));
    let res = assert_some!(assert_ok!(alice_s.process_incoming(enc.cipher_text)));
    let bob_upd = assert_some!(res.proposal);
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_s.encrypt(b"confirm-a".to_vec()));
    let res = assert_some!(assert_ok!(bob_s.process_incoming(enc.cipher_text)));
    assert_some!(res.proposal);

    // Full commit in Alice's direction: she commits Bob's Upd into her send group
    // with the cross-party PSK exported from her recv group (Group_B — created by
    // the DEDICATED client). Bob applies the commit on his recv mirror, resolving
    // that PSK through the stores of the invitation-derived client that joined it.
    assert_ok!(alice_s.queue_proposal(bob_upd.digest));
    let prep = assert_ok!(alice_s.prepare_to_encrypt(None));
    assert!(prep.did_commit);
    let enc = assert_ok!(alice_s.encrypt(b"full-a".to_vec()));
    let res = assert_some!(assert_ok!(bob_s.process_incoming(enc.cipher_text)));
    // Each frame stages a fresh Upd(sender); Bob queues the LATEST offer (the
    // single offered slot supersedes the one from `confirm-a`).
    let alice_upd = assert_some!(res.proposal);
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"full-a".to_vec()
    );

    // And in Bob's direction: his send group (dedicated client) commits Alice's Upd
    // with the PSK exported from his recv group (invitation-joined).
    assert_ok!(bob_s.queue_proposal(alice_upd.digest));
    let prep = assert_ok!(bob_s.prepare_to_encrypt(None));
    assert!(prep.did_commit);
    let enc = assert_ok!(bob_s.encrypt(b"full-b".to_vec()));
    let res = assert_some!(assert_ok!(alice_s.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"full-b".to_vec()
    );

    // A.4 bootstrap: Bob's deferred send-PQ half is created by the dedicated client.
    let kp = assert_ok!(alice_s.pq_bootstrap_begin(None));
    assert_ok!(bob_s.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob_s.pq_take_pending_outbound());
    assert_ok!(alice_s.pq_bootstrap_apply(bind));
    assert!(alice_s.is_fully_established());
    assert!(bob_s.is_fully_established());

    // A.3 ratchet round end-to-end.
    let ek = assert_ok!(alice_s.pq_ratchet_begin());
    assert_ok!(bob_s.pq_ratchet_respond(ek));
    let ct = assert_some!(bob_s.pq_take_pending_outbound());
    assert_ok!(alice_s.pq_ratchet_bind(ct, b"pq-app".to_vec()));
    let bind = assert_some!(alice_s.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob_s.pq_ratchet_apply(bind)), b"pq-app");

    // Archive/restore of the dedicated-principal acceptor: the archive carries the
    // dedicated signing identity; the restored session keeps the principal and the
    // conversation.
    let archive = assert_ok!(bob_s.archive());
    let restored = assert_ok!(TwoMlsPqSession::from_archive(archive));
    assert_eq!(restored.my_principal_state().client_id().bytes, dedicated);
    assert_ok!(restored.prepare_to_encrypt(None));
    let enc = assert_ok!(restored.encrypt(b"post-restore".to_vec()));
    let res = assert_some!(assert_ok!(alice_s.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"post-restore".to_vec()
    );

    // Inbound after restore: Alice folds the restored session's Upd into a full
    // commit (referencing the cross-party PSK ledger) — the restored receive
    // mirror, now running under the single rebuilt dedicated client, must resolve
    // the PSK and apply it.
    let restored_upd = assert_some!(res.proposal);
    assert_ok!(alice_s.queue_proposal(restored_upd.digest));
    let prep = assert_ok!(alice_s.prepare_to_encrypt(None));
    assert!(prep.did_commit);
    let enc = assert_ok!(alice_s.encrypt(b"inbound-post-restore".to_vec()));
    let res = assert_some!(assert_ok!(restored.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"inbound-post-restore".to_vec()
    );
}

/// A re-sent envelope has a fresh HPKE ephemeral (different outer bytes) but the same
/// plaintext — so a spawn token computed over the opened frame is replay-stable, and a
/// last-resort invitation opens both.
#[test]
fn test_initial_envelope_resend_same_plaintext() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // Two independent initiations to the same KP seal different outer bytes…
    let a1 = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp.clone(),
        Some(b"p".to_vec())
    ));
    let e1 = assert_some!(a1.pending_outbound());
    let a2 = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp,
        Some(b"p".to_vec())
    ));
    let e2 = assert_some!(a2.pending_outbound());
    assert_ne!(
        e1, e2,
        "fresh HPKE ephemeral per seal → different outer bytes"
    );
    // …but each opens to an app_payload the host can key a stable token on.
    assert_eq!(
        assert_ok!(bob_inv.open_initial(e1)).app_payload,
        Some(b"p".to_vec())
    );
    assert_eq!(
        assert_ok!(bob_inv.open_initial(e2)).app_payload,
        Some(b"p".to_vec())
    );
}

/// A spent single-use invitation cannot `open_initial` (its KP′ material is gone), so
/// replays after consumption are dropped as undecryptable.
#[test]
fn test_spent_invitation_cannot_open_initial() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let carol = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::new(assert_ok!(
        bob.generate_invitation(false)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // Alice consumes the single-use invitation.
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp.clone(),
        None
    ));
    let opened = assert_ok!(bob_inv.open_initial(assert_some!(alice_s.pending_outbound())));
    assert_ok!(bob_inv.receive(opened.welcome, alice_kp, b"tok".to_vec(), None, None));

    // Carol's later envelope can no longer be opened — the KP′ material is spent.
    let carol_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
    assert_err!(
        bob_inv.open_initial(assert_some!(carol_s.pending_outbound())),
        TwoMlsPqError::InvitationSpent
    );
}

/// The initiator's message-frame staple stays the plaintext `APQWelcome_A` (first byte
/// 0x01) even though `pending_outbound` is the opaque envelope — the two are
/// deliberately split in `initiate`.
#[test]
fn test_initiator_staple_is_plaintext_welcome() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    assert_eq!(
        alice_s.test_initial_welcome().first(),
        Some(&super::APQ_TAG)
    );
    assert_ne!(
        assert_some!(alice_s.pending_outbound()).first(),
        Some(&super::APQ_TAG)
    );
}

#[test]
fn test_dropped_commit_frame_healed_by_next_staple() {
    // The headline self-healing property: the frame that carries a commit is LOST,
    // and the next frame's re-stapled commit brings the peer up to date anyway.
    let (alice_session, bob_session) = establish_sessions();

    // Alice proposes; Bob approves; Alice… no — BOB commits (he owns his send group).
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"propose".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_ok!(bob_session.queue_proposal(assert_some!(result.proposal).digest));

    let prep = assert_ok!(bob_session.prepare_to_encrypt(None));
    assert!(prep.did_commit);
    let lost = assert_ok!(bob_session.encrypt(b"lost frame".to_vec()));
    drop(lost); // never delivered

    // Bob's next round: no new commit (nothing queued), but the staple re-sends the
    // last one; Alice applies it and decrypts this frame at the new epoch.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let healing = assert_ok!(bob_session.encrypt(b"healing frame".to_vec()));
    let result = assert_some!(assert_ok!(
        alice_session.process_incoming(healing.cipher_text)
    ));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"healing frame"
    );
    // The re-stapled commit applied on this frame.
    assert_some!(result.remote_commit);

    // And the direction keeps flowing both ways afterwards.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"after".to_vec()));
    assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
}

#[test]
fn test_epoch_ahead_staple_surfaces_desync() {
    let (alice_session, bob_session) = establish_confirmed_sessions();

    // Two approved commits on Alice's send group with every frame in between
    // lost: the staple that reaches Bob bridges only the LATEST commit, so his
    // recv group cannot catch up from any frame — the desync must surface
    // distinguishably, before the app ciphertext is touched.
    // Round 1: an approved commit whose frame is lost (epoch 1 → 2)…
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let upd = assert_ok!(bob_session.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(alice_session.process_incoming(upd.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(alice_session.prepare_to_encrypt(None)).did_commit);
    drop(assert_ok!(alice_session.encrypt(b"lost".to_vec()))); // never delivered

    // …round 2: an A.3 bind whose classical commit (epoch 2 → 3) also never
    // arrives — the EK/CT legs are epoch-independent, so Bob participates
    // without ever seeing a classical frame.
    let ek = assert_ok!(alice_session.pq_ratchet_begin());
    assert_ok!(bob_session.pq_ratchet_respond(ek));
    let ct = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_ratchet_bind(ct, b"bind-lost".to_vec()));
    drop(assert_some!(alice_session.pq_take_pending_outbound())); // bind lost

    // Alice's next frame staples only the LATEST commit (epoch 3): two ahead
    // of Bob's recv group.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let ahead = assert_ok!(alice_session.encrypt(b"ahead".to_vec()));

    assert_err!(
        bob_session.process_incoming(ahead.cipher_text),
        TwoMlsPqError::EpochDesync
    );
}

#[test]
fn test_rotation_proposal_rides_first_frame() {
    // Rotation is proposal-driven now: it CANNOT displace the welcome staple (the
    // staple slot and the proposal slot are distinct), so a freshly established
    // session may propose its successor on its very first frame — the structural
    // impossibility that used to require the peer-confirmed gate.
    let (alice_session, bob_session) = establish_sessions();
    let new_id = make_client().client_id();
    assert_ok!(alice_session.stage_rotation(new_id.bytes.clone()));
    assert_ok!(alice_session.prepare_to_encrypt(Some(new_id.clone())));
    let enc = assert_ok!(alice_session.encrypt(b"first".to_vec()));
    // The frame still carries the welcome staple AND the rotation proposal.
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(assert_some!(got.proposal).proposing, new_id);
}

#[test]
fn test_rotation_folds_queued_proposal() {
    let (alice_session, bob_session) = establish_confirmed_sessions();

    // Alice's routine frame staples an Upd; Bob approves it…
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"propose".to_vec()));
    let res = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_ok!(bob_session.queue_proposal(assert_some!(res.proposal).digest));

    // …then Bob's rotation-proposing round ALSO commits the queued proposal:
    // mls-rs auto-includes the cached Upd, the PSK refresh rides along, and the
    // consumption is reported — while the frame's own proposal slot carries
    // Bob's rotation candidate.
    let new_bob = make_client().client_id();
    assert_ok!(bob_session.stage_rotation(new_bob.bytes.clone()));
    let prep = assert_ok!(bob_session.prepare_to_encrypt(Some(new_bob.clone())));
    assert!(prep.did_commit);
    assert_eq!(
        assert_some!(prep.committed_remote_client_id).bytes,
        enc.sender.bytes
    );
    let enc2 = assert_ok!(bob_session.encrypt(b"rotated".to_vec()));

    // Alice applies the commit staple and receives Bob's candidate proposal —
    // the rotation round stages a proposal like any round (no skipped beat).
    let res = assert_some!(assert_ok!(alice_session.process_incoming(enc2.cipher_text)));
    assert_some!(res.remote_commit);
    assert_eq!(assert_some!(res.proposal).proposing, new_bob);

    // The queued digest was cleared by the fold: the next routine round has
    // nothing to commit — no spurious empty PSK-commit.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc3 = assert_ok!(bob_session.encrypt(b"routine".to_vec()));
    let res3 = assert_some!(assert_ok!(alice_session.process_incoming(enc3.cipher_text)));
    assert!(res3.remote_commit.is_none(), "no spurious follow-up commit");
}

#[test]
fn test_different_welcome_on_live_session_rejected() {
    let (alice_session, _bob_session) = establish_sessions();

    // A welcome that is NOT the one Alice's recv group was joined from — from an
    // unrelated establishment — is a mis-route, not a benign re-delivery.
    let carol = make_client();
    let dave = make_client();
    let dave_kp = make_combiner_kp(&dave);
    let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), dave_kp, None));
    let foreign_welcome = carol_session.test_initial_welcome();

    assert_err!(
        alice_session.process_incoming(foreign_welcome),
        TwoMlsPqError::UnexpectedWelcome
    );
}

#[test]
fn test_archive_rejects_malformed_staple() {
    use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};

    let (alice_session, _bob_session) = establish_sessions();
    let archive = assert_ok!(alice_session.archive());

    // Strip the [version][suite×4] header, corrupt the staple, re-frame. The
    // staple's first byte must be a welcome (0x01) or an MLSMessage (0x00) — the
    // same check that structurally rejects pre-rework archive layouts.
    let mut rest = &archive.bytes[5..];
    let mut wire = assert_ok!(super::archive_wire::SessionArchive::mls_decode(&mut rest));
    wire.current_staple = vec![0xFF];
    let mut bytes = archive.bytes[..5].to_vec();
    assert_ok!(wire.mls_encode(&mut bytes));
    assert_err!(
        TwoMlsPqSession::from_archive(crate::Archive { bytes }),
        TwoMlsPqError::ArchiveInvalid
    );
}

#[test]
fn test_psk_export_is_domain_separated_and_consumed_once() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let bob_id = bob.client_id().bytes;
    alice
        .combiner()
        .auth_view()
        .with(|core| core.theirs.commit(bob_id));

    let (mut group, _) = assert_ok!(apq::create_group_with_member(
        alice.classical(),
        &bob_kp.classical,
        &[],
        apq::GroupCreation::bare(assert_ok!(alice.combiner().random_group_id())),
    ));

    // The two domains are distinct exporter-tree leaves → distinct store keys/values.
    let apq = assert_ok!(apq::export_psk(&mut group, apq::PskDomain::Apq));
    let cross = assert_ok!(apq::export_psk(&mut group, apq::PskDomain::CrossParty));
    assert_ne!(apq.storage_id(), cross.storage_id());
    assert_ne!(apq.psk().raw_value(), cross.psk().raw_value());

    // The exporter tree consumes each component's leaf: re-export at this epoch fails.
    assert!(apq::export_psk(&mut group, apq::PskDomain::Apq).is_err());
}

#[test]
fn test_apq_psk_is_exported_from_pq_group_not_classical() {
    // draft-ietf-mls-combiner §4/§6.2: the APQ-PSK is exported from the PQ session and
    // imported into the traditional session (pq -> classical). `export_and_register_psk`
    // on a PQ group installs the value under its application-PSK store key in the
    // classical (and PQ) stores — so a classical-group commit can resolve it. Under the
    // reverted (classical -> pq) direction the PQ group is the importer and nothing is
    // registered classically, so this lookup would fail.
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    alice
        .combiner()
        .auth_view()
        .with(|core| core.theirs.commit(bob.client_id().bytes));

    let (mut pq_group, _) = assert_ok!(apq::create_group_with_member(
        alice.pq(),
        &bob_kp.pq,
        &[],
        apq::GroupCreation::bare(assert_ok!(alice.combiner().random_group_id())),
    ));
    let apq_psk = assert_ok!(apq::export_and_register_psk(
        &mut pq_group,
        alice.combiner(),
        apq::PskDomain::Apq
    ));
    assert!(
        alice
            .classical()
            .secret_store()
            .get(apq_psk.storage_id())
            .is_some(),
        "APQ-PSK must be exported from the PQ group and importable classically (§6.2)"
    );
}

#[test]
fn test_prepare_to_encrypt_before_established_returns_error() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert_err!(
        session.prepare_to_encrypt(None),
        TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_prepare_to_encrypt_rotation_client_id_mismatch_returns_error() {
    let (alice_session, _) = establish_sessions();
    let new_alice = make_client();
    let other = make_client();
    assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
    assert_err!(
        alice_session.prepare_to_encrypt(Some(other.client_id())),
        TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_encrypt_without_prepare_returns_session_not_ready() {
    let (alice_session, _) = establish_sessions();
    assert_err!(
        alice_session.encrypt(b"no prepare".to_vec()),
        TwoMlsPqError::SessionNotReady
    );
}

#[test]
fn test_receive_group_id_none_before_recv_group() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(session.receive_group_id().is_none());
}

#[test]
fn test_receive_group_id_some_after_established() {
    let (alice_session, bob_session) = establish_sessions();
    assert!(alice_session.receive_group_id().is_some());
    assert!(bob_session.receive_group_id().is_some());
}

#[test]
fn test_has_receive_group_false_for_initiator_before_welcome() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(!session.has_receive_group());
}

#[test]
fn test_has_receive_group_true_for_acceptor_immediately() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = alice_session.test_initial_welcome();
    let bob_session = assert_ok!(TwoMlsPqSession::accept(bob, welcome, alice_kp));
    assert!(bob_session.has_receive_group());
}

#[test]
fn test_proposal_context_none_before_recv_group() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(session.proposal_context().is_none());
}

#[test]
fn test_proposal_context_some_after_established() {
    let (alice_session, bob_session) = establish_sessions();
    let alice_ctx = assert_some!(alice_session.proposal_context());
    let bob_ctx = assert_some!(bob_session.proposal_context());
    assert!(!alice_ctx.is_empty());
    assert!(!bob_ctx.is_empty());
}

#[test]
fn test_my_principal_state_initial_is_sync() {
    let alice = make_client();
    let alice_id = alice.client_id();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    assert!(matches!(
        session.my_principal_state(),
        PrincipalState::Sync { .. }
    ));
    assert_eq!(session.my_principal_state().client_id(), alice_id);
}

#[test]
fn test_my_principal_state_becomes_pending_after_rotation_commit() {
    let (alice_session, _) = establish_confirmed_sessions();
    let new_alice = make_client();
    let new_id = new_alice.client_id();
    assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
    assert_ok!(alice_session.prepare_to_encrypt(Some(new_id.clone())));
    assert!(matches!(
        alice_session.my_principal_state(),
        PrincipalState::Pending { .. }
    ));
}

#[test]
fn test_no_commit_round_surfaces_proposal() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"with nonce".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    let proposal = assert_some!(result.proposal);
    assert!(!proposal.digest.is_empty());
    assert_eq!(
        proposal.sender,
        alice_session.my_principal_state().client_id()
    );
}

#[test]
fn test_multiple_sequential_no_commit_rounds_stay_in_sync() {
    let (alice_session, bob_session) = establish_sessions();

    for i in 0..3u8 {
        let msg = vec![i];
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(msg.clone()));
        let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
        assert_eq!(
            assert_some!(result.application_message).app_message_data,
            msg
        );
    }
}

#[test]
fn test_routine_round_is_classical_only() {
    let (alice_session, bob_session) = establish_sessions();

    // (send.pq epoch, recv.pq epoch, recv.classical epoch) for a session.
    let epochs = |s: &Arc<TwoMlsPqSession>| {
        let inner = s.inner.lock().unwrap_or_else(|e| e.into_inner());
        (
            inner
                .send_group
                .as_ref()
                .and_then(|g| g.pq.as_ref().map(|p| p.current_epoch())),
            inner
                .recv_group
                .as_ref()
                .and_then(|g| g.pq.as_ref().map(|p| p.current_epoch())),
            inner
                .recv_group
                .as_ref()
                .map(|g| g.classical.current_epoch()),
        )
    };

    let (pq_send_before, pq_recv_before, cl_recv_before) = epochs(&alice_session);

    // Routine round: no queued proposal → traditional-only commit, no PQ exchange.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"hello".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"hello"
    );

    let (pq_send_after, pq_recv_after, cl_recv_after) = epochs(&alice_session);
    assert_eq!(
        pq_send_after, pq_send_before,
        "PQ send group must not ratchet on a routine round"
    );
    assert_eq!(
        pq_recv_after, pq_recv_before,
        "PQ recv group must not ratchet on a routine round"
    );
    assert_eq!(
        cl_recv_after, cl_recv_before,
        "a routine round is proposal-only (A.2) — no classical commit until the peer \
         queues and consumes our Upd"
    );
}

#[test]
fn test_full_round_is_classical_only_and_propagates() {
    let (alice_session, bob_session) = establish_sessions();

    // (send.pq, recv.pq, send.classical, recv.classical) epochs for a session.
    let epochs = |s: &Arc<TwoMlsPqSession>| {
        let inner = s.inner.lock().unwrap_or_else(|e| e.into_inner());
        (
            inner
                .send_group
                .as_ref()
                .and_then(|g| g.pq.as_ref().map(|p| p.current_epoch())),
            inner
                .recv_group
                .as_ref()
                .and_then(|g| g.pq.as_ref().map(|p| p.current_epoch())),
            inner
                .send_group
                .as_ref()
                .map(|g| g.classical.current_epoch()),
            inner
                .recv_group
                .as_ref()
                .map(|g| g.classical.current_epoch()),
        )
    };

    // Bob sends a routine message so Alice receives an app-layer proposal to queue.
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"propose".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));

    let (pq_send_0, pq_recv_0, cl_send_0, cl_recv_0) = epochs(&alice_session);

    // Full round (queued proposal present): traditional-only cross-party PSK refresh.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"full".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"full"
    );

    let (pq_send_1, pq_recv_1, cl_send_1, cl_recv_1) = epochs(&alice_session);
    // PQ groups untouched — no per-round ML-KEM (PQ is established once, at setup).
    assert_eq!(
        pq_send_1, pq_send_0,
        "PQ send group must not ratchet on a full round"
    );
    assert_eq!(
        pq_recv_1, pq_recv_0,
        "PQ recv group must not ratchet on a full round"
    );
    // Both classical message groups advance — cross-party PCS reaches both directions.
    assert_eq!(
        cl_send_1.map(|e| e.saturating_sub(1)),
        cl_send_0,
        "full round must advance the classical send group"
    );
    assert_eq!(
        cl_recv_1, cl_recv_0,
        "the recv group is the peer's to commit (A.2) — cross-party PCS travels via \
         the PSK inside our send-group commit, not a recv commit"
    );
}

#[test]
fn test_routine_frame_is_classical_sized() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = alice_s.test_initial_welcome();
    let bob_s = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a.clone(),
        alice_kp
    ));
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(welcome_b.clone()));

    // Pre-first-commit, the initiator's frames re-staple her full two-half APQ
    // welcome — welcome-sized by design (the one unavoidably large staple; the
    // peer skips the repeats). The steady state begins at her first commit.
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let pre_commit = assert_ok!(alice_s.encrypt(b"warm-up".to_vec()));
    assert!(
        pre_commit.cipher_text.len() > welcome_a.len(),
        "pre-commit initiator frames carry the welcome staple"
    );
    assert_some!(assert_ok!(bob_s.process_incoming(pre_commit.cipher_text)));

    // One round so Alice commits (consuming Bob's approved Upd): her staple
    // switches from the welcome to her classical commit.
    assert_ok!(bob_s.prepare_to_encrypt(None));
    let from_bob = assert_ok!(bob_s.encrypt(b"bob-round".to_vec()));
    let res = assert_some!(assert_ok!(alice_s.process_incoming(from_bob.cipher_text)));
    assert_ok!(alice_s.queue_proposal(assert_some!(res.proposal).digest));
    let prep = assert_ok!(alice_s.prepare_to_encrypt(None));
    assert!(prep.did_commit);
    let committing = assert_ok!(alice_s.encrypt(b"commit round".to_vec()));
    assert_some!(assert_ok!(bob_s.process_incoming(committing.cipher_text)));

    // Routine round in the steady state: the staple is the latest classical commit.
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let routine = assert_ok!(alice_s.encrypt(b"the quick brown fox".to_vec())).cipher_text;

    eprintln!(
        "[sizes] welcome_a={} B  welcome_b={} B  routine(0x03)={} B",
        welcome_a.len(),
        welcome_b.len(),
        routine.len()
    );

    // The steady-state frame must be classical-sized even though it always carries
    // a commit staple: a classical stapled commit has no PQ keys (PQ work rides
    // partial PQ commits on the side-band; big ML-KEM updatePaths are isolated to
    // A.5 on the PQ groups alone).
    assert!(
        routine.len() < 2000,
        "routine frame should be classical-sized, got {} B",
        routine.len()
    );
}

#[test]
fn test_folding_commit_after_multiple_no_commit_rounds() {
    let (alice_session, bob_session) = establish_sessions();

    for _ in 0..2 {
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"no-commit".to_vec()));
        assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    }

    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"propose".to_vec()));
    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"full".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"full"
    );
    assert_some!(result.remote_commit);
}

#[test]
fn test_bob_to_alice_full_commit_cycle() {
    let (alice_session, bob_session) = establish_sessions();

    assert_ok!(alice_session.prepare_to_encrypt(None));
    let enc = assert_ok!(alice_session.encrypt(b"propose".to_vec()));
    let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

    assert_ok!(bob_session.queue_proposal(assert_some!(result.proposal).digest));
    assert_ok!(bob_session.prepare_to_encrypt(None));
    let enc = assert_ok!(bob_session.encrypt(b"full".to_vec()));

    let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    assert_eq!(
        assert_some!(result.application_message).app_message_data,
        b"full"
    );
    assert_some!(result.remote_commit);
}

#[test]
fn test_decode_message_frame_truncated_returns_error() {
    assert_err!(
        super::decode_message_frame(&[super::MESSAGE_FRAME_TAG]),
        TwoMlsPqError::Mls
    );
}

#[test]
fn test_decode_message_frame_trailing_bytes_returns_error() {
    let mut good = super::encode_message_frame(b"staple", b"p".to_vec(), b"app".to_vec());
    good.push(0xFF);
    assert_err!(super::decode_message_frame(&good), TwoMlsPqError::Mls);
}

#[test]
fn test_encode_decode_message_frame_roundtrip() {
    let staple = b"send-commit".to_vec();
    let proposal = b"upd-proposal".to_vec();
    let app = b"app-data".to_vec();
    let encoded = super::encode_message_frame(&staple, proposal.clone(), app.clone());
    let (dec_s, dec_p, dec_app) = assert_ok!(super::decode_message_frame(&encoded));
    assert_eq!(dec_s, staple);
    assert_eq!(dec_p, proposal);
    assert_eq!(dec_app, app);
}

#[test]
fn test_decode_message_frame_rejects_empty_sections() {
    // No section is optional: an empty slot is a retired shape (e.g. the old
    // commitless ratchet frame) or a malformed frame. Built by hand — the encoder
    // debug-asserts against empty sections, this exercises the decoder's guard.
    for (s, p, a) in [
        (&b""[..], &b"p"[..], &b"a"[..]),
        (&b"s"[..], &b""[..], &b"a"[..]),
        (&b"s"[..], &b"p"[..], &b""[..]),
    ] {
        let mut encoded = vec![super::MESSAGE_FRAME_TAG];
        super::push_section(&mut encoded, s);
        super::push_section(&mut encoded, p);
        super::push_section(&mut encoded, a);
        assert_err!(super::decode_message_frame(&encoded), TwoMlsPqError::Mls);
    }
}

#[test]
fn test_process_incoming_malformed_message_frame_returns_error() {
    let (alice_session, _) = establish_sessions();
    // Sections parse, but the staple is neither a welcome (0x01) nor an MLS
    // message (0x00) that decodes.
    let fake = super::encode_message_frame(b"junk", b"junk".to_vec(), b"junk".to_vec());
    assert_err!(
        alice_session.process_incoming(fake),
        TwoMlsPqError::DecryptionFailed
    );
}

#[test]
fn test_process_incoming_bare_mls_and_unknown_tags_rejected() {
    let (alice_session, _) = establish_sessions();
    // Bare MLS ciphertext no longer occurs on the send path; unrecognized
    // plaintext fails loudly instead of being fed to the MLS parser.
    assert_err!(
        alice_session.process_incoming(vec![0x00, 0x01, 0x02]),
        TwoMlsPqError::DecryptionFailed
    );
    // The retired pre-rework tags (BUNDLED 0x03 is now the message frame, but the
    // old STAPLED_WELCOME value 0x09 is now PQ BIND and 0x13 is unassigned).
    assert_err!(
        alice_session.process_incoming(vec![0x13, 0x00]),
        TwoMlsPqError::DecryptionFailed
    );
}

#[test]
fn test_suite_mismatch_key_package_rejected_before_group_built() {
    use crate::key_packages::CombinerKeyPackage;
    use crate::MlsCipherSuite;

    let alice = make_client();
    let peer = make_client();

    // Both halves classical (peer offers no PQ protection) → the specific PqNotAvailable.
    let both_classical = CombinerKeyPackage {
        classical: assert_ok!(peer.generate_key_package(MlsCipherSuite::x25519_chacha())),
        pq: assert_ok!(peer.generate_key_package(MlsCipherSuite::x25519_chacha())),
    };
    assert_err!(
        TwoMlsPqSession::initiate(Arc::clone(&alice), both_classical, None),
        TwoMlsPqError::PqNotAvailable
    );

    // Halves swapped (PQ suite in the classical slot) → CipherSuiteMismatch, rejected
    // before any send group is created.
    let swapped = CombinerKeyPackage {
        classical: assert_ok!(peer.generate_key_package(MlsCipherSuite::ml_kem_768())),
        pq: assert_ok!(peer.generate_key_package(MlsCipherSuite::x25519_chacha())),
    };
    assert_err!(
        TwoMlsPqSession::initiate(Arc::clone(&alice), swapped, None),
        TwoMlsPqError::CipherSuiteMismatch
    );
}

#[test]
fn test_welcome_with_swapped_suites_rejected_before_join() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = alice_s.test_initial_welcome();
    // Swap the welcome's two halves so each slot's cleartext cipher suite is wrong for the
    // acceptor's expected pair — caught pre-join, not as a late decrypt failure.
    let (classical, pq) = assert_ok!(apq::decode_apq_welcome(&welcome));
    let swapped = apq::encode_apq_welcome(pq, classical);
    let alice_kp = make_combiner_kp(&alice);
    assert_err!(
        TwoMlsPqSession::accept(Arc::clone(&bob), swapped, alice_kp),
        TwoMlsPqError::CipherSuiteMismatch
    );
}

#[test]
fn test_archive_rejects_a_wrong_suite_header() {
    let (alice, _bob) = establish_sessions();
    let archive = assert_ok!(alice.archive());
    let mut bytes = archive.bytes;
    // Byte 0 is the version; byte 1 is the classical suite's high byte. Corrupt it so the
    // archived pair no longer equals this build's pinned suite. Restore is self-contained
    // (the archive rebuilds its own client), so no identity is passed.
    bytes[1] ^= 0x01;
    assert_err!(
        TwoMlsPqSession::from_archive(crate::Archive { bytes }),
        TwoMlsPqError::ArchiveInvalid
    );
}

// --- draft-ietf-mls-combiner-02 conformance ---------------------------------------

/// Establishment carries the APQInfo GroupContext extension end to end: Alice's full
/// send group records both epochs live, and Bob's deferred (classical-only) send
/// group records the PQ side as pending (EPOCH_UNBOUND) with a pre-allocated group
/// id. Both are verified inside the join paths; here we assert the recorded shape.
#[test]
fn test_establishment_carries_apqinfo_with_deferred_sentinel() {
    use apq::component::{read_apqinfo, EPOCH_UNBOUND};
    let (alice, bob) = establish_sessions();

    // Alice's send group (full APQ pair): both halves live at epoch 1.
    {
        let inner = alice.lock();
        let send = inner.send_group.as_ref().unwrap();
        let info = read_apqinfo(&send.classical).unwrap();
        assert_eq!(info.t_epoch, 1);
        assert_eq!(info.pq_epoch, 1);
        assert_eq!(info.t_session_group_id, send.classical.group_id());
        assert_eq!(
            info.pq_session_group_id,
            send.pq.as_ref().unwrap().group_id()
        );
    }

    // Bob's send group (deferred): classical live, PQ pending with a non-empty
    // pre-allocated id.
    {
        let inner = bob.lock();
        let send = inner.send_group.as_ref().unwrap();
        assert!(send.pq.is_none());
        let info = read_apqinfo(&send.classical).unwrap();
        assert_eq!(info.t_epoch, 1);
        assert_eq!(info.pq_epoch, EPOCH_UNBOUND);
        assert!(!info.pq_session_group_id.is_empty());
    }
}

/// A.4 stands the deferred PQ half up under exactly the group id the classical
/// half's APQInfo pre-allocated at establishment.
#[test]
fn test_a4_uses_preallocated_pq_group_id() {
    use apq::component::read_apqinfo;
    let (alice, bob) = establish_confirmed_sessions();

    let preallocated = {
        let inner = bob.lock();
        read_apqinfo(&inner.send_group.as_ref().unwrap().classical)
            .unwrap()
            .pq_session_group_id
    };

    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let bind = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_apply(bind));

    {
        let inner = bob.lock();
        let pq = inner.send_group.as_ref().unwrap().pq.as_ref().unwrap();
        assert_eq!(pq.group_id(), preallocated.as_slice());
    }
}

/// The deferred-branch joiner verifier and the full-pair verifier are not
/// interchangeable: feeding a full session's classical half (which records
/// `pq_epoch == 1`, not the deferred sentinel) to the deferred verifier fails. This
/// is what stops a full-pair welcome masquerading as a deferred one (or vice versa),
/// and a welcome carrying no APQInfo at all fails the same `read_apqinfo` guard.
#[test]
fn test_apqinfo_deferred_verifier_rejects_bound_pq_epoch() {
    use apq::component::{verify_apqinfo_deferred, EPOCH_UNBOUND};
    let (alice, _bob) = establish_sessions();
    let inner = alice.lock();
    let send = inner.send_group.as_ref().unwrap();
    let info = apq::component::read_apqinfo(&send.classical).unwrap();
    assert_ne!(info.pq_epoch, EPOCH_UNBOUND);
    assert!(verify_apqinfo_deferred(&send.classical, inner.suite).is_err());
}

/// The A.3 bind is a -02 FULL: each round carries the AppDataUpdate in both halves,
/// and `pq_ratchet_apply` verifies the two copies agree AND match the actual
/// post-apply epochs of both groups before decrypting the stapled app message — so a
/// clean delivery is proof the attestation verified end to end. Both directions
/// (turn-flipped) exercise it. (The epoch-arithmetic rejection itself is unit-tested
/// at the apq layer, where a mismatched attestation can be crafted directly.)
#[test]
fn test_a3_bind_full_round_verifies_attestation_both_directions() {
    let (alice, bob) = establish_full();

    let ek = assert_ok!(alice.pq_ratchet_begin());
    assert_ok!(bob.pq_ratchet_respond(ek));
    let ct = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_ratchet_bind(ct, b"a-to-b".to_vec()));
    let bind = assert_some!(alice.pq_take_pending_outbound());
    assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"a-to-b");

    // Turn flipped to Bob; his bind's attestation verifies on Alice's apply too.
    let ek2 = assert_ok!(bob.pq_ratchet_begin());
    assert_ok!(alice.pq_ratchet_respond(ek2));
    let ct2 = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct2, b"b-to-a".to_vec()));
    let bind2 = assert_some!(bob.pq_take_pending_outbound());
    assert_eq!(assert_ok!(alice.pq_ratchet_apply(bind2)), b"b-to-a");
}

/// A.5 re-key commits must not carry an AppDataUpdate — that is the wire-visible
/// difference from an A.3 bind, and it is what lets the pq_epoch reconcile lazily at
/// the next bind. A full A.5 round (which carries none) completes cleanly under the
/// new receiver checks; a smuggled attestation is rejected in `pq_rekey_apply`. After
/// `establish_full` the turn is Bob's, so Bob initiates.
#[test]
fn test_a5_rekey_round_completes_without_attestation() {
    let (alice, bob) = establish_full();
    assert!(bob.my_pq_turn());
    let upd = assert_ok!(bob.pq_rekey_begin(None));
    assert_ok!(alice.pq_rekey_respond(upd));
    let commit = assert_some!(alice.pq_take_pending_outbound());
    assert!(assert_ok!(bob.pq_rekey_apply(commit)));
    let commit2 = assert_some!(bob.pq_take_pending_outbound());
    assert!(!assert_ok!(alice.pq_rekey_apply(commit2)));
    // A.5 advanced only the PQ epochs; the classical stream is untouched.
    assert_eq!(alice.epochs().pq_epoch, 2);
    assert_eq!(bob.epochs().pq_epoch, 2);
}

/// The cross-party injection is event-driven, not procedural: the acceptor's first full
/// commit re-binds the peer's send group at the epoch establishment already bound, so it
/// carries NO fresh cross-party PSK (the watermark is unchanged). Once the peer advances
/// its send group, the next full commit does inject (watermark moves).
#[test]
fn test_cross_party_injection_is_event_driven() {
    let (alice, bob) = establish_sessions();
    // Establishment bound the peer (Alice) at her send-group epoch 1.
    assert_eq!(bob.lock().last_cross_injected, Some(1));

    // Alice sends a no-commit round: her send group stays at epoch 1.
    assert_ok!(alice.prepare_to_encrypt(None));
    let a1 = assert_ok!(alice.encrypt(b"propose".to_vec()));
    let r = assert_some!(assert_ok!(bob.process_incoming(a1.cipher_text)));

    // Bob's first full commit: Alice's group is unchanged (still epoch 1), so no fresh
    // cross-party PSK is injected — the watermark is untouched.
    assert_ok!(bob.queue_proposal(assert_some!(r.proposal).digest));
    assert_ok!(bob.prepare_to_encrypt(None));
    let b1 = assert_ok!(bob.encrypt(b"full-1".to_vec()));
    assert_eq!(
        bob.lock().last_cross_injected,
        Some(1),
        "no re-bind while the peer's send group is unchanged"
    );
    assert_eq!(
        assert_some!(
            assert_some!(assert_ok!(alice.process_incoming(b1.cipher_text))).application_message
        )
        .app_message_data,
        b"full-1"
    );

    // Now Alice does a full commit (advancing her send group to epoch 2), then Bob
    // commits again: this time the peer HAS advanced, so Bob re-binds — the watermark
    // moves to 2.
    let rb = r_from(&bob, &alice, b"b-propose");
    assert_ok!(alice.queue_proposal(assert_some!(rb.proposal).digest));
    assert_ok!(alice.prepare_to_encrypt(None));
    let a2 = assert_ok!(alice.encrypt(b"a-full".to_vec()));
    let r2 = assert_some!(assert_ok!(bob.process_incoming(a2.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(r2.proposal).digest));
    assert_ok!(bob.prepare_to_encrypt(None));
    let b2 = assert_ok!(bob.encrypt(b"full-2".to_vec()));
    assert_eq!(
        bob.lock().last_cross_injected,
        Some(2),
        "re-bind once the peer's send group advanced"
    );
    assert_some!(assert_ok!(alice.process_incoming(b2.cipher_text)));
}

/// Drive one no-commit round from `from` to `to` and return `to`'s surfaced decrypt
/// result (carrying the stapled proposal) — a small helper for multi-round setups.
fn r_from(
    from: &Arc<TwoMlsPqSession>,
    to: &Arc<TwoMlsPqSession>,
    msg: &[u8],
) -> crate::DecryptResult {
    assert_ok!(from.prepare_to_encrypt(None));
    let enc = assert_ok!(from.encrypt(msg.to_vec()));
    assert_some!(assert_ok!(to.process_incoming(enc.cipher_text)))
}

/// A combiner key package round-trips through the -02 §7 APQKeyPackage encoding
/// (v2), and a v1-framed blob is rejected outright (the capability hard-cut).
#[test]
fn test_combiner_kp_v2_round_trips_and_rejects_v1() {
    let client = make_client();
    let kp = make_combiner_kp(&client);
    let encoded = crate::key_packages::encode_combiner_key_package(kp.clone());
    assert_eq!(encoded[0], 2, "version byte is 2");
    let decoded = assert_ok!(crate::key_packages::decode_combiner_key_package(encoded));
    assert_eq!(decoded.classical, kp.classical);
    assert_eq!(decoded.pq, kp.pq);

    // A v1 blob (old bespoke framing) is rejected.
    let mut v1 = vec![1u8];
    v1.extend_from_slice(&(kp.classical.len() as u32).to_le_bytes());
    v1.extend_from_slice(&kp.classical);
    v1.extend_from_slice(&(kp.pq.len() as u32).to_le_bytes());
    v1.extend_from_slice(&kp.pq);
    assert_err!(
        crate::key_packages::decode_combiner_key_package(v1),
        TwoMlsPqError::InvalidKeyPackage
    );
}
