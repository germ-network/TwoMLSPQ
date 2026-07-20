use std::sync::Arc;

use super::{SideBandSealing, TwoMlsPqSession};

use crate::{
    assert_err, assert_ok, assert_some,
    test_utils::{
        commitment_of, establish_confirmed_sessions, establish_sessions, make_classical_kp,
        make_client, make_combiner_kp,
    },
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
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    // The bind rides Alice's next classical COMMIT as the staple; Bob applies it
    // from the message frame.
    discharge_bind(&alice, &bob, b"bootstrap-bind");

    assert!(alice.is_fully_established());
    assert!(bob.is_fully_established());
    // Completing the operation passes the turn (Alice's at discharge, Bob takes it
    // applying the staple).
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

/// A re-sent A.4 welcome, after the initiator has already joined and bound, is a discardable
/// `DuplicateSideBand` — not the retriable `SessionNotReady` that would invite the host to
/// retry a bootstrap that is over. The responder re-staples its welcome until the stapled
/// bind lands, so these re-sends are steady-state, and the initiator's recv-PQ being up is
/// what proves the step is done (its `pq_inflight` is already `None`, so this must be checked
/// before the in-flight gate).
#[test]
fn test_duplicate_bootstrap_welcome_is_discardable() {
    let (alice, bob) = establish_confirmed_sessions();
    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    // Keep the welcome as plaintext so the re-send does not depend on header-seal windows.
    let welcome_sealed = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    let welcome = assert_some!(assert_ok!(alice.open_incoming(welcome_sealed))).frame;
    assert_ok!(alice.pq_bootstrap_bind(welcome.clone()));
    discharge_bind(&alice, &bob, b"bootstrap-bind");
    assert!(alice.is_fully_established());

    // Alice's recv-PQ is up now: the same welcome re-sent is a duplicate, discardable.
    assert_err!(
        alice.pq_bootstrap_bind(welcome),
        TwoMlsPqError::DuplicateSideBand
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

/// The A.4 KP′ must hash to the commitment pinned at establishment: a substituted PQ key
/// package — valid suite, honest shape, wrong bytes — is rejected before any group is
/// stood up, and the genuine pre-committed KP still completes the round. This is the
/// check that anchors the ML-KEM key material to the SIGNED establishment payload: the
/// side-band channel is confidential to the established peer, but a bare KP message
/// carries no anchor signature of its own, so before the commitment a compromised
/// classical channel could substitute the PQ leaf here.
#[test]
fn test_pq_bootstrap_respond_rejects_a_substituted_key_package() {
    use crate::MlsCipherSuite;

    let (alice, bob) = establish_confirmed_sessions();

    // A stranger's genuine PQ-suite key package, framed exactly like the honest KP′.
    let stranger = make_client();
    let forged = assert_ok!(stranger.generate_key_package(MlsCipherSuite::ml_kem_768()));
    let mut kp_msg = vec![super::PQ_BOOTSTRAP_KP_TAG];
    kp_msg.extend_from_slice(&forged);
    assert_err!(
        bob.pq_bootstrap_respond(kp_msg),
        TwoMlsPqError::BootstrapKpMismatch
    );

    // Rejected before any state was touched: the genuine round completes end-to-end.
    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"bootstrap-bind");
    assert!(alice.is_fully_established());
    assert!(bob.is_fully_established());
}

/// The commitment accessor serves the host's reply-time envelope composition and goes
/// quiet once `pq_bootstrap_begin` consumes the retained KP; an acceptor never has one.
#[test]
fn test_bootstrap_kp_commitment_lifecycle() {
    let (alice, bob) = establish_confirmed_sessions();
    // The initiator exposes the commitment from `initiate` until `begin` consumes it.
    assert_eq!(assert_some!(alice.bootstrap_kp_commitment()).len(), 32);
    // The acceptor holds the PIN, not the KP — nothing to expose.
    assert!(bob.bootstrap_kp_commitment().is_none());
    let _kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert!(alice.bootstrap_kp_commitment().is_none());
}

/// A commitment of the wrong length could never match any KP′ — `receive` rejects it up
/// front (before any invitation state is claimed) rather than letting it surface as a
/// confusing A.4 failure long after establishment.
#[test]
fn test_receive_rejects_malformed_commitment() {
    use crate::key_packages::TwoMlsPqInvitation;

    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let envelope = assert_some!(alice_session.pending_outbound());
    let opened = assert_ok!(bob_inv.open_establishment(envelope));
    let welcome = assert_some!(opened.welcome);
    assert_err!(
        bob_inv.receive(
            welcome.clone(),
            alice_kp.clone(),
            vec![0u8; 31], // one byte short of a SHA-256
            b"tok".to_vec(),
            None,
            None,
            None
        ),
        TwoMlsPqError::BootstrapKpMismatch
    );
    // Rejected lock-free: the invitation is untouched and the genuine receive works.
    assert_ok!(bob_inv.receive(
        welcome,
        alice_kp,
        commitment_of(&alice_session),
        b"tok".to_vec(),
        None,
        None,
        None
    ));
}

/// The pre-committed bootstrap KP survives a restore between reply and A.4: the public
/// bytes ride the session archive and the private material rides the client's retaining
/// key-package store inside it, so a restored-at-establishment initiator still opens the
/// round with the KP the establishment signature committed to — and can join the
/// Welcome' built around it. Without either half the anchor-signed commitment could
/// never be honoured after a restart.
#[test]
fn test_precommitted_bootstrap_kp_survives_restore() {
    let (alice, bob) = establish_confirmed_sessions();
    let restored = round_trip(&alice);
    drop(alice);

    let kp = assert_ok!(restored.pq_bootstrap_begin(None));
    // Bob's pinned commitment accepts the restored initiator's KP′ — the same bytes
    // committed at initiate, or `BootstrapKpMismatch` here.
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    // The join resolves the KP's private key from the restored client's store.
    assert_ok!(restored.pq_bootstrap_bind(welcome));
    discharge_bind(&restored, &bob, b"bootstrap-bind");
    assert!(restored.is_fully_established());
    assert!(bob.is_fully_established());
}

/// The pre-committed bootstrap KP carries the FROZEN establishment credential. Enough
/// peer rotations before a deferred A.4 evict that id from the acceptor's
/// credential-history window — but the acceptor PINS it (eviction-exempt) from the
/// hash-authenticated KP, so `validate_member` still admits the lazily-created leaf and
/// the round completes. Without the pin this wedges: `UnknownIdentity` → opaque `Mls`,
/// unrecoverable (the KP cannot be re-minted — its hash is signed into establishment).
/// A.5 later retires the pin once both peer PQ leaves have caught up.
#[test]
fn test_bootstrap_survives_credential_window_eviction() {
    let (alice, bob) = establish_confirmed_sessions();

    // Rotate Alice past the window so Bob's `theirs` evicts her establishment id — the
    // exact credential the bootstrap KP (minted at establishment) still carries. One
    // commit past the window guarantees the founding element is popped.
    let mut current = alice.my_principal_state().client_id();
    for _ in 0..=apq::authentication::CREDENTIAL_HISTORY_WINDOW {
        let next = make_client().client_id();
        rotate_round(&alice, &bob, next.clone());
        current = next;
    }
    // The bootstrap was never begun, so its KP still carries the (now-evicted)
    // establishment credential.
    let _ = &current;

    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp)); // pins the evicted establishment id
    let welcome = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"post-eviction-bind");
    assert!(alice.is_fully_established());
    assert!(bob.is_fully_established());

    // Messaging still flows on both PQ halves after the round.
    assert_ok!(alice.prepare_to_encrypt(None));
    let enc = assert_ok!(alice.encrypt(b"post-eviction".to_vec()));
    let got = assert_ok!(bob.process_incoming(enc.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-eviction".to_vec()
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let apq_welcome_a = assert_some!(alice_session.initial_welcome());

    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        bob,
        apq_welcome_a,
        alice_kp,
        commitment_of(&alice_session),
        None
    ));
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
    let alice_kp = make_classical_kp(&alice);
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
    let welcome_a = assert_some!(alice_s.initial_welcome());
    let bob_s = assert_ok!(TwoMlsPqSession::accept(
        bob,
        welcome_a,
        alice_kp,
        commitment_of(&alice_s),
        None
    ));
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

/// Discharge `binder`'s owed bind and deliver it; `app` is asserted through to `peer`.
///
/// A bind does not go out on its own. The PQ commit lands at the trigger and the classical
/// half is OWED until the next classical COMMIT carries it (rule 3) — and a classical round
/// commits only when it folds an app-approved peer proposal. So the peer must offer one,
/// which is why this is an approved-commit round rather than just an `encrypt`.
///
/// That coupling is the design, not a harness quirk: "classical may hold up the PQ ratchet."
/// A test that binds and then merely encrypts sits at 2/1 forever. Do NOT reach for a forced
/// commit to avoid it — making a round commit *because* a bind is owed is precisely the "next
/// send" rule we rejected: it lets a routine fold take the reserved `t_epoch`, and the peer
/// then refuses the bind with our PQ leaf already spent and unrebuildable.
///
/// The bind rides that commit's staple as an `APQPrivateMessage`, so `peer` applies both
/// halves — and the app — from the one frame.
fn discharge_bind(binder: &Arc<TwoMlsPqSession>, peer: &Arc<TwoMlsPqSession>, app: &[u8]) {
    // The peer offers an Upd; approving it is what makes the binder's next round commit.
    assert_ok!(peer.prepare_to_encrypt(None));
    let upd = assert_ok!(peer.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(binder.process_incoming(upd.cipher_text)));
    let offered = assert_some!(got.proposal);
    assert_ok!(binder.queue_proposal(offered.digest));

    let prepared = assert_ok!(binder.prepare_to_encrypt(None));
    assert!(prepared.did_commit, "a bind needs a COMMITTING round");
    let frame = assert_ok!(binder.encrypt(app.to_vec()));
    let got = assert_some!(assert_ok!(peer.process_incoming(frame.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        app,
        "the bind's frame carries its app like any message frame"
    );
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

/// PQ liveness must not depend on the app's approval policy. Rule 3 makes a bind wait for a
/// classical COMMIT, and while folding an app-approved Upd was the only way to commit, an app
/// that received offers and never approved them stranded every PQ round at 2/1 forever — the
/// peer parked in `Responding`, the turn never passing.
///
/// The discharge now rides a proposal-less commit as soon as the peer's stapled offer
/// licenses it (evidence-gating). Bob's app here never calls `queue_proposal`.
#[test]
fn test_never_approving_app_still_discharges_its_bind() {
    let (alice, bob) = establish_full();

    // Bob holds the turn: he opens an A.3 round with a send and runs it to the trigger. PQ
    // moves, classical is owed.
    let before = bob.epochs();
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    assert_eq!(bob.epochs().pq_epoch, before.pq_epoch + 1);
    assert_eq!(bob.epochs().classical_epoch, before.classical_epoch);

    // Alice sends an ordinary frame. Bob's app ignores the offer it carries — but that
    // offer is the LICENSE, and the license is not the app's to withhold.
    assert_ok!(alice.prepare_to_encrypt(None));
    let frame = assert_ok!(alice.encrypt(b"ordinary".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(frame.cipher_text)));
    assert_some!(got.proposal); // offered, and deliberately never approved

    // Bob's next round commits anyway, discharging the bind: 2/2.
    let prepared = assert_ok!(bob.prepare_to_encrypt(None));
    assert!(
        prepared.did_commit,
        "an owed bind must not wait on an approval that may never come"
    );
    assert!(
        prepared.committed_remote_client_id.is_none(),
        "nothing was folded — the peer's leaf stays where the app left it"
    );
    assert_eq!(bob.epochs().classical_epoch, before.classical_epoch + 1);

    // Alice applies both halves from the staple and the round closes.
    let discharge = assert_ok!(bob.encrypt(b"discharge".to_vec()));
    let got = assert_some!(assert_ok!(alice.process_incoming(discharge.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"discharge"
    );
    assert!(alice.my_pq_turn(), "the bind landed; the turn passed");
}

/// The license is the peer's stapled offer, not the app's approval — so a discharge WAITS
/// when nothing proves the peer applied our last commit. Without this, a second commit would
/// leave the peer two behind and supersede the bind's own staple before it ever landed,
/// stranding the PQ half with the exporter leaf already spent.
#[test]
fn test_unlicensed_discharge_waits_for_evidence() {
    let (alice, bob) = establish_full();

    // Bob commits, and Alice's answering frame is deliberately never delivered — so Bob has
    // no evidence she applied it.
    assert_ok!(alice.prepare_to_encrypt(None));
    let upd = assert_ok!(alice.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(upd.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    drop(assert_ok!(bob.encrypt(b"committed".to_vec()))); // never delivered

    // Bob binds, then tries to discharge with nothing licensing him.
    let ek = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    let prepared = assert_ok!(bob.prepare_to_encrypt(None));
    assert!(
        !prepared.did_commit,
        "unlicensed: Alice has not proven she applied Bob's last commit, so committing here \
         would leave her two behind and supersede the bind's staple"
    );
    assert_ok!(bob.encrypt(b"still-owed".to_vec()));

    // Bob's re-stapled commit reaches Alice; her next frame's offer is bound to his current
    // epoch, which licenses the discharge on the very next round.
    assert_ok!(bob.prepare_to_encrypt(None));
    let healing = assert_ok!(bob.encrypt(b"heal".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(healing.cipher_text)));
    assert_ok!(alice.prepare_to_encrypt(None));
    let evidence = assert_ok!(alice.encrypt(b"applied".to_vec()));
    assert_some!(assert_ok!(bob.process_incoming(evidence.cipher_text)));

    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let discharge = assert_ok!(bob.encrypt(b"discharge".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(discharge.cipher_text)));
    assert!(alice.my_pq_turn());
}

/// The license must AUTHENTICATE the offer, not trust the epoch field of raw proposal bytes.
/// The peer's Upd is built in its recv group (= our send group), so its epoch is coupled to
/// ours and an HONEST offer can never claim an epoch above our send group — but a malicious
/// peer could SPLICE in a proposal claiming a higher one, forging the license into
/// discharging a bind the peer has not applied (two commits outstanding, the hazard the gate
/// exists to prevent). Here a legit frame from Alice is rewritten to carry a FOREIGN,
/// higher-epoch Upd (from an unrelated session): it parses with a high `.epoch()` but does
/// not validate against Bob's send group, so the watermark must not move.
#[test]
fn test_forged_high_epoch_offer_does_not_license() {
    let (alice, bob) = establish_confirmed_sessions();
    let bob_send_epoch = bob
        .lock()
        .send_group
        .as_ref()
        .unwrap()
        .classical
        .current_epoch();

    // An unrelated session driven so its stapled Upd sits well above Bob's send epoch.
    let (carol, dave) = establish_confirmed_sessions();
    for _ in 0..4 {
        approved_commit_round(&dave, &carol);
    }
    assert_ok!(carol.prepare_to_encrypt(None));
    let carol_frame = assert_ok!(carol.encrypt(b"carol".to_vec()));
    let carol_open = assert_some!(assert_ok!(dave.open_incoming(carol_frame.cipher_text)));
    let (_, carol_section, _) = super::decode_message_frame(&carol_open.frame).unwrap();
    let (_, foreign_upd) = super::decode_proposal_section(&carol_section).unwrap();
    let forged_epoch = mls_rs::MlsMessage::from_bytes(&foreign_upd)
        .unwrap()
        .epoch()
        .unwrap();
    assert!(
        forged_epoch > bob_send_epoch,
        "the foreign Upd must claim a higher epoch than Bob's send group to be a real forgery"
    );

    // Splice the foreign high-epoch Upd into an otherwise-legit frame from Alice to Bob.
    assert_ok!(alice.prepare_to_encrypt(None));
    let alice_frame = assert_ok!(alice.encrypt(b"alice".to_vec()));
    let alice_open = assert_some!(assert_ok!(bob.open_incoming(alice_frame.cipher_text)));
    let (staple, _, app) = super::decode_message_frame(&alice_open.frame).unwrap();
    let forged_section =
        super::encode_proposal_section(&make_client().client_id().bytes, &foreign_upd);
    let forged_frame = super::encode_message_frame(&staple, forged_section, app);
    let forged_sealed = alice.lock().seal(&forged_frame).unwrap();

    assert_some!(assert_ok!(bob.process_incoming(forged_sealed)));

    // The forged high epoch did NOT license Bob: the offer failed to validate against his
    // send group, so the watermark stayed put. (The old raw-epoch read would have jumped it
    // to `forged_epoch`.)
    let watermark = bob.lock().peer_applied_send_epoch;
    assert!(
        watermark.is_none_or(|m| m < forged_epoch),
        "an unauthenticated high-epoch offer must not advance the license: {watermark:?} vs {forged_epoch}"
    );
}

/// A rotation canonicalized by a DISCHARGING commit must land on the receiver exactly as
/// one canonicalized by a plain commit.
///
/// A discharge that FOLDS is the routine folding commit, carrying the same canonical
/// credential step; it differs only in the shape that delivers it — an `APQPrivateMessage`
/// staple instead of a bare commit — which is a wire detail the identity bookkeeping must not
/// depend on. (A discharge may also ride a proposal-less commit when the app never approves;
/// that one moves no leaf, which is exactly why the bookkeeping keys off what the applied
/// commit MOVED rather than off which staple form carried it.)
///
/// The failure this pins is silent and permanent: the receiver's group leaf moves to the
/// winner while its principal, AS sequence and signing client stay on the retired identity,
/// so it re-proposes an identity the peer now refuses (CredentialRejected) with no way back.
#[test]
fn test_rotation_canonicalized_by_a_discharging_commit() {
    let (alice, bob) = establish_full();
    // Bob holds the turn after A.4: he opens an A.3 round with a send and binds, so his next
    // COMMITTING round is the one that must discharge it.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));

    // Alice proposes her successor on the very frame Bob folds into that discharge.
    let new_alice = make_client().client_id();
    assert_ok!(alice.stage_rotation(new_alice.bytes.clone()));
    assert!(matches!(
        alice.my_principal_state(),
        PrincipalState::Pending { .. }
    ));
    assert_ok!(alice.prepare_to_encrypt(Some(new_alice.clone())));
    let rotation = assert_ok!(alice.encrypt(b"rotate".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(rotation.cipher_text)));
    let offered = assert_some!(got.proposal);
    assert_eq!(offered.proposing.bytes, new_alice.bytes);
    assert_ok!(bob.queue_proposal(offered.digest));

    // One round folds the rotation AND discharges the bind into a single staple.
    let prepared = assert_ok!(bob.prepare_to_encrypt(None));
    assert!(prepared.did_commit);
    assert_eq!(
        assert_some!(prepared.committed_remote_client_id).bytes,
        new_alice.bytes,
        "Bob's commit canonicalizes Alice's candidate"
    );
    let frame = assert_ok!(bob.encrypt(b"fold+bind".to_vec()));

    // Alice applies it from the APQPrivateMessage staple: the canonical step must land.
    let got = assert_some!(assert_ok!(alice.process_incoming(frame.cipher_text)));
    let commit = assert_some!(got.remote_commit);
    assert_eq!(
        commit.new_recipient.bytes, new_alice.bytes,
        "the bind staple carried our canonical step; the app must observe it"
    );
    assert_eq!(
        alice.my_principal_state().client_id().bytes,
        new_alice.bytes
    );
    assert!(matches!(
        alice.my_principal_state(),
        PrincipalState::Sync { .. }
    ));
    // The bind rode the same staple, so the PQ round closed on it too.
    assert!(alice.my_pq_turn());

    // The session survives, which is the point: Alice now signs as the winner, so her
    // next proposal is one Bob can commit. A dropped canonical step surfaces here — she
    // would re-propose the retired identity and Bob would refuse it.
    approved_commit_round(&bob, &alice);
    message_round(&alice, &bob, b"after-rotation");
}

/// An owed bind leaves the queued tally alone: the trigger commits only the PQ half
/// (2/1 — classical owed), so the app-approved peer proposal stays queued, and the
/// NEXT committing round both folds it and discharges the bind. (The old bind frame
/// committed classical at the trigger and dropped the then-stale tally; the queued
/// proposal and the discharge now ride the same commit by design — a folding round
/// is exactly what a discharge needs.)
#[test]
fn test_queued_proposal_survives_bind_and_folds_with_discharge() {
    let (alice, bob) = establish_full();
    // Bob holds the turn: he opens an A.3 round with a send BEFORE any proposal is queued
    // (a queued proposal would make the opener COMMIT instead of staging the ratchet).
    let ek = open_ratchet(&bob, &alice);

    // Alice proposes a candidate; Bob approves it (the running tally).
    let id_a = make_client().client_id();
    assert_ok!(alice.stage_rotation(id_a.bytes.clone()));
    assert_ok!(alice.prepare_to_encrypt(Some(id_a.clone())));
    let f = assert_ok!(alice.encrypt(b"propose".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(f.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert_eq!(bob.queued_remote_successor(), Some(id_a.clone()));

    // Complete the A.3 up to the bind: PQ moves, classical is owed, and the tally is untouched.
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    assert_eq!(bob.queued_remote_successor(), Some(id_a.clone()));

    // One committing round folds the queued proposal AND carries the bind's staple.
    let prepared = assert_ok!(bob.prepare_to_encrypt(None));
    assert!(prepared.did_commit);
    assert_eq!(
        assert_some!(prepared.committed_remote_client_id).bytes,
        id_a.bytes
    );
    let frame = assert_ok!(bob.encrypt(b"fold+bind".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(frame.cipher_text)));
    // The bind landed with the fold: the round is closed and the turn is Alice's.
    assert!(alice.my_pq_turn());
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
fn test_pq_ratchet_discharge_mints_new_listen_address() {
    let (alice, bob) = establish_full();
    let before = assert_ok!(bob.should_listen_on()).rendezvous_by_epoch.len();

    // Bob holds the turn: he opens an A.3 to the trigger. The PQ commit touches nothing
    // classical, so no new address yet — the listen map tracks the classical epoch, which
    // is owed.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    assert_eq!(
        assert_ok!(bob.should_listen_on()).rendezvous_by_epoch.len(),
        before
    );

    // The discharge IS the classical commit: it advances bob's send-group epoch and
    // mints the new epoch's address; Alice's post address lands on it once she applies
    // the stapled bind.
    discharge_bind(&bob, &alice, b"bind");
    let listen_b = assert_ok!(bob.should_listen_on());
    assert_eq!(listen_b.rendezvous_by_epoch.len(), before + 1);
    let alice_post = assert_some!(assert_ok!(alice.send_rendezvous()));
    assert!(listen_b
        .rendezvous_by_epoch
        .iter()
        .any(|e| e.rendezvous_id.bytes == alice_post.bytes));
}

/// Send-driven A.5 open: the initiator (turn holder, whose PQ leaf lags a rotated principal)
/// sends an ordinary message, which auto-stages the A.5 Upd'; `responder` consumes the opener
/// and the peeked Upd' is returned. The rekey mirror of `open_ratchet`.
fn open_rekey(initiator: &Arc<TwoMlsPqSession>, responder: &Arc<TwoMlsPqSession>) -> Vec<u8> {
    assert_ok!(initiator.prepare_to_encrypt(None));
    let opener = assert_ok!(initiator.encrypt(b"rekey-open".to_vec()));
    assert_ok!(responder.process_incoming(opener.cipher_text));
    assert_some!(initiator.pq_pending_outbound(SideBandSealing::Fresh))
}

/// Drive one full A.5 rekey, rotation-driven. The session self-drives A.5 ONLY as a credential
/// catch-up — there is no host-callable plain rekey — so this rotates the initiator's principal
/// to make its send-PQ leaf lag, then lets sends carry the catch-up.
///
/// `initiator` must be the NON-turn-holder (`responder` holds the turn). The rotation's
/// canonicalize is sent by the turn-holding responder, which auto-stages one incidental A.3 —
/// the one-round catch-up deferral (a staged A.3 can't be upgraded to A.5 mid-flight). Draining
/// that A.3 passes the turn to the initiator, whose next send then auto-stages the A.5 Upd'
/// announcing `new_id`. Upd' -> Commit' -> the stapled ack closes it (turn back to the responder).
fn rekey_round(
    initiator: &Arc<TwoMlsPqSession>,
    responder: &Arc<TwoMlsPqSession>,
    new_id: crate::ClientId,
) {
    let reply = rekey_to_commit(initiator, responder, new_id);
    // Leg 3 applies the Commit' and acks: PQ moves, classical is owed.
    assert_ok!(initiator.pq_rekey_apply(reply));
    // The ack rides the initiator's next classical COMMIT as the staple.
    discharge_bind(initiator, responder, b"rekey-ack");
}

/// Drive a rotation-driven A.5 up to — but not through — the initiator's apply, returning the
/// responder's Commit' frame (its `pq_rekey_respond` reply). Same preconditions and mechanics as
/// [`rekey_round`]: `initiator` must be the NON-turn-holder; the rotation's incidental A.3 is
/// drained, then the initiator's send auto-stages the A.5 Upd' announcing `new_id`, and the
/// responder answers with its Commit'. Used where a test needs to interpose on the apply.
fn rekey_to_commit(
    initiator: &Arc<TwoMlsPqSession>,
    responder: &Arc<TwoMlsPqSession>,
    new_id: crate::ClientId,
) -> Vec<u8> {
    // Rotate the initiator (it does not hold the turn, so its rotate-send stages nothing; the
    // responder's canonicalize send stages the incidental A.3).
    rotate_round(initiator, responder, new_id.clone());

    // Drain the responder's incidental A.3 (the catch-up deferral) — the turn passes to the
    // initiator, whose leaf now lags the rotated principal.
    let ek = assert_some!(responder.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(initiator.pq_ratchet_respond(ek));
    let ct = assert_some!(initiator.pq_take_pending_outbound());
    assert_ok!(responder.pq_ratchet_bind(ct));
    discharge_bind(responder, initiator, b"catch-up-deferral");

    // The initiator now holds the turn and its leaf lags: a send auto-stages the A.5 Upd'.
    let upd = open_rekey(initiator, responder);
    // The frame is sealed on the wire; opened, it classifies as the rekey Upd'.
    assert_eq!(
        assert_some!(assert_ok!(responder.open_incoming(upd.clone()))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RekeyUpdate
        }
    );
    // The catch-up announces the credential the initiator rotated to.
    assert_eq!(assert_ok!(responder.pq_rekey_respond(upd)), Some(new_id));
    assert_some!(responder.pq_take_pending_outbound())
}

/// Send-driven A.3 open. The session no longer exposes a ratchet `begin`: the turn holder
/// opens a round simply by SENDING an ordinary message, and `encrypt`'s `maybe_stage_next_round`
/// auto-stages the A.3 EK into the side-band slot. This helper does that send (delivering the
/// opener to `responder`) and returns the peeked EK for the responder to answer.
///
/// Preconditions the caller must meet, since they are exactly what the auto-driver gates on:
/// `initiator` is post-A.4 (both PQ halves live), holds the turn, and has nothing queued (a
/// queued proposal would make the opener COMMIT instead of a plain message) — so open a round
/// before queuing, not after.
fn open_ratchet(initiator: &Arc<TwoMlsPqSession>, responder: &Arc<TwoMlsPqSession>) -> Vec<u8> {
    assert_ok!(initiator.prepare_to_encrypt(None));
    let opener = assert_ok!(initiator.encrypt(b"ratchet-open".to_vec()));
    assert_ok!(responder.process_incoming(opener.cipher_text));
    assert_some!(initiator.pq_pending_outbound(SideBandSealing::Fresh))
}

/// Drive one full A.3 ratchet with `initiator` holding the turn: EK → CT → the
/// stapled bind, delivered by the discharge round (`app` is asserted through to the
/// responder by `discharge_bind`).
fn ratchet_round(initiator: &Arc<TwoMlsPqSession>, responder: &Arc<TwoMlsPqSession>, app: &[u8]) {
    let ek = open_ratchet(initiator, responder);
    assert_ok!(responder.pq_ratchet_respond(ek));
    let ct = assert_some!(responder.pq_take_pending_outbound());
    assert_ok!(initiator.pq_ratchet_bind(ct));
    discharge_bind(initiator, responder, app);
}

/// A rotation-driven A.5 rekey advances BOTH send-PQ epochs and keeps messaging flowing, and
/// consecutive rekeys alternate cleanly. (The old plain-rekey "classical untouched" invariant is
/// gone by design: A.5 now only fires as a credential catch-up, so a rotation's classical commits
/// ride along — see `rekey_round`.)
#[test]
fn test_pq_rekey_full_round() {
    let (alice, bob) = establish_full();
    // Rekey initiator = Alice (the non-turn-holder after bootstrap); she rotates and catches up.
    assert!(bob.my_pq_turn());
    let alice_pq = alice.epochs().pq_epoch;
    let bob_pq = bob.epochs().pq_epoch;

    let new_alice = make_client().client_id();
    rekey_round(&alice, &bob, new_alice);

    // Both send groups' PQ epochs advanced, and the turn flipped back to Bob (the responder).
    assert!(alice.epochs().pq_epoch > alice_pq);
    assert!(bob.epochs().pq_epoch > bob_pq);
    assert!(bob.my_pq_turn());
    assert!(!alice.my_pq_turn());

    // Messaging still flows both ways on the rekeyed groups.
    assert_ok!(bob.prepare_to_encrypt(None));
    let b2a = assert_ok!(bob.encrypt(b"post-rekey".to_vec()));
    let got = assert_ok!(alice.process_incoming(b2a.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-rekey".to_vec()
    );
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
    // Round 1: Alice (the non-turn-holder) rotates and catches up.
    assert!(bob.my_pq_turn());
    let a0 = alice.epochs().pq_epoch;
    let new_alice1 = make_client().client_id();
    rekey_round(&alice, &bob, new_alice1);
    assert!(alice.epochs().pq_epoch > a0);
    // The turn flipped to Bob (the responder).
    assert!(bob.my_pq_turn());
    assert!(!alice.my_pq_turn());

    // Archive + restore both parties between the rounds. The A.5 cross-party PSKs live
    // only in the ephemeral store, which does not ride the archive.
    let alice = round_trip(&alice);
    let bob = round_trip(&bob);
    assert!(bob.my_pq_turn());
    assert!(!alice.my_pq_turn());

    // Round 2: Alice rotates again on the restored sessions. If the second round tried to
    // re-export a send-PQ leaf the first round consumed, or the peer referenced a PSK
    // the empty store could not resolve, this would fail here.
    let a1 = alice.epochs().pq_epoch;
    let new_alice2 = make_client().client_id();
    rekey_round(&alice, &bob, new_alice2);
    assert!(alice.epochs().pq_epoch > a1);
    assert!(bob.my_pq_turn());

    // Messaging still flows on the twice-rekeyed, once-restored groups.
    assert_ok!(bob.prepare_to_encrypt(None));
    let b2a = assert_ok!(bob.encrypt(b"after-two-rekeys".to_vec()));
    let got = assert_ok!(alice.process_incoming(b2a.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"after-two-rekeys".to_vec()
    );
}

#[test]
fn test_pq_rekey_then_ratchet_still_works() {
    let (alice, bob) = establish_full();
    let new_alice = make_client().client_id();
    rekey_round(&alice, &bob, new_alice);
    // A.3 ratchet after a rekey: Bob holds the turn (the rekey responder) and his leaf does not
    // lag, so his next send drives an ordinary A.3.
    ratchet_round(&bob, &alice, b"post-rekey-ratchet");
}

/// A refused Commit' must leave the A.5 round exactly where it was, because the refusal
/// the design actually expects is RETRIABLE: `pq_rekey_respond`'s Commit' may carry the
/// responder's own-leaf credential catch-up, and the AS admits only an already-canonical
/// identity — so a Commit' racing ahead of the classical rotation staple is rejected until
/// that staple lands, and the responder re-sends it meanwhile.
///
/// Consuming the round state before that fallible apply made the retry unreachable: with no
/// round in flight and the turn still ours (it passes only at a discharge that never
/// happened), every re-sent Commit' would answer SessionNotReady — a permanent, persisted
/// deadlock on both sides. Here a foreign-group Commit' stands in for any refusal; the
/// property is that the round survives it.
#[test]
fn test_refused_rekey_commit_leaves_the_round_retriable() {
    let (alice, bob) = establish_full();
    let (carol, dave) = establish_full();

    // Drive a real rotation-driven A.5 up to the initiator's apply. Alice is the non-turn-holder
    // after bootstrap, so she is the rekey initiator; `rekey_to_commit` returns Bob's Commit'.
    let new_alice = make_client().client_id();
    let real = rekey_to_commit(&alice, &bob, new_alice);

    // An unrelated pair's Commit', opened to PLAINTEXT via its own initiator so it reaches
    // Alice's apply rather than dying at the header seal.
    let new_carol = make_client().client_id();
    let foreign_sealed = rekey_to_commit(&carol, &dave, new_carol);
    let foreign = assert_some!(assert_ok!(carol.open_incoming(foreign_sealed))).frame;

    // Refused — it commits another group entirely.
    assert_err!(alice.pq_rekey_apply(foreign), TwoMlsPqError::Mls);

    // The round is intact: the real Commit' still applies, and the ack still closes it.
    assert_ok!(alice.pq_rekey_apply(real));
    discharge_bind(&alice, &bob, b"after-refusal");
    assert!(bob.my_pq_turn());
}

/// The session self-drives A.5, so there is no host `begin` to guard — but a peer can still
/// replay a Commit' with no rekey in flight, and that unsolicited frame must be rejected.
#[test]
fn test_unsolicited_rekey_commit_is_rejected() {
    let (_alice, bob) = establish_full();
    let bogus = super::encode_pq_rekey_commit(vec![0u8; 8]);
    assert_err!(bob.pq_rekey_apply(bogus), TwoMlsPqError::SessionNotReady);
}

/// The session's own leaf signature public keys in (send-PQ, recv-PQ) — the two
/// leaves an A.5 credential handoff must move to the new principal: the recv-mirror
/// leaf via the initiator's Upd' (proposal replaces the proposer), the own-send-PQ
/// leaf via the Commit' of the round this party RESPONDS to (updatePath replaces
/// the committer).
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

/// A rotation catch-up A.5 hands the PQ credential to the new principal: the leg-1 Upd' replaces
/// the proposer, so the initiator's leaf in its recv-PQ mirror (the peer's send-PQ) moves to the
/// rotated identity, and the responder learns the announced id. (The initiator's OWN send-PQ leaf
/// follows only on a later round it RESPONDS to — reached once the peer rotates too; the
/// recv-mirror handoff is the credential step that keeps the peer's view canonical.)
#[test]
fn test_pq_rekey_rotation_hands_pq_leaf_to_new_principal() {
    let (alice, bob) = establish_full();
    // Bob is the party we rotate; make him the non-turn-holder rekey initiator (flip the turn).
    ratchet_round(&bob, &alice, b"flip");

    // Bob rotates and runs his catch-up A.5. `rekey_round` swaps Bob's client to the successor
    // and drives Upd' -> Commit' -> ack. The leg-1 Upd' announces the new id and moves Bob's
    // recv-mirror leaf to it; his own-send leaf still lags until a round he RESPONDS to.
    let new_bob_id = make_client().client_id();
    rekey_round(&bob, &alice, new_bob_id.clone());

    // The successor's PQ signing key is now the session's current client.
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
    let leaves = own_pq_leaf_signature_keys(&bob);
    assert_eq!(
        leaves.1, new_key,
        "the recv-mirror leaf moved to the rotated principal via the Upd'"
    );
    assert_ne!(
        leaves.0, new_key,
        "the own-send-PQ leaf still lags — it moves only on a round Bob RESPONDS to"
    );

    // The rekeyed, rotated groups keep working: Bob (now signing as the successor's canonical
    // credential in his recv mirror) sends and Alice reads it.
    assert_ok!(bob.prepare_to_encrypt(None));
    let msg = assert_ok!(bob.encrypt(b"post-handoff".to_vec()));
    let got = assert_ok!(alice.process_incoming(msg.cipher_text));
    assert_eq!(
        assert_some!(assert_some!(got).application_message).app_message_data,
        b"post-handoff".to_vec()
    );
}

/// Phase 8 swaps the session client, but the existing groups keep resolving
/// external PSKs from the stores of the clients that created them. Every
/// PSK-carrying flow must still work after a rotation — this pins the
/// psk_stores registry (a plain rekey, an A.3 ratchet, and a full classical
/// commit round, all post-rotation, no credential handoff involved).
#[test]
fn test_psk_flows_survive_rotation() {
    let (alice, bob) = establish_full();

    // A.5 rekey driven by rotating the non-turn-holder (Alice): after the client swap the group
    // halves must still resolve their cross-party PSKs from the creation-time stores.
    let new_alice = make_client().client_id();
    rekey_round(&alice, &bob, new_alice);

    // A.3 ratchet with the rotated side (Alice) responding — Bob holds the turn now.
    ratchet_round(&bob, &alice, b"post-rotation-ratchet");

    // Full classical commit round: Alice staples an Upd that Bob approves and commits with a
    // cross-party PSK refresh.
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
fn test_pq_bootstrap_begin_rotating_requires_current_agent() {
    let (alice, bob) = establish_confirmed_sessions();
    let stranger = make_client();
    assert_err!(
        alice.pq_bootstrap_begin(Some(stranger.client_id())),
        TwoMlsPqError::SessionNotReady
    );

    // After a Phase 8 rotation the bootstrap accepts the handoff id, and the KP' it
    // emits — the pre-committed one, per the v20 pin — completes A.4 as usual: the
    // peer's hash check admits the establishment-credential KP (the commitment
    // outranks the live-principal equality), and the bind joins the Welcome' because
    // the KP's private half is SESSION-owned and injected just-in-time — a
    // store-homed secret would have been dropped by this very client swap. A.5 hands
    // the PQ leaves to the rotated credential afterward.
    let new_alice = make_client();
    let new_alice_id = new_alice.client_id();
    rotate_round(&alice, &bob, new_alice_id.clone());

    let kp = assert_ok!(alice.pq_bootstrap_begin(Some(new_alice_id)));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"handoff-bootstrap-bind");
    assert!(bob.my_pq_turn());
}

#[test]
fn test_a4_bootstrap_mints_no_listen_addresses_but_advertises_pq_id() {
    let (alice, bob) = establish_sessions();
    let bob_before = assert_ok!(bob.should_listen_on());
    assert!(bob_before.send_group.pq.bytes.is_empty());

    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"bootstrap-bind");

    // The acceptor's side of A.4 is PQ-groups-only: Bob's send group commits nothing
    // classical (Alice's discharge advances HER classical), so his listen addresses
    // are untouched — but his send group now advertises its PQ half.
    let bob_after = assert_ok!(bob.should_listen_on());
    assert_eq!(
        bob_after.rendezvous_by_epoch.len(),
        bob_before.rendezvous_by_epoch.len()
    );
    assert!(!bob_after.send_group.pq.bytes.is_empty());
}

/// The bind's trigger must move the PQ half and OWE the classical one.
///
/// The PQ half has no choice: `apq_psk` is exported from its POST-commit epoch, so the
/// classical commit cannot even be built until the PQ one has applied. That ordering is
/// forced, and it is also what lets `S` be folded in and wiped rather than held.
///
/// The classical half is the opposite. Applying it advances the epoch Alice's ordinary
/// traffic rides, onto a commit whose `apq_psk` the peer can only derive from the bind's PQ
/// half. Applied at the trigger, every frame Alice sends before the bind lands is
/// undeliverable — and for A.4 the trigger is INBOUND, so she may have nothing to send at
/// all. So the trigger leaves 2/1, and the classical COMMIT that discharges the bind
/// makes it 2/2.
#[test]
fn test_bind_moves_pq_and_owes_classical() {
    let (alice, bob) = establish_full();
    let before = bob.epochs();

    // Bob holds the turn: he opens the A.3 with a send, Alice responds, Bob binds.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));

    let after = bob.epochs();
    assert_eq!(
        after.pq_epoch,
        before.pq_epoch + 1,
        "the PQ half must commit at the trigger — apq_psk comes from its post-commit epoch"
    );
    assert_eq!(
        after.classical_epoch, before.classical_epoch,
        "the classical half must NOT advance at the trigger — its commit is owed until \
         there is a send to carry the bind"
    );
}

/// The fatal `BindDischargeFailed` wrapper does NOT over-fire: an ordinary discharge — the
/// overwhelmingly common case — succeeds without tripping it, and so does a NON-discharging
/// committing round (a plain fold with no owed bind, which must keep its own retriable error
/// taxonomy). Only a failure while a bind is genuinely being discharged is fatal.
#[test]
fn test_ordinary_discharge_is_not_flagged_fatal() {
    let (alice, bob) = establish_full();
    // Bob holds the turn: a clean A.3 round through its discharge — no error, no fatal wrapper.
    ratchet_round(&bob, &alice, b"clean");
    // A plain fold with nothing owed still commits normally.
    approved_commit_round(&bob, &alice);
    message_round(&alice, &bob, b"after");
}

/// Finding 4, surfaced: if applying a peer's bind staple fails after the round's secret is
/// consumed, RECEIVING is broken (the peer re-staples the same unappliable bind forever) but
/// SENDING still works — and the break is queryable so a host classifies its severity, and
/// heals on restore because it was never persisted.
///
/// The failure is not reachable from an honest peer, so it is induced by corrupting the held
/// secret just before the responder applies the staple.
#[test]
fn test_failed_bind_apply_breaks_receive_not_send_and_heals_on_restore() {
    let (alice, bob) = establish_full();

    // Bob holds the turn after A.4, so he opens the round with a send; Alice responds and holds S.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));

    // Alice offers the Upd Bob's discharge will fold, and Bob builds the discharge staple.
    assert_ok!(alice.prepare_to_encrypt(None));
    let offer = assert_ok!(alice.encrypt(b"offer".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(offer.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let discharge = assert_ok!(bob.encrypt(b"discharge".to_vec()));

    // Snapshot Alice at her last good persisted state — AFTER she sent (and persisted) that
    // Upd, so the restore holds the leaf key Bob's commit folds, exactly as a real reload
    // from the last blob would. THEN corrupt the live Alice's held secret so applying the
    // discharge fails with the secret already consumed — the exact unrecoverable ordering.
    let alice_restore = round_trip(&alice);
    {
        let mut inner = alice.lock();
        assert!(
            matches!(inner.pq_inflight, Some(super::PqInflight::Responding(_))),
            "Alice should hold S as the A.3 responder"
        );
        if let Some(super::PqInflight::Responding(s)) = inner.pq_inflight.as_mut() {
            s[0] ^= 0xFF;
        }
    }

    // The discharge staple fails to apply, latching the break with the honest error.
    assert_err!(
        alice.process_incoming(discharge.cipher_text.clone()),
        TwoMlsPqError::BindApplyFailed
    );
    assert!(alice.pq_receive_broken());

    // Every further inbound frame is refused with the same queryable error — not the
    // retriable SessionNotReady the raw retry would surface.
    assert_ok!(bob.prepare_to_encrypt(None));
    let another = assert_ok!(bob.encrypt(b"more".to_vec()));
    assert_err!(
        alice.process_incoming(another.cipher_text),
        TwoMlsPqError::BindApplyFailed
    );

    // But SENDING is unaffected: Alice can still encrypt, and Bob reads it.
    assert_ok!(alice.prepare_to_encrypt(None));
    let out = assert_ok!(alice.encrypt(b"still-sending".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(out.cipher_text)));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"still-sending"
    );

    // Restoring the last good state heals it: the break was never persisted (inbound
    // processing persists on success only), so the restore starts clean AND holds the
    // uncorrupted secret. Bob re-staples the same bind on every frame, so the restored
    // Alice applies it and the round closes.
    assert!(!alice_restore.pq_receive_broken());
    let got = assert_some!(assert_ok!(
        alice_restore.process_incoming(discharge.cipher_text)
    ));
    assert_eq!(
        assert_some!(got.application_message).app_message_data,
        b"discharge"
    );
    assert!(
        alice_restore.my_pq_turn(),
        "the bind applied cleanly on the restore; the round closed and the turn passed"
    );
    assert!(!alice_restore.pq_receive_broken());
}

/// Negative control on the reservation re-check: `discharge_owed_bind` re-checks the
/// reserved epochs against the live groups rather than trusting them, because a stale
/// reservation shipped to the peer is refused with our PQ leaf already spent. Nothing
/// in the protocol can violate the reservation any more (every classical commit IS the
/// discharge, and rule 2 blocks further PQ commits), so the only way to prove the
/// check is load-bearing is to tamper: corrupt the reservation and watch the discharge
/// refuse loudly on OUR side, before anything reaches the wire.
#[test]
fn test_discharge_refuses_a_violated_reservation() {
    let (alice, bob) = establish_full();
    // Bob holds the turn: he opens the A.3 with a send, Alice responds, Bob binds.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));

    // Tamper with the reservation as a stand-in for the (structurally unreachable)
    // epoch theft the check guards against.
    {
        let mut inner = bob.lock();
        let owed = inner.owed_bind.as_mut().expect("bind is owed");
        owed.t_epoch += 1;
    }

    // The committing round that would discharge it refuses — on Bob's side, with nothing
    // sent. And because a bind was being discharged when the reservation check failed, the
    // error is the FATAL `BindDischargeFailed`, not the retriable one it would wear
    // otherwise: the reservation was already consumed and the leaf spent, so a host must
    // route to re-establishment rather than retry.
    assert_ok!(alice.prepare_to_encrypt(None));
    let upd = assert_ok!(alice.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(upd.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert_err!(
        bob.prepare_to_encrypt(None),
        TwoMlsPqError::BindDischargeFailed
    );
}

/// Archive mid-hold: the owed bind (public bytes and two reserved epochs — no key
/// material, because `apq_psk` is exported at discharge) rides the archive, so a
/// session restored between the trigger and the discharge still discharges, and the
/// peer accepts the stapled bind.
#[test]
fn test_archive_mid_hold_discharges_after_restore() {
    let (alice, bob) = establish_full();
    // Bob holds the turn: he opens the A.3 with a send, Alice responds, Bob binds.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));

    // Round-trip Bob while the bind is owed.
    let restored = round_trip(&bob);

    // The restored session discharges on its next committing round and Alice accepts.
    discharge_bind(&restored, &alice, b"post-restore-bind");
    assert!(alice.my_pq_turn());
    message_round(&restored, &alice, b"after");
}

#[test]
fn test_pq_ratchet_round_trip_delivers_app_message() {
    let (alice, bob) = establish_full();
    // Bob holds the turn after bootstrap, so Bob opens a PQ ratchet on his send group; Alice
    // responds; the bind rides Bob's next committing round, whose frame carries the app to Alice.
    ratchet_round(&bob, &alice, b"hello-pq");
}

/// A stale ciphertext re-sent from a completed round, arriving while the initiator holds a fresh
/// ephemeral from a LATER round, must be rejected with that ephemeral and its PQ leaf intact —
/// not silently decapsulated into a garbage secret that poisons the round.
///
/// (Send-driven advancement removed the old within-turn bundling — a round no longer opens while
/// its predecessor's bind is owed — so the fresh ephemeral is held by a later round the turn came
/// back around to, not one parked beside an owed bind. The hazard is the same: a lagging peer's
/// re-sent round-N CT reaches the bind guard. ML-KEM's implicit rejection would hand back garbage
/// for it; the sealed-secret open, keyed by the round's ephemeral AND its group epoch, fails
/// EXPLICITLY instead.)
#[test]
fn test_stale_ciphertext_crossing_rounds_is_rejected() {
    let (alice, bob) = establish_full();

    // Round N: Bob (the turn holder) initiates, Alice responds, Bob binds. Keep round N's
    // ciphertext as PLAINTEXT so the re-send below does not depend on header-seal windows.
    let ek1 = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek1));
    let ct1_sealed = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));
    let ct1 = assert_some!(assert_ok!(bob.open_incoming(ct1_sealed))).frame;
    assert_ok!(bob.pq_ratchet_bind(ct1.clone()));
    discharge_bind(&bob, &alice, b"round-n"); // turn -> alice; Bob's round-N ephemeral is spent

    // Round N+1 (Alice's) flips the turn back to Bob, and round N+2 has Bob open a fresh round —
    // so Bob now holds the round-N+2 ephemeral, waiting for Alice's CT.
    ratchet_round(&alice, &bob, b"round-n+1");
    let ek3 = open_ratchet(&bob, &alice);

    // The transport re-delivers round N's ciphertext. It answers a spent ephemeral and a prior
    // epoch, so the open fails explicitly — the round-N+2 ephemeral is untouched.
    assert_err!(bob.pq_ratchet_bind(ct1), TwoMlsPqError::Mls);

    // Proof the ephemeral survived: the CORRECT round-N+2 ciphertext still binds, and the round
    // completes cleanly.
    assert_ok!(alice.pq_ratchet_respond(ek3));
    let ct3 = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));
    let ct3 = assert_some!(assert_ok!(bob.open_incoming(ct3))).frame;
    assert_ok!(bob.pq_ratchet_bind(ct3));
    discharge_bind(&bob, &alice, b"round-n+2");
    assert!(alice.my_pq_turn());
}

/// The PQ side-band must survive a principal rotation: the injected-secret and apq PSKs
/// have to land in the stores the group halves actually resolve from (captured at
/// group creation), not the rotated-in client's stores — otherwise Alice's bind and
/// Bob's apply both fail to find their PSKs after the client swap.
#[test]
fn test_pq_ratchet_completes_after_principal_rotation() {
    let (alice, bob) = establish_full();

    // Rotate both principals (Phase 8 classical), so each session's `self.client` is swapped
    // to the winner while the PQ leaves still lag — the exact state whose PSK stores this pins.
    let new_alice = make_client().client_id();
    rotate_round(&alice, &bob, new_alice);
    let new_bob = make_client().client_id();
    rotate_round(&bob, &alice, new_bob);

    // A full A.3 round after both rotations: the injected-secret and apq PSKs must land in the
    // stores the group halves actually resolve from (captured at group creation), not the
    // rotated-in client's. Bob holds the turn, so he drives it.
    ratchet_round(&bob, &alice, b"pq-after-rotation");
}

/// Complete the A.4 bootstrap after establishment so both directions are full
/// APQ — required before the deferred acceptor side can ratchet.
/// Drive A.4 to completion the way a re-staple host does: through the retained PEEK, not
/// `pq_take_pending_outbound`.
///
/// This matters more than it looks. The take empties the slot, so a take-driven helper
/// cannot see anything that goes wrong with a RETAINED bootstrap frame — which is how the
/// A.4/A.3 slot collision hid from the entire suite. (Bob's welcome is retained until the
/// stapled bind lands; applying the staple in `discharge_bind` is what clears it, so the
/// helper leaves both slots empty.)
fn establish_full() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
    let (alice, bob) = establish_confirmed_sessions();
    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    // A.4's third leg: joining commits Alice's send-PQ and OWES the classical half, which
    // her next committing round carries as an APQPrivateMessage staple.
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"bootstrap-bind");
    (alice, bob)
}

/// A bootstrap key package naming a principal other than the established peer is
/// rejected before any PQ group is stood up around it: the new half's added leaf
/// becomes a sender identity this library reports, so it must be the peer's. With a
/// commitment pinned at establishment (every v20 session), the strictly stronger
/// `BootstrapKpMismatch` gate fires first — it pins the exact committed bytes,
/// identity included.
#[test]
fn test_bootstrap_kp_from_unknown_principal_rejected() {
    let (_alice, bob) = establish_confirmed_sessions();
    let mallory = make_client();
    let mallory_pq_kp = make_combiner_kp(&mallory).pq;
    let mut frame = vec![super::PQ_BOOTSTRAP_KP_TAG];
    frame.extend_from_slice(&mallory_pq_kp);
    assert_err!(
        bob.pq_bootstrap_respond(frame),
        TwoMlsPqError::BootstrapKpMismatch
    );
    // The turn state is untouched — the peer's real bootstrap still works.
    assert!(!bob.my_pq_turn());
}

#[test]
fn test_pq_ratchet_turn_flips_to_responder() {
    let (alice, bob) = establish_full();
    // Round 1: Bob holds the turn after bootstrap, so Bob initiates; the turn passes at his
    // discharge and Alice takes it applying the staple.
    ratchet_round(&bob, &alice, b"b1");
    assert!(alice.my_pq_turn());
    assert!(!bob.my_pq_turn());
    // Round 2: turn flipped — Alice initiates on her send group, Bob applies.
    ratchet_round(&alice, &bob, b"a1");
    assert!(bob.my_pq_turn());
    assert!(!alice.my_pq_turn());
}

#[test]
fn test_pq_ratchet_bind_guarded_while_commit_staged() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());

    // A prepared-but-unsent round holds the staple slot: the bind's PQ commit must
    // not fire while a prepared commit has never ridden a frame (the peer would hit
    // EpochDesync with zero loss on the wire).
    assert_ok!(bob.prepare_to_encrypt(None));
    assert_err!(
        bob.pq_ratchet_bind(ct.clone()),
        TwoMlsPqError::SessionNotReady
    );

    // Retriable: once the round's encrypt has gone out, the bind proceeds.
    let enc = assert_ok!(bob.encrypt(b"round".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(enc.cipher_text)));
    assert_ok!(bob.pq_ratchet_bind(ct));
    discharge_bind(&bob, &alice, b"app");
}

/// A.4's bind calls the same `commit_pq_and_owe_bind` as A.3's, so it carries the identical
/// hazard: a prepared-but-unsent classical commit is sitting in `current_staple` waiting for
/// its `encrypt`, and the bind's commit would fire out from under it. A displaced commit
/// never rides a frame again, so the peer hits the epoch-ahead desync with zero loss on the
/// wire.
///
/// A.3 guards this; A.4 did not. The exposure is worse here, because A.4's trigger is
/// INBOUND: a host that prepares a round and then receives the peer's welcome before its
/// `encrypt` hits this without doing anything wrong, and the ordering is not its to control.
#[test]
fn test_pq_bootstrap_bind_guarded_while_commit_staged() {
    let (alice, bob) = establish_confirmed_sessions();
    let kp = assert_ok!(alice.pq_bootstrap_begin(None));
    assert_ok!(bob.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));

    assert_ok!(alice.prepare_to_encrypt(None));
    assert_err!(
        alice.pq_bootstrap_bind(welcome.clone()),
        TwoMlsPqError::SessionNotReady
    );

    // Retriable, and the refusal cost nothing: the guard sits above the persist choke point,
    // so the round is untouched and the welcome still good once the encrypt has gone out.
    let enc = assert_ok!(alice.encrypt(b"round".to_vec()));
    assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"bootstrap-bind");
    assert!(alice.is_fully_established());
    assert!(bob.is_fully_established());
}

/// The overtaking window is unconstructible now. A message frame once could carry the
/// bind's classical commit as its staple while the bind FRAME was still in transit —
/// a staple Bob could not apply until the bind landed, a retriable desync this test
/// used to pin. The bind's classical half no longer exists apart from its PQ partner:
/// they travel as ONE `APQPrivateMessage` staple on the committing round itself, and
/// until that round commits, every frame re-staples the previous, already-applied
/// commit. There is no frame that can outrun the bind, because no frame carries the
/// bind's classical half without the bind.
#[test]
fn test_no_message_frame_can_overtake_the_bind() {
    let (alice, bob) = establish_full();

    // Put Bob in the unlicensed hold window. He folds an Alice offer and commits — Alice
    // applies that commit, but her return frame proving it is never delivered, so Bob's
    // evidence watermark stays behind his own send epoch. This is the only state in which a
    // mid-hold frame could try to overtake the bind: with the turn-holder freshly licensed,
    // an owed bind simply discharges on the next round. The committing send also auto-stages
    // Bob's A.3 EK.
    assert_ok!(alice.prepare_to_encrypt(None));
    let offer = assert_ok!(alice.encrypt(b"offer".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(offer.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    let committed = assert_ok!(bob.encrypt(b"committed".to_vec()));
    assert_some!(assert_ok!(alice.process_incoming(committed.cipher_text))); // Alice applies it

    // Bob's A.3 round up to the trigger: PQ committed, classical owed.
    let ek = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));

    // A frame sent mid-hold is a NON-committing round (unlicensed: Alice has not proven she
    // applied Bob's last commit), so its staple re-sends the previous, already-applied commit
    // — Alice skips it idempotently — where the old design handed her a staple she could not
    // use yet.
    let prepared = assert_ok!(bob.prepare_to_encrypt(None));
    assert!(
        !prepared.did_commit,
        "unlicensed mid-hold: this round must not commit"
    );
    let mid_hold = assert_ok!(bob.encrypt(b"mid-hold".to_vec()));
    let res = assert_some!(assert_ok!(alice.process_incoming(mid_hold.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"mid-hold"
    );

    // The bind then rides the next committing round as its staple, PQ half attached.
    discharge_bind(&bob, &alice, b"bound");
}

#[test]
fn test_pq_ratchet_bind_without_begin_is_rejected() {
    let (alice, _bob) = establish_sessions();
    let mut ct = vec![super::PQ_CT_TAG];
    ct.extend_from_slice(&[0u8; 1088]);
    assert_err!(alice.pq_ratchet_bind(ct), TwoMlsPqError::SessionNotReady);
}

#[test]
fn test_classical_round_still_works_after_pq_ratchet() {
    let (alice, bob) = establish_full();
    ratchet_round(&bob, &alice, b"pq");

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
    // Bob holds the turn after bootstrap, so the ping-pong starts with him.
    for (i, (initiator, responder)) in [(&bob, &alice), (&alice, &bob), (&bob, &alice)]
        .iter()
        .enumerate()
    {
        let payload = vec![i as u8; 8];
        ratchet_round(initiator, responder, &payload);
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
fn test_pq_side_band_frame_from_stranger_is_rejected() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    // A different session cannot open the sealed CT (its header window holds none
    // of this session's keys), so it is rejected at the seal — `Mls` on the
    // passed-through, unparseable blob — before any KEM state is consulted.
    let (a2, _b2) = establish_sessions();
    assert_err!(a2.pq_ratchet_bind(ct), TwoMlsPqError::Mls);
}

#[test]
fn test_pq_ratchet_tampered_frame_fails_to_bind() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let mut ct = assert_some!(alice.pq_take_pending_outbound());
    // Flip a byte of the sealed ciphertext frame: the header AEAD tag no longer
    // verifies, so Bob cannot open it and the bind is rejected at the seal (the
    // passed-through blob's nonce byte is not `PQ_CT_TAG`). Header encryption makes
    // any wire-level tamper a seal failure before the ML-KEM layer is reached.
    // (ML-KEM implicit rejection itself is exercised at the `apq` layer, below the
    // seal.)
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    assert_err!(bob.pq_ratchet_bind(ct), TwoMlsPqError::Mls);
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
    let alice_kp = make_classical_kp(&alice);
    assert_err!(
        TwoMlsPqSession::accept(
            bob,
            vec![0xFF; 32],
            alice_kp,
            vec![0u8; 32], // no A.4 in this test — any 32-byte commitment passes the length gate
            None
        ),
        TwoMlsPqError::Mls
    );
}

#[test]
fn test_session_id_is_same_from_both_sides() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let apq_welcome_a = assert_some!(alice_session.initial_welcome());

    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        apq_welcome_a,
        alice_kp,
        commitment_of(&alice_session),
        None
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = assert_some!(alice_session.initial_welcome());
    assert_ok!(TwoMlsPqSession::accept(
        bob,
        welcome,
        alice_kp,
        commitment_of(&alice_session),
        None
    ));
}

#[test]
fn test_join_send_group_with_my_principal_succeeds() {
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = assert_some!(alice_session.initial_welcome());
    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome,
        alice_kp,
        commitment_of(&alice_session),
        None
    ));
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
/// The whole archive/restore corpus therefore flows through `ArchiveSink` + `restore`,
/// not just the legacy whole-blob `archive()`. (Equivalent outcome — the baseline checkpoint
/// is the full state — while exercising install_sink/encode_checkpoint/reconcile.)
fn round_trip(session: &Arc<TwoMlsPqSession>) -> Arc<TwoMlsPqSession> {
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(session.install_sink(sink.clone()));
    assert_ok!(TwoMlsPqSession::restore(
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

    // A PQ side-band round (A.3 ratchet) pushes Checkpoint(s).
    ratchet_round(&bob, &alice, b"pq-round");
    assert!(
        sink.kinds()
            .iter()
            .any(|k| *k == crate::BlobKind::Checkpoint && sink.kinds().len() > 1),
        "a PQ op must push a Checkpoint"
    );

    // Restore from the newest pushed blobs and keep going.
    let restored = assert_ok!(TwoMlsPqSession::restore(
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

/// Guard-first discipline: a call that fails a precondition (or is an idempotent no-op) mutates
/// nothing, so it must neither advance `state_seq` nor push a blob. Pushing per rejected call —
/// especially a peer-replayable side-band frame that would force a full ML-KEM Checkpoint — is a
/// DoS amplifier the choke point must avoid. This pins the checks OUTSIDE `mutate_and_persist`.
#[test]
fn test_guard_first_rejection_neither_pushes_nor_bumps() {
    let (alice, bob) = establish_full();
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(alice.install_sink(sink.clone()));

    // (1) Core path — a real mutation followed by its idempotent Ok no-op: staging a fresh id
    // pushes a Core; re-staging the SAME id changes nothing and must neither bump nor push.
    assert_ok!(alice.stage_rotation(b"successor-1".to_vec()));
    let seq = alice.state_seq();
    let pushes = sink.kinds().len();
    assert_ok!(alice.stage_rotation(b"successor-1".to_vec()));
    assert_eq!(
        alice.state_seq(),
        seq,
        "an idempotent stage_rotation must not advance state_seq"
    );
    assert_eq!(
        sink.kinds().len(),
        pushes,
        "an idempotent stage_rotation must not push a blob"
    );

    // (2) Checkpoint path — a peer-replayable side-band frame that fails its guard. Bob opens an
    // A.3 with a send; Alice's respond is a real mutation (pushes a Checkpoint). A REPLAY of the
    // same EK — the peer re-sending it until Alice's CT lands — is the amplifier class: it is
    // rejected as a duplicate ABOVE the persist choke point, so it must neither bump `state_seq`
    // nor push a second full ML-KEM Checkpoint for a no-op.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek.clone()));
    let seq = alice.state_seq();
    let pushes = sink.kinds().len();
    assert_err!(
        alice.pq_ratchet_respond(ek),
        TwoMlsPqError::DuplicateSideBand
    );
    assert_eq!(
        alice.state_seq(),
        seq,
        "a rejected duplicate respond must not advance state_seq"
    );
    assert_eq!(
        sink.kinds().len(),
        pushes,
        "a rejected duplicate respond must not push a Checkpoint"
    );
}

/// Fail-closed restore: a `core` whose PQ-epoch manifest does not match the reconciling
/// `checkpoint` (a PQ op advanced without emitting a checkpoint — impossible normally, but
/// the manifest guards a lost/torn checkpoint) is rejected rather than restored spliced.
#[test]
fn test_restore_fails_closed_on_stale_checkpoint() {
    let (alice, bob) = establish_full();
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(alice.install_sink(sink.clone()));
    // The baseline checkpoint carries the pre-rekey PQ epochs.
    let stale_checkpoint = sink.latest(crate::BlobKind::Checkpoint);
    assert!(stale_checkpoint.is_some());

    // A PQ round advances alice's PQ halves (and pushes a fresh checkpoint we deliberately
    // ignore); a classical message then pushes a Core whose manifest names the NEW PQ epochs.
    ratchet_round(&bob, &alice, b"pq-round");
    message_round(&alice, &bob, b"post-rekey");
    let core = sink.latest(crate::BlobKind::Core);
    assert!(core.is_some());

    // Splicing that newer Core onto the pre-rekey checkpoint would pair classical state with a
    // stale PQ tree — the manifest catches it.
    assert_err!(
        TwoMlsPqSession::restore(core, stale_checkpoint),
        TwoMlsPqError::ArchiveInvalid
    );
}

/// A session-driven A.5 rekey is staged inside `encrypt` (a Core push), but `stage_rekey`
/// mutates the recv-PQ group (a pending update + its new leaf secret) — state only a Checkpoint
/// captures. Restoring from the A.5-staging Core spliced onto an OLDER checkpoint must still be
/// able to complete the round (the pending update + leaf secret survive the crash window).
#[test]
fn test_staged_a5_survives_core_only_push_restore() {
    let (alice, bob) = establish_full();
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(alice.install_sink(sink.clone()));

    // Rotate Alice (the non-turn-holder) and drain Bob's incidental A.3 — the turn passes to
    // Alice and her send-PQ leaf now lags. The discharge's apply pushes the last checkpoint.
    let new_alice = make_client().client_id();
    rotate_round(&alice, &bob, new_alice.clone());
    let ek = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    discharge_bind(&bob, &alice, b"deferral");

    // Alice's next send auto-stages the A.5 Upd' — the Core push under test.
    let upd = open_rekey(&alice, &bob);

    // Restore Alice from the latest pushed blobs: the Core is the A.5-staging send; the
    // checkpoint predates the staged proposal. The round must still complete.
    let core = sink.latest(crate::BlobKind::Core);
    let checkpoint = sink.latest(crate::BlobKind::Checkpoint);
    let restored = assert_ok!(TwoMlsPqSession::restore(core, checkpoint));

    assert_eq!(assert_ok!(bob.pq_rekey_respond(upd)), Some(new_alice));
    let reply = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(restored.pq_rekey_apply(reply));
    discharge_bind(&restored, &bob, b"rekey-ack");
    assert!(bob.my_pq_turn());
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = assert_some!(alice_session.initial_welcome());

    // Archive and restore the initiator BEFORE it has joined the return welcome.
    let restored_alice = round_trip(&alice_session);
    assert!(restored_alice.receive_group_id().is_none());

    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp,
        commitment_of(&alice_session),
        None
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
    let welcome = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_bind(welcome));
    discharge_bind(&alice_session, &bob_session, b"bootstrap-bind");
    assert!(alice_session.is_fully_established());

    let restored = round_trip(&alice_session);
    assert!(restored.is_fully_established());

    // The PQ side-band still runs: a full A.3 ratchet round against the restored
    // side (Bob holds the turn after the bootstrap).
    ratchet_round(&bob_session, &restored, b"pq-after-restore");
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
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(crate::key_packages::TwoMlsPqInvitation::restore(
        assert_ok!(bob.generate_invitation(true))
    ));
    let bob_kp = bob_inv.combiner_key_package();
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = assert_some!(alice_session.initial_welcome());
    let token = b"spawn-token".to_vec();
    let bob_session = assert_ok!(bob_inv.receive(
        welcome_a,
        alice_kp,
        commitment_of(&alice_session),
        token.clone(),
        None,
        None,
        None
    ));

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

/// A parked responder side-band frame survives the round trip; dropping it would
/// desync the side-band permanently. (The old shape of this test archived a parked
/// bind FRAME — a bind is the staple now and is never parked, so the responder's CT
/// is the frame that carries the property.)
#[test]
fn test_archive_preserves_parked_pq_frame() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_bind(welcome));
    discharge_bind(&alice_session, &bob_session, b"bootstrap-bind");

    // Bob initiates a ratchet round; Alice responds and parks the CT frame, then
    // archives with it parked.
    let ek = open_ratchet(&bob_session, &alice_session);
    assert_ok!(alice_session.pq_ratchet_respond(ek));
    let restored_alice = round_trip(&alice_session);

    // The parked CT is still deliverable from the restored session, and the round
    // completes against it.
    let ct = assert_some!(restored_alice.pq_take_pending_outbound());
    assert_ok!(bob_session.pq_ratchet_bind(ct));
    discharge_bind(&bob_session, &restored_alice, b"pq-msg");
}

/// A.5 rekey markers hold no secrets and archive on both sides mid-round.
#[test]
fn test_archive_mid_rekey_round_completes_after_restore() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_bind(welcome));
    discharge_bind(&alice_session, &bob_session, b"bootstrap-bind");

    // Make Bob the rekey initiator (the non-turn-holder): flip the turn to Alice, rotate Bob so
    // his leaf lags, and drain the deferral A.3 back to Bob.
    ratchet_round(&bob_session, &alice_session, b"flip");
    let new_bob = make_client().client_id();
    rotate_round(&bob_session, &alice_session, new_bob.clone());
    let drain_ek = assert_some!(alice_session.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(bob_session.pq_ratchet_respond(drain_ek));
    let drain_ct = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_ratchet_bind(drain_ct));
    discharge_bind(&alice_session, &bob_session, b"catch-up-deferral");

    // Bob opens the A.5 Upd', then archives mid-round (RekeyInitiated).
    let upd = open_rekey(&bob_session, &alice_session);
    let restored_bob = round_trip(&bob_session);

    assert_eq!(
        assert_ok!(alice_session.pq_rekey_respond(upd)),
        Some(new_bob)
    );
    // Alice archives mid-round too (RekeyResponded, parked reply survives).
    let restored_alice = round_trip(&alice_session);

    let reply = assert_some!(restored_alice.pq_take_pending_outbound());
    assert_ok!(restored_bob.pq_rekey_apply(reply));
    // The ack rides the restored initiator's next committing round; the restored
    // responder applies it from the staple.
    discharge_bind(&restored_bob, &restored_alice, b"rekey-ack");
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

/// Total archive #2: archive mid-A.3 as the INITIATOR (after the send that opened the round,
/// before the ciphertext arrives). The held ephemeral survives the jump, so the restored
/// initiator binds the responder's ciphertext and the round completes.
#[test]
fn test_archive_mid_a3_as_initiator_completes_after_restore() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_bind(welcome));
    discharge_bind(&alice_session, &bob_session, b"bootstrap-bind");

    // Bob holds the turn after the bootstrap: he is the A.3 initiator, opening it with a send.
    let ek = open_ratchet(&bob_session, &alice_session);
    // Archive Bob mid-round (Initiating, holding the ephemeral) before the ct arrives.
    let restored_bob = round_trip(&bob_session);

    // Alice responds; the restored Bob binds across the jump with his rebuilt ephemeral.
    assert_ok!(alice_session.pq_ratchet_respond(ek));
    let ct = assert_some!(alice_session.pq_take_pending_outbound());
    assert_ok!(restored_bob.pq_ratchet_bind(ct));
    discharge_bind(&restored_bob, &alice_session, b"initiator-jump");
    message_round(&restored_bob, &alice_session, b"classical-after-jump");
}

/// Total archive #3: archive mid-A.3 as the RESPONDER (after `pq_ratchet_respond`,
/// holding the shared secret S). S survives the jump, so the restored responder
/// applies the initiator's stapled bind cleanly — the desync that discarding S would
/// cause is exactly why S must be serialized.
#[test]
fn test_archive_mid_a3_as_responder_completes_after_restore() {
    let (alice_session, bob_session) = establish_sessions();
    let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
    assert_ok!(bob_session.pq_bootstrap_respond(kp));
    let welcome = assert_some!(bob_session.pq_take_pending_outbound());
    assert_ok!(alice_session.pq_bootstrap_bind(welcome));
    discharge_bind(&alice_session, &bob_session, b"bootstrap-bind");

    // Bob initiates with a send; Alice responds and holds S (having emitted the ciphertext).
    let ek = open_ratchet(&bob_session, &alice_session);
    assert_ok!(alice_session.pq_ratchet_respond(ek));
    let ct = assert_some!(alice_session.pq_take_pending_outbound());
    // Archive Alice mid-round (Responding, holding S).
    let restored_alice = round_trip(&alice_session);

    // Bob binds; the restored Alice applies the stapled bind across the jump.
    assert_ok!(bob_session.pq_ratchet_bind(ct));
    discharge_bind(&bob_session, &restored_alice, b"responder-jump");
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
/// received bytes — equals it; and the receiver's ordering `context` equals the
/// *sender's* `proposal_context` (the value the sender signs its handoff against).
/// The sender's recv group is the receiver's send group, so the receiver binds its
/// send group; binding the receiver's *own* proposal_context (its recv group) would
/// be the reverse channel and every cross-endpoint handoff signature would fail.
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
    // Cross-endpoint contract: the receiver's ordering context equals the SENDER's
    // proposal_context — the exact value the sender signed the handoff against.
    assert_eq!(
        proposal.context,
        assert_some!(bob_session.proposal_context())
    );
}

/// `PrepareEncryptResult.proposal_message` is the RAW staged Upd(self): `sha256(bytes)`
/// equals the same result's `proposal_hash` AND the receiver's independently derived
/// digest for the same rotation Upd — the coherence a signed anchor handoff relies on,
/// with bytes and digest from one critical section so no later prepare can interpose.
/// Mirrors `test_proposal_hash_is_digest_of_the_staple_both_sides_agree_on` for raw bytes.
#[test]
fn test_prepare_result_proposal_message_digests_to_the_value_both_sides_agree_on() {
    let (alice_session, bob_session) = establish_confirmed_sessions();

    let new_alice = make_client();
    let new_alice_id = new_alice.client_id();

    assert_ok!(alice_session.stage_rotation(new_alice_id.bytes.clone()));
    let prep = assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone())));

    // Sender coherence: the caller's own digest of the returned bytes is the round's
    // binding value.
    assert_eq!(crate::sha256(&prep.proposal_message), prep.proposal_hash);

    // Cross-side coherence: the receiver digests the bytes it pulls off the frame, and
    // the Upd carries the rotation candidate's credential.
    let enc = assert_ok!(alice_session.encrypt(b"rotation".to_vec()));
    let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
    let proposal = assert_some!(got.proposal);
    assert_eq!(crate::sha256(&prep.proposal_message), proposal.digest);
    assert_eq!(proposal.proposing, new_alice_id);
}

/// The anchor-onboarding moment: an acceptor fresh out of `receive(new_client_id:)` —
/// no peer frame processed yet — stages the dedicated id and prepares; the prepare's
/// `proposal_message` binds the handoff signature before its first `encrypt`. The
/// digest must already be cross-side coherent on that very first frame.
#[test]
fn test_prepare_result_proposal_message_at_establishment_binds_the_dedicated_candidate() {
    use crate::key_packages::TwoMlsPqInvitation;

    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        None
    ));
    let opened =
        assert_ok!(bob_inv.open_establishment(assert_some!(alice_session.pending_outbound())));

    let dedicated_id = make_client().client_id();
    let bob_session = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_session),
        b"anchor".to_vec(),
        Some(dedicated_id.bytes.clone()),
        None,
        None
    ));

    // Stage → prepare, all before any peer frame: the result carries the bytes, already
    // digesting to the round's binding value.
    assert_ok!(bob_session.stage_rotation(dedicated_id.bytes.clone()));
    let prep = assert_ok!(bob_session.prepare_to_encrypt(Some(dedicated_id.clone())));
    assert_eq!(crate::sha256(&prep.proposal_message), prep.proposal_hash);

    // The first frame delivers that exact Upd: the initiator derives the same digest
    // and sees the dedicated candidate's credential.
    let enc = assert_ok!(bob_session.encrypt(b"first frame".to_vec()));
    let got = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
    let proposal = assert_some!(got.proposal);
    assert_eq!(crate::sha256(&prep.proposal_message), proposal.digest);
    assert_eq!(proposal.proposing, dedicated_id);
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = assert_some!(alice_session.initial_welcome());
    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp,
        commitment_of(&alice_session),
        None
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    // Alice initiates; her welcome_a is delivered separately so Bob can accept.
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = assert_some!(alice_s.initial_welcome());
    let bob_s = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a,
        alice_kp,
        commitment_of(&alice_s),
        None
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
/// The header key length tracks the declared suite's header-AEAD key size — so a future
/// suite variant with a different-key-length cipher can't silently desync key
/// derivation from the seal. (Sanity for the crypto-agility wiring; today both are 32
/// for ChaCha20-Poly1305, `TwoMlsSuite::CURRENT.header_aead()`.)
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

/// Feature B: with a sizing intent, the auto-driven side-band frame pads up to the co-stapled
/// message's sealed length, so the two co-stapled payloads are size-indistinguishable — and the
/// padded frame still round-trips, its padding stripped on open before any decoder sees it.
#[test]
fn test_side_band_padding_equalizes_with_message() {
    let (alice, bob) = establish_full();
    bob.set_pad_target(Some(3072));
    // A message under the cap: the co-stapled A.3 EK (naturally smaller) pads up to it exactly.
    assert_ok!(bob.prepare_to_encrypt(None));
    let msg = assert_ok!(bob.encrypt(vec![7u8; 500]));
    let ek = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_eq!(
        ek.len(),
        msg.cipher_text.len(),
        "a padded side-band frame must seal to exactly the message's length"
    );
    // Round-trip: the padded EK opens (padding stripped) and drives the round to completion.
    assert_ok!(alice.process_incoming(msg.cipher_text));
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    discharge_bind(&bob, &alice, b"padded-round");
}

/// Feature B: the sizing intent is a CAP. A message larger than the target does not drag the
/// side-band frame past the push-payload budget — it pads only up to the target.
#[test]
fn test_side_band_padding_honors_the_cap() {
    let (_alice, bob) = establish_full();
    bob.set_pad_target(Some(3072));
    assert_ok!(bob.prepare_to_encrypt(None));
    let msg = assert_ok!(bob.encrypt(vec![7u8; 5000]));
    let ek = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert!(
        ek.len() < msg.cipher_text.len(),
        "an over-cap message must not equalize the frame past the budget"
    );
    // Bounded on BOTH sides: the frame is padded UP to the cap (>= 3072, else a padding-disabled
    // impl — natural EK ~1.2 KB — would pass the upper bound alone), but no further than the cap
    // (+ the 4-byte prefix and seal overhead).
    assert!(
        (3072..=3072 + 64).contains(&ek.len()),
        "the frame pads up to — and only to — the target cap, got {}",
        ek.len()
    );
}

/// Feature B: absent a sizing intent (the default), frames go out at their natural size — the
/// side-band frame is left SMALLER than its co-stapled message, not padded.
#[test]
fn test_no_pad_target_leaves_frames_natural() {
    let (_alice, bob) = establish_full();
    assert_ok!(bob.prepare_to_encrypt(None));
    let msg = assert_ok!(bob.encrypt(vec![7u8; 500]));
    let ek = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert!(
        ek.len() < msg.cipher_text.len(),
        "no pad_target ⇒ the frame stays at its natural, smaller size"
    );
}

/// Feature B: padding only ever GROWS a frame. A frame naturally larger than the target keeps its
/// natural size (the A.4 welcome / A.5 Commit' case, stood in for by a target below the EK size).
#[test]
fn test_side_band_padding_never_shrinks_a_larger_frame() {
    let (_a1, natural_sess) = establish_full();
    let (_a2, clamped_sess) = establish_full();
    clamped_sess.set_pad_target(Some(8)); // far below any real frame

    assert_ok!(natural_sess.prepare_to_encrypt(None));
    let _ = assert_ok!(natural_sess.encrypt(vec![7u8; 1]));
    let natural = assert_some!(natural_sess.pq_pending_outbound(SideBandSealing::Fresh));

    assert_ok!(clamped_sess.prepare_to_encrypt(None));
    let _ = assert_ok!(clamped_sess.encrypt(vec![7u8; 1]));
    let clamped = assert_some!(clamped_sess.pq_pending_outbound(SideBandSealing::Fresh));

    assert_eq!(
        natural.len(),
        clamped.len(),
        "a target below the frame size must not shrink it"
    );
}

/// full A.3 round drives end-to-end through sealed frames.
#[test]
fn test_sealed_side_band_opens_and_classifies() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);
    // Sealed on the wire; opens on Alice's window as the ratchet EK frame.
    assert_eq!(
        assert_some!(assert_ok!(alice.open_incoming(ek.clone()))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RatchetEphemeralKey
        }
    );
    // And the round completes through the sealed frames (receivers auto-open).
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_take_pending_outbound());
    assert_ok!(bob.pq_ratchet_bind(ct));
    discharge_bind(&bob, &alice, b"a");
}

/// The point of the PQ family: a side-band frame is keyed by `pq_epoch`, so it
/// survives classical churn that evicts the message-path window — proving it does not
/// ride the (async) classical key. Contrast: a message frame from the same pre-churn
/// moment is evicted and no longer opens.
#[test]
fn test_side_band_survives_classical_churn() {
    let (alice, bob) = establish_full();
    // Flip the turn to Alice so she can open the A.3 by sending (Bob holds it after bootstrap).
    ratchet_round(&bob, &alice, b"flip");

    // Capture two pre-churn frames Bob will try to open later: a message frame
    // (classical-keyed) and a side-band EK (PQ-keyed). Alice's send auto-stages the EK; the
    // message frame is held back, not delivered.
    assert_ok!(alice.prepare_to_encrypt(None));
    let early_message = assert_ok!(alice.encrypt(b"early".to_vec())).cipher_text;
    let ek = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));

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
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"bootstrap-bind");
    assert!(alice.is_fully_established() && bob.is_fully_established());
}

/// A restored session opens an in-flight side-band frame — the PQ window rides the
/// archive.
#[test]
fn test_restored_session_opens_in_flight_side_band() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);

    // Alice archives and restores before opening the EK.
    let restored = assert_ok!(TwoMlsPqSession::from_archive(assert_ok!(alice.archive())));
    assert_eq!(
        assert_some!(assert_ok!(restored.open_incoming(ek))).kind,
        super::OpenedFrameKind::PqSideBand {
            kind: super::PqFrameKind::RatchetEphemeralKey
        }
    );
}

/// The initiator's initial welcome (invitation channel) is NOT sealed symmetrically —
/// it has no symmetric key yet — but travels as the tagged §A.1 envelope; the
/// acceptor's return welcome (recv group live) IS sealed. The v15 payload contract:
/// an attached app payload is establishment-SELF-SUFFICIENT (it carries the welcome
/// inside — read via `initial_welcome`), and composed envelopes then omit the bare
/// sections (the either/or rule).
#[test]
fn test_initial_envelope_roundtrip_return_welcome_sealed() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    // The host payload carries the welcome inside its own framing (here a trivial
    // prefix; production wraps it in a signed identity envelope).
    const PREFIX: &[u8] = b"app-layer-welcome:";
    let welcome_a = assert_some!(alice_s.initial_welcome());
    let mut app = PREFIX.to_vec();
    app.extend_from_slice(&welcome_a);
    assert_ok!(alice_s.set_initial_app_payload(app.clone()));
    let envelope = assert_some!(alice_s.pending_outbound());
    // The frame is the opaque HPKE blob (no outer tag since contract 21): it does not begin
    // with the plaintext welcome's tag, and the welcome bytes never appear in the ciphertext.
    assert_ne!(
        envelope.first(),
        Some(&super::APQ_TAG),
        "the initial frame is the opaque HPKE envelope, not the plaintext welcome"
    );
    assert!(
        !envelope.windows(4).any(|w| w == &welcome_a[..4]),
        "the plaintext welcome must not appear in the envelope"
    );

    // Bob opens the envelope: the payload round-trips; the bare sections are omitted
    // (a present payload IS the establishment vector); the host recovers the welcome
    // from its own payload framing.
    let opened = assert_ok!(bob_inv.open_establishment(envelope));
    assert_eq!(opened.app_payload, Some(app));
    assert_eq!(
        opened.welcome, None,
        "payload present → bare welcome section omitted"
    );
    let recovered = welcome_a.clone();
    assert_eq!(recovered.first(), Some(&super::APQ_TAG));

    let bob_s = assert_ok!(bob_inv.receive(
        recovered,
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None
    ));
    // Bob's return welcome is symmetric-sealed (Bob has the recv group) and opens on
    // Alice's window to the APQWelcome.
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ne!(welcome_b.first(), Some(&super::APQ_TAG));
    assert_eq!(
        open_frame(&alice_s, &welcome_b).first(),
        Some(&super::APQ_TAG)
    );
}

/// No app payload: the envelope carries the bare welcome section (`app_payload`
/// round-trips as `None`), and the welcome still recovers.
#[test]
fn test_initial_envelope_no_app_payload() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    assert_eq!(opened.app_payload, None);
    assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None,
    ));
}

/// Part 3: the parallel bootstrap-KP frame — the verbatim `[0x13][KP′]` side-band frame
/// sealed as a RAW HPKE blob (`seal_hpke_blob`, no outer tag, no sections) — HPKE-opens and
/// dispatches to `OpenedInitial::BootstrapKp`, returning the frame byte-for-byte. This is the
/// shape the initiator ships in parallel with the reply; the inner 0x13 leading tag is what
/// tells it apart from an establishment vector after opening.
#[test]
fn test_bootstrap_kp_envelope_roundtrips() {
    use crate::key_packages::TwoMlsPqInvitation;
    let bob = make_client();
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // The verbatim 0x13 A.4 frame; the envelope never interprets it past the leading tag.
    let mut kp_frame = vec![super::PQ_BOOTSTRAP_KP_TAG];
    kp_frame.extend_from_slice(b"opaque-a4-bootstrap-frame");
    let sealed = assert_ok!(crate::key_packages::seal_hpke_blob(&bob_kp, &kp_frame));
    // `open_bootstrap_kp` requires the 0x13 dispatch (an establishment vector → `Err`), so a
    // clean open proves the inner-tag dispatch AND the verbatim round-trip.
    assert_eq!(assert_ok!(bob_inv.open_bootstrap_kp(sealed)), kp_frame);
}

/// Negative control: an establishment vector with EVERY section absent is rejected — a valid
/// reply must carry at least an `app_payload` or a `welcome` (see `decode_initial_plaintext`).
#[test]
fn test_all_empty_initial_envelope_rejected() {
    use crate::key_packages::TwoMlsPqInvitation;
    let bob = make_client();
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let sealed = assert_ok!(crate::key_packages::seal_initial_envelope(
        &bob_inv.combiner_key_package(),
        None,
        None,
        None,
        None,
    ));
    assert!(bob_inv.open_initial(sealed).is_err());
}

/// Part 3 end-to-end: the initiator delivers its A.4 KP′ IN PARALLEL with the establishment
/// reply, and A.4 completes with NO separate post-establishment `pq_bootstrap_begin` round.
/// The acceptor opens the early bootstrap-only envelope, HOLDS the KP′ until the reply
/// establishes its session, then feeds it to `pq_bootstrap_respond` and sends `Welcome'`
/// alongside its return welcome; the initiator — whose emit registered the A.4 round and
/// carried it through the establishment cutover — binds the early `Welcome'`. Proves the
/// verbatim carriage into `respond` and that the round registration survives the cutover.
#[test]
fn test_parallel_bootstrap_completes_a4_without_a_begin_round() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    // Read the commitment BEFORE emitting: the emit consumes the pre-committed KP and quiets
    // the accessor (in the app the host reads it at reply time, before the parallel send).
    let commitment = commitment_of(&alice_s);

    // Alice emits the parallel bootstrap envelope + her reply (coin-flipped on the wire).
    let env_kp = assert_ok!(alice_s.pq_bootstrap_envelope());
    let env_reply = assert_some!(alice_s.pending_outbound());

    // Bob opens the parallel envelope and HOLDS the KP′ (dispatched by its inner 0x13 tag).
    let held_kp = assert_ok!(bob_inv.open_bootstrap_kp(env_kp));

    // Bob opens the reply and establishes.
    let opened_reply = assert_ok!(bob_inv.open_establishment(env_reply));
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened_reply.welcome),
        alice_kp,
        commitment,
        b"tok".to_vec(),
        None,
        None,
        None,
    ));

    // Bob feeds the held KP′ to respond — standing up its deferred send-PQ half — and can
    // now send Welcome' alongside its return welcome (the latency win).
    assert_ok!(bob_s.pq_bootstrap_respond(held_kp));
    let welcome_prime = assert_some!(bob_s.pq_take_pending_outbound());
    let return_welcome = assert_some!(bob_s.pending_outbound());

    // Alice establishes off the return welcome, then binds the EARLY Welcome' — her emit
    // registered the A.4 round, so no separate `pq_bootstrap_begin` was ever called.
    assert_ok!(alice_s.process_incoming(return_welcome));
    assert!(alice_s.is_established());
    assert_ok!(alice_s.pq_bootstrap_bind(welcome_prime));
    discharge_bind(&alice_s, &bob_s, b"parallel-bind");

    assert!(alice_s.is_fully_established());
    assert!(bob_s.is_fully_established());
    assert!(bob_s.epochs().pq_epoch > 0);
}

/// Part 3 delta #3 — retriability of an EARLY `Welcome'`. Registering the A.4 round at emit
/// (pre-establishment) makes it reachable for a reordered `Welcome'` to arrive before the
/// initiator has joined its classical half. Binding it then is a NON-CORRUPTING, retriable
/// failure (guard-first — the pre-committed secret is never spent), and the SAME welcome
/// binds intact once the return welcome establishes the session.
#[test]
fn test_parallel_bootstrap_welcome_before_establishment_is_retriable() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let commitment = commitment_of(&alice_s);
    let env_kp = assert_ok!(alice_s.pq_bootstrap_envelope());
    let env_reply = assert_some!(alice_s.pending_outbound());
    let held_kp = assert_ok!(bob_inv.open_bootstrap_kp(env_kp));
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(assert_ok!(bob_inv.open_establishment(env_reply)).welcome),
        alice_kp,
        commitment,
        b"tok".to_vec(),
        None,
        None,
        None,
    ));
    assert_ok!(bob_s.pq_bootstrap_respond(held_kp));
    let welcome_prime = assert_some!(bob_s.pq_take_pending_outbound());
    let return_welcome = assert_some!(bob_s.pending_outbound());

    // Bind BEFORE establishing (no classical half yet): a non-corrupting, retriable error —
    // and GUARD-FIRST: the recv-group guard rejects it before the persist choke point, so a
    // replayed early Welcome' cannot force a Checkpoint push per replay (the amplification
    // the guard block exists to prevent). The sink count proves it.
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(alice_s.install_sink(sink.clone()));
    let persists_before = sink.kinds().len();
    assert!(alice_s.pq_bootstrap_bind(welcome_prime.clone()).is_err());
    assert!(alice_s.pq_bootstrap_bind(welcome_prime.clone()).is_err());
    assert_eq!(
        sink.kinds().len(),
        persists_before,
        "a pre-establishment Welcome' must be rejected guard-first, persisting nothing"
    );
    assert!(!alice_s.is_fully_established());

    // Establish, then the SAME welcome binds — the retry is intact.
    assert_ok!(alice_s.process_incoming(return_welcome));
    assert_ok!(alice_s.pq_bootstrap_bind(welcome_prime));
    discharge_bind(&alice_s, &bob_s, b"retried-bind");
    assert!(alice_s.is_fully_established());
    assert!(bob_s.is_fully_established());
}

/// `pq_take_pending_outbound` in the pre-establishment window the parallel envelope creates
/// is a guarded no-op, NOT a destructive take: there is no side-band to take from yet, and
/// the parked `[0x13][KP′]` is the round's only carrier (an unguarded take would swallow the
/// doomed seal and persist the stranded slot — an unhealable A.4).
#[test]
fn test_take_pending_outbound_pre_establishment_leaves_bootstrap_round_intact() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let commitment = commitment_of(&alice_s);
    let env_kp = assert_ok!(alice_s.pq_bootstrap_envelope());

    // The guarded no-op: nothing to take on the side-band pre-establishment...
    assert!(alice_s.pq_take_pending_outbound().is_none());
    // ...and the round's carrier survived — the parallel envelope still re-sends.
    assert_ok!(alice_s.pq_bootstrap_envelope());

    // The round completes end-to-end afterwards.
    let env_reply = assert_some!(alice_s.pending_outbound());
    let held_kp = assert_ok!(bob_inv.open_bootstrap_kp(env_kp));
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(assert_ok!(bob_inv.open_establishment(env_reply)).welcome),
        alice_kp,
        commitment,
        b"tok".to_vec(),
        None,
        None,
        None,
    ));
    assert_ok!(bob_s.pq_bootstrap_respond(held_kp));
    let welcome_prime = assert_some!(bob_s.pq_take_pending_outbound());
    let return_welcome = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(return_welcome));
    assert_ok!(alice_s.pq_bootstrap_bind(welcome_prime));
    discharge_bind(&alice_s, &bob_s, b"take-guarded");
    assert!(alice_s.is_fully_established());
    assert!(bob_s.is_fully_established());
}

/// After the parallel envelope registered the A.4 round, `pq_bootstrap_begin` is IDEMPOTENT —
/// it re-seals and returns the retained frame (no state change) instead of erroring — so a
/// host that keeps its standard post-establishment A.4 kickoff after adopting the parallel
/// envelope self-heals a dropped parallel frame through the classic flow.
#[test]
fn test_bootstrap_begin_idempotent_after_parallel_envelope() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let commitment = commitment_of(&alice_s);
    // The parallel KP frame is emitted... and DROPPED in transit.
    let _dropped = assert_ok!(alice_s.pq_bootstrap_envelope());

    // Establishment completes without it.
    let env_reply = assert_some!(alice_s.pending_outbound());
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(assert_ok!(bob_inv.open_establishment(env_reply)).welcome),
        alice_kp,
        commitment,
        b"tok".to_vec(),
        None,
        None,
        None,
    ));
    let return_welcome = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(return_welcome));

    // The standard post-establishment kickoff: idempotent re-send, not SessionNotReady —
    // and the frame it returns drives the round to completion.
    let kp_frame = assert_ok!(alice_s.pq_bootstrap_begin(None));
    assert_ok!(bob_s.pq_bootstrap_respond(kp_frame));
    let welcome_prime = assert_some!(bob_s.pq_take_pending_outbound());
    assert_ok!(alice_s.pq_bootstrap_bind(welcome_prime));
    discharge_bind(&alice_s, &bob_s, b"begin-idempotent");
    assert!(alice_s.is_fully_established());
    assert!(bob_s.is_fully_established());
}

/// Part 3 — register-once, re-seal-per-send PURE. The first `pq_bootstrap_envelope` registers
/// the A.4 round (one Checkpoint); every later pre-cutover emit re-seals the SAME retained KP′
/// under a FRESH HPKE ephemeral (distinct ciphertext, unlinkable) WITHOUT advancing state — so
/// no extra Checkpoint is pushed. Both envelopes open to the identical verbatim `[0x13][KP′]`.
#[test]
fn test_parallel_bootstrap_envelope_reseals_fresh_without_extra_checkpoint() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));

    let sink = Arc::new(RecordingSink::default());
    // `install_sink` pushes exactly one baseline Checkpoint.
    assert_ok!(alice_s.install_sink(sink.clone()));
    assert_eq!(sink.kinds(), vec![crate::BlobKind::Checkpoint]);

    // First emit REGISTERS the round → one more Checkpoint.
    let env1 = assert_ok!(alice_s.pq_bootstrap_envelope());
    assert_eq!(
        sink.kinds(),
        vec![crate::BlobKind::Checkpoint, crate::BlobKind::Checkpoint],
        "the first emit registers the A.4 round with a Checkpoint"
    );

    // Second emit is a PURE re-seal → fresh ciphertext, NO extra Checkpoint.
    let env2 = assert_ok!(alice_s.pq_bootstrap_envelope());
    assert_ne!(
        env1, env2,
        "fresh HPKE per send — the re-seals are unlinkable"
    );
    assert_eq!(
        sink.kinds().len(),
        2,
        "re-seal-per-send is pure — no extra Checkpoint"
    );

    // Both envelopes carry the identical verbatim `[0x13][KP′]` frame.
    let f1 = assert_ok!(bob_inv.open_bootstrap_kp(env1));
    let f2 = assert_ok!(bob_inv.open_bootstrap_kp(env2));
    assert_eq!(f1, f2);
    assert_eq!(f1.first(), Some(&super::PQ_BOOTSTRAP_KP_TAG));
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
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));

    let dedicated = crate::test_utils::test_client_id();
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        Some(dedicated.clone()),
        None,
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
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    assert!(matches!(
        bob_inv.receive(
            assert_some!(opened.welcome.clone()),
            alice_kp.clone(),
            commitment_of(&alice_s),
            b"tok".to_vec(),
            Some(Vec::new()),
            None,
            None
        ),
        Err(TwoMlsPqError::InvalidClientId)
    ));
    assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None,
    ));

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
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    let dedicated = crate::test_utils::test_client_id();
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        Some(dedicated.clone()),
        None,
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
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    let dedicated = crate::test_utils::test_client_id();
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        Some(dedicated.clone()),
        None,
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
    let welcome = assert_some!(bob_s.pq_take_pending_outbound());
    assert_ok!(alice_s.pq_bootstrap_bind(welcome));
    discharge_bind(&alice_s, &bob_s, b"bootstrap-bind");
    assert!(alice_s.is_fully_established());
    assert!(bob_s.is_fully_established());

    // A.3 ratchet round end-to-end.
    ratchet_round(&bob_s, &alice_s, b"pq-app");

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
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // Two independent initiations to the same KP seal different outer bytes…
    let a1 = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp.clone(),
        None
    ));
    assert_ok!(a1.set_initial_app_payload(b"p".to_vec()));
    let e1 = assert_some!(a1.pending_outbound());
    let a2 = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    assert_ok!(a2.set_initial_app_payload(b"p".to_vec()));
    let e2 = assert_some!(a2.pending_outbound());
    assert_ne!(
        e1, e2,
        "fresh HPKE ephemeral per seal → different outer bytes"
    );
    // …but each opens to an app_payload the host can key a stable token on.
    assert_eq!(
        assert_ok!(bob_inv.open_establishment(e1)).app_payload,
        Some(b"p".to_vec())
    );
    assert_eq!(
        assert_ok!(bob_inv.open_establishment(e2)).app_payload,
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
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(false)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // Alice consumes the single-use invitation.
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp.clone(),
        None
    ));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None,
    ));

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
        assert_some!(alice_s.initial_welcome()).first(),
        Some(&super::APQ_TAG)
    );
    assert_ne!(
        assert_some!(alice_s.pending_outbound()).first(),
        Some(&super::APQ_TAG)
    );
}

// ---------------------------------------------------------------------------
// §A.1 pre-establishment sends (v15): the initiator sends app messages
// immediately after `initiate`, before the acceptor's return welcome — each
// frame a fresh §A.1 envelope re-stapling the establishment sections plus the
// app message. See prepare_pre_establishment / compose_initial_envelope.
// ---------------------------------------------------------------------------

/// Live replier-first (bare envelope shape): two pre-establishment sends; the acceptor
/// joins from the FIRST frame alone (welcome + return KP ride it) and reads its staple;
/// the SECOND frame routes to the spawned session via the content-keyed processed
/// ledger. The acceptor's reply then establishes the initiator, whose next send takes
/// the normal 0x03 path.
#[test]
fn test_pre_establishment_sends_acceptor_joins_from_restaple() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        None
    ));
    assert_ok!(alice_s.set_initial_return_key_package(alice_kp));
    let welcome_a = assert_some!(alice_s.initial_welcome());

    // Pre-establishment prepare is a NO-OP round: nothing staged, nothing committed;
    // the hash is the WELCOME digest (the AAD binding to the establishment vector).
    let prep = assert_ok!(alice_s.prepare_to_encrypt(None));
    assert!(prep.proposal_message.is_empty());
    assert!(!prep.did_commit);
    assert!(prep.committed_remote_client_id.is_none());
    assert_eq!(prep.proposal_hash, crate::sha256(&welcome_a));

    let frame1 = assert_ok!(alice_s.encrypt(b"hello-1".to_vec()));
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let frame2 = assert_ok!(alice_s.encrypt(b"hello-2".to_vec()));
    assert_ne!(frame1.cipher_text, frame2.cipher_text);
    // Each pre-establishment frame is a fresh opaque HPKE envelope (no outer tag since
    // contract 21): distinct bytes per send (above), and not the plaintext welcome.
    assert_ne!(frame1.cipher_text.first(), Some(&super::APQ_TAG));

    // Frame 1 alone is a complete establishment vector: welcome + return KP + staple.
    let opened1 = assert_ok!(bob_inv.open_establishment(frame1.cipher_text));
    let w1 = assert_some!(opened1.welcome);
    assert_eq!(w1, welcome_a, "the stable prefix is the birth welcome");
    let kp1 = assert_some!(opened1.return_key_package);
    let bob_s = assert_ok!(bob_inv.receive(
        w1,
        kp1,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None
    ));
    let got1 = assert_some!(assert_ok!(
        bob_s.process_incoming(assert_some!(opened1.stapled_message))
    ));
    let app1 = assert_some!(got1.application_message);
    assert_eq!(app1.app_message_data, b"hello-1");
    assert!(got1.proposal.is_none(), "a 0x13 staple carries no proposal");
    assert!(got1.remote_commit.is_none());

    // Frame 2: same welcome → the content-keyed ledger routes to the spawned session
    // (a second `receive` would reject it as DuplicateWelcome); its staple delivers.
    let opened2 = assert_ok!(bob_inv.open_establishment(frame2.cipher_text));
    let w2 = assert_some!(opened2.welcome);
    let owner = assert_some!(bob_inv.processed_welcome_group_id(w2));
    assert_eq!(
        owner.bytes,
        assert_some!(bob_s.receive_group_id()).classical.bytes
    );
    let got2 = assert_some!(assert_ok!(
        bob_s.process_incoming(assert_some!(opened2.stapled_message))
    ));
    assert_eq!(
        assert_some!(got2.application_message).app_message_data,
        b"hello-2"
    );

    // The acceptor's reply establishes the initiator; sends switch to the 0x03 path.
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(welcome_b));
    message_round(&alice_s, &bob_s, b"post-establishment");
    message_round(&bob_s, &alice_s, b"both-ways");
}

/// THE REPRO MIRROR (germDM `restoredReplierSendsFirst`): the initiator is captured at
/// birth — attach setters FIRST (the documented capture-ordering contract), then a
/// fresh sink's install-time baseline checkpoint with NO core blob — and restored.
/// The restored replier must send first: restore → prepare/encrypt → encrypt again
/// (multiple re-staples), the acceptor joins from a re-staple, and establishment
/// completes across the restore boundary.
#[test]
fn test_birth_captured_replier_restores_send_ready() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));

    let live = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        None
    ));
    // Capture ordering: attach BEFORE the capture — the retained state must ride it.
    assert_ok!(live.set_initial_return_key_package(alice_kp));

    // The app's capture shape: a fresh sink's baseline checkpoint is the whole
    // capture; no classical mutation has pushed a core (`core: None`).
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(live.install_sink(sink.clone()));
    assert_eq!(sink.kinds(), vec![crate::BlobKind::Checkpoint]);
    assert!(sink.latest(crate::BlobKind::Core).is_none());
    let restored = assert_ok!(TwoMlsPqSession::restore(
        None,
        sink.latest(crate::BlobKind::Checkpoint),
    ));
    drop(live);
    assert_ok!(restored.install_sink(Arc::new(RecordingSink::default())));

    // Send-first from the restored object — twice (fresh envelopes each time).
    assert_ok!(restored.prepare_to_encrypt(None));
    let frame1 = assert_ok!(restored.encrypt(b"first".to_vec()));
    assert_ok!(restored.prepare_to_encrypt(None));
    let frame2 = assert_ok!(restored.encrypt(b"second".to_vec()));

    // The acceptor joins from the SECOND frame (any single frame suffices) and reads
    // both staples' messages in order of arrival.
    let opened2 = assert_ok!(bob_inv.open_establishment(frame2.cipher_text));
    let kp = assert_some!(opened2.return_key_package);
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened2.welcome),
        kp,
        commitment_of(&restored),
        b"tok".to_vec(),
        None,
        None,
        None
    ));
    assert_eq!(
        assert_some!(
            assert_some!(assert_ok!(
                bob_s.process_incoming(assert_some!(opened2.stapled_message))
            ))
            .application_message
        )
        .app_message_data,
        b"second"
    );
    // Frame 1 arrives late (out of order): same welcome routes via the ledger; its
    // staple still decrypts (mls-rs generation skipping).
    let opened1 = assert_ok!(bob_inv.open_establishment(frame1.cipher_text));
    assert_some!(bob_inv.processed_welcome_group_id(assert_some!(opened1.welcome)));
    assert_eq!(
        assert_some!(
            assert_some!(assert_ok!(
                bob_s.process_incoming(assert_some!(opened1.stapled_message))
            ))
            .application_message
        )
        .app_message_data,
        b"first"
    );

    // Establishment completes across the restore boundary.
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ok!(restored.process_incoming(welcome_b));
    message_round(&restored, &bob_s, b"restored->bob");
    message_round(&bob_s, &restored, b"bob->restored");
}

/// The establishment cutover: processing the acceptor's return welcome clears the
/// retained envelope state (observable: the parked envelope is gone) and STALES a
/// pre-establishment prepare that straddled it — the paired encrypt is rejected
/// instead of emitting an envelope the peer no longer needs (or a malformed 0x03).
#[test]
fn test_cutover_clears_envelope_state_and_stales_straddling_prepare() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        None
    ));
    assert_ok!(alice_s.set_initial_return_key_package(alice_kp));
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let frame = assert_ok!(alice_s.encrypt(b"pre".to_vec()));

    let opened = assert_ok!(bob_inv.open_establishment(frame.cipher_text));
    let kp = assert_some!(opened.return_key_package);
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None
    ));

    // A pre-establishment prepare straddles the cutover…
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(welcome_b));
    // …the parked envelope is cleared (nothing left to take)…
    assert!(alice_s.pending_outbound().is_none());
    // …and the stale prepare is rejected without burning a message generation.
    assert_err!(
        alice_s.encrypt(b"stale".to_vec()),
        TwoMlsPqError::SessionNotReady
    );
    // A fresh round takes the normal 0x03 path.
    message_round(&alice_s, &bob_s, b"fresh-round");
}

/// Pre-establishment guard rails: a rotation selection cannot ride (no recv group
/// carries an Upd), the attach setters are initiator-only + pre-establishment-only,
/// and a misfed envelope on an established session fails loudly without state.
#[test]
fn test_pre_establishment_guards() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        None
    ));
    // No recv group to carry a rotation Upd.
    assert_err!(
        alice_s.prepare_to_encrypt(Some(crate::ClientId {
            bytes: b"candidate".to_vec()
        })),
        TwoMlsPqError::SessionNotReady
    );

    // Establish, then: setters are pre-establishment-only on the initiator…
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let frame = assert_ok!(alice_s.encrypt(b"pre".to_vec()));
    let opened = assert_ok!(bob_inv.open_establishment(frame.cipher_text));
    let bob_s = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None
    ));
    let welcome_b = assert_some!(bob_s.pending_outbound());
    assert_ok!(alice_s.process_incoming(welcome_b));
    assert_err!(
        alice_s.set_initial_app_payload(b"late".to_vec()),
        TwoMlsPqError::SessionNotReady
    );
    // …and acceptor sessions never accept them (no retained seal target).
    assert_err!(
        bob_s.set_initial_app_payload(b"acceptor".to_vec()),
        TwoMlsPqError::SessionNotReady
    );

    // A §A.1 envelope misfed to an established session: `open_incoming` cannot open
    // it (silent None), and `process_incoming` rejects it loudly — no state touched.
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let post = assert_ok!(alice_s.encrypt(b"post".to_vec()));
    assert_some!(assert_ok!(bob_s.process_incoming(post.cipher_text)));
    let stray = {
        let carol = make_client();
        let carol_s = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&carol),
            bob_inv.combiner_key_package(),
            None
        ));
        assert_ok!(carol_s.prepare_to_encrypt(None));
        assert_ok!(carol_s.encrypt(b"stray".to_vec())).cipher_text
    };
    assert!(assert_ok!(bob_s.open_incoming(stray.clone())).is_none());
    let seq = bob_s.state_seq();
    assert_err!(
        bob_s.process_incoming(stray),
        TwoMlsPqError::DecryptionFailed
    );
    assert_eq!(
        bob_s.state_seq(),
        seq,
        "a rejected envelope must not mutate"
    );
}

/// Routing metadata is unauthenticated (the envelope seals to a PUBLIC key): a forged
/// envelope pairing a legitimate welcome with a staple from another group routes to
/// the owning session, whose group decrypt rejects the staple — fail-open drop, no
/// state. All consequential state keys off the signed, JOINED welcome.
#[test]
fn test_spliced_staple_fails_open_at_group_decrypt() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let carol = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    // Alice establishes toward Bob's invitation (pre-establishment frame).
    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp.clone(),
        None
    ));
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let frame_a = assert_ok!(alice_s.encrypt(b"real".to_vec()));
    let opened_a = assert_ok!(bob_inv.open_establishment(frame_a.cipher_text));
    let welcome_a = assert_some!(opened_a.welcome);
    let bob_s = assert_ok!(bob_inv.receive(
        welcome_a.clone(),
        alice_kp,
        commitment_of(&alice_s),
        b"tok".to_vec(),
        None,
        None,
        None
    ));

    // Carol (any envelope author — the seal target is public) forges an envelope
    // splicing Alice's welcome with a staple from CAROL's group.
    let carol_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
    assert_ok!(carol_s.prepare_to_encrypt(None));
    let frame_c = assert_ok!(carol_s.encrypt(b"carol".to_vec()));
    let carol_staple =
        assert_some!(assert_ok!(bob_inv.open_establishment(frame_c.cipher_text)).stapled_message);
    let forged = assert_ok!(crate::key_packages::seal_initial_envelope(
        &bob_inv.combiner_key_package(),
        None,
        Some(&welcome_a),
        None,
        Some(&carol_staple),
    ));

    // The welcome routes to Alice's spawned session — where the spliced staple fails
    // group decrypt and is dropped fail-open, mutating nothing.
    let opened_forged = assert_ok!(bob_inv.open_establishment(forged));
    assert_some!(bob_inv.processed_welcome_group_id(assert_some!(opened_forged.welcome)));
    let seq = bob_s.state_seq();
    assert_err!(
        bob_s.process_incoming(assert_some!(opened_forged.stapled_message)),
        TwoMlsPqError::DecryptionFailed
    );
    assert_eq!(bob_s.state_seq(), seq);
}

/// The attach setters regenerate the parked envelope under the either/or rule, and
/// frames re-stapling the attached material gate on the setter's own persisted seq
/// (`depends_on_seq`).
#[test]
fn test_setters_regenerate_envelope_and_stamp_depends_on_seq() {
    use crate::key_packages::TwoMlsPqInvitation;
    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        None
    ));
    let sink = Arc::new(RecordingSink::default());
    assert_ok!(alice_s.install_sink(sink.clone()));

    // Bare shape first: the return KP rides.
    assert_ok!(alice_s.set_initial_return_key_package(alice_kp));
    let seq_after_kp = alice_s.state_seq();
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    assert_some!(opened.welcome);
    assert_some!(opened.return_key_package);
    assert!(opened.app_payload.is_none());

    // Frames depend on the attach mutation being durable.
    assert_ok!(alice_s.prepare_to_encrypt(None));
    let frame = assert_ok!(alice_s.encrypt(b"gated".to_vec()));
    assert_eq!(frame.depends_on_seq, seq_after_kp);

    // Attaching a (self-sufficient) payload switches to the payload-only shape.
    let welcome = assert_some!(alice_s.initial_welcome());
    let mut payload = b"identity:".to_vec();
    payload.extend_from_slice(&welcome);
    assert_ok!(alice_s.set_initial_app_payload(payload.clone()));
    let opened = assert_ok!(bob_inv.open_establishment(assert_some!(alice_s.pending_outbound())));
    assert_eq!(opened.app_payload, Some(payload));
    assert!(
        opened.welcome.is_none(),
        "payload supersedes the bare sections"
    );
    assert!(opened.return_key_package.is_none());
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

    // Freeze a stale copy of Bob. A LOSSY LINK can no longer produce a two-ahead
    // staple: every classical commit is fold-gated (it needs a peer proposal at the
    // current epoch), so a second commit cannot exist until the peer provably applied
    // the first — the old construction rode the A.3 bind's unilateral classical
    // commit, which is gone. A receiver restored from a stale archive is what still
    // meets one.
    let stale_bob = round_trip(&bob_session);

    // Two approved-commit rounds advance Alice's send group two epochs, with the
    // LIVE Bob participating.
    approved_commit_round(&alice_session, &bob_session);
    approved_commit_round(&alice_session, &bob_session);

    // Alice's next frame staples only the LATEST commit: two ahead of the stale
    // restore's recv group, which no frame can bridge — the desync must surface
    // distinguishably, before the app ciphertext is touched.
    assert_ok!(alice_session.prepare_to_encrypt(None));
    let ahead = assert_ok!(alice_session.encrypt(b"ahead".to_vec()));
    assert_err!(
        stale_bob.process_incoming(ahead.cipher_text),
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
    let foreign_welcome = assert_some!(carol_session.initial_welcome());

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

/// v15 (§A.1): `prepare_to_encrypt` BEFORE establishment is a valid NO-OP round on the
/// initiated side, and the paired `encrypt` emits a §A.1 envelope. (Pre-v15 this
/// returned `SessionNotReady` — the replier could not send first.)
#[test]
fn test_prepare_to_encrypt_before_established_is_noop_round() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);
    let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp, None));
    let prep = assert_ok!(session.prepare_to_encrypt(None));
    assert!(prep.proposal_message.is_empty() && !prep.did_commit);
    // The replier can send first: encrypt emits a §A.1 envelope — an opaque HPKE blob (no
    // outer tag since contract 21), not the plaintext welcome.
    let frame = assert_ok!(session.encrypt(b"first".to_vec()));
    assert!(!frame.cipher_text.is_empty());
    assert_ne!(frame.cipher_text.first(), Some(&super::APQ_TAG));
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome = assert_some!(alice_session.initial_welcome());
    let bob_session = assert_ok!(TwoMlsPqSession::accept(
        bob,
        welcome,
        alice_kp,
        commitment_of(&alice_session),
        None
    ));
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
    let alice_kp = make_classical_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);

    let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
    let welcome_a = assert_some!(alice_s.initial_welcome());
    let bob_s = assert_ok!(TwoMlsPqSession::accept(
        Arc::clone(&bob),
        welcome_a.clone(),
        alice_kp,
        commitment_of(&alice_s),
        None
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
    // A byte the space does not assign at all (0x31 — past every band; see frames.rs) fails
    // loudly too. This must stay UNALLOCATED, and has now drifted twice: it read 0x13 until
    // the tag renumber made that the A.3 bind, then 0x19 until banding made that the A.3
    // ciphertext. A side-band tag reaching process_incoming returns SessionNotReady — the
    // host is meant to route those by `pq_frame_kind` — which is a different rejection than
    // the one under test, so the assertion would still pass while testing nothing.
    assert_err!(
        alice_session.process_incoming(vec![0x31, 0x00]),
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
    let welcome = assert_some!(alice_s.initial_welcome());
    // Swap the welcome's two halves so each slot's cleartext cipher suite is wrong for the
    // acceptor's expected pair — caught pre-join, not as a late decrypt failure.
    let (classical, pq) = assert_ok!(apq::decode_apq_welcome(&welcome));
    let swapped = apq::encode_apq_welcome(pq, classical);
    let alice_kp = make_classical_kp(&alice);
    assert_err!(
        TwoMlsPqSession::accept(
            Arc::clone(&bob),
            swapped,
            alice_kp,
            commitment_of(&alice_s),
            None
        ),
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
    let welcome = assert_some!(bob.pq_take_pending_outbound());
    assert_ok!(alice.pq_bootstrap_bind(welcome));
    discharge_bind(&alice, &bob, b"bootstrap-bind");

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
/// and the staple arm verifies the two copies agree AND match the actual post-apply
/// epochs of both groups before decrypting the frame's app message — so a clean
/// delivery is proof the attestation verified end to end. Both directions
/// (turn-flipped) exercise it. (The epoch-arithmetic rejection itself is unit-tested
/// at the apq layer, where a mismatched attestation can be crafted directly.)
#[test]
fn test_a3_bind_full_round_verifies_attestation_both_directions() {
    let (alice, bob) = establish_full();
    // Bob holds the turn after bootstrap, so he goes first.
    ratchet_round(&bob, &alice, b"b-to-a");
    // Turn flipped to Alice; her bind's attestation verifies on Bob's apply too.
    ratchet_round(&alice, &bob, b"a-to-b");
}

/// The A.5 side-band Commit' must not carry an AppDataUpdate — the round's reconciliation is the
/// stapled ACK's job (a conformant FULL commit pair). A full rotation-driven A.5 round completes
/// cleanly under the receiver checks: `pq_rekey_apply` accepts a Commit' precisely because it
/// carries no attestation (a smuggled one would be rejected there), so a clean apply is the proof.
#[test]
fn test_a5_rekey_round_completes_without_attestation() {
    let (alice, bob) = establish_full();
    let alice_pq = alice.epochs().pq_epoch;
    let bob_pq = bob.epochs().pq_epoch;
    let new_alice = make_client().client_id();
    rekey_round(&alice, &bob, new_alice);
    // Both send-PQ epochs advanced; the round completed through the (attestation-free) Commit'.
    assert!(alice.epochs().pq_epoch > alice_pq);
    assert!(bob.epochs().pq_epoch > bob_pq);
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
/// (v3), and blobs framed with any prior version byte are rejected outright (the
/// capability hard-cuts: v2 leaves lack the AppBinding advertisement, v1 the
/// APQInfo/AppDataUpdate ones).
#[test]
fn test_combiner_kp_v3_round_trips_and_rejects_prior_versions() {
    let client = make_client();
    let kp = make_combiner_kp(&client);
    let encoded = crate::key_packages::encode_combiner_key_package(kp.clone());
    assert_eq!(encoded[0], 3, "version byte is 3");
    let decoded = assert_ok!(crate::key_packages::decode_combiner_key_package(
        encoded.clone()
    ));
    assert_eq!(decoded.classical, kp.classical);
    assert_eq!(decoded.pq, kp.pq);

    // A v2 blob (identical payload, pre-AppBinding capability cut) is rejected.
    let mut v2 = encoded;
    v2[0] = 2;
    assert_err!(
        crate::key_packages::decode_combiner_key_package(v2),
        TwoMlsPqError::InvalidKeyPackage
    );

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

/// The AppBinding rides the persisted group state: a session established with a binding
/// reads back the same bytes after a push-persistence restore — the re-verification hook
/// a restored session's owner uses to confirm the session still belongs to the
/// relationship it was pinned to — and an unbound session reads back `None`.
#[test]
fn test_app_binding_survives_archive_restore() {
    use crate::key_packages::TwoMlsPqInvitation;

    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let binding = b"relationship-digest".to_vec();

    let bob_inv = assert_ok!(TwoMlsPqInvitation::restore(assert_ok!(
        bob.generate_invitation(true)
    )));
    let bob_kp = bob_inv.combiner_key_package();

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp,
        Some(binding.clone())
    ));
    let envelope = assert_some!(alice_session.pending_outbound());
    let opened = assert_ok!(bob_inv.open_establishment(envelope));
    let bob_session = assert_ok!(bob_inv.receive(
        assert_some!(opened.welcome),
        alice_kp,
        commitment_of(&alice_session),
        b"token".to_vec(),
        None,
        None,
        Some(binding.clone()),
    ));
    let welcome_b = assert_some!(bob_session.pending_outbound());
    assert_ok!(alice_session.process_incoming(welcome_b));
    message_round(&alice_session, &bob_session, b"before");

    // Both roles read the binding back after a restore, and messaging continues.
    let restored_alice = round_trip(&alice_session);
    assert_eq!(
        assert_ok!(restored_alice.app_binding()),
        Some(binding.clone())
    );
    let restored_bob = round_trip(&bob_session);
    assert_eq!(assert_ok!(restored_bob.app_binding()), Some(binding));
    message_round(&restored_alice, &restored_bob, b"after-restore");

    // An unbound session reads back None on the same getter.
    let (unbound, _) = establish_sessions();
    assert_eq!(assert_ok!(unbound.app_binding()), None);
}

/// The initiator refuses a return welcome that does not carry its own binding back: the
/// acceptor is required to mirror the (verified) incoming binding, so a stripped return
/// group — crafted here with the apq primitives below the session layer — fails the
/// return-welcome join with `AppBindingMismatch`, and the receive side stays unjoined.
#[test]
fn test_return_welcome_without_app_binding_rejected() {
    use apq::{create_bound_classical_send_group, encode_apq_welcome, join_combiner_group};

    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_combiner_kp(&alice);
    let bob_kp = make_combiner_kp(&bob);
    let binding = b"relationship-digest".to_vec();

    let alice_session = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_kp,
        Some(binding)
    ));
    let welcome_a = assert_some!(alice_session.initial_welcome());

    // Bob's side, hand-built below the session layer: join alice's welcome, then mint
    // the bound return group WITHOUT mirroring the binding (the strip).
    let mut bob_recv = assert_ok!(join_combiner_group(&welcome_a, bob.combiner()));
    let (_bob_send, classical_welcome) = assert_ok!(create_bound_classical_send_group(
        &alice_kp.classical,
        bob.combiner(),
        &mut bob_recv.classical,
        None,
    ));
    let welcome_b = encode_apq_welcome(classical_welcome, Vec::new());

    // Alice's return-welcome join refuses it before adopting any state.
    let mut inner = alice_session.lock();
    assert_err!(
        inner.process_welcome(&welcome_b),
        TwoMlsPqError::AppBindingMismatch
    );
    assert!(inner.recv_group.is_none());
}

/// An EMPTY binding is reserved as invalid: `initiate` rejects it up front (before even
/// the AS peer admission inside group creation), so an accidentally empty digest cannot
/// mint a session "bound" to nothing — `None` is the deliberate unbound state.
#[test]
fn test_initiate_rejects_empty_app_binding() {
    let alice = make_client();
    let bob = make_client();
    let bob_kp = make_combiner_kp(&bob);

    assert_err!(
        TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp.clone(), Some(Vec::new())),
        TwoMlsPqError::AppBindingMismatch
    );
    // The same client and key package still establish with a real binding.
    assert_ok!(TwoMlsPqSession::initiate(
        alice,
        bob_kp,
        Some(b"relationship-digest".to_vec())
    ));
}

/// Defense-in-depth: the binding lives on the classical halves ONLY. A crafted welcome
/// whose PQ half smuggles an `AppBinding` — even one equal to the classical half's — is
/// rejected at `receive` (`verify_pq_half_unbound` runs at every PQ-half join) before
/// any invitation state is claimed, and the invitation still serves an honest initiator
/// with the same binding afterwards.
#[test]
fn test_welcome_with_pq_half_binding_rejected() {
    use apq::component::{ApqInfo, ApqInfoUpdate};
    use apq::{
        create_group_with_member, encode_apq_welcome, export_and_register_psk, GroupCreation,
        PskDomain,
    };

    let alice = make_client();
    let bob = make_client();
    let alice_kp = make_classical_kp(&alice);
    let binding = b"relationship-digest".to_vec();

    let bob_inv = assert_ok!(crate::key_packages::TwoMlsPqInvitation::restore(
        assert_ok!(bob.generate_invitation(true))
    ));
    let bob_kp = bob_inv.combiner_key_package();

    // Hand-roll `create_combiner_send_group` with the binding ALSO on the PQ half — the
    // crafted shape a wired initiator cannot produce (its builders bind the classical
    // half only).
    let combiner = alice.combiner();
    let peer_id = assert_ok!(crate::key_packages::parse_combiner_key_package(
        bob_kp.clone()
    ))
    .client_id
    .bytes;
    combiner
        .auth_view()
        .with(move |core| core.theirs.commit(peer_id));
    let suite = combiner.cipher_suite();
    let t_gid = assert_ok!(combiner.random_group_id());
    let pq_gid = assert_ok!(combiner.random_group_id());
    let info = ApqInfo::new(suite, t_gid.clone(), pq_gid.clone(), 1, 1);
    let attestation = ApqInfoUpdate {
        t_epoch: 1,
        pq_epoch: 1,
    };
    let (mut pq_group, pq_welcome) = assert_ok!(create_group_with_member(
        combiner.pq(),
        &bob_kp.pq,
        &[],
        assert_ok!(
            assert_ok!(GroupCreation::new(pq_gid, &info, Some(attestation)))
                .with_app_binding(Some(&binding))
        ),
    ));
    let apq_psk = assert_ok!(export_and_register_psk(
        &mut pq_group,
        combiner,
        PskDomain::Apq
    ));
    let (_classical_group, classical_welcome) = assert_ok!(create_group_with_member(
        combiner.classical(),
        &bob_kp.classical,
        &[apq_psk],
        assert_ok!(
            assert_ok!(GroupCreation::new(t_gid, &info, Some(attestation)))
                .with_app_binding(Some(&binding))
        ),
    ));
    let crafted = encode_apq_welcome(classical_welcome, pq_welcome);

    // Even the matching expectation refuses the smuggled copy — and claims nothing.
    assert_err!(
        bob_inv.receive(
            crafted,
            alice_kp.clone(),
            vec![0u8; 32], // no A.4 in this test — any 32-byte commitment passes the length gate
            b"token".to_vec(),
            None,
            None,
            Some(binding.clone()),
        ),
        TwoMlsPqError::AppBindingMismatch
    );

    // The invitation still serves an honest, wired initiate with the same binding.
    let honest = assert_ok!(TwoMlsPqSession::initiate(
        Arc::clone(&alice),
        bob_inv.combiner_key_package(),
        Some(binding.clone())
    ));
    let bob_session = assert_ok!(bob_inv.receive(
        assert_some!(honest.initial_welcome()),
        alice_kp,
        commitment_of(&honest),
        b"token".to_vec(),
        None,
        None,
        Some(binding.clone()),
    ));
    assert_eq!(assert_ok!(bob_session.app_binding()), Some(binding));
}

// ===========================================================================
// Side-band re-staple (retention + non-consuming peek)
// ===========================================================================

/// The property the whole model rests on: a round's frame is RETAINED, so a host can
/// re-send it on every message frame the way `current_staple` already rides the classical
/// stream. Peeking must therefore be repeatable and must not consume.
#[test]
fn test_pq_pending_outbound_peek_is_repeatable_and_non_consuming() {
    let (alice, bob) = establish_full();
    // Bob holds the turn: his send opens the A.3, staging the EK.
    let _ = open_ratchet(&bob, &alice);

    // Three peeks, three sealed frames — each independently openable by the peer.
    let first = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    let second = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert!(bob.pq_pending_outbound(SideBandSealing::Fresh).is_some());

    // Fresh seals draw a new nonce each time, so the sealed bytes differ even though the
    // frame does not. (Belt-and-braces on the seal: identical ciphertext under Fresh would
    // mean a reused nonce.)
    assert_ne!(first, second);

    // And the peer opens the SECOND copy — a re-send is a real frame, not a stub.
    assert_ok!(alice.pq_ratchet_respond(second));
}

/// A dropped bind heals by the staple's own machinery: the bind is the committing
/// round's staple, re-sent on every subsequent frame until superseded, so losing the
/// frame that first carried it costs nothing — the next frame carries it again. (Under
/// the old bind-frame design this took dedicated side-band retention; the staple gets
/// it for free, which is the point of riding it.)
#[test]
fn test_dropped_bind_heals_on_restaple() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(bob.pq_ratchet_bind(ct));

    // The committing round discharges the bind, but the transport drops its frame.
    assert_ok!(alice.prepare_to_encrypt(None));
    let upd = assert_ok!(alice.encrypt(b"upd".to_vec()));
    let got = assert_some!(assert_ok!(bob.process_incoming(upd.cipher_text)));
    assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
    assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
    drop(assert_ok!(bob.encrypt(b"lost".to_vec()))); // never delivered

    // Bob's next frame re-staples the same APQPrivateMessage: Alice applies the bind
    // from it and the round closes as if nothing had been lost.
    assert_ok!(bob.prepare_to_encrypt(None));
    let healing = assert_ok!(bob.encrypt(b"healing".to_vec()));
    let res = assert_some!(assert_ok!(alice.process_incoming(healing.cipher_text)));
    assert_eq!(
        assert_some!(res.application_message).app_message_data,
        b"healing"
    );
    assert!(alice.my_pq_turn(), "the re-stapled bind closed the round");
}

/// Re-sends make duplicates steady-state traffic, not an edge case: a retained frame
/// rides every send until its answer lands. A receiver whose state proves the step is
/// DONE must read the repeat as a discardable duplicate — distinctly from
/// `SessionNotReady`, which a host is entitled to read as "wrong door". Mid-hold (bound
/// but not yet discharged) a repeat is `SessionNotReady` — retriable, and moot once the
/// discharge passes the turn.
#[test]
fn test_duplicate_side_band_frames_are_discardable_not_routing_errors() {
    let (alice, bob) = establish_full();

    // Duplicate EK: Alice already responded.
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek.clone()));
    assert_err!(
        alice.pq_ratchet_respond(ek),
        TwoMlsPqError::DuplicateSideBand
    );

    // Duplicate CT mid-hold: the owed-bind guard answers first (retriable).
    let ct = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(bob.pq_ratchet_bind(ct.clone()));
    assert_err!(
        bob.pq_ratchet_bind(ct.clone()),
        TwoMlsPqError::SessionNotReady
    );

    // Duplicate CT after the discharge: the turn has passed, so the state proves the
    // step is done — a discardable duplicate.
    discharge_bind(&bob, &alice, b"x");
    assert_err!(bob.pq_ratchet_bind(ct), TwoMlsPqError::DuplicateSideBand);

    // The bind's own repeats are the staple's: every post-discharge frame re-staples
    // it and the receiver skips it idempotently (see
    // `test_dropped_bind_heals_on_restaple`).
}

/// Silent when quiescent — what lets a host send a bare message. Every retained frame
/// clears when its answer lands: the initiator's at the bind (the inbound reply
/// answered its begin), the responder's at the staple arm (the stapled bind answered
/// its reply) — so after a completed round NEITHER side has anything to re-send.
#[test]
fn test_side_band_falls_silent_on_both_sides_after_the_round() {
    let (alice, bob) = establish_full();
    let ek = open_ratchet(&bob, &alice);
    assert_ok!(alice.pq_ratchet_respond(ek));
    let ct = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(bob.pq_ratchet_bind(ct));

    // Bob's EK is spent the moment he binds — the CT answered it. Nothing of his
    // re-sends (the bind travels the staple, not the side-band).
    assert!(bob.pq_pending_outbound(SideBandSealing::Fresh).is_none());
    // Alice's CT still re-sends: the stapled bind has not landed yet.
    assert!(alice.pq_pending_outbound(SideBandSealing::Fresh).is_some());

    discharge_bind(&bob, &alice, b"x");

    // Alice applied the staple: her CT is spent too, and she holds the turn.
    assert!(alice.pq_pending_outbound(SideBandSealing::Fresh).is_none());
    assert!(alice.my_pq_turn());

    // The next round starts on empty slots — Alice holds the turn now, so she opens it.
    let ek2 = open_ratchet(&alice, &bob);
    assert_ok!(bob.pq_ratchet_respond(ek2));
    let ct2 = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_ratchet_bind(ct2));
    discharge_bind(&alice, &bob, b"y");
}

/// Retention rides the archive: a session restored mid-round must still be able to
/// re-send. (`pending_pq_outbound` was already serialized; this pins that the new
/// hand-out path reads it back.)
#[test]
fn test_retained_frame_survives_archive_round_trip() {
    let (alice, bob) = establish_full();
    let _ = open_ratchet(&bob, &alice);

    let restored = round_trip(&bob);

    let resent = assert_some!(restored.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_ratchet_respond(resent));
}

/// The reason `Stable` exists: a chunking host cuts pieces out of the sealed bytes, so the
/// base must not move under it. Two hand-outs of an unchanged frame must be byte-identical
/// — otherwise chunk 1 of seal A and chunk 2 of seal B reassemble into garbage.
#[test]
fn test_stable_sealing_holds_the_base_still_for_chunking() {
    let (alice, bob) = establish_full();
    let _ = open_ratchet(&bob, &alice);

    let base = assert_some!(bob.pq_pending_outbound(SideBandSealing::Stable));
    let again = assert_some!(bob.pq_pending_outbound(SideBandSealing::Stable));
    assert_eq!(base, again, "Stable must hand out identical bytes");

    // Reassembling halves cut from two separate hand-outs yields the original — the
    // property a chunking transport depends on.
    let mid = base.len() / 2;
    let first_half = &assert_some!(bob.pq_pending_outbound(SideBandSealing::Stable))[..mid];
    let second_half = &assert_some!(bob.pq_pending_outbound(SideBandSealing::Stable))[mid..];
    let reassembled: Vec<u8> = [first_half, second_half].concat();
    assert_eq!(reassembled, base);

    // And the reassembly is a real frame, not just equal bytes.
    assert_ok!(alice.pq_ratchet_respond(reassembled));
}

/// `Fresh` is the opposite contract, and it is what an en-bloc host wants: repeated sends
/// of one retained frame must not repeat byte-identical ciphertext, which would let a
/// passive observer correlate the re-sends of a stalled round.
#[test]
fn test_fresh_sealing_differs_per_send_but_opens_the_same() {
    let (alice, bob) = establish_full();
    let _ = open_ratchet(&bob, &alice);

    let a = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    let b = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ne!(a, b, "Fresh must not repeat wire bytes");

    // Distinct bytes, same frame underneath: either copy drives the round.
    assert_ok!(alice.pq_ratchet_respond(b));
}

/// Stability is scoped to the FRAME, not to time. When the round moves past a frame,
/// the next `Stable` hand-out must not serve its stale seal — a chunking pass for a
/// superseded frame is worthless. The cache lives inside the frame it seals, so the
/// clear at the bind drops it structurally: the slot serves NOTHING mid-hold, and the
/// next round's frame starts a fresh base.
#[test]
fn test_stable_seal_is_invalidated_when_the_frame_advances() {
    let (alice, bob) = establish_full();
    let _ = open_ratchet(&bob, &alice);
    let ek_seal = assert_some!(bob.pq_pending_outbound(SideBandSealing::Stable));

    // Drive the round on: the CT answers the EK at the bind.
    assert_ok!(alice.pq_ratchet_respond(ek_seal.clone()));
    let ct = assert_some!(alice.pq_pending_outbound(SideBandSealing::Stable));
    assert_ok!(bob.pq_ratchet_bind(ct));

    // The EK (and its cached seal) is gone with the frame — not served stale.
    assert!(bob.pq_pending_outbound(SideBandSealing::Stable).is_none());
    discharge_bind(&bob, &alice, b"payload");

    // The next round's frame is a fresh base, not the old cache. Alice holds the turn now.
    let ek2 = open_ratchet(&alice, &bob);
    assert_ok!(bob.pq_ratchet_respond(ek2));
    let ct2 = assert_some!(bob.pq_pending_outbound(SideBandSealing::Stable));
    assert_ne!(ct2, ek_seal, "a new frame must never reuse a stale base");
    assert_ok!(alice.pq_ratchet_bind(ct2));
    discharge_bind(&alice, &bob, b"round-two");
}

/// The A.4 begin-return / Stable-base agreement: its KP' is minted
/// pre-establishment and is the one frame sealed classically, so it takes a different path
/// through `seal_side_band` and is worth pinning separately.
#[test]
fn test_bootstrap_begin_return_matches_the_stable_base() {
    let (alice, bob) = establish_confirmed_sessions();
    let returned = assert_ok!(alice.pq_bootstrap_begin(None));
    let peeked = assert_some!(alice.pq_pending_outbound(SideBandSealing::Stable));
    assert_eq!(returned, peeked, "A.4 begin disagrees with the Stable base");
    assert_ok!(bob.pq_bootstrap_respond(returned));
}

// ===========================================================================
// A.4 as a well-formed round
// ===========================================================================
//
// There is no terminal-frame retirement section any more, and that is the point: every
// round's last leg is a stapled bind, so every SIDE-BAND frame is answered by the
// round's next leg and clears on the ordinary round-complete rule. The receipt
// machinery an earlier cut recovered from header encryption (the epoch of the key that
// opens a frame proves what the peer applied) was real, but nothing needs it — see the
// changeset.

/// Each leg re-sends until the leg that answers it lands, and CLEARS the moment it
/// does. This is the test that catches a dropped slot-clear: without the clear at the
/// bind, Alice's KP' re-sends forever into a round that is past it — a frame the peer
/// must decide to ignore; without the clear at the staple arm, Bob's welcome does.
#[test]
fn test_each_bootstrap_leg_re_sends_until_it_is_answered() {
    let (alice, bob) = establish_confirmed_sessions();
    assert_ok!(alice.pq_bootstrap_begin(None));

    // The KP' rides every send until the welcome answers it.
    assert!(alice.pq_pending_outbound(SideBandSealing::Fresh).is_some());
    let kp = assert_some!(alice.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(bob.pq_bootstrap_respond(kp));

    // The welcome likewise, until the stapled bind answers it.
    assert!(bob.pq_pending_outbound(SideBandSealing::Fresh).is_some());
    let welcome = assert_some!(bob.pq_pending_outbound(SideBandSealing::Fresh));
    assert_ok!(alice.pq_bootstrap_bind(welcome));

    // The KP' is SPENT — the welcome answered it, and the round's close travels the
    // staple, not this slot. Alice's side-band falls silent immediately.
    assert!(
        alice.pq_pending_outbound(SideBandSealing::Fresh).is_none(),
        "the welcome answered the KP'; nothing of Alice's may re-send"
    );
    // Bob's welcome keeps re-sending: the stapled bind has not landed yet.
    assert!(bob.pq_pending_outbound(SideBandSealing::Fresh).is_some());

    discharge_bind(&alice, &bob, b"bootstrap-bind");

    // The staple answered the welcome: the responder's part is over too.
    assert!(bob.pq_pending_outbound(SideBandSealing::Fresh).is_none());
}
