#[allow(unused_imports)]
use crate::{
    derive_session_id,
    key_packages::{
        parse_combiner_key_package, parse_mls_key_package, CombinerKeyPackage, TwoMlsPqClient,
    },
    session::TwoMlsPqSession,
    MlsCipherSuite,
};

#[test]
#[ignore = "not yet implemented"]
fn test_install_generates_combiner_key_package() {
    // Bob installs. generateCombinerKeyPackage returns a paired (classical, pq)
    // bundle where both components carry the same ClientId.
}

#[test]
#[ignore = "not yet implemented"]
fn test_install_client_id_matches_signing_key_public_component() {
    // client.clientId() must equal the public key derived from the signing key
    // that was passed to TwoMlsPqClient.new.
}

#[test]
#[ignore = "not yet implemented"]
fn test_install_combiner_key_package_client_ids_match() {
    // Both components of the CombinerKeyPackage must carry the same ClientId.
    // parse_combiner_key_package returns an error if they differ.
}

#[test]
#[ignore = "not yet implemented"]
fn test_install_classical_suite_is_0x0003() {
    // The classical component of a CombinerKeyPackage must use suite 0x0003.
}

#[test]
#[ignore = "not yet implemented"]
fn test_install_pq_suite_is_0xfe4c() {
    // The PQ component of a CombinerKeyPackage must use suite 0xFE4C (XWing).
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_parse_mls_key_package_returns_correct_suite() {
    // parseMlsKeyPackage on the classical bytes returns suite 0x0003.
    // parseMlsKeyPackage on the PQ bytes returns suite 0xFE4C.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_xwing_suite_is_supported() {
    // MlsCipherSuite(0xFE4C).isSupported() == true
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_classical_suite_is_not_supported_but_is_combiner_classical() {
    // MlsCipherSuite(0x0003).isSupported() == false
    // MlsCipherSuite(0x0003).isCombinerClassical() == true
    // Caller should NOT route to mls-rs-uniffi-ios when a matching XWing KP is present.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_parse_combiner_key_package_validates_identity_match() {
    // parseCombinerKeyPackage succeeds when both components share the same ClientId.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_parse_combiner_key_package_rejects_mismatched_identities() {
    // parseCombinerKeyPackage returns InvalidKeyPackage when the classical and PQ
    // components carry different ClientIds.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_derive_session_id_is_symmetric() {
    // derive_session_id(alice, bob) == derive_session_id(bob, alice)
    // Both sides independently arrive at the same SessionId.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_derive_session_id_differs_for_different_pairs() {
    // derive_session_id(alice, bob) != derive_session_id(alice, carol)
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_initiate_produces_pending_outbound() {
    // TwoMlsPqSession.initiate(aliceClient, bobCombinerKP) succeeds and
    // session.pendingOutbound() returns Some(apqWelcomeBytes).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_initiate_session_not_yet_established() {
    // After initiate, before Bob has accepted, isEstablished() == false.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_accept_joins_alice_group_and_produces_pending_outbound() {
    // TwoMlsPqSession.accept(bobClient, apqWelcomeA, aliceCombinerKP) succeeds.
    // session.pendingOutbound() returns Some(apqWelcomeB).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_accept_session_not_yet_established() {
    // After accept, before Alice processes apqWelcomeB, isEstablished() == false
    // on Bob's side.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_alice_processes_welcome_b_and_both_sessions_established() {
    // Alice calls processIncoming with Bob's first message (containing apqWelcomeB).
    // After this, isEstablished() == true on both sides.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_has_receive_group_false_before_accept() {
    // Alice's session: hasReceiveGroup() == false until she processes apqWelcomeB.
    // Bob's session: hasReceiveGroup() == false until he processes apqWelcomeA.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_receive_group_id_present_after_both_established() {
    // receiveGroupId() returns Some(CombinerGroupId) once both groups are live.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_pending_outbound_returns_none_after_consumed() {
    // pendingOutbound() returns None after being read once.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_psk_binding_ties_alice_direction_to_bob_direction() {
    // The PSK exported from Alice's send group (Group A) is injected into
    // Bob's send group (Group B). Verified via exportSecret label/context/len.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_session_ids_match_on_both_sides() {
    // activeSessionId() returns the same SessionId on Alice's and Bob's sessions.
    // Must equal derive_session_id(aliceClientId, bobClientId).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_concurrent_initiations_deduplicated_by_session_id() {
    // Alice and Bob both call initiate simultaneously.
    // derive_session_id produces the same ID on both sides.
    // The protocol can identify the collision and select one session as canonical.
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_alice_encrypt_bob_decrypt_roundtrip() {
    // Alice: prepareToEncrypt(nil) + encrypt(plaintext)
    // Bob: processIncoming(ciphertext) → DecryptResult.applicationMessage.appMessageData == plaintext
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_sender_client_id_is_verified() {
    // DecryptResult.applicationMessage.senderClientId == aliceClientId
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_epoch_is_correct() {
    // DecryptResult.applicationMessage.epoch matches the current send group epoch.
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_proposal_hash_bound_into_authenticated_data() {
    // The proposalHash from PrepareEncryptResult is passed as authenticatedData
    // to MLS encryptApplicationMessage. Tampered authenticatedData causes decryption failure.
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_bob_encrypt_alice_decrypt_roundtrip() {
    // Reverse direction: Bob sends, Alice decrypts.
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_multiple_sequential_messages_same_epoch() {
    // Multiple messages sent without committing stay in the same epoch.
}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_did_commit_false_when_no_pending_proposal() {
    // prepareToEncrypt(nil) with no staged remote proposal returns didCommit: false.
}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_send_epoch_unchanged() {
    // After a partial commit, the send group epoch does not advance.
}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_psk_not_refreshed() {
    // A partial commit does not export a new PSK or re-inject into the receive group.
}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_receiver_decrypts_successfully() {
    // Bob receives a message sent under a partial commit and decrypts it normally.
}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_receiver_sees_no_commit_result() {
    // DecryptResult.remoteCommit is None for a partial commit.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_triggered_by_queued_remote_proposal() {
    // Bob sends an Update proposal. Alice receives it → DecryptResult.proposal is Some.
    // Alice calls queueProposal(digest). Next prepareToEncrypt returns didCommit: true.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_did_commit_true() {
    // prepareToEncrypt after queueProposal returns didCommit: true.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_committed_remote_client_id_is_bob() {
    // PrepareEncryptResult.commitedRemoteClientId == Some(bobClientId).
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_send_epoch_advances() {
    // After a full commit the send group epoch increments by one.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_psk_refreshed() {
    // A full commit exports a new PSK from the send group's new epoch and
    // re-injects it into the receive group.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_receiver_sees_commit_result() {
    // Bob processes Alice's full-commit message and gets DecryptResult.remoteCommit = Some.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_receiver_commit_result_new_sender_none_for_key_refresh() {
    // A standard key-material refresh (not agent rotation): CommitResult.newSender == None.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_proposal_rejected_if_not_queued() {
    // A proposal that was never passed to queueProposal is not committed.
    // prepareToEncrypt does not pick it up.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_proposal_context_used_for_ordering() {
    // QueuedRemoteProposal.context is the receive group ID hash.
    // Proposals out of app-layer order should be rejectable via this field.
}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_prepare_to_encrypt_with_new_client_id_stages_update() {
    // prepareToEncrypt(proposing: newClientId) stages an Update proposal with
    // the new leaf credential on the send group.
}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_remote_side_receives_commit_result_with_new_sender() {
    // After Alice commits a rotation, Bob receives CommitResult.newSender = Some(newClientId).
}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_agent_state_pending_until_both_sides_commit() {
    // myAgentState() == AgentState.Pending { old, new } after sending the rotation
    // commit, until the remote side commits their half.
}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_agent_state_sync_after_both_sides_committed() {
    // myAgentState() == AgentState.Sync { clientId: newClientId } once both
    // sides have committed.
}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_round_trips_established_session() {
    // session.archive() → Archive bytes → TwoMlsPqSession.fromArchive(archive, client)
    // Restored session has the same sessionId, agent states, and group IDs.
}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_restored_session_can_encrypt_and_decrypt() {
    // After restore, encrypt and processIncoming work correctly.
}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_incompatible_bytes_returns_archive_invalid() {
    // fromArchive with corrupted bytes returns TwoMlsPqError::ArchiveInvalid.
}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_restored_session_listen_channels_match_original() {
    // shouldListenOn() returns the same CombinerGroupId and rendezvous epochs
    // before and after archive/restore.
}

#[test]
#[ignore = "not yet implemented"]
fn test_transport_should_listen_on_returns_combiner_group_id() {
    // shouldListenOn().sendGroup is a CombinerGroupId with both classical and PQ group IDs.
}

#[test]
#[ignore = "not yet implemented"]
fn test_transport_rendezvous_id_derived_per_epoch() {
    // rendezvousByEpoch contains one entry per tracked epoch.
    // Each RendezvousId == exportSecret(label="rendezvous", context="TwoMLSPQ", len=32).
}

#[test]
#[ignore = "not yet implemented"]
fn test_transport_send_rendezvous_matches_current_epoch() {
    // sendRendezvous() returns the RendezvousId for the current send epoch.
}

#[test]
#[ignore = "not yet implemented"]
fn test_reconnect_process_incoming_returns_none_when_epoch_unknown() {
    // processIncoming with a message from an epoch outside the history window
    // returns Ok(None), signalling the caller to initiate a rejoin.
}

#[test]
#[ignore = "not yet implemented"]
fn test_reconnect_has_receive_group_false_triggers_rejoin_path() {
    // hasReceiveGroup() == false after epoch loss → caller initiates reconnect.
}

#[test]
#[ignore = "not yet implemented"]
fn test_reconnect_fresh_accept_re_establishes_receive_group() {
    // After a rejoin, the reconnected session passes processIncoming successfully.
}
