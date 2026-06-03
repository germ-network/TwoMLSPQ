/// End-to-end scenario tests covering the full TwoMLSPQ lifecycle.
/// Scenario actors: Bob is a new user; Alice is an existing user.
/// Tests are ordered to mirror the real flow: install → discover → establish
/// → message exchange → partial commit → full commit → rotation → restore.
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
fn test_install_classical_suite_is_0x0003() {}

#[test]
#[ignore = "not yet implemented"]
fn test_install_pq_suite_is_0xfe4c() {}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_parse_mls_key_package_returns_correct_suite() {
    // parseMlsKeyPackage on the classical bytes returns suite 0x0003.
    // parseMlsKeyPackage on the PQ bytes returns suite 0xFE4C.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_xwing_suite_is_supported() {}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_classical_suite_is_not_supported_but_is_combiner_classical() {
    // MlsCipherSuite(0x0003).isSupported() == false
    // MlsCipherSuite(0x0003).isCombinerClassical() == true
    // Caller should NOT route to mls-rs-uniffi-ios when a matching XWing KP is present.
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_parse_combiner_key_package_validates_identity_match() {}

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
}

#[test]
#[ignore = "not yet implemented"]
fn test_discover_derive_session_id_differs_for_different_pairs() {}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_initiate_produces_pending_outbound() {
    // TwoMlsPqSession.initiate(aliceClient, bobCombinerKP) succeeds and
    // session.pendingOutbound() returns Some(apqWelcomeBytes).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_initiate_session_not_yet_established() {}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_accept_joins_alice_group_and_produces_pending_outbound() {
    // TwoMlsPqSession.accept(bobClient, apqWelcomeA, aliceCombinerKP) succeeds.
    // session.pendingOutbound() returns Some(apqWelcomeB).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_accept_session_not_yet_established() {}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_alice_processes_welcome_b_and_both_sessions_established() {
    // Alice calls processIncoming with Bob's first message (containing apqWelcomeB).
    // After this, isEstablished() == true on both sides.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_has_receive_group_false_before_accept() {}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_receive_group_id_present_after_both_established() {
    // receiveGroupId() returns Some(CombinerGroupId) once both groups are live.
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_pending_outbound_returns_none_after_consumed() {}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_psk_binding_ties_alice_direction_to_bob_direction() {
    // PSK exported from Group_A is injected into Group_B.
    // Verified via exportSecret(label="exportSecret", context="derive", len=32).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_session_ids_match_on_both_sides() {
    // activeSessionId() on both sessions must equal derive_session_id(aliceClientId, bobClientId).
}

#[test]
#[ignore = "not yet implemented"]
fn test_establish_concurrent_initiations_deduplicated_by_session_id() {
    // Alice and Bob both call initiate simultaneously.
    // derive_session_id produces the same ID on both sides, allowing deduplication.
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_alice_encrypt_bob_decrypt_roundtrip() {
    // Alice: prepareToEncrypt(nil) + encrypt(plaintext)
    // Bob: processIncoming → appMessageData == plaintext
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_sender_client_id_is_verified() {}

#[test]
#[ignore = "not yet implemented"]
fn test_message_epoch_is_correct() {}

#[test]
#[ignore = "not yet implemented"]
fn test_message_proposal_hash_bound_into_authenticated_data() {
    // Tampered authenticatedData must cause decryption failure.
}

#[test]
#[ignore = "not yet implemented"]
fn test_message_bob_encrypt_alice_decrypt_roundtrip() {}

#[test]
#[ignore = "not yet implemented"]
fn test_message_multiple_sequential_messages_same_epoch() {}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_did_commit_false_when_no_pending_proposal() {}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_send_epoch_unchanged() {}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_psk_not_refreshed() {}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_receiver_decrypts_successfully() {}

#[test]
#[ignore = "not yet implemented"]
fn test_partial_commit_receiver_sees_no_commit_result() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_triggered_by_queued_remote_proposal() {
    // Bob sends Update proposal → Alice receives QueuedRemoteProposal.
    // Alice calls queueProposal(digest) → next prepareToEncrypt returns didCommit: true.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_did_commit_true() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_committed_remote_client_id_is_bob() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_send_epoch_advances() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_psk_refreshed() {
    // New PSK exported from send group epoch N+1, injected into receive group.
}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_receiver_sees_commit_result() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_receiver_commit_result_new_sender_none_for_key_refresh() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_proposal_rejected_if_not_queued() {}

#[test]
#[ignore = "not yet implemented"]
fn test_full_commit_proposal_context_used_for_ordering() {
    // QueuedRemoteProposal.context is the receive group ID hash for sequencing.
}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_prepare_to_encrypt_with_new_client_id_stages_update() {}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_remote_side_receives_commit_result_with_new_sender() {}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_agent_state_pending_until_both_sides_commit() {}

#[test]
#[ignore = "not yet implemented"]
fn test_rotation_agent_state_sync_after_both_sides_committed() {}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_round_trips_established_session() {
    // archive() → fromArchive(archive, client) restores same sessionId, agent states, group IDs.
}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_restored_session_can_encrypt_and_decrypt() {}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_incompatible_bytes_returns_archive_invalid() {}

#[test]
#[ignore = "not yet implemented"]
fn test_archive_restored_session_listen_channels_match_original() {}

#[test]
#[ignore = "not yet implemented"]
fn test_transport_should_listen_on_returns_combiner_group_id() {
    // shouldListenOn().sendGroup is a CombinerGroupId { classical, pq }.
}

#[test]
#[ignore = "not yet implemented"]
fn test_transport_rendezvous_id_derived_per_epoch() {
    // Each RendezvousId == exportSecret(label="rendezvous", context="TwoMLS", len=32).
}

#[test]
#[ignore = "not yet implemented"]
fn test_transport_send_rendezvous_matches_current_epoch() {}

#[test]
#[ignore = "not yet implemented"]
fn test_reconnect_process_incoming_returns_none_when_epoch_unknown() {}

#[test]
#[ignore = "not yet implemented"]
fn test_reconnect_has_receive_group_false_triggers_rejoin_path() {}

#[test]
#[ignore = "not yet implemented"]
fn test_reconnect_fresh_accept_re_establishes_receive_group() {}
