use std::sync::{Arc, Mutex};

use crate::{
    key_packages::{CombinerKeyPackage, TwoMlsPqClient},
    AgentState, Archive, ClientId, CombinerGroupId, DecryptResult, EncryptResult, ListenChannels,
    MlsSenderMessage, PrepareEncryptResult, RendezvousId, Result, SessionId, TwoMlsPqDigest,
};

#[allow(dead_code)]
#[derive(uniffi::Object)]
pub struct TwoMlsPqSession {
    client: Arc<TwoMlsPqClient>,
    pending_outbound: Mutex<Option<Vec<u8>>>,
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Create a session as the initiating party targeting `their_key_package`.
    /// Retrieve the outbound APQWelcome bytes via `pending_outbound`.
    #[uniffi::constructor]
    pub fn initiate(
        _client: Arc<TwoMlsPqClient>,
        _their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        todo!()
    }

    /// Join a session from an APQWelcome produced by the remote `initiate`.
    /// Retrieve this party's return Welcome via `pending_outbound`.
    #[uniffi::constructor]
    pub fn accept(
        _client: Arc<TwoMlsPqClient>,
        _welcome: Vec<u8>,
        _their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        todo!()
    }

    /// Restore a session from a serialised archive.
    #[uniffi::constructor]
    pub fn from_archive(_archive: Archive, _client: Arc<TwoMlsPqClient>) -> Result<Arc<Self>> {
        todo!()
    }

    /// Welcome bytes to deliver to the remote party to complete group establishment.
    /// Returns `None` once consumed or when both groups are live.
    pub fn pending_outbound(&self) -> Option<Vec<u8>> {
        todo!()
    }

    pub fn proposal_context(&self) -> Option<TwoMlsPqDigest> {
        todo!()
    }

    pub fn send_rendezvous(&self) -> Result<Option<RendezvousId>> {
        todo!()
    }

    pub fn archive(&self) -> Result<Archive> {
        todo!()
    }

    pub fn prepare_to_encrypt(
        &self,
        _proposing: Option<ClientId>,
    ) -> Result<Option<PrepareEncryptResult>> {
        todo!()
    }

    pub fn encrypt(&self, _app_message: Vec<u8>) -> Result<EncryptResult> {
        todo!()
    }

    pub fn process_incoming(&self, _ciphertext: Vec<u8>) -> Result<Option<DecryptResult>> {
        todo!()
    }

    pub fn queue_proposal(&self, _digest: TwoMlsPqDigest) -> Result<()> {
        todo!()
    }

    /// Process a message forwarded from another of the user's own devices.
    /// The transport envelope has already been decrypted by the originating device;
    /// `header_decrypted` is the inner MLS payload. Returns `None` for non-application
    /// messages (proposals, commits) forwarded in error.
    pub fn forwarded(&self, _header_decrypted: Vec<u8>) -> Result<Option<MlsSenderMessage>> {
        todo!()
    }

    pub fn should_listen_on(&self) -> Result<ListenChannels> {
        todo!()
    }

    pub fn is_established(&self) -> bool {
        todo!()
    }

    pub fn active_session_id(&self) -> SessionId {
        todo!()
    }

    pub fn my_agent_state(&self) -> AgentState {
        todo!()
    }

    pub fn their_agent_state(&self) -> AgentState {
        todo!()
    }

    pub fn receive_group_id(&self) -> Option<CombinerGroupId> {
        todo!()
    }

    pub fn has_receive_group(&self) -> bool {
        todo!()
    }
}

/// Create one half of a Combiner send group (classical or PQ, identified by suite).
/// Returns (MLS Welcome bytes, serialised group state).
#[allow(dead_code)]
fn create_send_group(
    _their_keypackage: &[u8],
    _my_agent: &[u8],
    _suite: u16,
) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!()
}

/// Join one half of a Combiner send group from an MLS Welcome.
/// Returns the serialised group state.
#[allow(dead_code)]
fn join_send_group(_welcome: &[u8], _my_agent: &[u8], _suite: u16) -> Result<Vec<u8>> {
    todo!()
}

/// Create one half of a Combiner send group bound to the opposing direction via PSK.
/// Returns (MLS Welcome bytes, serialised group state).
#[allow(dead_code)]
fn create_bound_send_group(
    _their_keypackage: &[u8],
    _my_agent: &[u8],
    _psk: &crate::psk::BoundPsk,
    _suite: u16,
) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!()
}

/// Create both halves of a Combiner send group (classical + PQ) from a CombinerKeyPackage.
/// Returns (APQWelcome bytes, serialised CombinerGroupState).
#[allow(dead_code)]
fn create_combiner_send_group(
    _their_kp: &CombinerKeyPackage,
    _my_agent: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!()
}

/// Join both halves of a Combiner send group from an APQWelcome.
/// Returns the serialised CombinerGroupState.
#[allow(dead_code)]
fn join_combiner_send_group(_apq_welcome: &[u8], _my_agent: &[u8]) -> Result<Vec<u8>> {
    todo!()
}

/// Create both halves of a Combiner send group bound to the opposing direction via PSK.
/// Returns (APQWelcome bytes, serialised CombinerGroupState).
#[allow(dead_code)]
fn create_bound_combiner_send_group(
    _their_kp: &CombinerKeyPackage,
    _my_agent: &[u8],
    _psk: &crate::psk::BoundPsk,
) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "not yet implemented"]
    fn test_initiate_stores_outbound_welcome() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_accept_stores_outbound_welcome() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_pending_outbound_returns_none_after_take() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_create_send_group_with_valid_keypackage_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_join_send_group_with_my_agent_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_create_bound_send_group_classical_with_psk_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_create_bound_send_group_xwing_with_psk_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_prepare_to_encrypt_returns_proposal_hash() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_prepare_to_encrypt_did_commit_true_when_remote_proposal_staged() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_encrypt_after_prepare_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_process_incoming_app_message_returns_decrypt_result() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_process_incoming_proposal_returns_none_until_queued() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_process_incoming_returns_none_on_rejoin_needed() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_queue_proposal_stages_for_next_ratchet() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_session_id_is_same_from_both_sides() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_session_id_differs_for_different_pairs() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_is_established_false_before_both_groups_ready() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_full_establishment_sequence_combiner() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_full_establishment_sequence_xwing() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_concurrent_sessions_same_did_pair_both_valid() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_agent_rotation_migrates_session_to_new_agent() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_welcome_stapled_in_first_round_only() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_archive_round_trips_session_state() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_should_listen_on_returns_correct_group_and_epochs() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_psk_export_uses_correct_label_and_context() {}
}
