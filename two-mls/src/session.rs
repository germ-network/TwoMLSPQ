use std::sync::Arc;

use crate::{
    AgentState, Archive, ClientId, DecryptResult, EncryptResult, ListenChannels, MlsGroupId,
    MlsSenderMessage, PrepareEncryptResult, PqCapability, RendezvousId, Result, SessionId,
    TwoMlsDigest,
};

/// A live TwoMLS session (two asymmetric send groups, one per direction).
/// Interior mutability required — UniFFI Object methods take `&self`.
#[derive(uniffi::Object)]
pub struct TwoMlsSession;

#[uniffi::export]
impl TwoMlsSession {
    #[uniffi::constructor]
    pub fn from_archive(_archive: Archive) -> Result<Arc<Self>> {
        todo!()
    }

    pub fn proposal_context(&self) -> Option<TwoMlsDigest> {
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

    pub fn queue_proposal(&self, _digest: TwoMlsDigest) -> Result<()> {
        todo!()
    }

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

    pub fn receive_group_id(&self) -> Option<MlsGroupId> {
        todo!()
    }

    pub fn has_receive_group(&self) -> bool {
        todo!()
    }
}

/// Create the initial send group targeting the other party's KeyPackage.
/// Returns (group_state, welcome_bytes). The Welcome is stapled into the
/// first-round message so the remote party can join.
#[allow(dead_code)]
fn create_send_group(
    _their_keypackage: &[u8],
    _my_agent: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!()
}

/// Join a send group from a stapled Welcome.
#[allow(dead_code)]
fn join_send_group(_welcome: &[u8], _my_agent: &[u8]) -> Result<Vec<u8>> {
    todo!()
}

/// Create Alice's send group cryptographically bound to Bob's via PSK injection.
/// PSK: `exportSecret(label="exportSecret", context="derive", len=32)`.
/// PSK ID: `LinearEncode(epoch, groupId)`.
/// Uses `MLS_128_XWING_AES128GCM_SHA256_Ed25519` when `pq` is `XWing`.
#[allow(dead_code)]
fn create_bound_send_group(
    _their_keypackage: &[u8],
    _my_agent: &[u8],
    _psk: &crate::psk::BoundPsk,
    _pq: PqCapability,
) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!()
}

#[cfg(test)]
mod tests {
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
    fn test_full_establishment_sequence_classical() {}

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
