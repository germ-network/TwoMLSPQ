use std::sync::{Arc, Mutex};

use mls_rs::{
    group::ReceivedMessage,
    psk::{ExternalPskId, PreSharedKey},
    ExtensionList, Group, MlsMessage,
};

use crate::{
    key_packages::{
        parse_mls_key_package, CombinerKeyPackage, MlsClient, OurConfig, TwoMlsPqClient,
    },
    AgentState, Archive, ClientId, CombinerGroupId, CommitResult, DecryptResult, EncryptResult,
    ListenChannels, MlsGroupId, MlsSenderMessage, PrepareEncryptResult, RendezvousId, Result,
    SessionId, TwoMlsPqDigest, TwoMlsPqError,
};

type MlsGroup = Group<OurConfig>;

struct CombinerGroup {
    classical: MlsGroup,
    pq: MlsGroup,
}

struct SessionInner {
    client: Arc<TwoMlsPqClient>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    pending_proposal_hash: Option<TwoMlsPqDigest>,
    pending_commit_message: Option<Vec<u8>>,
    queued_proposal: Option<TwoMlsPqDigest>,
    pending_new_client: Option<Arc<TwoMlsPqClient>>,
    session_id: SessionId,
    my_state: AgentState,
    their_state: AgentState,
}

/// A TwoMLSPQ session holding two asymmetric Combiner send groups.
#[derive(uniffi::Object)]
pub struct TwoMlsPqSession {
    inner: Mutex<SessionInner>,
}

// APQWelcome wire format: [0x01 tag][u32-LE classical-len][classical bytes][u32-LE pq-len][pq bytes]
const APQ_TAG: u8 = 0x01;
// Bundled commit+app wire format: [0x03 tag][u32-LE commit-len][commit][u32-LE app-len][app]
const BUNDLED_TAG: u8 = 0x03;

fn encode_apq_welcome(classical: Vec<u8>, pq: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + classical.len() + 4 + pq.len());
    out.push(APQ_TAG);
    out.extend_from_slice(&(classical.len() as u32).to_le_bytes());
    out.extend_from_slice(&classical);
    out.extend_from_slice(&(pq.len() as u32).to_le_bytes());
    out.extend_from_slice(&pq);
    out
}

fn decode_apq_welcome(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != APQ_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    if rest.len() < 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let c_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() < c_len + 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let classical = rest[..c_len].to_vec();
    let rest = &rest[c_len..];
    let p_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() != p_len {
        return Err(TwoMlsPqError::Mls);
    }
    Ok((classical, rest.to_vec()))
}

fn encode_bundled(commit: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + commit.len() + 4 + app.len());
    out.push(BUNDLED_TAG);
    out.extend_from_slice(&(commit.len() as u32).to_le_bytes());
    out.extend_from_slice(&commit);
    out.extend_from_slice(&(app.len() as u32).to_le_bytes());
    out.extend_from_slice(&app);
    out
}

fn decode_bundled(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != BUNDLED_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    if rest.len() < 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let c_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() < c_len + 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let commit = rest[..c_len].to_vec();
    let rest = &rest[c_len..];
    let a_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() != a_len {
        return Err(TwoMlsPqError::Mls);
    }
    Ok((commit, rest.to_vec()))
}

/// Construct the PSK identifier: 8-byte LE epoch || group_id bytes.
fn make_psk_id(epoch: u64, group_id: &[u8]) -> ExternalPskId {
    let mut id = epoch.to_le_bytes().to_vec();
    id.extend_from_slice(group_id);
    ExternalPskId::new(id)
}

/// Export 32 bytes from `group` via exportSecret and register them in the client's PSK store.
/// Both parties derive the same value from the same epoch, enabling independent PSK registration.
fn export_and_register_psk(group: &MlsGroup, client: &TwoMlsPqClient) -> Result<ExternalPskId> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| TwoMlsPqError::Mls)?;
    let psk_id = make_psk_id(group.current_epoch(), group.group_id());
    let mut store = client.classical().secret_store();
    store.insert(
        psk_id.clone(),
        PreSharedKey::new(secret.as_bytes().to_vec()),
    );
    Ok(psk_id)
}

/// Create a group and commit the given key package in as the first member.
/// Returns (group-at-epoch-1, MLS-encoded Welcome bytes).
fn create_group_with_member(
    mls_client: &MlsClient,
    their_kp_bytes: &[u8],
) -> Result<(MlsGroup, Vec<u8>)> {
    let mut group = mls_client
        .create_group(ExtensionList::new(), ExtensionList::new())
        .map_err(|_| TwoMlsPqError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    let commit_output = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| TwoMlsPqError::Mls)?
        .build()
        .map_err(|_| TwoMlsPqError::Mls)?;
    group
        .apply_pending_commit()
        .map_err(|_| TwoMlsPqError::Mls)?;
    let welcome = commit_output
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(TwoMlsPqError::MissingWelcome)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
    Ok((group, welcome_bytes))
}

/// Create a group with a member commit that also injects an external PSK binding.
/// The PSK must already be registered in the client's store before calling this.
/// Returns (group-at-epoch-1, MLS-encoded Welcome bytes).
fn create_bound_group_with_member(
    mls_client: &MlsClient,
    their_kp_bytes: &[u8],
    psk_id: ExternalPskId,
) -> Result<(MlsGroup, Vec<u8>)> {
    let mut group = mls_client
        .create_group(ExtensionList::new(), ExtensionList::new())
        .map_err(|_| TwoMlsPqError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    let commit_output = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| TwoMlsPqError::Mls)?
        .add_external_psk(psk_id)
        .map_err(|_| TwoMlsPqError::Mls)?
        .build()
        .map_err(|_| TwoMlsPqError::Mls)?;
    group
        .apply_pending_commit()
        .map_err(|_| TwoMlsPqError::Mls)?;
    let welcome = commit_output
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(TwoMlsPqError::MissingWelcome)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
    Ok((group, welcome_bytes))
}

/// Join a group from an MLS-encoded Welcome message.
fn join_group_from_welcome(mls_client: &MlsClient, welcome_bytes: &[u8]) -> Result<MlsGroup> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| TwoMlsPqError::Mls)?;
    let (group, _) = mls_client
        .join_group(None, &welcome)
        .map_err(|_| TwoMlsPqError::Mls)?;
    Ok(group)
}

/// Create the initiator's Combiner send group (Group_A) from the remote's CombinerKeyPackage.
/// Chain: classical Group_A → PSK → PQ Group_A.
/// Returns (send_group, APQWelcome_A bytes).
fn create_combiner_send_group(
    their_kp: &CombinerKeyPackage,
    client: &Arc<TwoMlsPqClient>,
) -> Result<(CombinerGroup, Vec<u8>)> {
    let (classical_group, classical_welcome) =
        create_group_with_member(client.classical(), &their_kp.classical)?;
    let psk_id = export_and_register_psk(&classical_group, client)?;
    let (pq_group, pq_welcome) =
        create_bound_group_with_member(client.classical(), &their_kp.pq, psk_id)?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup {
            classical: classical_group,
            pq: pq_group,
        },
        apq,
    ))
}

/// Join both halves of a Combiner group from an APQWelcome.
/// The joiner independently re-derives the same PSK that was used to bind the PQ group,
/// registering it before processing the PQ Welcome.
fn join_combiner_group(apq_welcome: &[u8], client: &Arc<TwoMlsPqClient>) -> Result<CombinerGroup> {
    let (classical_welcome, pq_welcome) = decode_apq_welcome(apq_welcome)?;
    let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
    // Derive the same PSK the creator used to bind the PQ group.
    export_and_register_psk(&classical, client)?;
    let pq = join_group_from_welcome(client.classical(), &pq_welcome)?;
    Ok(CombinerGroup { classical, pq })
}

/// Create the acceptor's bound Combiner send group (Group_B) using the PSK exported from
/// the already-joined recv group's classical half.
/// Chain: recv classical (Group_A) → PSK_recv → Group_B classical → PSK_B → Group_B PQ.
/// Returns (send_group, APQWelcome_B bytes).
fn create_bound_combiner_send_group(
    their_kp: &CombinerKeyPackage,
    client: &Arc<TwoMlsPqClient>,
    recv_classical: &MlsGroup,
) -> Result<(CombinerGroup, Vec<u8>)> {
    let psk_id = export_and_register_psk(recv_classical, client)?;
    let (classical_group, classical_welcome) =
        create_bound_group_with_member(client.classical(), &their_kp.classical, psk_id)?;
    let psk_id2 = export_and_register_psk(&classical_group, client)?;
    let (pq_group, pq_welcome) =
        create_bound_group_with_member(client.classical(), &their_kp.pq, psk_id2)?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup {
            classical: classical_group,
            pq: pq_group,
        },
        apq,
    ))
}

/// Extract the `ClientId` of the member at `leaf_index` in `group` using the Basic credential.
fn sender_client_id(group: &MlsGroup, leaf_index: u32) -> Result<ClientId> {
    let member = group
        .roster()
        .member_with_index(leaf_index)
        .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
    let basic = member
        .signing_identity
        .credential
        .as_basic()
        .ok_or(TwoMlsPqError::DecryptionFailed)?;
    Ok(ClientId {
        bytes: basic.identifier.clone(),
    })
}

fn build_session(
    client: Arc<TwoMlsPqClient>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    session_id: SessionId,
    my_id: ClientId,
    their_id: ClientId,
) -> Arc<TwoMlsPqSession> {
    Arc::new(TwoMlsPqSession {
        inner: Mutex::new(SessionInner {
            client,
            send_group,
            recv_group,
            pending_outbound,
            pending_proposal_hash: None,
            pending_commit_message: None,
            queued_proposal: None,
            pending_new_client: None,
            session_id,
            my_state: AgentState::Sync { client_id: my_id },
            their_state: AgentState::Sync {
                client_id: their_id,
            },
        }),
    })
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Create a session as the initiating party targeting `their_key_package`.
    /// Retrieve the outbound APQWelcome bytes via `pending_outbound`.
    #[uniffi::constructor]
    pub fn initiate(
        client: Arc<TwoMlsPqClient>,
        their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let my_id = client.client_id();
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(my_id.clone(), their_id.clone())?;

        let (send_group, apq_welcome) = create_combiner_send_group(&their_key_package, &client)?;

        Ok(build_session(
            client,
            Some(send_group),
            None,
            Some(apq_welcome),
            session_id,
            my_id,
            their_id,
        ))
    }

    /// Join a session from an APQWelcome produced by the remote `initiate`.
    /// Retrieve this party's return Welcome via `pending_outbound`.
    #[uniffi::constructor]
    pub fn accept(
        client: Arc<TwoMlsPqClient>,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let my_id = client.client_id();
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(my_id.clone(), their_id.clone())?;

        let recv_group = join_combiner_group(&welcome, &client)?;
        let (send_group, apq_welcome) =
            create_bound_combiner_send_group(&their_key_package, &client, &recv_group.classical)?;

        Ok(build_session(
            client,
            Some(send_group),
            Some(recv_group),
            Some(apq_welcome),
            session_id,
            my_id,
            their_id,
        ))
    }

    /// Restore a session from a serialised archive.
    #[uniffi::constructor]
    pub fn from_archive(_archive: Archive, _client: Arc<TwoMlsPqClient>) -> Result<Arc<Self>> {
        Err(TwoMlsPqError::ArchiveInvalid)
    }

    /// Welcome bytes to deliver to the remote party to complete group establishment.
    /// Returns `None` once consumed or when both groups are live.
    pub fn pending_outbound(&self) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending_outbound
            .take()
    }

    pub fn is_established(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.send_group.is_some() && inner.recv_group.is_some()
    }

    pub fn has_receive_group(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_group
            .is_some()
    }

    pub fn active_session_id(&self) -> SessionId {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .session_id
            .clone()
    }

    pub fn my_agent_state(&self) -> AgentState {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .my_state
            .clone()
    }

    pub fn their_agent_state(&self) -> AgentState {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .their_state
            .clone()
    }

    pub fn receive_group_id(&self) -> Option<CombinerGroupId> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.recv_group.as_ref().map(|rg| CombinerGroupId {
            classical: MlsGroupId {
                bytes: rg.classical.group_id().to_vec(),
            },
            pq: MlsGroupId {
                bytes: rg.pq.group_id().to_vec(),
            },
        })
    }

    /// Prepare a pending proposal nonce and stage it for binding into the next outbound message.
    /// Returns `Err(SessionNotReady)` until both groups are established.
    ///
    /// - `proposing: None` with a queued remote proposal → empty commit (epoch advance), `did_commit: true`
    /// - `proposing: Some(new_id)` → rotation commit with new leaf credential, `did_commit: true`
    /// - Otherwise → nonce only, `did_commit: false`
    pub fn prepare_to_encrypt(
        &self,
        proposing: Option<ClientId>,
    ) -> Result<Option<PrepareEncryptResult>> {
        let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;

        // Phase 8: key rotation commit.
        // The new agent's ClientId is encoded in the commit's authenticated_data so the
        // recipient can extract it from CommitMessageDescription without a full credential
        // rotation (which BasicIdentityProvider rejects for mismatched identifiers).
        if let Some(new_id) = proposing {
            let new_client = inner
                .pending_new_client
                .take()
                .ok_or(TwoMlsPqError::SessionNotReady)?;

            if new_client.client_id() != new_id {
                return Err(TwoMlsPqError::SessionNotReady);
            }

            let commit_output = {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.pq
                    .commit_builder()
                    .authenticated_data(new_id.bytes.clone())
                    .build()
                    .map_err(|_| TwoMlsPqError::Mls)?
            };

            {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.pq
                    .apply_pending_commit()
                    .map_err(|_| TwoMlsPqError::Mls)?;
            }

            let commit_bytes = commit_output
                .commit_message
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?;

            inner.pending_commit_message = Some(commit_bytes);

            let old_id = inner.my_state.client_id();
            inner.my_state = AgentState::Pending {
                old: old_id,
                new: new_id,
            };
            inner.client = new_client;

            let nonce = inner
                .send_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .pq
                .export_secret(b"proposal", b"prepare", 32)
                .map_err(|_| TwoMlsPqError::Mls)?;

            let proposal_hash = TwoMlsPqDigest {
                hash_type: 0,
                digest: nonce.as_bytes().to_vec(),
            };
            inner.pending_proposal_hash = Some(proposal_hash.clone());

            return Ok(Some(PrepareEncryptResult {
                proposal_hash,
                committed_remote_client_id: None,
                did_commit: true,
            }));
        }

        // Phase 7: empty epoch-advance commit to clear a queued remote proposal
        if let Some(_queued) = inner.queued_proposal.take() {
            let commit_output = {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.pq
                    .commit_builder()
                    .build()
                    .map_err(|_| TwoMlsPqError::Mls)?
            };

            {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.pq
                    .apply_pending_commit()
                    .map_err(|_| TwoMlsPqError::Mls)?;
            }

            let commit_bytes = commit_output
                .commit_message
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?;

            inner.pending_commit_message = Some(commit_bytes);

            let their_id = inner.their_state.client_id();

            let nonce = inner
                .send_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .pq
                .export_secret(b"proposal", b"prepare", 32)
                .map_err(|_| TwoMlsPqError::Mls)?;

            let proposal_hash = TwoMlsPqDigest {
                hash_type: 0,
                digest: nonce.as_bytes().to_vec(),
            };
            inner.pending_proposal_hash = Some(proposal_hash.clone());

            return Ok(Some(PrepareEncryptResult {
                proposal_hash,
                committed_remote_client_id: Some(their_id),
                did_commit: true,
            }));
        }

        // Phase 6: no commit — export a per-epoch nonce to bind into authenticated_data.
        let nonce = inner
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .pq
            .export_secret(b"proposal", b"prepare", 32)
            .map_err(|_| TwoMlsPqError::Mls)?;

        let proposal_hash = TwoMlsPqDigest {
            hash_type: 0,
            digest: nonce.as_bytes().to_vec(),
        };
        inner.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(Some(PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: None,
            did_commit: false,
        }))
    }

    /// Encrypt `app_message` using the PQ send group.
    /// Must be called after `prepare_to_encrypt`; the pending proposal hash is used as
    /// authenticated data and cleared on return.
    /// When a commit was staged (did_commit: true), the output is a bundled commit+app message.
    pub fn encrypt(&self, app_message: Vec<u8>) -> Result<EncryptResult> {
        let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;

        let proposal_hash = inner
            .pending_proposal_hash
            .take()
            .ok_or(TwoMlsPqError::SessionNotReady)?;

        let (app_bytes, epoch) = {
            let send = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;

            let cipher_msg = send
                .pq
                .encrypt_application_message(&app_message, proposal_hash.digest)
                .map_err(|_| TwoMlsPqError::Mls)?;

            let epoch = send.pq.current_epoch();
            let bytes = cipher_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
            (bytes, epoch)
        };

        let cipher_text = if let Some(commit_bytes) = inner.pending_commit_message.take() {
            encode_bundled(commit_bytes, app_bytes)
        } else {
            app_bytes
        };

        let sender = inner.my_state.client_id();
        let recipient = inner.their_state.client_id();

        Ok(EncryptResult {
            cipher_text,
            sender,
            recipient,
            epoch,
        })
    }

    /// Process an incoming message.
    ///
    /// - APQWelcome (0x01 prefix) → join recv groups; returns `Ok(None)`
    /// - Bundled commit+app (0x03 prefix) → advance epoch then decrypt; returns `DecryptResult`
    /// - MLS ciphertext → decrypt on recv_group.pq; returns `DecryptResult`
    pub fn process_incoming(&self, ciphertext: Vec<u8>) -> Result<Option<DecryptResult>> {
        if ciphertext.first() == Some(&APQ_TAG) {
            let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;
            let client = inner.client.clone();

            // Re-derive the PSK that was used to bind Group_B classical.
            if let Some(sg) = &inner.send_group {
                export_and_register_psk(&sg.classical, &client)?;
            }

            let (classical_welcome, pq_welcome) = decode_apq_welcome(&ciphertext)?;
            let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
            export_and_register_psk(&classical, &client)?;
            let pq = join_group_from_welcome(client.classical(), &pq_welcome)?;

            inner.recv_group = Some(CombinerGroup { classical, pq });
            return Ok(None);
        }

        // Phase 7/8: bundled commit + app message
        if ciphertext.first() == Some(&BUNDLED_TAG) {
            let (commit_bytes, app_bytes) = decode_bundled(&ciphertext)?;

            let commit_msg = MlsMessage::from_bytes(&commit_bytes)
                .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;

            // Process commit — advances epoch in recv_group.pq.
            let (_committer_index, commit_auth_data) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .pq
                    .process_incoming_message(commit_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::Commit(desc) => (desc.committer, desc.authenticated_data),
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            // Detect key rotation: a non-empty commit authenticated_data carries
            // the new agent's ClientId bytes (set in prepare_to_encrypt Phase 8).
            let new_sender = if commit_auth_data.is_empty() {
                None
            } else {
                Some(ClientId {
                    bytes: commit_auth_data,
                })
            };

            if let Some(ref new_id) = new_sender {
                inner.their_state = AgentState::Sync {
                    client_id: new_id.clone(),
                };
            }

            // Process the bundled app message in the new epoch.
            let (app_data, sender_id, epoch) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .pq
                    .process_incoming_message(app_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::ApplicationMessage(desc) => {
                        let sender = sender_client_id(&recv.pq, desc.sender_index)?;
                        let ep = recv.pq.current_epoch();
                        (desc.data().to_vec(), sender, ep)
                    }
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            let my_id = inner.my_state.client_id();

            return Ok(Some(DecryptResult {
                application_message: Some(MlsSenderMessage {
                    app_message_data: app_data,
                    sender_client_id: sender_id,
                    epoch,
                }),
                proposal: None,
                remote_commit: Some(CommitResult {
                    new_sender,
                    new_recipient: my_id,
                }),
            }));
        }

        // MLS messages start with version bytes (0x00 ...) — attempt decryption.
        let msg =
            MlsMessage::from_bytes(&ciphertext).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

        let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;
        let recv = inner
            .recv_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?;

        let received = recv
            .pq
            .process_incoming_message(msg)
            .map_err(|_| TwoMlsPqError::DecryptionFailed)?;

        match received {
            ReceivedMessage::ApplicationMessage(desc) => {
                let sender_id = sender_client_id(&recv.pq, desc.sender_index)?;
                let epoch = recv.pq.current_epoch();
                // A non-empty authenticated_data carries the sender's proposal nonce —
                // surface it as a queued remote proposal for the app layer to accept.
                let proposal = if desc.authenticated_data.is_empty() {
                    None
                } else {
                    Some(crate::QueuedRemoteProposal {
                        digest: TwoMlsPqDigest {
                            hash_type: 0,
                            digest: desc.authenticated_data.clone(),
                        },
                        sender: sender_id.clone(),
                        proposing: sender_id.clone(),
                        context: TwoMlsPqDigest {
                            hash_type: 0,
                            digest: recv.pq.group_id().to_vec(),
                        },
                    })
                };
                Ok(Some(DecryptResult {
                    application_message: Some(MlsSenderMessage {
                        app_message_data: desc.data().to_vec(),
                        sender_client_id: sender_id,
                        epoch,
                    }),
                    proposal,
                    remote_commit: None,
                }))
            }
            _ => Ok(None),
        }
    }

    pub fn proposal_context(&self) -> Option<TwoMlsPqDigest> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.recv_group.as_ref().map(|rg| TwoMlsPqDigest {
            hash_type: 0,
            digest: rg.pq.group_id().to_vec(),
        })
    }

    pub fn send_rendezvous(&self) -> Result<Option<RendezvousId>> {
        todo!()
    }

    pub fn archive(&self) -> Result<Archive> {
        todo!()
    }

    /// Accept a remote proposal for the next epoch advance.
    /// On the next `prepare_to_encrypt(None)` call, an empty commit will be staged.
    pub fn queue_proposal(&self, digest: TwoMlsPqDigest) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;
        inner.queued_proposal = Some(digest);
        Ok(())
    }

    /// Register a new agent client for the next rotation commit.
    /// Call before `prepare_to_encrypt(Some(new_client.client_id()))`.
    pub fn stage_rotation(&self, new_client: Arc<TwoMlsPqClient>) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| TwoMlsPqError::Mls)?;
        inner.pending_new_client = Some(new_client);
        Ok(())
    }

    /// Process a message forwarded from another of the user's own devices.
    pub fn forwarded(&self, _header_decrypted: Vec<u8>) -> Result<Option<MlsSenderMessage>> {
        todo!()
    }

    pub fn should_listen_on(&self) -> Result<ListenChannels> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    use super::TwoMlsPqSession;
    use crate::{
        assert_ok,
        key_packages::{CombinerKeyPackage, TwoMlsPqClient},
        MlsCipherSuite,
    };

    fn test_signing_key() -> Vec<u8> {
        let crypto = RustCryptoProvider::new();
        let cs = crypto
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .expect("suite supported");
        let (secret, _) = assert_ok!(cs.signature_key_generate());
        secret.as_bytes().to_vec()
    }

    fn make_client() -> Arc<TwoMlsPqClient> {
        assert_ok!(TwoMlsPqClient::new(test_signing_key()))
    }

    // Generate two distinct classical key packages used as the classical and pq halves.
    // ML-KEM-768 is not available with RustCrypto; both halves use suite 0x0003 for testing.
    fn make_combiner_kp(client: &TwoMlsPqClient) -> CombinerKeyPackage {
        let classical = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        let pq = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        CombinerKeyPackage { classical, pq }
    }

    fn establish_sessions() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let apq_welcome_a = alice_session.pending_outbound().expect("alice outbound");

        let bob_session = assert_ok!(TwoMlsPqSession::accept(
            Arc::clone(&bob),
            apq_welcome_a,
            alice_kp
        ));
        let apq_welcome_b = bob_session.pending_outbound().expect("bob outbound");

        assert_ok!(alice_session.process_incoming(apq_welcome_b));

        (alice_session, bob_session)
    }

    #[test]
    fn test_initiate_stores_outbound_welcome() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(session.pending_outbound().is_some());
    }

    #[test]
    fn test_pending_outbound_returns_none_after_take() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
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
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(!session.is_established());
    }

    #[test]
    fn test_accept_stores_outbound_welcome() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let apq_welcome_a = alice_session.pending_outbound().expect("alice welcome");

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
    fn test_session_id_is_same_from_both_sides() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let apq_welcome_a = alice_session.pending_outbound().expect("alice outbound");

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
        let result = assert_ok!(alice_session.prepare_to_encrypt(None)).expect("some result");
        assert!(!result.proposal_hash.digest.is_empty());
        assert!(!result.did_commit);
    }

    #[test]
    fn test_encrypt_after_prepare_succeeds() {
        let (alice_session, _bob_session) = establish_sessions();
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let result = assert_ok!(alice_session.encrypt(b"hello world".to_vec()));
        assert!(!result.cipher_text.is_empty());
        assert_eq!(result.sender, alice_session.my_agent_state().client_id());
    }

    #[test]
    fn test_process_incoming_app_message_returns_decrypt_result() {
        let (alice_session, bob_session) = establish_sessions();

        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"secret".to_vec()));

        let result =
            assert_ok!(bob_session.process_incoming(enc.cipher_text)).expect("some result");

        let app_msg = result.application_message.expect("application message");
        assert_eq!(app_msg.app_message_data, b"secret");
        assert_eq!(
            app_msg.sender_client_id,
            alice_session.my_agent_state().client_id()
        );
    }

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
    #[cfg(feature = "cryptokit")]
    fn test_create_bound_send_group_ml_kem_768_with_psk_succeeds() {}

    #[test]
    fn test_queue_proposal_stages_for_next_ratchet() {
        let (alice_session, bob_session) = establish_sessions();

        // Bob sends to Alice; Alice should receive a proposal in the result.
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"hello from bob".to_vec()));
        let result =
            assert_ok!(alice_session.process_incoming(enc.cipher_text)).expect("some result");
        let proposal = result.proposal.expect("proposal present");

        // Alice queues it; next prepare must commit.
        assert_ok!(alice_session.queue_proposal(proposal.digest));
        let prep = assert_ok!(alice_session.prepare_to_encrypt(None)).expect("some result");

        assert!(prep.did_commit, "should commit after queued proposal");
        assert!(prep.committed_remote_client_id.is_some());
    }

    #[test]
    fn test_prepare_to_encrypt_did_commit_true_when_remote_proposal_staged() {
        let (alice_session, bob_session) = establish_sessions();

        // Bob proposes; Alice queues; Alice sends bundled commit+app.
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"proposal msg".to_vec()));
        let result = assert_ok!(alice_session.process_incoming(enc.cipher_text)).expect("some");
        assert_ok!(alice_session.queue_proposal(result.proposal.expect("proposal").digest));

        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"reply".to_vec()));

        let result = assert_ok!(bob_session.process_incoming(enc.cipher_text)).expect("some");

        let app = result.application_message.expect("app message");
        assert_eq!(app.app_message_data, b"reply");
        let commit = result.remote_commit.expect("remote commit");
        assert!(
            commit.new_sender.is_none(),
            "no rotation, new_sender should be None"
        );
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn test_process_incoming_proposal_returns_none_until_queued() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_process_incoming_returns_none_on_rejoin_needed() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_session_id_differs_for_different_pairs() {}

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_full_establishment_sequence_ml_kem_768() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_concurrent_sessions_same_did_pair_both_valid() {}

    #[test]
    fn test_agent_rotation_migrates_session_to_new_agent() {
        let (alice_session, bob_session) = establish_sessions();

        let new_alice = make_client();
        let new_alice_id = new_alice.client_id();

        // Stage rotation and commit with new identity.
        assert_ok!(alice_session.stage_rotation(Arc::clone(&new_alice)));
        let prep =
            assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone()))).expect("some");
        assert!(prep.did_commit);

        let enc = assert_ok!(alice_session.encrypt(b"rotated".to_vec()));

        // Bob sees the new_sender in the commit result.
        let result = assert_ok!(bob_session.process_incoming(enc.cipher_text)).expect("some");

        let commit = result.remote_commit.expect("remote commit");
        assert_eq!(
            commit.new_sender.expect("new sender present"),
            new_alice_id,
            "Bob must observe Alice's new identity"
        );
        assert_eq!(
            result.application_message.expect("app").app_message_data,
            b"rotated"
        );
        assert_eq!(bob_session.their_agent_state().client_id(), new_alice_id);
    }

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
