use std::sync::{Arc, Mutex};

use mls_rs::{group::ReceivedMessage, MlsMessage};

#[cfg(not(feature = "cryptokit"))]
use apq::create_group_with_member;
use apq::{
    create_bound_classical_send_group, create_combiner_send_group, decode_apq_welcome,
    encode_apq_welcome, export_and_register_psk, join_combiner_group, join_group_from_welcome,
    sender_client_id, APQ_TAG,
};

use crate::key_package_store::CombinerGroup;

use crate::{
    key_packages::{
        ensure_pq_available, parse_mls_key_package, CombinerKeyPackage, TwoMlsPqClient,
    },
    AgentState, Archive, ClientId, CombinerGroupId, CommitResult, DecryptResult, EncryptResult,
    ListenChannels, MlsGroupId, MlsSenderMessage, PrepareEncryptResult, RendezvousId, Result,
    SessionId, TwoMlsPqDigest, TwoMlsPqError,
};

#[cfg(feature = "cryptokit")]
use apq::{export_and_register_psk_pq, pq_create_group_with_member, pq_join_group_from_welcome};
#[cfg(feature = "cryptokit")]
use zeroize::Zeroizing;

struct SessionInner {
    client: Arc<TwoMlsPqClient>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    pending_proposal_hash: Option<TwoMlsPqDigest>,
    /// Send-group commit to bundle with the next outbound app message (rotation, or epoch advance).
    pending_commit_message: Option<Vec<u8>>,
    /// Recv-group commit to bundle with the next outbound app message (self-Update or PSK refresh).
    pending_recv_commit_message: Option<Vec<u8>>,
    queued_proposal: Option<TwoMlsPqDigest>,
    pending_new_client: Option<Arc<TwoMlsPqClient>>,
    #[cfg(feature = "cryptokit")]
    pq_inflight: Option<PqInflight>,
    session_id: SessionId,
    my_state: AgentState,
    their_state: AgentState,
    /// Whose move the PQ side-band is: the initiator owes the A.4 bootstrap; thereafter
    /// completing an operation passes the turn to the peer.
    pq_turn_mine: bool,
}

/// A TwoMLSPQ session holding two asymmetric Combiner send groups.
#[derive(uniffi::Object)]
pub struct TwoMlsPqSession {
    inner: Mutex<SessionInner>,
}

// APQWelcome wire format (0x01) + encode/decode live in the `apq` crate (imported above).
// Rotation commit+app: [0x03 tag][u32-LE commit-len][commit][u32-LE app-len][app]
// Used only for Phase 8 agent rotation (no PSK refresh).
const BUNDLED_TAG: u8 = 0x03;
// Partial commit: [0x05 tag][u32-LE recv-commit-len][recv-commit][u32-LE app-len][app]
// Alice commits on Group_B (recv group) to refresh her HPKE leaf key, then sends app on Group_A.
const PARTIAL_TAG: u8 = 0x05;
// Full bundle: [0x07 tag][u32-LE send-commit-len][send-commit][u32-LE recv-commit-len][recv-commit][u32-LE app-len][app]
// Epoch-advance commit on Group_A + PSK-refresh commit on Group_B + app on Group_A.
const FULL_BUNDLE_TAG: u8 = 0x07;
// Stapled welcome: [0x09 tag][u32-LE welcome-len][APQWelcome bytes][inner frame bytes].
// The acceptor staples its return APQWelcome onto its first app frame; the inner frame is an
// ordinary tagged frame (0x05/0x07/0x03/raw). First round only — consumed after one send.
const STAPLED_WELCOME_TAG: u8 = 0x09;
// PQ ratchet (architecture-diagrams PR #2 §A.3), cryptokit only:
// 0x0B carries the initiator's ML-KEM encapsulation key, 0x0D the responder's ciphertext,
// 0x0F the bind = [pq partial-commit][classical commit][app], all length-prefixed.
#[cfg(feature = "cryptokit")]
const PQ_EK_TAG: u8 = 0x0B;
#[cfg(feature = "cryptokit")]
const PQ_CT_TAG: u8 = 0x0D;
#[cfg(feature = "cryptokit")]
const PQ_BIND_TAG: u8 = 0x0F;

/// A.4 bootstrap: this side's PQ key package, sent so the peer can stand up its deferred
/// send-group PQ half.
const PQ_BOOTSTRAP_KP_TAG: u8 = 0x11;

/// A.4 bootstrap reply: the new PQ group's welcome plus the classical APQ-PSK bind commit.
const PQ_BOOTSTRAP_BIND_TAG: u8 = 0x13;

/// PQ ratchet round state carried between the messages of one exchange.
#[cfg(feature = "cryptokit")]
enum PqInflight {
    /// Initiator holds the ephemeral (decapsulation key) until it receives the ciphertext.
    Initiating(apq::pq_ratchet::PqEphemeral),
    /// Responder holds the shared secret until it receives the stapled bind. `Zeroizing` wipes the
    /// secret from memory on drop, whether it is consumed by the bind or abandoned.
    Responding(Zeroizing<Vec<u8>>),
}

/// Append `part` to `out` as a u32-LE length-prefixed section.
fn push_section(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

/// Read exactly `N` u32-LE length-prefixed sections from `body` (the frame payload *after* the
/// 1-byte tag), rejecting truncation and any trailing bytes. Single source of truth for the
/// length-prefixed framing used by all bundle/commit frames, so the bounds checks live in one
/// audited place rather than being re-derived per frame type.
fn read_sections<const N: usize>(body: &[u8]) -> Result<[Vec<u8>; N]> {
    let mut rest = body;
    let mut out: [Vec<u8>; N] = std::array::from_fn(|_| Vec::new());
    for slot in out.iter_mut() {
        if rest.len() < 4 {
            return Err(TwoMlsPqError::Mls);
        }
        let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return Err(TwoMlsPqError::Mls);
        }
        *slot = rest[..len].to_vec();
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return Err(TwoMlsPqError::Mls);
    }
    Ok(out)
}

#[cfg(feature = "cryptokit")]
fn encode_pq_bind(pq_commit: Vec<u8>, classical_commit: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(1 + 4 + pq_commit.len() + 4 + classical_commit.len() + 4 + app.len());
    out.push(PQ_BIND_TAG);
    push_section(&mut out, &pq_commit);
    push_section(&mut out, &classical_commit);
    push_section(&mut out, &app);
    out
}

/// Encode the A.4 bootstrap reply: `[0x13][u32-LE welcome-len][pq_welcome][classical_commit…]`.
fn encode_bootstrap_bind(pq_welcome: Vec<u8>, classical_commit: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + pq_welcome.len() + classical_commit.len());
    out.push(PQ_BOOTSTRAP_BIND_TAG);
    out.extend_from_slice(&(pq_welcome.len() as u32).to_le_bytes());
    out.extend_from_slice(&pq_welcome);
    out.extend_from_slice(&classical_commit);
    out
}

fn decode_bootstrap_bind(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BOOTSTRAP_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    if rest.len() < 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let w_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() < w_len {
        return Err(TwoMlsPqError::Mls);
    }
    Ok((rest[..w_len].to_vec(), rest[w_len..].to_vec()))
}

#[cfg(feature = "cryptokit")]
fn decode_pq_bind(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [pq_commit, classical_commit, app] = read_sections::<3>(rest)?;
    Ok((pq_commit, classical_commit, app))
}

#[cfg(feature = "cryptokit")]
#[uniffi::export]
impl TwoMlsPqSession {
    /// Initiator step 1 — generate an ML-KEM ephemeral and return the encapsulation-key message
    /// (tag 0x0B). The decapsulation key is held until the ciphertext arrives.
    pub fn pq_ratchet_begin(&self) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        if inner.pq_inflight.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let eph = apq::pq_ratchet::generate_ephemeral()?;
        let mut msg = vec![PQ_EK_TAG];
        msg.extend_from_slice(&eph.encapsulation_key());
        inner.pq_inflight = Some(PqInflight::Initiating(eph));
        Ok(msg)
    }

    /// Responder — encapsulate a fresh secret to the initiator's EK, hold it, and return the
    /// ciphertext message (tag 0x0D).
    pub fn pq_ratchet_respond(&self, ek_msg: Vec<u8>) -> Result<Vec<u8>> {
        let (&tag, ek) = ek_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_EK_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pq_inflight.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let (s, ct) = apq::pq_ratchet::encapsulate(ek)?;
        inner.pq_inflight = Some(PqInflight::Responding(Zeroizing::new(s)));
        let mut msg = vec![PQ_CT_TAG];
        msg.extend_from_slice(&ct);
        Ok(msg)
    }

    /// Initiator step 2 — decapsulate S, inject it into the send group's PQ half via a pathless
    /// commit, bind the exported apq_psk into the classical half, and staple an app message.
    /// Returns the bind frame (tag 0x0F).
    pub fn pq_ratchet_bind(&self, ct_msg: Vec<u8>, app: Vec<u8>) -> Result<Vec<u8>> {
        let (&tag, ct) = ct_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_CT_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        let eph = match inner.pq_inflight.take() {
            Some(PqInflight::Initiating(eph)) => eph,
            _ => return Err(TwoMlsPqError::SessionNotReady),
        };
        let s = Zeroizing::new(apq::pq_ratchet::decapsulate(&eph, ct)?);
        let client = inner.client.clone();
        let send = inner
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_pq = send.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        let (pq_commit, apq_psk_id) =
            apq::pq_ratchet::inject_and_commit(send_pq, &s, client.combiner())?;
        let cl_out = send
            .classical
            .commit_builder()
            .add_external_psk(apq_psk_id)
            .map_err(|_| TwoMlsPqError::Mls)?
            .build()
            .map_err(|_| TwoMlsPqError::Mls)?;
        send.classical
            .apply_pending_commit()
            .map_err(|_| TwoMlsPqError::Mls)?;
        let cl_commit = cl_out
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        let app_ct = send
            .classical
            .encrypt_application_message(&app, vec![])
            .map_err(|_| TwoMlsPqError::Mls)?
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        // Our operation is complete once the peer applies; the turn passes.
        inner.pq_turn_mine = false;
        Ok(encode_pq_bind(pq_commit, cl_commit, app_ct))
    }

    /// Responder — apply the stapled bind: register the held secret, apply the PQ partial commit
    /// and classical commit on the recv group, and return the decrypted app message.
    pub fn pq_ratchet_apply(&self, bind_msg: Vec<u8>) -> Result<Vec<u8>> {
        let (pq_commit, cl_commit, app_ct) = decode_pq_bind(&bind_msg)?;
        let mut inner = self.lock();
        let s = match inner.pq_inflight.take() {
            Some(PqInflight::Responding(s)) => s,
            _ => return Err(TwoMlsPqError::SessionNotReady),
        };
        let client = inner.client.clone();
        let recv = inner
            .recv_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let recv_pq = recv.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        apq::pq_ratchet::apply_injected_commit(recv_pq, &s, &pq_commit, client.combiner())?;
        let cl = MlsMessage::from_bytes(&cl_commit).map_err(|_| TwoMlsPqError::Mls)?;
        recv.classical
            .process_incoming_message(cl)
            .map_err(|_| TwoMlsPqError::Mls)?;
        let app = MlsMessage::from_bytes(&app_ct).map_err(|_| TwoMlsPqError::Mls)?;
        let out = match recv
            .classical
            .process_incoming_message(app)
            .map_err(|_| TwoMlsPqError::Mls)?
        {
            ReceivedMessage::ApplicationMessage(m) => Ok(m.data().to_vec()),
            _ => Err(TwoMlsPqError::DecryptionFailed),
        };
        // We finished receiving this operation; the next one is ours to start.
        inner.pq_turn_mine = true;
        out
    }
}

fn encode_stapled_welcome(welcome: &[u8], inner: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + welcome.len() + inner.len());
    out.push(STAPLED_WELCOME_TAG);
    out.extend_from_slice(&(welcome.len() as u32).to_le_bytes());
    out.extend_from_slice(welcome);
    out.extend_from_slice(&inner);
    out
}

fn decode_stapled_welcome(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != STAPLED_WELCOME_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    if rest.len() < 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let w_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() < w_len {
        return Err(TwoMlsPqError::Mls);
    }
    Ok((rest[..w_len].to_vec(), rest[w_len..].to_vec()))
}

fn encode_bundled(commit: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + commit.len() + 4 + app.len());
    out.push(BUNDLED_TAG);
    push_section(&mut out, &commit);
    push_section(&mut out, &app);
    out
}

fn decode_bundled(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != BUNDLED_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [commit, app] = read_sections::<2>(rest)?;
    Ok((commit, app))
}

fn encode_partial(recv_commit: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + recv_commit.len() + 4 + app.len());
    out.push(PARTIAL_TAG);
    push_section(&mut out, &recv_commit);
    push_section(&mut out, &app);
    out
}

fn decode_partial(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PARTIAL_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [recv_commit, app] = read_sections::<2>(rest)?;
    Ok((recv_commit, app))
}

fn encode_full_bundle(send_commit: Vec<u8>, recv_commit: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(1 + 4 + send_commit.len() + 4 + recv_commit.len() + 4 + app.len());
    out.push(FULL_BUNDLE_TAG);
    push_section(&mut out, &send_commit);
    push_section(&mut out, &recv_commit);
    push_section(&mut out, &app);
    out
}

fn decode_full_bundle(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != FULL_BUNDLE_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [send_commit, recv_commit, app] = read_sections::<3>(rest)?;
    Ok((send_commit, recv_commit, app))
}

/// Build a `QueuedRemoteProposal` from an application message's authenticated_data.
/// Returns `None` when `authenticated_data` is empty (no proposal nonce).
fn make_queued_proposal(
    group_id: &[u8],
    sender_id: &ClientId,
    authenticated_data: &[u8],
) -> Option<crate::QueuedRemoteProposal> {
    if authenticated_data.is_empty() {
        return None;
    }
    Some(crate::QueuedRemoteProposal {
        digest: TwoMlsPqDigest {
            hash_type: crate::DIGEST_SHA256,
            digest: authenticated_data.to_vec(),
        },
        sender: sender_id.clone(),
        proposing: sender_id.clone(),
        context: TwoMlsPqDigest {
            hash_type: crate::DIGEST_SHA256,
            digest: group_id.to_vec(),
        },
    })
}

impl SessionInner {
    /// Transition `my_state` from `Pending { old, new }` to `Sync { new }`.
    /// Called when any message is successfully decrypted from the recv group,
    /// confirming the peer has processed our rotation commit.
    fn resolve_pending_rotation(&mut self) {
        if let AgentState::Pending { new, .. } = &self.my_state {
            self.my_state = AgentState::Sync {
                client_id: new.clone(),
            };
        }
    }

    /// Phase 8: encode a rotation commit on send_group.pq with `new_id` in authenticated_data.
    fn prepare_rotation(&mut self, new_id: ClientId) -> Result<crate::PrepareEncryptResult> {
        let new_client = self
            .pending_new_client
            .take()
            .ok_or(TwoMlsPqError::SessionNotReady)?;

        if new_client.client_id() != new_id {
            return Err(TwoMlsPqError::SessionNotReady);
        }

        let commit_output = {
            let send = self
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            send.classical
                .commit_builder()
                .authenticated_data(new_id.bytes.clone())
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        {
            let send = self
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            send.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
        }

        let commit_bytes = commit_output
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        self.pending_commit_message = Some(commit_bytes);

        let old_id = self.my_state.client_id();
        self.my_state = AgentState::Pending {
            old: old_id,
            new: new_id,
        };
        self.client = new_client;

        let nonce = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .classical
            .export_secret(b"proposal", b"prepare", 32)
            .map_err(|_| TwoMlsPqError::Mls)?;

        let proposal_hash = TwoMlsPqDigest {
            hash_type: crate::DIGEST_SHA256,
            digest: nonce.as_bytes().to_vec(),
        };
        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: None,
            did_commit: true,
        })
    }

    /// Full round (queued proposal): traditional-only cross-party PSK refresh. Advance
    /// send_group.classical, export a TwoMLS-PSK from it, and commit it into recv_group.classical
    /// so post-compromise security propagates to both message groups. No PQ exchange — the PQ
    /// secret established at setup is preserved via the APQ-PSK already in the key schedule.
    fn prepare_full_commit(&mut self) -> Result<crate::PrepareEncryptResult> {
        // Consume the queued proposal to enter this branch.
        let _ = self.queued_proposal.take();
        let client = self.client.clone();

        let send_commit_output = {
            let send = self
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            send.classical
                .commit_builder()
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        {
            let send = self
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            send.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
        }
        let send_commit_bytes = send_commit_output
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;

        let psk_id = {
            let send = self
                .send_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            export_and_register_psk(&send.classical, client.combiner())?
        };

        let recv_commit_output = {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            recv.classical
                .commit_builder()
                .add_external_psk(psk_id)
                .map_err(|_| TwoMlsPqError::Mls)?
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            recv.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
        }
        let recv_commit_bytes = recv_commit_output
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;

        self.pending_commit_message = Some(send_commit_bytes);
        self.pending_recv_commit_message = Some(recv_commit_bytes);

        let their_id = self.their_state.client_id();

        let nonce = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .classical
            .export_secret(b"proposal", b"prepare", 32)
            .map_err(|_| TwoMlsPqError::Mls)?;

        let proposal_hash = TwoMlsPqDigest {
            hash_type: crate::DIGEST_SHA256,
            digest: nonce.as_bytes().to_vec(),
        };
        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: Some(their_id),
            did_commit: true,
        })
    }

    /// Routine round: traditional-only self-Update commit on recv_group.classical to refresh
    /// the committer's HPKE leaf key. No PQ exchange — the PQ group is untouched this round.
    fn prepare_partial_commit(&mut self) -> Result<crate::PrepareEncryptResult> {
        let recv_commit_output = {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            recv.classical
                .commit_builder()
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            recv.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
        }
        let recv_commit_bytes = recv_commit_output
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        self.pending_recv_commit_message = Some(recv_commit_bytes);

        let nonce = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .classical
            .export_secret(b"proposal", b"prepare", 32)
            .map_err(|_| TwoMlsPqError::Mls)?;

        let proposal_hash = TwoMlsPqDigest {
            hash_type: crate::DIGEST_SHA256,
            digest: nonce.as_bytes().to_vec(),
        };
        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: None,
            did_commit: false,
        })
    }
}

fn build_session(
    client: Arc<TwoMlsPqClient>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    session_id: SessionId,
    their_id: ClientId,
    initiated: bool,
) -> Arc<TwoMlsPqSession> {
    let my_id = client.client_id();
    Arc::new(TwoMlsPqSession {
        inner: Mutex::new(SessionInner {
            client,
            send_group,
            recv_group,
            pending_outbound,
            pending_proposal_hash: None,
            pending_commit_message: None,
            pending_recv_commit_message: None,
            queued_proposal: None,
            pending_new_client: None,
            #[cfg(feature = "cryptokit")]
            pq_inflight: None,
            session_id,
            my_state: AgentState::Sync { client_id: my_id },
            their_state: AgentState::Sync {
                client_id: their_id,
            },
            pq_turn_mine: initiated,
        }),
    })
}

impl TwoMlsPqSession {
    /// Lock the session state, recovering from a poisoned mutex rather than propagating a panic.
    /// A poisoned lock means a prior holder panicked mid-update; we surface the inner state and let
    /// the normal `Option`/`AgentState` checks reject any half-applied operation. Used everywhere so
    /// the lock policy is uniform and panic-free (the crate denies `unwrap`/`expect`/`panic`).
    fn lock(&self) -> std::sync::MutexGuard<'_, SessionInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
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
        ensure_pq_available(&their_key_package)?;
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(client.client_id(), their_id.clone())?;

        let (send_group, apq_welcome) = create_combiner_send_group(
            &their_key_package.classical,
            &their_key_package.pq,
            client.combiner(),
        )?;

        Ok(build_session(
            client,
            Some(send_group),
            None,
            Some(apq_welcome),
            session_id,
            their_id,
            true,
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
        ensure_pq_available(&their_key_package)?;
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(client.client_id(), their_id.clone())?;

        let recv_group = join_combiner_group(&welcome, client.combiner())?;
        // A.4: the send group's PQ half is deferred — classical only, bound to the
        // cross-party PSK. The bootstrap flow stands it up off the critical path, so the
        // return welcome carries an empty PQ slot.
        let (send_group, classical_welcome) = create_bound_classical_send_group(
            &their_key_package.classical,
            client.combiner(),
            &recv_group.classical,
        )?;
        let apq_welcome = encode_apq_welcome(classical_welcome, Vec::new());

        Ok(build_session(
            client,
            Some(send_group),
            Some(recv_group),
            Some(apq_welcome),
            session_id,
            their_id,
            false,
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
        self.lock().pending_outbound.take()
    }

    /// True once both directions' PQ halves are live (post-A.4 bootstrap).
    pub fn is_fully_established(&self) -> bool {
        let inner = self.lock();
        matches!(
            (&inner.send_group, &inner.recv_group),
            (Some(s), Some(r)) if s.pq.is_some() && r.pq.is_some()
        )
    }

    /// Whose move the PQ side-band is: true when this side owes the next operation.
    /// The initiator owes the A.4 bootstrap; completing an operation passes the turn.
    pub fn my_pq_turn(&self) -> bool {
        self.lock().pq_turn_mine
    }

    /// The send group's APQ epoch pair (PQ side-band, classical message group).
    /// Zeros until the corresponding group exists.
    pub fn epochs(&self) -> crate::ApqEpochs {
        let inner = self.lock();
        let (pq_epoch, classical_epoch) = inner
            .send_group
            .as_ref()
            .map(|g| {
                (
                    g.pq.as_ref().map(|p| p.current_epoch()).unwrap_or(0),
                    g.classical.current_epoch(),
                )
            })
            .unwrap_or((0, 0));
        crate::ApqEpochs {
            pq_epoch,
            classical_epoch,
        }
    }

    /// A.4 initiator — emit this side's PQ key package (tag 0x11) so the peer can stand
    /// up its deferred send-group PQ half. The key package's private material is retained
    /// in this client, so the returned welcome can be joined by `pq_bootstrap_apply`.
    pub fn pq_bootstrap_begin(&self) -> Result<Vec<u8>> {
        let inner = self.lock();
        if !inner.pq_turn_mine {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let ready = inner.send_group.is_some()
            && inner
                .recv_group
                .as_ref()
                .map(|g| g.pq.is_none())
                .unwrap_or(false);
        if !ready {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        #[cfg(feature = "cryptokit")]
        let kp = inner.client.combiner().generate_pq_key_package()?;
        #[cfg(not(feature = "cryptokit"))]
        let kp = inner.client.combiner().generate_classical_key_package()?;
        let mut msg = vec![PQ_BOOTSTRAP_KP_TAG];
        msg.extend_from_slice(&kp);
        Ok(msg)
    }

    /// A.4 responder — stand up the deferred send-group PQ half around the peer's key
    /// package, bind its exported APQ-PSK into the classical half, and return the
    /// bootstrap frame (tag 0x13). Taking this turn makes the next operation ours.
    pub fn pq_bootstrap_respond(&self, kp_msg: Vec<u8>) -> Result<Vec<u8>> {
        let (&tag, kp) = kp_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_BOOTSTRAP_KP_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        let client = inner.client.clone();
        let frame = {
            let send = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if send.pq.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            #[cfg(feature = "cryptokit")]
            let (pq_group, pq_welcome) = pq_create_group_with_member(client.pq(), kp, &[])?;
            #[cfg(not(feature = "cryptokit"))]
            let (pq_group, pq_welcome) = create_group_with_member(client.classical(), kp, &[])?;
            #[cfg(feature = "cryptokit")]
            let apq_psk = export_and_register_psk_pq(&pq_group, client.combiner())?;
            #[cfg(not(feature = "cryptokit"))]
            let apq_psk = export_and_register_psk(&pq_group, client.combiner())?;
            let cl_out = send
                .classical
                .commit_builder()
                .add_external_psk(apq_psk)
                .map_err(|_| TwoMlsPqError::Mls)?
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?;
            send.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
            let cl_commit = cl_out
                .commit_message
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?;
            send.pq = Some(pq_group);
            encode_bootstrap_bind(pq_welcome, cl_commit)
        };
        inner.pq_turn_mine = true;
        Ok(frame)
    }

    /// A.4 initiator completion — join the peer's new PQ group (our key package's
    /// private material is retained in this client), register its APQ-PSK, and apply
    /// the classical bind on the recv group. The turn passes to the peer.
    pub fn pq_bootstrap_apply(&self, bind_msg: Vec<u8>) -> Result<()> {
        let (pq_welcome, cl_commit) = decode_bootstrap_bind(&bind_msg)?;
        let mut inner = self.lock();
        let client = inner.client.clone();
        {
            let recv = inner
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if recv.pq.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            #[cfg(feature = "cryptokit")]
            let pq = pq_join_group_from_welcome(client.pq(), &pq_welcome)?;
            #[cfg(not(feature = "cryptokit"))]
            let pq = join_group_from_welcome(client.classical(), &pq_welcome)?;
            // Register the APQ-PSK before applying the classical bind that references it.
            #[cfg(feature = "cryptokit")]
            export_and_register_psk_pq(&pq, client.combiner())?;
            #[cfg(not(feature = "cryptokit"))]
            export_and_register_psk(&pq, client.combiner())?;
            let cl = MlsMessage::from_bytes(&cl_commit).map_err(|_| TwoMlsPqError::Mls)?;
            recv.classical
                .process_incoming_message(cl)
                .map_err(|_| TwoMlsPqError::Mls)?;
            recv.pq = Some(pq);
        }
        inner.pq_turn_mine = false;
        Ok(())
    }

    pub fn is_established(&self) -> bool {
        let inner = self.lock();
        inner.send_group.is_some() && inner.recv_group.is_some()
    }

    pub fn has_receive_group(&self) -> bool {
        self.lock().recv_group.is_some()
    }

    pub fn active_session_id(&self) -> SessionId {
        self.lock().session_id.clone()
    }

    pub fn my_agent_state(&self) -> AgentState {
        self.lock().my_state.clone()
    }

    pub fn their_agent_state(&self) -> AgentState {
        self.lock().their_state.clone()
    }

    pub fn receive_group_id(&self) -> Option<CombinerGroupId> {
        let inner = self.lock();
        inner.recv_group.as_ref().map(|rg| CombinerGroupId {
            classical: MlsGroupId {
                bytes: rg.classical.group_id().to_vec(),
            },
            // Empty until the deferred PQ half is bootstrapped (A.4).
            pq: MlsGroupId {
                bytes: rg
                    .pq
                    .as_ref()
                    .map(|pq| pq.group_id().to_vec())
                    .unwrap_or_default(),
            },
        })
    }

    /// Prepare a pending proposal nonce and stage it for binding into the next outbound message.
    /// Returns `Err(SessionNotReady)` until both groups are established.
    ///
    /// - `proposing: None` with a queued remote proposal → full commit (epoch advance + PSK refresh), `did_commit: true`
    /// - `proposing: Some(new_id)` → rotation commit with new leaf credential, `did_commit: true`
    /// - Otherwise → recv self-Update only, `did_commit: false`
    pub fn prepare_to_encrypt(&self, proposing: Option<ClientId>) -> Result<PrepareEncryptResult> {
        let mut inner = self.lock();
        if let Some(new_id) = proposing {
            return inner.prepare_rotation(new_id);
        }
        if inner.queued_proposal.is_some() {
            return inner.prepare_full_commit();
        }
        inner.prepare_partial_commit()
    }

    /// Encrypt `app_message` using the PQ send group.
    /// Must be called after `prepare_to_encrypt`; the pending proposal hash is used as
    /// authenticated data and cleared on return.
    /// When a commit was staged (did_commit: true), the output is a bundled commit+app message.
    pub fn encrypt(&self, app_message: Vec<u8>) -> Result<EncryptResult> {
        let mut inner = self.lock();

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
                .message_group_mut()
                .encrypt_application_message(&app_message, proposal_hash.digest)
                .map_err(|_| TwoMlsPqError::Mls)?;

            let epoch = send.message_group().current_epoch();
            let bytes = cipher_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
            (bytes, epoch)
        };

        let cipher_text = match (
            inner.pending_commit_message.take(),
            inner.pending_recv_commit_message.take(),
        ) {
            // Phase 7: epoch advance + PSK refresh → FULL_BUNDLE_TAG
            (Some(send), Some(recv)) => encode_full_bundle(send, recv, app_bytes),
            // Phase 8: rotation commit only → BUNDLED_TAG
            (Some(send), None) => encode_bundled(send, app_bytes),
            // Phase 6: recv self-Update only → PARTIAL_TAG
            (None, Some(recv)) => encode_partial(recv, app_bytes),
            // bare app message (should not occur after prepare_to_encrypt, but safe fallback)
            (None, None) => app_bytes,
        };

        // Welcome stapling: the acceptor (already has a recv group) rides its return APQWelcome
        // on its first app frame, so the peer joins and decrypts in one shot. First round only —
        // `pending_outbound` is consumed here. The initiator's welcome has no recv group yet and
        // is delivered separately via `pending_outbound()` before the peer's `accept`.
        let cipher_text = if inner.recv_group.is_some() {
            match inner.pending_outbound.take() {
                Some(welcome) => encode_stapled_welcome(&welcome, cipher_text),
                None => cipher_text,
            }
        } else {
            cipher_text
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
    /// - APQWelcome (0x01) → join recv groups; `Ok(None)`
    /// - Rotation commit+app (0x03) → advance send epoch then decrypt; `DecryptResult`
    /// - Partial bundle (0x05) → advance send.pq then decrypt app; `DecryptResult`
    /// - Full bundle (0x07) → epoch advance + PSK refresh then decrypt; `DecryptResult`
    /// - MLS ciphertext → decrypt on recv_group.pq; `DecryptResult`
    ///
    /// PQ-ratchet frames (0x0B/0x0D/0x0F) are **not** handled here — the host must route them to
    /// `pq_ratchet_respond`/`pq_ratchet_bind`/`pq_ratchet_apply` by their leading tag byte. Passing
    /// one here returns `SessionNotReady` rather than attempting (and failing) MLS decryption.
    pub fn process_incoming(&self, ciphertext: Vec<u8>) -> Result<Option<DecryptResult>> {
        // Stapled welcome: process the embedded APQWelcome (joins the recv group), then the
        // inner app frame. Each sub-frame is a self-contained tagged frame.
        if ciphertext.first() == Some(&STAPLED_WELCOME_TAG) {
            let (welcome, inner_frame) = decode_stapled_welcome(&ciphertext)?;
            self.process_incoming(welcome)?;
            return self.process_incoming(inner_frame);
        }

        if ciphertext.first() == Some(&APQ_TAG) {
            let mut inner = self.lock();
            let client = inner.client.clone();

            // Re-derive the cross-party TwoMLS-PSK from our own send group (Group_A classical).
            if let Some(sg) = &inner.send_group {
                export_and_register_psk(&sg.classical, client.combiner())?;
            }

            let (classical_welcome, pq_welcome) = decode_apq_welcome(&ciphertext)?;
            // An empty PQ slot is the acceptor's deferred (A.4) return welcome: join the
            // classical group only; the PQ half arrives with the bootstrap flow.
            if pq_welcome.is_empty() {
                let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
                inner.recv_group = Some(CombinerGroup {
                    classical,
                    pq: None,
                });
                return Ok(None);
            }
            // Join the PQ group first, then re-derive the intra-party APQ-PSK from it.
            #[cfg(feature = "cryptokit")]
            let pq = pq_join_group_from_welcome(client.pq(), &pq_welcome)?;
            #[cfg(not(feature = "cryptokit"))]
            let pq = join_group_from_welcome(client.classical(), &pq_welcome)?;
            #[cfg(feature = "cryptokit")]
            export_and_register_psk_pq(&pq, client.combiner())?;
            #[cfg(not(feature = "cryptokit"))]
            export_and_register_psk(&pq, client.combiner())?;
            // Join the classical group (bound with the cross-party + APQ PSKs).
            let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;

            inner.recv_group = Some(CombinerGroup {
                classical,
                pq: Some(pq),
            });
            return Ok(None);
        }

        // Phase 6: partial bundle — recv-group self-Update commit + app message.
        // The sender committed on their recv group (our send group) to refresh their HPKE leaf
        // key. We must advance our send group epoch before reading the app message.
        if ciphertext.first() == Some(&PARTIAL_TAG) {
            let (recv_commit_bytes, app_bytes) = decode_partial(&ciphertext)?;

            let recv_commit_msg = MlsMessage::from_bytes(&recv_commit_bytes)
                .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.lock();

            // Advance send_group.classical (Group_B on sender's side) — updates sender's leaf key.
            {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match send
                    .classical
                    .process_incoming_message(recv_commit_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::Commit(_) => {}
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            }

            // Decrypt app message from recv_group.classical (Group_A — sender's send group).
            let (app_data, sender_id, epoch, proposal) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .classical
                    .process_incoming_message(app_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::ApplicationMessage(desc) => {
                        let sender = ClientId {
                            bytes: sender_client_id(&recv.classical, desc.sender_index)?,
                        };
                        let ep = recv.classical.current_epoch();
                        let proposal = make_queued_proposal(
                            recv.classical.group_id(),
                            &sender,
                            &desc.authenticated_data,
                        );
                        (desc.data().to_vec(), sender, ep, proposal)
                    }
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            inner.resolve_pending_rotation();

            return Ok(Some(DecryptResult {
                application_message: Some(MlsSenderMessage {
                    app_message_data: app_data,
                    sender_client_id: sender_id,
                    epoch,
                }),
                proposal,
                remote_commit: None,
            }));
        }

        // Phase 7: full bundle — send-group epoch advance + recv-group PSK refresh + app.
        // Order: apply send commit (advances Group_A) → derive new PSK → apply recv commit
        // (injects PSK into Group_B) → decrypt app at new Group_A epoch.
        if ciphertext.first() == Some(&FULL_BUNDLE_TAG) {
            let (send_commit_bytes, recv_commit_bytes, app_bytes) =
                decode_full_bundle(&ciphertext)?;

            let send_commit_msg = MlsMessage::from_bytes(&send_commit_bytes)
                .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
            let recv_commit_msg = MlsMessage::from_bytes(&recv_commit_bytes)
                .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.lock();
            let client = inner.client.clone();

            // Step 1 — advance recv_group.classical (Group_A) with the sender's commit.
            {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .classical
                    .process_incoming_message(send_commit_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::Commit(_) => {}
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            }

            // Step 2 — derive the same cross-party PSK from Group_A at the new epoch and register it.
            {
                let recv = inner
                    .recv_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                export_and_register_psk(&recv.classical, client.combiner())?;
            }

            // Step 3 — apply the PSK-refresh commit on send_group.classical (Group_B).
            {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match send
                    .classical
                    .process_incoming_message(recv_commit_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::Commit(_) => {}
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            }

            // Step 4 — decrypt the app message from recv_group.classical at the new epoch.
            let (app_data, sender_id, epoch) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .classical
                    .process_incoming_message(app_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::ApplicationMessage(desc) => {
                        let sender = ClientId {
                            bytes: sender_client_id(&recv.classical, desc.sender_index)?,
                        };
                        let ep = recv.classical.current_epoch();
                        (desc.data().to_vec(), sender, ep)
                    }
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            let my_id = inner.my_state.client_id();
            inner.resolve_pending_rotation();

            return Ok(Some(DecryptResult {
                application_message: Some(MlsSenderMessage {
                    app_message_data: app_data,
                    sender_client_id: sender_id,
                    epoch,
                }),
                proposal: None,
                remote_commit: Some(CommitResult {
                    new_sender: None,
                    new_recipient: my_id,
                }),
            }));
        }

        // Phase 8: rotation commit (BUNDLED_TAG) — send-group commit only, no PSK refresh.
        if ciphertext.first() == Some(&BUNDLED_TAG) {
            let (commit_bytes, app_bytes) = decode_bundled(&ciphertext)?;

            let commit_msg = MlsMessage::from_bytes(&commit_bytes)
                .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.lock();

            // Process commit — advances epoch in recv_group.classical.
            let (_committer_index, commit_auth_data) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                match recv
                    .classical
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
                    .classical
                    .process_incoming_message(app_msg)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                {
                    ReceivedMessage::ApplicationMessage(desc) => {
                        let sender = ClientId {
                            bytes: sender_client_id(&recv.classical, desc.sender_index)?,
                        };
                        let ep = recv.classical.current_epoch();
                        (desc.data().to_vec(), sender, ep)
                    }
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            let my_id = inner.my_state.client_id();
            inner.resolve_pending_rotation();

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

        // PQ-ratchet frames (0x0B/0x0D/0x0F) are driven through the dedicated `pq_ratchet_*` API,
        // not this method — they are a stateful KEM exchange, not a self-contained decryptable
        // message. Reject them explicitly so a host that misroutes one gets a clear signal instead
        // of an opaque `DecryptionFailed` from the MLS parser below. See `pq_ratchet_begin`.
        #[cfg(feature = "cryptokit")]
        if let Some(&b) = ciphertext.first() {
            if b == PQ_EK_TAG || b == PQ_CT_TAG || b == PQ_BIND_TAG {
                return Err(TwoMlsPqError::SessionNotReady);
            }
        }

        // MLS messages start with version bytes (0x00 ...) — attempt decryption.
        let msg =
            MlsMessage::from_bytes(&ciphertext).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

        let mut inner = self.lock();
        let recv = inner
            .recv_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?;

        let received = recv
            .classical
            .process_incoming_message(msg)
            .map_err(|_| TwoMlsPqError::DecryptionFailed)?;

        match received {
            ReceivedMessage::ApplicationMessage(desc) => {
                let sender_id = ClientId {
                    bytes: sender_client_id(&recv.classical, desc.sender_index)?,
                };
                let epoch = recv.classical.current_epoch();
                let proposal = make_queued_proposal(
                    recv.classical.group_id(),
                    &sender_id,
                    &desc.authenticated_data,
                );
                let app_data = desc.data().to_vec();
                inner.resolve_pending_rotation();
                Ok(Some(DecryptResult {
                    application_message: Some(MlsSenderMessage {
                        app_message_data: app_data,
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
        let inner = self.lock();
        inner.recv_group.as_ref().map(|rg| TwoMlsPqDigest {
            hash_type: crate::DIGEST_SHA256,
            digest: rg
                .pq
                .as_ref()
                .map(|pq| pq.group_id().to_vec())
                .unwrap_or_else(|| rg.classical.group_id().to_vec()),
        })
    }

    pub fn send_rendezvous(&self) -> Result<Option<RendezvousId>> {
        Err(TwoMlsPqError::SessionNotReady)
    }

    pub fn archive(&self) -> Result<Archive> {
        Err(TwoMlsPqError::ArchiveInvalid)
    }

    /// Accept a remote proposal for the next epoch advance.
    /// On the next `prepare_to_encrypt(None)` call, an empty commit will be staged.
    pub fn queue_proposal(&self, digest: TwoMlsPqDigest) -> Result<()> {
        let mut inner = self.lock();
        inner.queued_proposal = Some(digest);
        Ok(())
    }

    /// Register a new agent client for the next rotation commit.
    /// Call before `prepare_to_encrypt(Some(new_client.client_id()))`.
    pub fn stage_rotation(&self, new_client: Arc<TwoMlsPqClient>) -> Result<()> {
        let mut inner = self.lock();
        inner.pending_new_client = Some(new_client);
        Ok(())
    }

    /// Process a message forwarded from another of the user's own devices.
    pub fn forwarded(&self, _header_decrypted: Vec<u8>) -> Result<Option<MlsSenderMessage>> {
        Err(TwoMlsPqError::SessionNotReady)
    }

    pub fn should_listen_on(&self) -> Result<ListenChannels> {
        Err(TwoMlsPqError::SessionNotReady)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::TwoMlsPqSession;
    use crate::{
        assert_err, assert_ok, assert_some,
        test_utils::{establish_sessions, make_client, make_combiner_kp},
        AgentState, TwoMlsPqError,
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

        let kp_msg = assert_ok!(alice.pq_bootstrap_begin());
        let bind = assert_ok!(bob.pq_bootstrap_respond(kp_msg));
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
            bob.pq_bootstrap_begin(),
            crate::TwoMlsPqError::SessionNotReady
        );
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
        let apq_welcome_a = assert_some!(alice_session.pending_outbound());

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
    #[cfg(feature = "cryptokit")]
    fn test_pq_ratchet_round_trip_delivers_app_message() {
        let (alice, bob) = establish_sessions();
        // Alice initiates a PQ ratchet on her send group; Bob responds and applies.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        let ct = assert_ok!(bob.pq_ratchet_respond(ek));
        let bind = assert_ok!(alice.pq_ratchet_bind(ct, b"hello-pq".to_vec()));
        let got = assert_ok!(bob.pq_ratchet_apply(bind));
        assert_eq!(got, b"hello-pq");
    }

    /// Complete the A.4 bootstrap after establishment so both directions are full
    /// APQ — required before the deferred acceptor side can ratchet.
    #[cfg(feature = "cryptokit")]
    fn establish_full() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
        let (alice, bob) = establish_sessions();
        let kp = assert_ok!(alice.pq_bootstrap_begin());
        let bind = assert_ok!(bob.pq_bootstrap_respond(kp));
        assert_ok!(alice.pq_bootstrap_apply(bind));
        (alice, bob)
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_pq_ratchet_turn_flips_to_responder() {
        let (alice, bob) = establish_full();
        // Round 1: Alice initiates.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        let ct = assert_ok!(bob.pq_ratchet_respond(ek));
        let bind = assert_ok!(alice.pq_ratchet_bind(ct, b"a1".to_vec()));
        assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"a1");
        // Round 2: turn flips — Bob initiates on his send group, Alice applies.
        let ek2 = assert_ok!(bob.pq_ratchet_begin());
        let ct2 = assert_ok!(alice.pq_ratchet_respond(ek2));
        let bind2 = assert_ok!(bob.pq_ratchet_bind(ct2, b"b1".to_vec()));
        assert_eq!(assert_ok!(alice.pq_ratchet_apply(bind2)), b"b1");
    }

    #[test]
    #[cfg(feature = "cryptokit")]
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
    #[cfg(feature = "cryptokit")]
    fn test_classical_round_still_works_after_pq_ratchet() {
        let (alice, bob) = establish_sessions();
        let ek = assert_ok!(alice.pq_ratchet_begin());
        let ct = assert_ok!(bob.pq_ratchet_respond(ek));
        let bind = assert_ok!(alice.pq_ratchet_bind(ct, b"pq".to_vec()));
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
    #[cfg(feature = "cryptokit")]
    fn test_three_sequential_pq_ratchets_alternate_and_deliver() {
        let (alice, bob) = establish_full();
        for (i, (initiator, responder)) in [(&alice, &bob), (&bob, &alice), (&alice, &bob)]
            .iter()
            .enumerate()
        {
            let payload = vec![i as u8; 8];
            let ek = assert_ok!(initiator.pq_ratchet_begin());
            let ct = assert_ok!(responder.pq_ratchet_respond(ek));
            let bind = assert_ok!(initiator.pq_ratchet_bind(ct, payload.clone()));
            assert_eq!(assert_ok!(responder.pq_ratchet_apply(bind)), payload);
        }
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_pq_ratchet_respond_rejects_wrong_tag() {
        let (_alice, bob) = establish_sessions();
        assert_err!(
            bob.pq_ratchet_respond(vec![0xAB, 1, 2, 3]),
            TwoMlsPqError::Mls
        );
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_pq_frame_routed_to_process_incoming_is_rejected() {
        let (_alice, bob) = establish_sessions();
        // A PQ-ratchet EK frame must never be silently swallowed as an MLS ciphertext.
        let mut ek = vec![super::PQ_EK_TAG];
        ek.extend_from_slice(&[0u8; 8]);
        assert_err!(bob.process_incoming(ek), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_pq_ratchet_apply_without_respond_is_rejected() {
        let (alice, bob) = establish_sessions();
        let ek = assert_ok!(alice.pq_ratchet_begin());
        let ct = assert_ok!(bob.pq_ratchet_respond(ek));
        let bind = assert_ok!(alice.pq_ratchet_bind(ct, b"x".to_vec()));
        // A different session that never responded has no held secret.
        let (_a2, b2) = establish_sessions();
        assert_err!(b2.pq_ratchet_apply(bind), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_pq_ratchet_double_begin_is_rejected() {
        let (alice, _bob) = establish_sessions();
        assert_ok!(alice.pq_ratchet_begin());
        assert_err!(alice.pq_ratchet_begin(), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_pq_ratchet_tampered_ciphertext_fails_to_apply() {
        let (alice, bob) = establish_sessions();
        let ek = assert_ok!(alice.pq_ratchet_begin());
        let mut ct = assert_ok!(bob.pq_ratchet_respond(ek));
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        // Alice binds a divergent S (ML-KEM implicit rejection); Bob holds the real S → apply fails.
        let bind = assert_ok!(alice.pq_ratchet_bind(ct, b"x".to_vec()));
        assert_err!(bob.pq_ratchet_apply(bind), TwoMlsPqError::Mls);
    }

    #[test]
    #[cfg(feature = "cryptokit")]
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
    #[cfg(feature = "cryptokit")]
    fn test_initiate_fails_when_both_suites_classical() {
        let alice = make_client();
        let bob = make_client();
        let classical =
            assert_ok!(bob.generate_key_package(crate::MlsCipherSuite::x25519_chacha()));
        let pq = assert_ok!(bob.generate_key_package(crate::MlsCipherSuite::x25519_chacha()));
        let bad_kp = crate::key_packages::CombinerKeyPackage { classical, pq };
        assert_err!(
            TwoMlsPqSession::initiate(alice, bad_kp),
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

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let apq_welcome_a = assert_some!(alice_session.pending_outbound());

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
            alice_session.my_agent_state().client_id()
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
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome = assert_some!(alice_session.pending_outbound());
        assert_ok!(TwoMlsPqSession::accept(bob, welcome, alice_kp));
    }

    #[test]
    fn test_join_send_group_with_my_agent_succeeds() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome = assert_some!(alice_session.pending_outbound());
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
    #[cfg(feature = "cryptokit")]
    fn test_create_bound_send_group_ml_kem_768_with_psk_succeeds() {
        let (alice_session, bob_session) = establish_sessions();
        assert!(alice_session.is_established());
        assert!(bob_session.is_established());
    }

    #[test]
    fn test_from_archive_returns_archive_invalid() {
        let client = make_client();
        assert_err!(
            TwoMlsPqSession::from_archive(crate::Archive { bytes: vec![] }, client),
            TwoMlsPqError::ArchiveInvalid
        );
    }

    #[test]
    fn test_archive_returns_archive_invalid() {
        let (alice_session, _) = establish_sessions();
        assert_err!(alice_session.archive(), TwoMlsPqError::ArchiveInvalid);
    }

    #[test]
    fn test_send_rendezvous_returns_session_not_ready() {
        let (alice_session, _) = establish_sessions();
        assert_err!(
            alice_session.send_rendezvous(),
            TwoMlsPqError::SessionNotReady
        );
    }

    #[test]
    fn test_should_listen_on_returns_session_not_ready() {
        let (alice_session, _) = establish_sessions();
        assert_err!(
            alice_session.should_listen_on(),
            TwoMlsPqError::SessionNotReady
        );
    }

    #[test]
    fn test_forwarded_returns_session_not_ready() {
        let (alice_session, _) = establish_sessions();
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

        let partial = assert_ok!(bob_session.encrypt(b"no-commit".to_vec()));
        assert_some!(assert_ok!(
            alice_session.process_incoming(partial.cipher_text)
        ));

        assert_ok!(bob_session.queue_proposal(proposal.digest));
        let prep2 = assert_ok!(bob_session.prepare_to_encrypt(None));
        assert!(prep2.did_commit, "must commit after queue_proposal");
    }

    #[test]
    #[ignore = "reconnect (Phase 11) not yet implemented"]
    fn test_process_incoming_returns_none_on_rejoin_needed() {}

    #[test]
    fn test_session_id_differs_for_different_pairs() {
        let alice = make_client();
        let bob = make_client();
        let carol = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let carol_kp = make_combiner_kp(&carol);

        let alice_bob = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let alice_carol = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), carol_kp));

        assert_ne!(
            alice_bob.active_session_id().bytes,
            alice_carol.active_session_id().bytes,
            "different peer pairs must produce different session IDs"
        );
    }

    #[test]
    #[cfg(feature = "cryptokit")]
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
            alice_session.my_agent_state().client_id()
        );
    }

    #[test]
    #[ignore = "concurrent-session dedup not yet implemented"]
    fn test_concurrent_sessions_same_did_pair_both_valid() {}

    #[test]
    fn test_agent_rotation_migrates_session_to_new_agent() {
        let (alice_session, bob_session) = establish_sessions();

        let new_alice = make_client();
        let new_alice_id = new_alice.client_id();

        assert_ok!(alice_session.stage_rotation(Arc::clone(&new_alice)));
        let prep = assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone())));
        assert!(prep.did_commit);

        let enc = assert_ok!(alice_session.encrypt(b"rotated".to_vec()));
        let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

        let commit = assert_some!(result.remote_commit);
        assert_eq!(
            assert_some!(commit.new_sender),
            new_alice_id,
            "Bob must observe Alice's new identity"
        );
        assert_eq!(
            assert_some!(result.application_message).app_message_data,
            b"rotated"
        );
        assert_eq!(bob_session.their_agent_state().client_id(), new_alice_id);
    }

    #[test]
    fn test_agent_rotation_resolves_pending_state_after_peer_reply() {
        let (alice_session, bob_session) = establish_sessions();

        let new_alice = make_client();
        let new_alice_id = new_alice.client_id();

        assert_ok!(alice_session.stage_rotation(Arc::clone(&new_alice)));
        assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone())));
        let enc = assert_ok!(alice_session.encrypt(b"rotation".to_vec()));
        assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

        // Alice's state is Pending until she receives a message from Bob.
        assert!(matches!(
            alice_session.my_agent_state(),
            AgentState::Pending { .. }
        ));

        // Bob replies; Alice's state must resolve to Sync { new }.
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let reply = assert_ok!(bob_session.encrypt(b"ack".to_vec()));
        assert_some!(assert_ok!(alice_session.process_incoming(reply.cipher_text)));

        assert!(
            matches!(alice_session.my_agent_state(), AgentState::Sync { .. }),
            "Pending must resolve to Sync after peer reply"
        );
        assert_eq!(alice_session.my_agent_state().client_id(), new_alice_id);
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
        assert!(app.epoch > 1, "send epoch must advance after full commit");
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
    fn test_partial_commit_recv_advances_send_group_on_peer() {
        let (alice_session, bob_session) = establish_sessions();

        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"partial".to_vec()));

        let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
        assert_eq!(
            assert_some!(result.application_message).app_message_data,
            b"partial"
        );
    }

    #[test]
    fn test_partial_commit_followed_by_bob_send_still_decrypts() {
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

    #[test]
    fn test_welcome_stapled_in_first_round_only() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        // Alice initiates; her welcome_a is delivered separately so Bob can accept.
        let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_s.pending_outbound());
        let bob_s = assert_ok!(TwoMlsPqSession::accept(
            Arc::clone(&bob),
            welcome_a,
            alice_kp
        ));

        // Bob does NOT deliver welcome_b separately — his first app frame staples it.
        assert!(
            !alice_s.is_established(),
            "alice has no recv group before welcome_b"
        );
        assert_ok!(bob_s.prepare_to_encrypt(None));
        let first = assert_ok!(bob_s.encrypt(b"hello".to_vec())).cipher_text;
        assert_eq!(
            first.first(),
            Some(&super::STAPLED_WELCOME_TAG),
            "first frame must staple the welcome"
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
        // The welcome was consumed by the staple.
        assert!(bob_s.pending_outbound().is_none());

        // Subsequent frames are NOT stapled.
        assert_ok!(bob_s.prepare_to_encrypt(None));
        let second = assert_ok!(bob_s.encrypt(b"world".to_vec())).cipher_text;
        assert_ne!(
            second.first(),
            Some(&super::STAPLED_WELCOME_TAG),
            "subsequent frames must not staple"
        );
        let result2 = assert_some!(assert_ok!(alice_s.process_incoming(second)));
        assert_eq!(
            assert_some!(result2.application_message).app_message_data,
            b"world"
        );
    }

    #[test]
    #[ignore = "archive() is not yet implemented"]
    fn test_archive_round_trips_session_state() {}

    #[test]
    #[ignore = "should_listen_on() is not yet implemented"]
    fn test_should_listen_on_returns_correct_group_and_epochs() {}

    #[test]
    #[ignore = "forwarded() is not yet implemented"]
    fn test_forwarded_decrypts_inner_payload() {}

    #[test]
    #[ignore = "send_rendezvous() is not yet implemented"]
    fn test_send_rendezvous_returns_current_epoch_channel() {}

    #[test]
    fn test_psk_export_uses_correct_label_and_context() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);

        let (group, _) = assert_ok!(apq::create_group_with_member(
            alice.classical(),
            &bob_kp.classical,
            &[]
        ));

        let s1 = assert_ok!(group.export_secret(b"exportSecret", b"derive", 32));
        let s2 = assert_ok!(group.export_secret(b"exportSecret", b"derive", 32));
        assert_eq!(s1.as_bytes(), s2.as_bytes());
        assert_eq!(s1.as_bytes().len(), 32);

        let other = assert_ok!(group.export_secret(b"otherLabel", b"derive", 32));
        assert_ne!(s1.as_bytes(), other.as_bytes());

        let psk_id = assert_ok!(apq::export_and_register_psk(&group, alice.combiner()));
        let expected_id = {
            let mut v = group.current_epoch().to_le_bytes().to_vec();
            v.extend_from_slice(group.group_id());
            mls_rs::psk::ExternalPskId::new(v)
        };
        assert_eq!(psk_id, expected_id);
    }

    #[test]
    fn test_apq_psk_is_exported_from_pq_group_not_classical() {
        // draft-ietf-mls-combiner §4/§6.2: the APQ-PSK is exported from the PQ session and
        // imported into the traditional session (pq -> classical). Regression guard against the
        // old (wrong) classical -> pq direction: a PSK keyed by the PQ group's (epoch, group_id)
        // must be registered (it is the export source); under the reverted direction the PQ
        // group is the importer and its id is never a PSK source, so this would fail.
        let (alice_session, _bob_session) = establish_sessions();
        let inner = alice_session
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let send = assert_some!(inner.send_group.as_ref());

        let apq_id_from_pq = {
            let send_pq = send.pq.as_ref().expect("send pq");
            let mut v = send_pq.current_epoch().to_le_bytes().to_vec();
            v.extend_from_slice(send_pq.group_id());
            mls_rs::psk::ExternalPskId::new(v)
        };
        assert!(
            inner
                .client
                .classical()
                .secret_store()
                .get(&apq_id_from_pq)
                .is_some(),
            "APQ-PSK must be exported from the PQ group (pq -> classical), per draft §6.2"
        );
    }

    #[test]
    fn test_prepare_to_encrypt_before_established_returns_error() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
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
        assert_ok!(alice_session.stage_rotation(Arc::clone(&new_alice)));
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
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
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
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(!session.has_receive_group());
    }

    #[test]
    fn test_has_receive_group_true_for_acceptor_immediately() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome = assert_some!(alice_session.pending_outbound());
        let bob_session = assert_ok!(TwoMlsPqSession::accept(bob, welcome, alice_kp));
        assert!(bob_session.has_receive_group());
    }

    #[test]
    fn test_proposal_context_none_before_recv_group() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(session.proposal_context().is_none());
    }

    #[test]
    fn test_proposal_context_some_after_established() {
        let (alice_session, bob_session) = establish_sessions();
        let alice_ctx = assert_some!(alice_session.proposal_context());
        let bob_ctx = assert_some!(bob_session.proposal_context());
        assert!(!alice_ctx.digest.is_empty());
        assert!(!bob_ctx.digest.is_empty());
    }

    #[test]
    fn test_my_agent_state_initial_is_sync() {
        let alice = make_client();
        let alice_id = alice.client_id();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(matches!(session.my_agent_state(), AgentState::Sync { .. }));
        assert_eq!(session.my_agent_state().client_id(), alice_id);
    }

    #[test]
    fn test_my_agent_state_becomes_pending_after_rotation_commit() {
        let (alice_session, _) = establish_sessions();
        let new_alice = make_client();
        let new_id = new_alice.client_id();
        assert_ok!(alice_session.stage_rotation(Arc::clone(&new_alice)));
        assert_ok!(alice_session.prepare_to_encrypt(Some(new_id.clone())));
        assert!(matches!(
            alice_session.my_agent_state(),
            AgentState::Pending { .. }
        ));
    }

    #[test]
    fn test_partial_commit_surfaces_proposal_nonce() {
        let (alice_session, bob_session) = establish_sessions();

        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"with nonce".to_vec()));
        let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

        let proposal = assert_some!(result.proposal);
        assert!(!proposal.digest.digest.is_empty());
        assert_eq!(proposal.sender, alice_session.my_agent_state().client_id());
    }

    #[test]
    fn test_multiple_sequential_partial_commits_stay_in_sync() {
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
            cl_recv_after.map(|e| e.saturating_sub(1)),
            cl_recv_before,
            "routine round must advance the classical recv group by one epoch"
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
            cl_recv_1.map(|e| e.saturating_sub(1)),
            cl_recv_0,
            "full round must advance the classical recv group (cross-party propagation)"
        );
    }

    #[test]
    fn test_routine_frame_is_classical_sized() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_s.pending_outbound());
        let bob_s = assert_ok!(TwoMlsPqSession::accept(
            Arc::clone(&bob),
            welcome_a.clone(),
            alice_kp
        ));
        let welcome_b = assert_some!(bob_s.pending_outbound());
        assert_ok!(alice_s.process_incoming(welcome_b.clone()));

        // Routine (partial) round — the steady-state frame.
        assert_ok!(alice_s.prepare_to_encrypt(None));
        let partial = assert_ok!(alice_s.encrypt(b"the quick brown fox".to_vec())).cipher_text;

        eprintln!(
            "[sizes] welcome_a={} B  welcome_b={} B  routine(0x05)={} B",
            welcome_a.len(),
            welcome_b.len(),
            partial.len()
        );

        // The routine frame must be classical-sized — no ML-KEM ciphertext in the steady state.
        // (Pre-rework the routine frame carried ~4 KB of ML-KEM-768 under `cryptokit`.)
        assert!(
            partial.len() < 2000,
            "routine frame should be classical-sized, got {} B",
            partial.len()
        );
    }

    #[test]
    fn test_full_commit_after_multiple_partial_commits() {
        let (alice_session, bob_session) = establish_sessions();

        for _ in 0..2 {
            assert_ok!(alice_session.prepare_to_encrypt(None));
            let enc = assert_ok!(alice_session.encrypt(b"partial".to_vec()));
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
    fn test_decode_bundled_truncated_returns_error() {
        assert_err!(
            super::decode_bundled(&[super::BUNDLED_TAG]),
            TwoMlsPqError::Mls
        );
    }

    #[test]
    fn test_decode_partial_truncated_returns_error() {
        assert_err!(
            super::decode_partial(&[super::PARTIAL_TAG]),
            TwoMlsPqError::Mls
        );
    }

    #[test]
    fn test_decode_full_bundle_truncated_returns_error() {
        assert_err!(
            super::decode_full_bundle(&[super::FULL_BUNDLE_TAG]),
            TwoMlsPqError::Mls
        );
    }

    #[test]
    fn test_decode_full_bundle_trailing_bytes_returns_error() {
        let mut good = super::encode_full_bundle(b"sc".to_vec(), b"rc".to_vec(), b"app".to_vec());
        good.push(0xFF);
        assert_err!(super::decode_full_bundle(&good), TwoMlsPqError::Mls);
    }

    #[test]
    fn test_encode_decode_bundled_roundtrip() {
        let commit = b"commit-bytes".to_vec();
        let app = b"app-bytes".to_vec();
        let encoded = super::encode_bundled(commit.clone(), app.clone());
        let (dec_commit, dec_app) = assert_ok!(super::decode_bundled(&encoded));
        assert_eq!(dec_commit, commit);
        assert_eq!(dec_app, app);
    }

    #[test]
    fn test_encode_decode_full_bundle_roundtrip() {
        let sc = b"send-commit".to_vec();
        let rc = b"recv-commit".to_vec();
        let app = b"app-data".to_vec();
        let encoded = super::encode_full_bundle(sc.clone(), rc.clone(), app.clone());
        let (dec_sc, dec_rc, dec_app) = assert_ok!(super::decode_full_bundle(&encoded));
        assert_eq!(dec_sc, sc);
        assert_eq!(dec_rc, rc);
        assert_eq!(dec_app, app);
    }

    #[test]
    fn test_process_incoming_bundled_malformed_returns_error() {
        let (alice_session, _) = establish_sessions();
        let fake = super::encode_bundled(b"junk".to_vec(), b"junk".to_vec());
        assert_err!(
            alice_session.process_incoming(fake),
            TwoMlsPqError::DecryptionFailed
        );
    }
}
