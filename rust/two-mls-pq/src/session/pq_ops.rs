//! PQ side-band operations: the A.4 ratchet (pq_ratchet_*), the A.3
//! bootstrap of the deferred send-group PQ half (pq_bootstrap_*), and the
//! A.5 PQ-only re-key (pq_rekey_*), plus the in-flight round state and the
//! pq turn/outbound accessors. Every method here operates on the PQ frames
//! classified in `frames` and is security-reviewed as a unit -- see
//! the book's Protocol Flows chapter, A.3-A.5.

use super::*;

/// PQ ratchet round state carried between the messages of one exchange.
///
/// Every side-band round registers here, and every `*_begin` gates on it being empty — that
/// single-occupancy IS the mutual exclusion between A.3, A.4 and A.5. A.3 was long absent
/// from it, which is exactly why a ratchet round could open during a bootstrap and evict its
/// irreplaceable frame; being a well-formed round now, it takes its place.
pub(in crate::session) enum PqInflight {
    /// Initiator holds the ephemeral (decapsulation key) until it receives the ciphertext.
    Initiating(apq::pq_ratchet::PqEphemeral),
    /// A.3 initiator awaiting the responder's `Welcome'`. Carries nothing: the welcome is
    /// self-sufficient, and the secret this round injects is exported from the group it
    /// carries rather than held across the round.
    BootstrapInitiated,
    /// A.3 responder awaiting the initiator's bind — the frame that proves it joined.
    BootstrapResponded,
    /// Responder holds the shared secret until it receives the stapled bind. `Zeroizing` wipes the
    /// secret from memory on drop, whether it is consumed by the bind or abandoned.
    Responding(Zeroizing<Vec<u8>>),
    /// A.5 initiator awaiting the responder's Commit'. Carries nothing: the round's
    /// credential handoff already rode the leg-1 Upd' (the proposal replaces the
    /// proposer's leaf), and the leg-3 ack is a pathless partial commit that touches
    /// no leaf.
    RekeyInitiated,
    /// A.5 responder awaiting the initiator's ack — a stapled bind, which arrives via
    /// `process_incoming` like A.3's and A.4's.
    RekeyResponded,
}

/// Authenticate an inbound A.4 leg (the EK or the CT) delivered as an MLS **application
/// message** in `group`, and return its payload (the ek bytes, or the `[enc][sealed S]`
/// wire_ct). Framing the legs as MLS messages is what gives A.4 the same two-factor
/// authentication MLS gives every member message — a leaf **signature** AND proof of the
/// **current epoch's** secrets (the receive ratchet won't decrypt otherwise) — so a stolen
/// signing key alone can no longer forge a leg the peer will act on (the PCS property a bare
/// signature lacked).
///
/// MUTATES `group`: `process_incoming_message` advances the sender's receive ratchet,
/// consuming this leg's generation. Two rules follow, both load-bearing (see the R1 tests in
/// `apq/tests/r1_mls_assumptions.rs`):
///   1. Call this only from INSIDE the persist closure and only after the guard phase has
///      confirmed the leg is expected — a re-sent leg must be caught by the `pq_inflight`
///      guard BEFORE it reaches here, because a replayed application frame does not
///      re-decrypt (mls-rs replay protection), it errors. Should one ever slip the guard it
///      reports `StaleFrame` (`map_app_message_err`), not `Mls`: the guard is still the
///      contract, but a hole in it must cost the frame, not the session — `Mls` carries the
///      `fatal` disposition, which tells a host its state is inconsistent and earns a
///      teardown. Double delivery is designed-in traffic for a host running a push relay
///      alongside a socket, so that default was the wrong way round here.
///   2. On the wire the leg is header-sealed; a network tamper breaks the OUTER seal and is
///      dropped at `open_incoming` before mls-rs is invoked. That matters because a frame
///      with valid sender-data but corrupt content would consume its generation here — so the
///      header seal, not this function, is what keeps a network attacker from stranding a
///      generation.
///
/// The peer-sender check is belt-and-braces over mls-rs's own `CantProcessMessageFromSelf`:
/// in a two-party group a successfully processed application message is necessarily the
/// peer's, but the leg kind is only meaningful from the peer, so we assert it.
fn process_a4_leg(
    group: &mut crate::key_package_store::PqMlsGroup,
    inner_tag: u8,
    msg: MlsMessage,
) -> Result<Vec<u8>> {
    let my_index = group.current_member_index();
    let desc = match group
        .process_incoming_message(msg)
        .map_err(map_app_message_err)?
    {
        ReceivedMessage::ApplicationMessage(desc) => desc,
        _ => return Err(TwoMlsPqError::Mls),
    };
    if desc.sender_index == my_index {
        return Err(TwoMlsPqError::Mls);
    }
    let (&tag, payload) = desc.data().split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != inner_tag {
        return Err(TwoMlsPqError::Mls);
    }
    Ok(payload.to_vec())
}

/// Encode an A.4 leg's authenticated CONTENT: the domain tag then the payload
/// (`[0x17][ek]` or `[0x19][wire_ct]`). This is the plaintext handed to
/// `encrypt_application_message`, so the tag is covered by the MLS signature — binding the
/// leg's KIND into what is authenticated, not just its routing.
fn encode_a4_leg_content(inner_tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(inner_tag);
    out.extend_from_slice(payload);
    out
}

/// Wrap a produced MLS application message as an outbound side-band frame: the routing tag
/// then the `MLSMessage` bytes (`[0x17][mls]` / `[0x19][mls]`). The outer tag routes at
/// `open_incoming`/`pq_frame_kind`; the inner (authenticated) tag guides parsing after the
/// group decrypts it — the same transport-routes-then-inner-tag-parses discipline the §A.1
/// envelope follows.
fn encode_a4_leg_frame(outer_tag: u8, mls: &MlsMessage) -> Result<Vec<u8>> {
    let mls_bytes = mls.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
    let mut frame = Vec::with_capacity(1 + mls_bytes.len());
    frame.push(outer_tag);
    frame.extend_from_slice(&mls_bytes);
    Ok(frame)
}

/// Require that a processed proposal is an Update from the peer's leaf — the only
/// proposal kind members of this protocol ever exchange. An MLS Update always covers
/// its sender's own leaf, so a member sender other than ourselves pins it to the one
/// other member (the rules filter re-checks the same at commit time; this rejects at
/// ingest, before the proposal enters any cache).
pub(in crate::session) fn require_peer_update(
    desc: &ProposalMessageDescription,
    my_index: u32,
) -> Result<()> {
    let is_update = matches!(desc.proposal, Proposal::Update(_));
    let from_peer = matches!(desc.sender, ProposalSender::Member(index) if index != my_index);
    if is_update && from_peer {
        Ok(())
    } else {
        Err(TwoMlsPqError::ProposalRejected)
    }
}

/// Retire any bootstrap pin (a frozen establishment credential held admissible past
/// window eviction — see `PartySequence::pin`) that NO live PQ-half leaf still carries.
/// The initiator pins its OWN establishment id in `mine` (to join the Welcome' whose
/// added leaf still bears it) and the responder pins the peer's in `theirs` (to admit
/// that leaf) — both catch up over separate A.5 rounds (a leaf in BSG-PQ and one in
/// ASG-PQ), so BOTH sequences are pruned here. Sound: a credential a leaf still bears
/// stays pinned, so an in-progress catch-up never loses admissibility. Cheap: at most two
/// 2-party PQ halves, only on A.5 applies.
pub(in crate::session) fn retire_stale_pins(inner: &SessionInner) {
    let mut carried: Vec<Vec<u8>> = Vec::new();
    for group in [inner.send_group.as_ref(), inner.recv_group.as_ref()] {
        let Some(pq) = group.and_then(|g| g.pq.as_ref()) else {
            continue;
        };
        for idx in 0u32..2 {
            if let Ok(id) = sender_client_id(pq, idx) {
                carried.push(id);
            }
        }
    }
    inner.with_auth(|core| {
        let prune = |seq: &mut apq::authentication::PartySequence| {
            let stale: Vec<Vec<u8>> = seq
                .pinned_ids()
                .filter(|p| !carried.iter().any(|c| c.as_slice() == *p))
                .map(<[u8]>::to_vec)
                .collect();
            for id in &stale {
                seq.unpin(id);
            }
        };
        prune(&mut core.mine);
        prune(&mut core.theirs);
    });
}

// --- Session-driven A.4/A.5 advancement (the side-band is the session's job, not the host's) ---
//
// The host never opens A.4/A.5 rounds: it drives A.3 bootstrap, then just sends messages. On
// each send `maybe_stage_next_round` opens the next round automatically when it is our turn and
// the side-band is idle — A.5 when our send-PQ leaf still lags the canonical identity (a Phase 8
// classical rotation moved `self.client` and the PQ leaf hasn't caught up), else A.4. Emission is
// send-driven and best-effort: the staged frame rides the send that opened it (re-staple peek),
// and a transient staging failure simply retries on the next send. "A.4 begins immediately" is
// nothing more than the first send after the turn becomes ours.
//
// These `stage_*` helpers are the state-mutation cores of `pq_ratchet_begin`/`pq_rekey_begin`
// minus the seal (the frame is parked UNSEALED — the peek seals it fresh per send). They run
// inside a caller's `mutate_and_persist`, so the staged state is persisted with the send.
impl SessionInner {
    /// A.4 leg 1: generate an ML-KEM ephemeral, hold its decapsulation key, and park the EK
    /// frame (tag 0x17) — the EK carried as an MLS **application message** in our send-PQ, so
    /// the peer authenticates it (leaf signature + current-epoch secrets) before responding.
    ///
    /// `encrypt_application_message` advances our send-PQ **application** ratchet (not its
    /// epoch — no commit), so unlike the old bare-frame stage this mutates PQ-group state the
    /// `Core` blob omits: `maybe_stage_next_round` now reports a staged A.4 the same as an A.5
    /// so the caller follows with a `Checkpoint`. Built once and retained — every re-send only
    /// re-seals the OUTER header layer; the inner MLS message (and its generation) is fixed, so
    /// re-sends stay idempotent and are caught by the responder's `pq_inflight` guard.
    fn stage_ratchet(&mut self) -> Result<()> {
        let eph = apq::pq_ratchet::generate_ephemeral(&providers::pq_kem()?)?;
        let content = encode_a4_leg_content(PQ_EK_TAG, &eph.encapsulation_key());
        let send_pq = self
            .send_group
            .as_mut()
            .and_then(|g| g.pq.as_mut())
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        // `encrypt_application_message` refuses (`CommitRequired`) if the group holds an
        // uncommitted by-ref proposal. It never does here: the only by-ref proposal a PQ group
        // sees is an A.5 `Upd'`, which `pq_rekey_respond` commits in the same closure, and this
        // stage is gated on `pq_inflight.is_none()` (see `maybe_stage_next_round`) — so no A.5 is
        // mid-round. Best-effort regardless: a failure just leaves the slot empty for the next send.
        let mls = send_pq
            .encrypt_application_message(&content, Vec::new())
            .map_err(|_| TwoMlsPqError::Mls)?;
        let frame = encode_a4_leg_frame(PQ_EK_TAG, &mls)?;
        self.pq_inflight = Some(PqInflight::Initiating(eph));
        self.pending_side_band = Some(RetainedFrame::unsealed(frame));
        Ok(())
    }

    /// A.5 leg 1: propose `Upd'(self)` into our recv-PQ mirror (catching the leaf up to
    /// `rotating` when it lags — the same handoff `pq_rekey_begin` builds) and park the Upd'
    /// frame (tag 0x1B). Caller persists.
    fn stage_rekey(&mut self, rotating: Option<ClientId>) -> Result<()> {
        let handoff = match &rotating {
            Some(new_id) => {
                if self.client.client_id() != *new_id {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                let (new_signer, new_public) = self.client.combiner().pq_signature_keypair();
                Some((new_signer, new_public, new_id.bytes.clone()))
            }
            None => None,
        };
        let recv_pq = self
            .recv_group
            .as_mut()
            .and_then(|g| g.pq.as_mut())
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let proposal = match handoff {
            Some((new_signer, new_public, announced_id)) => {
                let identity = SigningIdentity::new(
                    BasicCredential::new(announced_id.clone()).into_credential(),
                    new_public,
                );
                recv_pq
                    .propose_update_with_identity(new_signer, identity, announced_id)
                    .map_err(map_credential_err)?
            }
            None => recv_pq
                .propose_update(Vec::new())
                .map_err(|_| TwoMlsPqError::Mls)?,
        };
        let mut msg = vec![PQ_REKEY_UPD_TAG];
        msg.extend_from_slice(&proposal.to_bytes().map_err(|_| TwoMlsPqError::Mls)?);
        self.pq_inflight = Some(PqInflight::RekeyInitiated);
        self.pending_side_band = Some(RetainedFrame::unsealed(msg));
        Ok(())
    }

    /// True when our own send-PQ leaf still signs as a principal the session has rotated past
    /// (a Phase 8 classical rotation swapped `self.client`; the PQ leaf lags until an A.5 catch-up
    /// updatePath). Drives the A.5-vs-A.4 auto-selection; false (no catch-up owed) if unreadable.
    fn send_pq_leaf_lags(&self) -> bool {
        let Some(send_pq) = self.send_group.as_ref().and_then(|g| g.pq.as_ref()) else {
            return false;
        };
        let idx = send_pq.current_member_index();
        matches!(sender_client_id(send_pq, idx), Ok(leaf) if leaf != self.client.client_id().bytes)
    }

    /// Open the next PQ side-band round automatically when it is our turn and the side-band is
    /// idle — A.5 (credential catch-up) if our leaf lags, else A.4. Best-effort: any staging
    /// failure leaves the slot empty for the next send to retry. No-op unless fully post-A.3, the
    /// turn is ours, nothing is in flight, no bind is owed, and nothing is already staged.
    ///
    /// Returns `true` iff it staged a round that mutated PQ-group state the caller's `Core`
    /// push omits — so the caller must follow with a `Checkpoint`. That is now BOTH an A.5 (a
    /// pending update + its new leaf secret in the recv-PQ group) AND an A.4 (the EK is an MLS
    /// application message, so staging it advanced the send-PQ application ratchet — see
    /// `stage_ratchet`). Only a no-op or a staging failure returns `false`.
    pub(in crate::session) fn maybe_stage_next_round(&mut self) -> bool {
        if !self.pq_turn_mine
            || !self.pq_halves_live()
            || self.pq_inflight.is_some()
            || self.owed_bind.is_some()
            || self.pending_side_band.is_some()
        {
            return false;
        }
        if self.send_pq_leaf_lags() {
            let id = self.client.client_id();
            self.stage_rekey(Some(id)).is_ok()
        } else {
            self.stage_ratchet().is_ok()
        }
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Responder — authenticate the initiator's EK, SEAL a fresh secret to it (bound to our
    /// current PQ epoch), hold it, and park the ciphertext message (tag 0x19, itself an MLS
    /// application message). The secret is random and sealed rather than the KEM output
    /// itself, so the initiator's open is an explicit receipt (see
    /// `apq::pq_ratchet::seal_injected_secret`).
    ///
    /// The EK arrives as an MLS application message in our recv-PQ mirror; decrypting it (in
    /// the closure) is what authenticates it — a leaf signature AND proof of the current epoch,
    /// so a stolen signing key alone cannot forge an EK we will answer (see `process_a4_leg`).
    pub fn pq_ratchet_respond(&self, ek_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): parse the frame and check the turn/slot state
        // before the persist choke point, so a replayed or ill-timed EK can't force a
        // full-Checkpoint push for a no-op. Parse comes first to preserve the precedence a
        // stranger's blob is rejected as `Mls` before the state is consulted. The parse is
        // structural ONLY (`MlsMessage::from_bytes` mutates nothing); the mutating decrypt runs
        // in the closure — this is what makes the `pq_inflight` gate, NOT the frame
        // re-decrypting, the thing that discards a re-send (a replayed application frame does
        // not re-decrypt; R1(a) in `apq/tests/r1_mls_assumptions.rs`).
        let ek_leg = {
            let inner = self.lock();
            let ek_msg = inner.open_or_raw(ek_msg);
            let (&tag, mls_bytes) = ek_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_EK_TAG {
                return Err(TwoMlsPqError::Mls);
            }
            let ek_leg = MlsMessage::from_bytes(mls_bytes).map_err(|_| TwoMlsPqError::Mls)?;
            // `pq_inflight` alone gates a double-respond (a first one parks `Responding`).
            // Slot occupancy is deliberately not a gate: frames are retained for re-send,
            // so occupancy is round progress, not "busy" — and a duplicate EK re-sent by
            // the peer must be discardable, not an error.
            match inner.pq_inflight {
                // We already answered this round's EK; the peer is re-sending it until our
                // CT lands. Nothing to do — and nothing done: this is above the choke point.
                Some(PqInflight::Responding(_)) => return Err(TwoMlsPqError::DuplicateSideBand),
                // Any other in-flight state is a genuinely ill-timed EK (e.g. a turn
                // collision, both sides opening a round at once) — the host's problem to
                // resolve, not a frame to silently drop.
                Some(_) => return Err(TwoMlsPqError::SessionNotReady),
                None => {}
            }
            ek_leg
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            // Authenticate + decrypt the EK leg in our recv-PQ mirror. This MUTATES recv-PQ
            // (consumes the initiator's application generation); it is safe here because the
            // guard above proved this round is unanswered, so a re-send never reaches this
            // decrypt to be rejected as a replay. Everything after is either infallible or a
            // peer-fault (`process_a4_leg`'s tag/sender checks) — an honest peer never trips it,
            // so the mutating decrypt is followed only by steps that do not strand the round.
            let ek = {
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                process_a4_leg(recv_pq, PQ_EK_TAG, ek_leg)?
            };
            // The PSK binds the round to the group the secret is injected into — the
            // initiator's send-PQ, which we mirror as our recv-PQ — at its current epoch.
            let psk = {
                let recv_pq = inner
                    .recv_group
                    .as_ref()
                    .and_then(|g| g.pq.as_ref())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                ct_seal_psk(recv_pq)?
            };
            let (s, wire_ct) = apq::pq_ratchet::seal_injected_secret(
                &providers::pq_kem()?,
                &providers::header_aead_suite()?,
                &ek,
                &psk,
            )?;
            // Emit the CT as an MLS application message in the same recv-PQ mirror, so the
            // initiator authenticates it (our leaf signature + current epoch) before binding.
            let ct_mls = {
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                recv_pq
                    .encrypt_application_message(
                        &encode_a4_leg_content(PQ_CT_TAG, &wire_ct),
                        Vec::new(),
                    )
                    .map_err(|_| TwoMlsPqError::Mls)?
            };
            inner.pq_inflight = Some(PqInflight::Responding(s));
            // Parked for re-send until the initiator's stapled bind answers it.
            inner.pending_side_band = Some(RetainedFrame::unsealed(encode_a4_leg_frame(
                PQ_CT_TAG, &ct_mls,
            )?));
            Ok(())
        })
    }

    /// Initiator step 2 — authenticate + decapsulate the CT, recover S, and inject it into the
    /// send group's PQ half via a pathless commit, OWING the classical half: the bind rides our
    /// next classical COMMIT as an `APQPrivateMessage` staple (see `discharge_owed_bind`), which
    /// is also where the round's app message travels — an ordinary message frame's own section.
    pub fn pq_ratchet_bind(&self, ct_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): parse the frame and every turn/slot/staple
        // precondition before the persist choke point, so a displaced, stale, or ill-timed CT
        // is a no-op that neither bumps the seq nor pushes a Checkpoint. UNLIKE the old bare
        // frame, decrypting the CT now MUTATES our send-PQ (it is an MLS application message,
        // and that decrypt is what authenticates it), so it cannot be a guard-phase "pure read"
        // and moves into the closure — matching `pq_rekey_respond`. The retriable guards below
        // (`pending_proposal_hash`, `owed_bind`, non-`Initiating`) all still fire HERE, before
        // any mutation, so those cases stay pure no-ops the host can safely retry.
        let ct_leg = {
            let inner = self.lock();
            let ct_msg = inner.open_or_raw(ct_msg);
            let (&tag, mls_bytes) = ct_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_CT_TAG {
                return Err(TwoMlsPqError::Mls);
            }
            let ct_leg = MlsMessage::from_bytes(mls_bytes).map_err(|_| TwoMlsPqError::Mls)?;
            // No slot check: our own EK is parked here for re-send, and binding is exactly
            // what should replace it. The `Initiating` check below is the real gate.
            //
            // Staple-stacking guard: a prepared-but-unsent classical commit is sitting in
            // `current_staple` waiting for its `encrypt`. The bind commit below would replace
            // it, and a displaced commit never rides a frame again — the peer would hit the
            // epoch-ahead desync with zero loss on the wire. Retriable: bind after `encrypt`.
            if inner.pending_proposal_hash.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Rule 2: at most one owed bind. A second `inject_and_commit` would advance
            // `pq_epoch` out from under the epoch the outstanding bind's attestation already
            // reserved, and the peer rejects a stale attestation pre-apply — with our PQ leaf
            // spent and unrebuildable. The turn does not cover this, because we deliberately
            // keep it while a bind is owed (see below), so the check has to be its own.
            //
            // Retriable, and self-clearing: our next classical commit discharges the owed bind
            // and this bind proceeds.
            if inner.owed_bind.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Only an initiator holding the A.4 ephemeral can bind the ciphertext.
            match &inner.pq_inflight {
                Some(PqInflight::Initiating(_)) => {}
                // We already bound: the ephemeral was consumed and the turn passed, so this
                // is the peer re-sending its CT until our bind lands. Discard — and note the
                // guard is what makes this a no-op, since a replayed application frame would
                // NOT re-decrypt in the closure below (R1(a)).
                None if !inner.pq_turn_mine => return Err(TwoMlsPqError::DuplicateSideBand),
                _ => return Err(TwoMlsPqError::SessionNotReady),
            }
            ct_leg
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            // Authenticate + decrypt the CT leg in our send-PQ (MUTATES it — consumes the
            // responder's application generation). Safe here for the same reason as
            // `pq_ratchet_respond`: the guard proved the round is still `Initiating`, so a
            // re-send never reaches this decrypt to be rejected as a replay.
            let wire_ct = {
                let send_pq = inner
                    .send_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                process_a4_leg(send_pq, PQ_CT_TAG, ct_leg)?
            };
            // OPEN the sealed secret. The PSK binds the group the secret is injected into
            // (our send-PQ) at its current epoch; the AEAD key binds that AND the KEM shared
            // secret, so a CT answering a DIFFERENT ephemeral (a stale round's, re-sent
            // across the bundling window) or a different epoch fails the open EXPLICITLY —
            // rejected here, PQ leaf intact, where a bare `decapsulate` would have handed back
            // ML-KEM's implicit-rejection garbage to inject and strand the round on an
            // unshared secret. (The MLS decrypt above already advanced the generation; a
            // failing open past that point means a genuinely misdirected CT — an honest
            // responder answering our live ephemeral always opens.)
            let s = {
                let send_pq_ref = inner
                    .send_group
                    .as_ref()
                    .and_then(|g| g.pq.as_ref())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let psk = ct_seal_psk(send_pq_ref)?;
                let eph = match &inner.pq_inflight {
                    Some(PqInflight::Initiating(eph)) => eph,
                    _ => return Err(TwoMlsPqError::SessionNotReady),
                };
                apq::pq_ratchet::open_injected_secret(
                    &providers::pq_kem()?,
                    &providers::header_aead_suite()?,
                    eph,
                    &wire_ct,
                    &psk,
                )?
            };
            // Capture the departing epoch's PSK before the classical bind commit below.
            inner.remember_send_psk()?;
            // The ephemeral's only use — the open above — is done; discard it. Re-check of the
            // state the guard read, which nothing races under sequential driving.
            match inner.pq_inflight.take() {
                Some(PqInflight::Initiating(_)) => {}
                other => {
                    inner.pq_inflight = other;
                    return Err(TwoMlsPqError::SessionNotReady);
                }
            }
            // Commit the PQ half and OWE the classical one. NOTHING is parked in
            // `pending_side_band` here — deliberately. The two commits ride our next classical
            // COMMIT as an APQPrivateMessage in the STAPLE (`discharge_owed_bind`), which is
            // the message path, and the staple's own re-send until superseded is what heals a
            // lost one. Parking a bind frame here instead would put it on the side-band wire,
            // persist it under side-band retention rather than staple semantics, and contend
            // for the slot with the next round's EK below.
            inner.commit_pq_and_owe_bind(&s)?;
            // Our EK is spent — the CT we just consumed answered it. Clearing is this side's
            // ordinary "my part is done" (the round's next outbound is the staple, not a
            // side-band frame); leaving it would re-send a frame the peer's round is past,
            // which the peer must then decide to ignore.
            inner.pending_side_band = None;
            // The turn does NOT pass here. It passes at discharge, when the bind actually
            // reaches the wire — which is what lets us open the next round while this one's
            // classical half is owed and bundle its EK into the same EncryptResult as the
            // bind. Both land before the peer takes a turn, so that saves a round trip.
            //
            // The two rounds are then in flight together, but on DIFFERENT paths: this round's
            // bind in the staple, the next round's EK in `pending_side_band`. They never
            // contend.
            //
            // Rule 2 — no second PQ commit while a bind is owed — is therefore NOT enforced by
            // the turn here, and must be explicit: see the `owed_bind` check above, which is
            // what keeps `pq_epoch` from moving out from under the reservation this trigger
            // just made.
            //
            // Our send-PQ's pq_epoch advanced — capture its new header key. NOT the listen
            // address: that tracks the CLASSICAL epoch, which has deliberately not moved.
            inner.record_pq_header_key()?;
            Ok(())
        })
    }

    /// A.5 responder — commit the initiator's Upd' on our own send-PQ with an updatePath
    /// and a PSK exported from our recv-PQ mirror (the initiator derives the same PSK from
    /// its send-PQ), then park the Commit' frame for re-send via `pq_pending_outbound`.
    /// The initiator answers it with the round's ack — a pathless partial commit that
    /// rides its next classical COMMIT as the staple — so this frame is never terminal.
    ///
    /// The round's two leaf replacements both happen here: the folded Upd' replaces the
    /// PROPOSER's (initiator's) leaf, and the commit's updatePath replaces the COMMITTER's
    /// (our own). That makes this commit the A.5 credential channel for both parties:
    /// the initiator's handoff rides its Upd' (see `pq_rekey_begin`), and our own leaf
    /// catches up to the session's canonical identity whenever it lags — the PQ analogue
    /// of `prepare_ratchet_commit`'s classical own-leaf catch-up, validated by the AS's
    /// catch-up rule (a leaf may only move to an ALREADY-canonical identity). Each party's
    /// send-PQ leaf therefore hands off when it RESPONDS, and the turn alternation is what
    /// brings that round around.
    ///
    /// Returns the ClientId the initiator announced in the Upd's authenticated_data when
    /// this rekey carries an A.5 credential handoff (see `pq_rekey_begin`), else `None`.
    /// By the time this returns, the initiator's leaf in our send-PQ has already moved
    /// to the new principal's signing key. The classical Phase 8 commit remains the
    /// authoritative identity-rotation channel — this reports the PQ half catching up
    /// and does not touch the session's principal state.
    pub fn pq_rekey_respond(&self, upd_msg: Vec<u8>) -> Result<Option<ClientId>> {
        // Guard-first (see `pq_ratchet_begin`): check the slot/inflight state and validate the
        // frame before the persist choke point, so a replayed or ill-timed Upd' is a no-op.
        let proposal_msg = {
            let inner = self.lock();
            let upd_msg = inner.open_or_raw(upd_msg);
            let (&tag, proposal_bytes) = upd_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_REKEY_UPD_TAG {
                return Err(TwoMlsPqError::Mls);
            }
            let proposal_msg =
                MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
            // Inflight only (see `pq_ratchet_respond`): the slot may hold our own retained
            // frame from the previous round.
            if inner.pq_inflight.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            proposal_msg
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            // Cross-PSK from our recv-PQ mirror (§A.5: "Export PSK from [ASG-PQ]"), but only
            // when the peer's send-PQ has advanced since we last cross-injected it — the same
            // event-driven rule as the classical ratchet (see `last_cross_injected_pq`). Across
            // two consecutive re-keys without a PQ commit from the peer in between, this recv-PQ
            // epoch is unchanged and already entangled, so we skip re-deriving a consumed leaf
            // (the commit still rotates our leaf via the updatePath). The initiator registers
            // the same value from its own send-PQ at this epoch.
            let recv_pq_epoch = inner
                .recv_group
                .as_ref()
                .and_then(|g| g.pq.as_ref())
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .current_epoch();
            let cross_psk = if inner.last_cross_injected_pq == Some(recv_pq_epoch) {
                None
            } else {
                let exported = inner.export_cross_from_recv_pq()?;
                inner.register_psk(exported.storage_id(), exported.psk());
                Some(exported)
            };
            // Snapshot of the peer's canonical history for the announced-id check below,
            // and our own identity/keys for the committer catch-up (both taken before the
            // group borrow).
            let canonical_theirs = inner.with_auth(|core| core.theirs.to_parts().0);
            let current_id = inner.client.client_id();
            let (my_signer, my_public) = inner.client.combiner().pq_signature_keypair();
            let rotated;
            let commit_bytes = {
                let send_pq = inner
                    .send_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let my_index = send_pq.current_member_index();
                match send_pq
                    .process_incoming_message(proposal_msg)
                    .map_err(|_| TwoMlsPqError::Mls)?
                {
                    ReceivedMessage::Proposal(desc) => {
                        // Only the peer's own-leaf Update is a legitimate A.5 opener.
                        require_peer_update(&desc, my_index)?;
                        rotated = (!desc.authenticated_data.is_empty()).then(|| ClientId {
                            bytes: desc.authenticated_data.clone(),
                        });
                    }
                    _ => return Err(TwoMlsPqError::Mls),
                }
                // The classical ratchet leads the credential sequence; a PQ handoff may
                // only catch a leaf up to an ALREADY-canonical identity.
                if let Some(announced) = &rotated {
                    if !canonical_theirs.iter().any(|h| h == &announced.bytes) {
                        return Err(TwoMlsPqError::CredentialRejected);
                    }
                }
                // Own-leaf catch-up: this commit's updatePath replaces OUR leaf — the
                // committer replacement that is this round's other half. When the leaf
                // still signs as a principal the session has rotated past (Phase 8 swapped
                // `self.client`; the PQ leaves lag until their next updatePath), move it to
                // the current identity here. The peer's AS validates the catch-up when it
                // applies this Commit' (canonical-only), so a commit racing ahead of our
                // classical rotation staple is refused retriably, exactly like the
                // initiator-side handoff.
                let my_leaf = sender_client_id(send_pq, my_index)?;
                let handoff = if my_leaf != current_id.bytes {
                    let identity = SigningIdentity::new(
                        BasicCredential::new(current_id.bytes.clone()).into_credential(),
                        my_public,
                    );
                    Some((my_signer, identity))
                } else {
                    None
                };
                let mut builder = send_pq.commit_builder();
                if let Some(psk) = &cross_psk {
                    builder = psk.add_to_commit(builder)?;
                }
                if let Some((signer, identity)) = handoff {
                    builder = builder.set_new_signing_identity(signer, identity);
                }
                let out = builder.build().map_err(map_credential_err)?;
                send_pq
                    .apply_pending_commit()
                    .map_err(|_| TwoMlsPqError::Mls)?;
                // The commit folded the peer's Upd' from the cache: reject a roster change
                // (only an Update is legitimate there — an Add would grow the roster
                // through OUR commit).
                apq::ensure_two_party(send_pq)?;
                out.commit_message
                    .to_bytes()
                    .map_err(|_| TwoMlsPqError::Mls)?
            };
            // Our send-PQ commit above consumed the one-shot cross-party PSK (when one rode
            // it); drop it from the ephemeral store now the commit is applied.
            if let Some(psk) = &cross_psk {
                inner.forget_psk(psk.storage_id());
            }
            // The peer's leaf in our send-PQ just caught up: retire a bootstrap pin no live
            // PQ leaf still carries (see `retire_stale_pins`).
            retire_stale_pins(inner);
            inner.pq_inflight = Some(PqInflight::RekeyResponded);
            // REPLACES our previous frame; the initiator's stapled ack answers it, and the
            // staple arm's clear is what empties the slot — no retirement stamp (this is a
            // middle leg now, not a terminal one).
            inner.pending_side_band = Some(RetainedFrame::unsealed(encode_pq_rekey_commit(
                commit_bytes,
            )));
            // Our send-PQ's pq_epoch advanced (updatePath commit) — capture its new key.
            inner.record_pq_header_key()?;
            Ok(rotated)
        })
    }

    /// A.5 initiator, leg 3 — apply the responder's Commit' to our recv mirror, then CLOSE
    /// the round with the ack: export the cross-party secret from the mirror's NEW
    /// (post-Commit') epoch, inject it into our own send-PQ with a pathless partial
    /// commit, and OWE the classical half. The ack rides our next classical COMMIT as an
    /// `APQPrivateMessage` staple — this IS A.3's and A.4's bind (`commit_pq_and_owe_bind`),
    /// differing only in where S comes from, and it is what answers the round's one large
    /// frame: S is derivable only by a party that has applied the Commit', so a bind that
    /// applies at all is the receipt. The responder receives it via `process_incoming`
    /// (the staple arm), never here — the turn passes at discharge, and the peer takes it
    /// on applying the staple.
    pub fn pq_rekey_apply(&self, msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): decode the frame and check every turn/slot/
        // staple precondition before the persist choke point, so a replayed or ill-timed
        // Commit' is a no-op. The closure still `take`s the (now guaranteed `RekeyInitiated`)
        // inflight state below.
        let commit_bytes = {
            let inner = self.lock();
            let msg = inner.open_or_raw(msg);
            let commit_bytes = decode_pq_rekey_commit(&msg)?;
            // Staple-stacking guard, as the other two binds have (see `pq_ratchet_bind`): a
            // prepared-but-unsent classical commit sits in `current_staple` waiting for its
            // `encrypt`, and the ack's commit below would displace it. Retriable: apply
            // after the round's `encrypt`.
            if inner.pending_proposal_hash.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Rule 2, as the other two binds (see `pq_ratchet_bind`): at most one owed bind.
            // Retriable — our next classical commit discharges the outstanding one.
            if inner.owed_bind.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Only the initiator of THIS rekey may close it.
            match inner.pq_inflight {
                Some(PqInflight::RekeyInitiated) => {}
                // We already acked: the round closed for us and the turn passed at (or
                // awaits) discharge, so this is the peer re-sending its Commit' until our
                // stapled ack lands. Discard.
                None if !inner.pq_turn_mine => return Err(TwoMlsPqError::DuplicateSideBand),
                _ => return Err(TwoMlsPqError::SessionNotReady),
            }
            commit_bytes
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let commit_msg =
                MlsMessage::from_bytes(&commit_bytes).map_err(|_| TwoMlsPqError::Mls)?;
            // Pre-register our own send-PQ cross-party PSK so the peer's Commit' (which
            // cross-injects from its recv-PQ mirror = our send-PQ) can resolve it. Export
            // it at most once per send-PQ epoch (`last_send_pq_exported`): the value stays
            // in the store, and re-exporting a consumed leaf across two re-keys without our
            // send-PQ advancing would fail. (The send-PQ analogue of the classical
            // `send_psk_ledger`.) When the export is skipped (watermark already at this
            // epoch) the peer's commit skips referencing it too — the lockstep invariant —
            // so there is nothing new to forget.
            let pre_registered_send_pq: Option<ExternalPskId> = {
                let inner: &mut SessionInner = &mut *inner;
                let send_pq_epoch = inner
                    .send_group
                    .as_ref()
                    .and_then(|g| g.pq.as_ref())
                    .ok_or(TwoMlsPqError::SessionNotReady)?
                    .current_epoch();
                if inner.last_send_pq_exported != Some(send_pq_epoch) {
                    let exported = inner.export_cross_from_send_pq()?;
                    inner.register_psk(exported.storage_id(), exported.psk());
                    Some(exported.storage_id().clone())
                } else {
                    None
                }
            };
            // Exhaustiveness defense should the guard at the top of this function and this
            // body ever drift apart — a pure READ, never a take: the inflight state has to
            // survive every fallible step below (see the clear after the apply).
            if !matches!(inner.pq_inflight, Some(PqInflight::RekeyInitiated)) {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Apply the responder's Commit' to our recv mirror. It may carry the
            // responder's own-leaf credential catch-up (see `pq_rekey_respond`), which the
            // AS validates against its canonical sequence — hence `map_credential_err`.
            {
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                match recv_pq
                    .process_incoming_message(commit_msg)
                    .map_err(map_credential_err)?
                {
                    // The responder's Commit' is PQ-group-only and carries no
                    // AppDataUpdate — reconciliation is OUR ack's job (a FULL commit,
                    // below). An attestation smuggled in here is rejected.
                    ReceivedMessage::Commit(desc) => {
                        if commit_attestation(&desc)?.is_some() {
                            return Err(TwoMlsPqError::ApqInfoMismatch);
                        }
                    }
                    _ => return Err(TwoMlsPqError::Mls),
                }
                // A peer commit must never change the two-party shape.
                apq::ensure_two_party(&*recv_pq)?;
            }
            // The Commit' has APPLIED: the round's inbound leg is complete, so the inflight
            // state goes now — deliberately not before it.
            //
            // Everything above is fallible, and the credential catch-up this Commit' may
            // carry is refused RETRIABLY by design (see `pq_rekey_respond`: the AS admits
            // only an already-canonical identity, so a Commit' racing ahead of our classical
            // rotation staple is rejected until that staple lands). Clearing the state
            // first would make that retry unreachable: the responder re-sends its Commit'
            // as designed, but our guard — seeing no round in flight and still holding the
            // turn, which passes only at a discharge that never happened — would answer
            // SessionNotReady forever, deadlocking both sides for good (the closure's
            // mutations persist even on Err).
            inner.pq_inflight = None;
            // The Commit' we just applied consumed the send-PQ cross-PSK we pre-registered
            // above; drop it from the store.
            if let Some(id) = &pre_registered_send_pq {
                inner.forget_psk(id);
            }
            // S: the cross-party secret off the mirror's NEW epoch (§A.5: "Export PSK from
            // [BSG-PQ]") — derivable only having applied the Commit', which is what makes
            // the ack a receipt. The responder re-derives the same value from its own
            // send-PQ as it applies our staple, so it never goes on the wire.
            let s = Zeroizing::new(inner.export_cross_from_recv_pq()?.psk().as_ref().to_vec());
            // As A.3 and A.4, whose `commit_pq_and_owe_bind` this shares: commit the PQ
            // half, owe the classical one, park NOTHING. The ack rides our next classical
            // COMMIT as an APQPrivateMessage staple, and the staple's re-send until
            // superseded heals a lost one.
            inner.commit_pq_and_owe_bind(&s)?;
            // The peer's leaf in our recv mirror caught up applying its Commit' above:
            // retire a bootstrap pin no live PQ leaf still carries (see
            // `retire_stale_pins`).
            retire_stale_pins(inner);
            // Our Upd' is spent — the Commit' we just applied answered it (the ordinary
            // "my part is done" clear; the ack travels the staple, not this slot).
            inner.pending_side_band = None;
            // The turn passes at DISCHARGE, not here — see `discharge_owed_bind`. Rule 2 is
            // checked explicitly at the bind entry points instead.
            //
            // Our send-PQ's pq_epoch advanced (the ack's pathless commit) — capture its
            // header key. NOT the listen address: that tracks the CLASSICAL epoch, which
            // has deliberately not moved.
            inner.record_pq_header_key()?;
            Ok(())
        })
    }
}

impl SessionInner {
    /// Register the A.3 bootstrap round around the pre-committed KP frame `msg`
    /// (`[0x13][KP′]`): pin the founding credential eviction-exempt in `mine`, consume the
    /// one-of-a-kind KP, retain the frame as the round's re-send carrier, and open the
    /// round. The ONE definition of "the A.3 round is open" — both registration entry
    /// points (`pq_bootstrap_begin`, side-band path, and `pq_bootstrap_envelope`, the
    /// Part 3 parallel path) go through here, so what registration MEANS cannot drift
    /// between them. `sealed` seeds the retained frame's `Stable` cache when the caller
    /// is about to hand those exact bytes back (`begin`); the parallel path retains
    /// unsealed (its §A.1 envelope seal is per-send and never cached).
    ///
    /// The fallible parse runs before any mutation, so an `Err` inside a
    /// `mutate_and_persist` closure leaves the KP and the round untouched (retriable).
    fn register_bootstrap_round(&mut self, msg: Vec<u8>, sealed: Option<&[u8]>) -> Result<()> {
        // Our OWN establishment credential, carried by this KP. Pin it eviction-exempt
        // in `mine` so the bind can join the Welcome' whose added leaf still bears it —
        // enough of our own rotations before A.3 would otherwise evict it from `mine`
        // and fail the self-leaf validation on join. Retired symmetrically once A.5
        // catches this leaf up (`retire_stale_pins`).
        let kp = msg.get(1..).ok_or(TwoMlsPqError::Mls)?;
        let founding = parse_mls_key_package(kp.to_vec())?.client_id.bytes;
        self.with_auth(|core| core.mine.pin(founding));
        // Consume the KP now that the retained frame (below) carries the round; the
        // commitment accessor goes quiet (the host read it at reply-composition time).
        self.bootstrap_kp = None;
        // Retain for re-send. A lost KP' is the worst of the three to strand: without
        // A.3 the session never reaches full establishment, and this frame is what the
        // peer's deferred send-PQ half is built around.
        self.pending_side_band = Some(match sealed {
            Some(sealed) => RetainedFrame::seeded(msg, sealed),
            None => RetainedFrame::unsealed(msg),
        });
        // Register the round. This is what stops A.4/A.5 opening beside a bootstrap —
        // every `*_begin` gates on `pq_inflight` being empty, and A.3's absence from it
        // is precisely why a ratchet round could evict this frame.
        self.pq_inflight = Some(PqInflight::BootstrapInitiated);
        Ok(())
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Whose move the PQ side-band is: true when this side owes the next operation.
    /// The initiator owes the A.3 bootstrap; completing an operation passes the turn.
    pub fn my_pq_turn(&self) -> bool {
        self.lock().pq_turn_mine
    }

    /// Whether receiving is broken: a peer bind staple failed to apply after the round's
    /// secret was consumed, so `process_incoming` now refuses every frame with
    /// [`TwoMlsPqError::BindApplyFailed`] (the peer re-staples the same unappliable bind
    /// forever). SENDING is unaffected. Not reachable from an honest peer, and healed by
    /// restoring the last persisted state — how urgent that is depends on what the session
    /// is for (a receive-critical role treats it as fatal; a send-mostly role can defer),
    /// which is why this is a query rather than only an error a host trips over.
    pub fn pq_receive_broken(&self) -> bool {
        self.lock().bind_apply_broken
    }

    /// The current round's outbound side-band frame, sealed, WITHOUT consuming it — the
    /// side-band analogue of re-stapling `current_staple` onto every message frame. `None`
    /// when the side-band is quiescent, which is what lets a host send a bare message.
    ///
    /// One frame at most: every side-band round registers in `pq_inflight`, and every
    /// `*_begin` gates on it, so A.3, A.4 and A.5 are mutually exclusive. (A.3 was once
    /// absent from that, which let a ratchet round open beside a bootstrap and evict it —
    /// the reason A.3 is now a well-formed round.)
    ///
    /// Call it on every send for as long as it returns anything: a side-band frame is the
    /// only carrier of its PQ half, so re-sending is how a dropped one heals (see
    /// [`SessionInner::pending_side_band`]). Duplicates are benign discards on the
    /// receiver, so over-sending is safe where under-sending stalls the ratchet.
    ///
    /// `sealing` picks the wire behaviour, and only the host can: [`SideBandSealing::Fresh`]
    /// makes every send distinct (a stalled round does not repeat identifiable bytes);
    /// [`SideBandSealing::Stable`] holds the base still so a host can CHUNK it. See
    /// [`SideBandSealing`] for the trade.
    ///
    /// Advances no protocol state either way: the frame stays, no `state_seq` bump, nothing
    /// to persist. (`Stable` fills a live-only seal cache — invisible to the archive and to
    /// the peer.)
    ///
    /// Epochs: `Fresh` seals at the epoch CURRENT to each call, so a frame retained across a
    /// ratchet keeps opening for the peer. `Stable` cannot, by construction — the bytes hold
    /// still, so the cached seal keeps the epoch it was first sealed at and the peer opens it
    /// from its retained header-key window. That is roomy for the PQ family (`seal_side_band`
    /// seals under recv-PQ, which advances only when the PEER commits — and applying a peer
    /// commit clears this side's retained frame anyway). It is tighter for the one frame that
    /// takes `seal_side_band`'s classical fallback, the pre-A.3 `BOOTSTRAP_KP`, whose key
    /// tracks the CLASSICAL epoch that ordinary messaging advances: a `Stable` pass over that
    /// frame wants to finish inside the peer's classical header window. `Fresh` has no such
    /// constraint.
    pub fn pq_pending_outbound(&self, sealing: SideBandSealing) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        // Contract 26 emission gate: nothing leaves a born-dedicated acceptor
        // before its establishment envelope installs.
        if inner.ensure_establishment_delegated().is_err() {
            return None;
        }
        inner.hand_out(sealing)
    }

    /// Consume the current round's side-band frame.
    ///
    /// Prefer [`Self::pq_pending_outbound`]: taking leaves the round's only carrier of its
    /// PQ half nowhere to be re-sent from, so a dropped frame stalls the ratchet with no
    /// way to heal. Retained for hosts that drive the side-band as a strict
    /// request/response and accept that.
    pub fn pq_take_pending_outbound(&self) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        // Contract 26 emission gate — see `pq_pending_outbound`.
        if inner.ensure_establishment_delegated().is_err() {
            return None;
        }
        // Pre-establishment there is no side-band to take from — and since Part 3 the slot
        // can be OCCUPIED then (`pq_bootstrap_envelope` parks the round's `[0x13][KP′]`
        // before any recv group exists). Taking it here would destroy the round's only
        // carrier: the seal below needs a recv group, its failure is swallowed, and the
        // emptied slot would be persisted — an unhealable A.3 strand. Guard first: leave
        // the frame parked for `pq_bootstrap_envelope` re-sends and the post-cutover
        // `hand_out`; the §A.1 envelope is the pre-establishment carrier.
        inner.recv_group.as_ref()?;
        let retained = inner.pending_side_band.take()?;
        // Side-band frames seal under the PQ family; with the recv group present (guard
        // above) the pre-A.3 classical fallback in `seal_side_band` also has its key, so
        // the seal cannot fail for want of a group.
        let out = inner.seal_side_band(&retained.frame).ok();
        // The take advanced state — persist Core (a side-band frame changes no group).
        // Keyed on the take, like `pending_outbound`: an (unreachable) seal failure still
        // consumed the parked frame.
        if let Some(s) = inner.state_seq.checked_add(1) {
            inner.state_seq = s;
        }
        let seq = inner.state_seq;
        if let Some(sink) = inner.sink.clone() {
            if let Ok(bytes) = archive::encode_core(&mut inner) {
                drop(inner);
                sink.persist(seq, crate::BlobKind::Core, bytes);
            }
        }
        out
    }

    /// A.3 initiator — emit this side's PQ key package (tag 0x13) so the peer can stand
    /// up its deferred send-group PQ half. The KP is the one PRE-COMMITTED at `initiate`
    /// (never a fresh mint): the peer holds `H(bootstrap_kp)` from the signed
    /// establishment payload and refuses anything else, so these exact bytes are the
    /// only KP′ that can complete the round. Its private material is retained in this
    /// client, so the returned welcome can be joined by `pq_bootstrap_bind`.
    ///
    /// `rotating` must name the session's CURRENT principal (like `pq_rekey_begin`) —
    /// a caller-sanity check only: the KP′ is pre-committed, so its leaf carries the
    /// ESTABLISHMENT credential regardless of any completed Phase 8 rotation (the
    /// commitment outranks the live principal; A.5 hands the PQ leaves to the rotated
    /// credential afterward).
    ///
    /// Idempotent once the round is registered — by an earlier call, or by the Part 3
    /// parallel `pq_bootstrap_envelope`: it then re-seals and returns the retained
    /// `[0x13][KP′]` frame with no state change and no persist, so a host keeping its
    /// standard post-establishment A.3 kickoff after adopting the parallel envelope is
    /// safe.
    pub fn pq_bootstrap_begin(&self, rotating: Option<ClientId>) -> Result<Vec<u8>> {
        // Guard-first (see `pq_ratchet_begin`): turn, the optional credential handoff, the
        // "send exists, recv-PQ absent" readiness, and the pre-committed KP's presence are
        // all pure reads — check them before the persist choke point so an ill-timed call
        // is a no-op.
        {
            let inner = self.lock();
            if !inner.pq_turn_mine {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            if let Some(new_id) = rotating {
                if inner.client.client_id() != new_id {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
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
            // Round already registered — by an earlier `begin` or by the Part 3 parallel
            // envelope (`pq_bootstrap_envelope`). Re-seal and return the retained frame:
            // a PURE idempotent re-send (no state change, no persist), so a host that
            // keeps its standard post-establishment A.3 kickoff after adopting the
            // parallel envelope gets the same frame back instead of an error. This is
            // what makes "begin is idempotent once the round is registered" true.
            if matches!(inner.pq_inflight, Some(PqInflight::BootstrapInitiated)) {
                let retained = inner
                    .pending_side_band
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                return inner.seal_side_band(&retained.frame);
            }
            // Only an initiator holds a pre-committed KP (minted at `initiate`, riding
            // the archive), and only an initiator ever owes the bootstrap — absence here
            // means this is not that session.
            if inner.bootstrap_kp.is_none() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
        }
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            // SEAL BEFORE CONSUMING. `mutate_and_persist` persists the closure's partial
            // mutations even when it returns `Err`, and the pre-committed KP is
            // one-of-a-kind — its hash is signed into establishment, so a lost KP can
            // never be re-minted. Build and seal the frame from a BORROW first; only once
            // the fallible `seal_side_band` has succeeded do we clear `bootstrap_kp` and
            // register the round. A seal failure then leaves the KP intact and the call
            // retriable, matching `pq_ratchet_begin` (whose ephemeral IS re-mintable).
            let kp = inner
                .bootstrap_kp
                .as_deref()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let mut msg = vec![PQ_BOOTSTRAP_KP_TAG];
            msg.extend_from_slice(kp);
            // Side-band frame. Pre-A.3 our recv-PQ (Group_B.pq) is the group the bootstrap
            // is creating, so `seal_side_band` falls back to the classical seal for exactly
            // this frame; the peer opens it from its classical window.
            let sealed = inner.seal_side_band(&msg)?;
            // Seal succeeded — register the round (the shared definition; see
            // `register_bootstrap_round`), seeding the retained frame with the bytes we
            // are about to return so a `Stable` hand-out agrees with them.
            inner.register_bootstrap_round(msg, Some(&sealed))?;
            Ok(sealed)
        })
    }

    /// Part 3 — parallel KP′ delivery. Emit the initiator's pre-committed A.3 KP′ (the same
    /// verbatim `[0x13][KP′]` frame `pq_bootstrap_respond` consumes) IN PARALLEL with the
    /// establishment reply, HPKE-sealed to the retained seal target `initial_their_kp` as a
    /// RAW §A.1 blob (`seal_hpke_blob`: `[u32 kem_len][kem_output][ciphertext]`, no sections,
    /// no outer tag). It shares that outer shape with the establishment reply — no per-frame
    /// "carries PQ material" distinguisher; the receiver tells them apart on unpacking, by the
    /// `0x13` inner leading tag vs. the reply's `ESTABLISHMENT_VECTOR_TAG`. Initiator-only,
    /// PRE-ESTABLISHMENT only: `initial_their_kp` exists solely in that window (cleared at the
    /// cutover), and `seal_side_band` — the steady-state carrier — needs a recv group that
    /// does not exist yet, which is exactly why this frame rides the HPKE envelope instead.
    ///
    /// The FIRST emit REGISTERS the A.3 round exactly as `pq_bootstrap_begin` does — the
    /// shared `register_bootstrap_round` (`pq_inflight = BootstrapInitiated`, the retained
    /// frame, the eviction-exempt `mine` credential pin) — and persists a Checkpoint, so the
    /// initiator can process an EARLY `Welcome'`: an acceptor that already holds this KP′
    /// when its return welcome goes out sends `Welcome'` alongside it, and A.3 completes ~one
    /// round trip sooner. **Read `bootstrap_kp_commitment()` BEFORE the first emit** — it
    /// consumes the pre-committed KP, and the signed reply must carry the commitment. EVERY
    /// LATER pre-cutover emit is a PURE re-seal of the retained frame — fresh HPKE, no state
    /// change, no persist (register-once, re-seal-per-send pure). After the establishment
    /// cutover the SAME retained frame flows over the steady-state side-band (`hand_out`
    /// re-seals it), so a dropped parallel envelope self-heals, and `pq_bootstrap_begin` is
    /// idempotent afterward — it re-seals and returns the retained frame (the round is
    /// registered). Fresh HPKE per call — the re-sends are unlinkable.
    ///
    /// Concurrency note: the guard block and the registering closure take the lock
    /// separately, so two concurrent FIRST emits can both fall through the guard. The
    /// closure's re-check keeps the state correct (the loser registers nothing), but the
    /// loser still records one redundant, idempotent Checkpoint — the register-once/pure
    /// contract is exact only under the sequential driving the session assumes throughout.
    pub fn pq_bootstrap_envelope(&self) -> Result<Vec<u8>> {
        // Guard-first (pure reads). Two shapes reach here; the seal target `initial_their_kp`
        // is required by both (present ONLY for a pre-establishment initiator):
        //  - REGISTERED re-send (the common per-send path): the round is already open, so
        //    re-seal its retained `[0x13][KP′]` frame PURELY — fresh HPKE, no state change, no
        //    persist (register-once, re-seal-per-send pure, like `pq_pending_outbound`). This
        //    arm RETURNS here, before the persist choke point.
        //  - FIRST emit: the pre-committed KP is still in hand; fall through to register.
        {
            let inner = self.lock();
            let their_kp = inner
                .initial_their_kp
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            match &inner.pq_inflight {
                Some(PqInflight::BootstrapInitiated) => {
                    let retained = inner
                        .pending_side_band
                        .as_ref()
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    return crate::key_packages::seal_hpke_blob(their_kp, &retained.frame);
                }
                None if inner.bootstrap_kp.is_some() => {}
                _ => return Err(TwoMlsPqError::SessionNotReady),
            }
        }
        // FIRST emit only — register the A.3 round (persist a Checkpoint), sealing the frame
        // built from the pre-committed KP.
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let their_kp = inner
                .initial_their_kp
                .clone()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            // Re-check under the persist lock: sequential driving is the norm, but if the round
            // registered between the guard read and here, re-seal the retained frame (the
            // persist below is then a harmless idempotent checkpoint).
            let msg = match inner.pending_side_band.as_ref() {
                Some(retained) => retained.frame.clone(),
                None => {
                    let kp = inner
                        .bootstrap_kp
                        .as_deref()
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    let mut m = Vec::with_capacity(1 + kp.len());
                    m.push(PQ_BOOTSTRAP_KP_TAG);
                    m.extend_from_slice(kp);
                    m
                }
            };
            // Seal the verbatim `[0x13][KP′]` frame as a raw HPKE blob FIRST (fallible HPKE):
            // `mutate_and_persist` persists partial mutations on `Err`, and the pre-committed
            // KP is one-of-a-kind, so register the round only AFTER the seal succeeds (mirrors
            // `pq_bootstrap_begin` — a seal failure leaves the KP intact and the call
            // retriable).
            let envelope = crate::key_packages::seal_hpke_blob(&their_kp, &msg)?;
            if inner.pq_inflight.is_none() {
                // The shared registration (see `register_bootstrap_round`) — retained
                // UNSEALED, no side-band seal to cache pre-establishment: this envelope's
                // §A.1 seal is per-send, and the steady-state seal comes from `hand_out`
                // after the cutover.
                inner.register_bootstrap_round(msg, None)?;
            }
            Ok(envelope)
        })
    }

    /// A.3 responder — stand up the deferred send-group PQ half around the peer's key
    /// package and return the bootstrap frame (tag 0x15) carrying its Welcome.
    /// PQ-groups-only: no classical commit rides here — the new half's APQ-PSK reaches
    /// the classical group at the next A.4 bind. Taking this turn makes the next
    /// operation ours.
    pub fn pq_bootstrap_respond(&self, kp_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): the slot check, the KP suite/identity
        // validation, and "our send-PQ half is not already up" are all pure reads of `inner`
        // and the frame — run them before the persist choke point so a replayed or malformed
        // bootstrap KP is a no-op rather than a full-Checkpoint push. The closure below assumes
        // these hold (sequential driving) and proceeds straight to standing up the group.
        let kp = {
            let inner = self.lock();
            let kp_msg = inner.open_or_raw(kp_msg);
            let (&tag, kp) = kp_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_BOOTSTRAP_KP_TAG {
                return Err(TwoMlsPqError::Mls);
            }
            // No slot check (see `pq_ratchet_respond`). The "our send-PQ is already up"
            // guard below is what makes a re-sent KP' idempotent — it is reached before any
            // group is built, so a duplicate is refused without touching state.
            //
            // Validate the peer's PQ key package suite before building a group around it — an
            // early, clear CipherSuiteMismatch rather than a late opaque mls-rs error.
            check_key_package_suite(kp, inner.suite.pq)?;
            // The KP′ must be the one the establishment SIGNED: the acceptor pinned
            // `H(initiator's PQ keyPackage)` at `receive` (`accept_with` REQUIRES it, so a
            // real acceptor always has one — its absence is an invariant violation, not a
            // fallback to a weaker policy). A KP′ hashing to anything else is a
            // substitution, rejected before any group is stood up. The hash pins the exact
            // committed bytes, NOT that they name the established peer — a substitution
            // reusing the acceptor's own id in the leaf is not caught here — but the leaf
            // is AS-validated when the group is created below (`validate_member` admits
            // only ids the acceptor already knows), so an unrelated third identity is
            // rejected there. Unlike a live-principal identity check the commitment still
            // admits the KP after a Phase 8 rotation, up to the acceptor's credential
            // history window (PQ leaves lag credentials by design; A.5 catches them up).
            let expected = inner
                .expected_bootstrap_kp_commitment
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if !expected.matches(kp) {
                return Err(TwoMlsPqError::BootstrapKpMismatch);
            }
            // Our send-PQ half must not already be up (checked last, matching the original body
            // order); the guard-first position prevents a full-Checkpoint push on a replay.
            // An already-up half means we answered this KP' — the peer is re-sending until
            // our bootstrap frame lands. Discard rather than report not-ready: it reaches
            // here before any group is built, so it is a true no-op.
            if inner
                .send_group
                .as_ref()
                .map(|g| g.pq.is_some())
                .unwrap_or(false)
            {
                return Err(TwoMlsPqError::DuplicateSideBand);
            }
            kp.to_vec()
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let client = inner.client.clone();
            let suite = inner.suite;
            // The new PQ half resolves PSKs from the CURRENT client's stores (A.3 runs on
            // the principal a Phase 8 rotation may have installed) — track them.
            inner.track_psk_stores(&client);
            // Pin the peer's ESTABLISHMENT credential (carried in the hash-authenticated
            // bootstrap KP) as eviction-exempt in `theirs`. This leaf is created lazily, so
            // enough peer rotations before A.3 could have evicted the frozen id from the
            // credential-history window — `create_group_with_member`'s `validate_member`
            // would then fail `UnknownIdentity` with the committed round unrecoverable. The
            // id was validly authenticated at establishment (the anchor-bound classical
            // session it created); the pin is retired once A.5 rotates this leaf onto the
            // current credential (`pq_rekey_respond`).
            let founding = parse_mls_key_package(kp.clone())?.client_id;
            inner.with_auth(|core| core.theirs.pin(founding.bytes.clone()));
            let frame = {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                // Defense-in-depth: send-PQ-absent was already checked guard-first above, so
                // under sequential driving this never fires; kept as a structural invariant.
                if send.pq.is_some() {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                // The classical half's creation-time APQInfo pre-allocated this PQ half's
                // group id at establishment: create the group under exactly that id, and
                // record the mirror view {t: EPOCH_UNBOUND, pq: 1} in the new half's own
                // APQInfo (no classical commit rides A.3, so its classical epoch is the
                // deferred sentinel until the next A.4 bind attests both).
                let classical_info = read_apqinfo(&send.classical)?;
                let pq_gid = classical_info.pq_session_group_id.clone();
                let info = ApqInfo::new(
                    suite,
                    classical_info.t_session_group_id.clone(),
                    pq_gid.clone(),
                    EPOCH_UNBOUND,
                    1,
                );
                let (pq_group, pq_welcome) = create_group_with_member(
                    client.pq(),
                    &kp,
                    &[],
                    GroupCreation::new(pq_gid, &info, None)?,
                )?;
                // PQ-groups-only (spec A.3): no classical bind here. The new PQ half's
                // secrecy reaches ASG-cl at the next A.4 ratchet; until then ASG-cl keeps
                // the PQ-derived security chained in at establishment.
                send.set_pq(pq_group, client.combiner());
                encode_bootstrap_welcome(pq_welcome)
            };
            // The turn is NOT taken here. A.3 has a leg to apply now, so it passes on the
            // same rule A.4 and A.5 follow: we take it applying the stapled bind (the
            // staple arm in `process_incoming`), by which point the bind has proved this
            // welcome landed. Taking it at our own send is what left us opening a ratchet
            // round beside an unconfirmed bootstrap — the collision this leg exists to
            // remove.
            inner.pq_inflight = Some(PqInflight::BootstrapResponded);
            // Parked for re-send until the initiator's stapled bind answers it (the staple
            // arm clears the slot as it applies).
            inner.pending_side_band = Some(RetainedFrame::unsealed(frame));
            // Our send-PQ half now exists (Group_B.pq) — capture its header key so we can
            // open side-band frames the peer seals to it.
            inner.record_pq_header_key()?;
            Ok(())
        })
    }

    /// A.3 initiator, leg 3 — join the peer's new PQ group (our key package's private
    /// material is retained in this client), then CLOSE the round with a bind: export the
    /// cross-party secret from the group we just joined, inject it into our own send-PQ with
    /// a pathless commit, and chain the exported apq_psk into our classical half.
    ///
    /// This is A.4's bind (`bind_with_secret`) — the only difference is where the secret
    /// comes from: an exporter off the joined group rather than a KEM decapsulation. Two
    /// things fall out of that, and they are the reason the leg exists:
    ///
    /// - **The receipt is free.** The secret is derivable only from INSIDE the welcomed
    ///   group, so a bind that applies at all proves we joined. The peer re-derives it
    ///   rather than receiving it, so nothing about it goes on the wire.
    /// - **A.3 becomes a well-formed round** (initiator → responder → initiator, as A.4 and
    ///   A.5 are), so the usual rule applies unchanged: we relinquish at this terminal send
    ///   and the peer takes the turn on applying it. Before this leg existed the peer took
    ///   the turn at its own send, and would open a ratchet round beside a bootstrap it had
    ///   no confirmation of.
    pub fn pq_bootstrap_bind(&self, welcome_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): confirm our recv-PQ half is not already up and
        // validate the welcome suite before the persist choke point, so a replayed or malformed
        // welcome is a no-op rather than a full-Checkpoint push.
        let pq_welcome = {
            let inner = self.lock();
            let welcome_msg = inner.open_or_raw(welcome_msg);
            let pq_welcome = decode_bootstrap_welcome(&welcome_msg)?;
            // Validate the peer's PQ welcome suite before joining — an early, clear
            // CipherSuiteMismatch rather than a late opaque mls-rs error (matches the
            // establishment welcome path).
            check_welcome_suite(&pq_welcome, inner.suite.pq)?;
            // An already-up recv-PQ means we joined and bound already — the peer is
            // re-sending its welcome until our stapled bind lands. Discard: re-staple makes
            // this steady-state, and it is reached before anything is touched.
            //
            // Checked BEFORE the `BootstrapInitiated` gate, not after: joining sets recv-PQ
            // and clears `pq_inflight` to `None` in one closure, so a post-bind re-send is
            // always {recv-PQ up, inflight None} — behind the inflight gate it would answer
            // the retriable `SessionNotReady`, inviting the host to retry a round that is
            // over, and the duplicate arm would be dead.
            if inner
                .recv_group
                .as_ref()
                .map(|g| g.pq.is_some())
                .unwrap_or(false)
            {
                return Err(TwoMlsPqError::DuplicateSideBand);
            }
            // Only the initiator of THIS bootstrap may close it — a welcome with no bootstrap
            // in flight (and recv-PQ still down, per the discard above) is genuinely
            // ill-timed, not a duplicate.
            if !matches!(inner.pq_inflight, Some(PqInflight::BootstrapInitiated)) {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Part 3 makes `BootstrapInitiated` reachable PRE-establishment (the parallel
            // envelope registers the round before any recv group exists), so an early,
            // reordered, or replayed Welcome' can arrive here with nothing to join into.
            // Guard-first like everything above: without this, each such frame would pass
            // every pure check and fail only INSIDE `mutate_and_persist` — a full
            // Checkpoint push per replay, exactly the amplification this block exists to
            // prevent. Retriable: the same welcome binds once establishment completes.
            if inner.recv_group.is_none() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Staple-stacking guard, as `pq_ratchet_bind` has: a prepared-but-unsent classical
            // commit is sitting in `current_staple` waiting for its `encrypt`, and the bind
            // commit below would replace it. A displaced commit never rides a frame again, so
            // the peer hits the epoch-ahead desync with zero loss on the wire. Retriable: bind
            // after `encrypt`.
            //
            // A.3 shares `bind_with_secret` with A.4, so it always had A.4's hazard — in a
            // sharper form. A.4's trigger is a CT the host asked for; A.3's is an INBOUND
            // welcome, so a host that prepares a round and then receives it before its
            // `encrypt` arrives here without having done anything wrong, and the ordering is
            // not its to control.
            //
            // Ordered after the duplicate check, where A.4 puts its guard first: a re-sent
            // welcome for a round we already closed is a discard whatever our staple state is,
            // and answering it with a retriable SessionNotReady would invite the host to retry
            // a round that is over.
            if inner.pending_proposal_hash.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Rule 2, as `pq_ratchet_bind` (see there): at most one owed bind. A second
            // `inject_and_commit` would move `pq_epoch` out from under the outstanding bind's
            // reserved attestation, which the peer rejects pre-apply with our PQ leaf already
            // spent. Retriable — our next classical commit discharges the owed bind.
            if inner.owed_bind.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            pq_welcome
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let client = inner.client.clone();
            let suite = inner.suite;
            // The joined PQ half resolves PSKs from the CURRENT client's stores — track them.
            inner.track_psk_stores(&client);
            {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                // Defense-in-depth: recv-PQ-absent was checked guard-first above.
                if recv.pq.is_some() {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                // Inject the pre-committed KP's session-owned secret just-in-time: the
                // welcome is addressed to the KP minted at `initiate`, and the CURRENT
                // client (a Phase 8 rotation may have swapped it since) has no other way
                // to hold its private half. Removed again right after the join — the
                // store is ephemeral plumbing, the session is the custodian — and on a
                // FAILED join the session copy is untouched, so a retriable failure
                // (e.g. an early Welcome' before the classical join) retries intact.
                let injected = inner.bootstrap_kp_secret.clone(); // Arc handle, not a deep copy
                let store = client.combiner().pq_kp_store();
                if let Some(secret) = injected.as_ref() {
                    // The one deep clone of the ~8 KB secret: the ephemeral store copy,
                    // removed again right after the join.
                    store.insert_entry((**secret).clone());
                }
                let joined = join_group_from_welcome(client.pq(), &pq_welcome);
                if let Some(secret) = injected.as_ref() {
                    store.remove_entry(&secret.0);
                }
                let pq = joined?;
                // -02 verification: the joined group must be the one whose id the classical
                // half's APQInfo pre-allocated at establishment, and its own APQInfo must be
                // the deferred mirror ({t: EPOCH_UNBOUND, pq: 1}, same identity fields).
                // Strict roster-set equality across the halves is NOT checked here — under
                // the AS lag model the classical half's leaves may trail a canonicalized
                // rotation while the fresh PQ half carries current principals; per-leaf
                // membership is enforced by the AS (`validate_member`) inside the join.
                let classical_info = read_apqinfo(&recv.classical)?;
                verify_deferred_pq_info(&pq, &classical_info, suite)?;
                // The app-state binding lives on the classical halves only: a PQ half
                // smuggling one is rejected at join, like every other PQ-half join site.
                verify_pq_half_unbound(&pq)?;
                recv.set_pq(pq, client.combiner());
            }
            // The join is now durable in `recv.pq`, so the pre-committed secret is spent —
            // clear the session copy. Deferred to HERE (not right after the join call): a
            // post-join validation above that fails leaves `recv.pq` unset (the round stays
            // retriable) AND the secret intact, so the retry can still resolve the KP. The
            // store copy was already the just-in-time one, removed above.
            inner.bootstrap_kp_secret = None;
            // The receipt, and the entropy, in one step: the cross-party secret off the
            // birth epoch of the group we just joined. Derivable only from inside it, and
            // the peer re-derives the same value from its own copy (same group, epoch and
            // domain), so it never goes on the wire.
            let s = Zeroizing::new(inner.export_cross_from_recv_pq()?.psk().as_ref().to_vec());

            // As A.4 (`pq_ratchet_bind`), which this shares `commit_pq_and_owe_bind` with:
            // commit the PQ half, owe the classical one, park NOTHING in `pending_side_band`.
            // The two commits ride our next classical COMMIT as an APQPrivateMessage staple —
            // the message path — and the staple's re-send until superseded heals a lost one.
            inner.commit_pq_and_owe_bind(&s)?;
            // A.3's round is over for us as far as the slot is concerned; the owed bind is
            // tracked by `owed_bind`, not here.
            inner.pq_inflight = None;
            // Our KP' is spent — the welcome we just joined answered it (see
            // `pq_ratchet_bind` for the rule). A KP' re-sent past this point is worse than
            // wasteful: the peer's send-PQ half is up, so it reads as a re-bootstrap attempt.
            inner.pending_side_band = None;
            // The turn passes at DISCHARGE, not here — see `discharge_owed_bind`. Rule 2 is
            // checked explicitly at the bind entry points instead.
            //
            // Our send-PQ's pq_epoch advanced — capture its header key. NOT the listen
            // address: that tracks the CLASSICAL epoch, which has deliberately not moved.
            inner.record_pq_header_key()?;
            Ok(())
        })
    }
}
