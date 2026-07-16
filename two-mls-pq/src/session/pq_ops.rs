//! PQ side-band operations: the A.3 ratchet (pq_ratchet_*), the A.4
//! bootstrap of the deferred send-group PQ half (pq_bootstrap_*), and the
//! A.5 PQ-only re-key (pq_rekey_*), plus the in-flight round state and the
//! pq turn/outbound accessors. Every method here operates on the PQ frames
//! classified in `frames` and is security-reviewed as a unit -- see
//! the book's Protocol Flows chapter, A.3-A.5.

use super::*;

/// PQ ratchet round state carried between the messages of one exchange.
///
/// Every side-band round registers here, and every `*_begin` gates on it being empty — that
/// single-occupancy IS the mutual exclusion between A.3, A.4 and A.5. A.4 was long absent
/// from it, which is exactly why a ratchet round could open during a bootstrap and evict its
/// irreplaceable frame; being a well-formed round now, it takes its place.
pub(in crate::session) enum PqInflight {
    /// Initiator holds the ephemeral (decapsulation key) until it receives the ciphertext.
    Initiating(apq::pq_ratchet::PqEphemeral),
    /// A.4 initiator awaiting the responder's `Welcome'`. Carries nothing: the welcome is
    /// self-sufficient, and the secret this round injects is exported from the group it
    /// carries rather than held across the round.
    BootstrapInitiated,
    /// A.4 responder awaiting the initiator's bind — the frame that proves it joined.
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

#[uniffi::export]
impl TwoMlsPqSession {
    /// Initiator step 1 — generate an ML-KEM ephemeral and return the encapsulation-key message
    /// (tag 0x17). The decapsulation key is held until the ciphertext arrives.
    pub fn pq_ratchet_begin(&self) -> Result<Vec<u8>> {
        // Guard-first (pre-lock, OUTSIDE `mutate_and_persist`): a call that fails a precondition
        // mutates nothing. Rejecting it here — rather than inside the closure — keeps the persist
        // choke point from bumping the seq and pushing a full blob for a no-op. That is the same
        // pure-guard rule `process_incoming` follows (a peer can replay a well-formed but
        // ill-timed side-band frame, so an in-closure guard would be a Checkpoint-per-frame
        // amplifier). Only genuine mutate-then-fail paths stay inside and push their advanced
        // state. The body keeps its own downstream borrow guards as defense.
        {
            let inner = self.lock();
            // A.3 is post-A.4 (both PQ halves live), so the recv group always exists here —
            // guard explicitly, both because the ratchet is meaningless pre-establishment and
            // because the header seal below needs the recv group's key.
            if inner.recv_group.is_none() {
                return Err(TwoMlsPqError::SessionNotEstablished);
            }
            if inner.pq_inflight.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
        }
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let eph = apq::pq_ratchet::generate_ephemeral(&providers::pq_kem()?)?;
            let mut msg = vec![PQ_EK_TAG];
            msg.extend_from_slice(&eph.encapsulation_key());
            let sealed = inner.seal_side_band(&msg)?;
            inner.pq_inflight = Some(PqInflight::Initiating(eph));
            // Retain for re-send as well as returning it: the EK is this round's only
            // carrier, and losing it strands the round — `pq_inflight` blocks a re-begin
            // and nothing else can re-emit the ephemeral's public half. Seeding the seal
            // cache keeps a Stable hand-out byte-identical to what we return here.
            inner.pending_side_band = Some(RetainedFrame::seeded(msg, &sealed));
            Ok(sealed)
        })
    }

    /// Responder — SEAL a fresh secret to the initiator's EK (bound to our current PQ epoch),
    /// hold it, and return the ciphertext message (tag 0x19). The secret is random and sealed
    /// rather than the KEM output itself, so the initiator's open is an explicit receipt (see
    /// `apq::pq_ratchet::seal_injected_secret`).
    pub fn pq_ratchet_respond(&self, ek_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): validate the frame and check the turn/slot
        // state before the persist choke point, so a replayed or ill-timed EK frame can't force
        // a full-Checkpoint push for a no-op. Frame validation comes first to preserve the
        // precedence a stranger's blob is rejected as `Mls` before the state is consulted.
        let ek = {
            let inner = self.lock();
            let ek_msg = inner.open_or_raw(ek_msg);
            let (&tag, ek) = ek_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_EK_TAG {
                return Err(TwoMlsPqError::Mls);
            }
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
            ek.to_vec()
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
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
            let (s, ct) = apq::pq_ratchet::seal_injected_secret(
                &providers::pq_kem()?,
                &providers::header_aead_suite()?,
                &ek,
                &psk,
            )?;
            inner.pq_inflight = Some(PqInflight::Responding(s));
            let mut msg = vec![PQ_CT_TAG];
            msg.extend_from_slice(&ct);
            // Parked for re-send until the initiator's stapled bind answers it.
            inner.pending_side_band = Some(RetainedFrame::unsealed(msg));
            Ok(())
        })
    }

    /// Initiator step 2 — decapsulate S and inject it into the send group's PQ half via a
    /// pathless commit, OWING the classical half: the bind rides our next classical COMMIT
    /// as an `APQPrivateMessage` staple (see `discharge_owed_bind`), which is also where
    /// the round's app message travels — an ordinary message frame's own section.
    pub fn pq_ratchet_bind(&self, ct_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): validate the frame and every turn/slot/staple
        // precondition — AND open the sealed secret — before the persist choke point. The open
        // is a PURE read (decapsulate and the exporter mutate nothing), so a displaced,
        // stale, or misdirected CT is a no-op that neither bumps the seq nor pushes a
        // Checkpoint, and never reaches the closure's `take` of the held ephemeral. The
        // opened secret is what the closure commits.
        let s = {
            let inner = self.lock();
            let ct_msg = inner.open_or_raw(ct_msg);
            let (&tag, wire_ct) = ct_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_CT_TAG {
                return Err(TwoMlsPqError::Mls);
            }
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
            // Only an initiator holding the A.3 ephemeral can bind the ciphertext.
            let eph = match &inner.pq_inflight {
                Some(PqInflight::Initiating(eph)) => eph,
                // We already bound: the ephemeral was consumed and the turn passed, so this
                // is the peer re-sending its CT until our bind lands. Discard.
                None if !inner.pq_turn_mine => return Err(TwoMlsPqError::DuplicateSideBand),
                _ => return Err(TwoMlsPqError::SessionNotReady),
            };
            // OPEN the sealed secret. The PSK binds the group the secret is injected into
            // (our send-PQ) at its current epoch; the AEAD key binds that AND the KEM shared
            // secret, so a CT answering a DIFFERENT ephemeral (a stale round's, re-sent
            // across the bundling window) or a different epoch fails the open EXPLICITLY —
            // rejected here, ephemeral and PQ leaf intact, where a bare `decapsulate` would
            // have handed back ML-KEM's implicit-rejection garbage to inject and strand the
            // round on an unshared secret.
            let psk = {
                let send_pq = inner
                    .send_group
                    .as_ref()
                    .and_then(|g| g.pq.as_ref())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                ct_seal_psk(send_pq)?
            };
            apq::pq_ratchet::open_injected_secret(
                &providers::pq_kem()?,
                &providers::header_aead_suite()?,
                eph,
                wire_ct,
                &psk,
            )?
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            // Capture the departing epoch's PSK before the classical bind commit below.
            inner.remember_send_psk()?;
            // The ephemeral's only use — the open above — is done; discard it. Defensive
            // re-check of the state the guard read, which nothing races under sequential
            // driving.
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

    /// A.5 initiator — propose Upd'(self) into the peer's send-PQ (our recv mirror) and
    /// return the Upd' frame (tag 0x1B). Requires both PQ halves live (post-A.4 only), the turn, and
    /// no other side-band operation in flight. Proposal only: no epochs move until the
    /// responder commits.
    ///
    /// `rotating` is the A.5 credential handoff: it must name the session's CURRENT
    /// principal (a Phase 8 rotation has already swapped `self.client` to it), and the Upd'
    /// then moves our leaf's signing key to that principal, announcing its ClientId in the
    /// proposal's authenticated_data — the same announcement convention as the Phase 8
    /// classical rotation commit. The leaf's credential BYTES stay what they were:
    /// `BasicIdentityProvider` requires a stable identity across leaf updates, so principal
    /// identity travels at the announcement level, not in the Basic Credential.
    pub fn pq_rekey_begin(&self, rotating: Option<ClientId>) -> Result<Vec<u8>> {
        // Guard-first (see `pq_ratchet_begin`): the turn/slot/inflight and send-PQ-present
        // preconditions are pure reads — check them before the persist choke point so an
        // ill-timed call is a no-op. (The `rotating` credential check stays in the closure: it
        // guards a handoff that only matters once we mutate, and it needs the moved id.)
        {
            let inner = self.lock();
            // Turn + inflight are the gates; the slot is not consulted (occupancy is round
            // progress under retention, never "busy").
            if !inner.pq_turn_mine || inner.pq_inflight.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            if inner
                .send_group
                .as_ref()
                .and_then(|g| g.pq.as_ref())
                .is_none()
            {
                return Err(TwoMlsPqError::SessionNotReady);
            }
        }
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let handoff = match &rotating {
                Some(new_id) => {
                    if inner.client.client_id() != *new_id {
                        return Err(TwoMlsPqError::SessionNotReady);
                    }
                    let (new_signer, new_public) = inner.client.combiner().pq_signature_keypair();
                    Some((new_signer, new_public, new_id.bytes.clone()))
                }
                None => None,
            };
            let recv_pq = inner
                .recv_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let proposal = match handoff {
                Some((new_signer, new_public, announced_id)) => {
                    // The PQ leaf catches up in the credential sequence: the new leaf
                    // carries the CANONICAL credential (already committed classically),
                    // validated by the AS's catch-up rule.
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
            let sealed = inner.seal_side_band(&msg)?;
            inner.pq_inflight = Some(PqInflight::RekeyInitiated);
            // Retain for re-send (see `pq_ratchet_begin`): a lost Upd' strands the rekey.
            inner.pending_side_band = Some(RetainedFrame::seeded(msg, &sealed));
            Ok(sealed)
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
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let exported = export_psk(recv_pq, PskDomain::CrossParty)?;
                inner.register_psk(exported.storage_id(), exported.psk());
                inner.last_cross_injected_pq = Some(recv_pq_epoch);
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
                    let send_pq = inner
                        .send_group
                        .as_mut()
                        .and_then(|g| g.pq.as_mut())
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    let exported = export_psk(send_pq, PskDomain::CrossParty)?;
                    inner.register_psk(exported.storage_id(), exported.psk());
                    inner.last_send_pq_exported = Some(send_pq_epoch);
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
            let (s, new_epoch) = {
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let epoch = recv_pq.current_epoch();
                (
                    Zeroizing::new(
                        export_psk(recv_pq, PskDomain::CrossParty)?
                            .psk()
                            .as_ref()
                            .to_vec(),
                    ),
                    epoch,
                )
            };
            // The exporter leaf is consumed on first export — record that this epoch's is
            // spent, so a later respond at this same epoch skips re-deriving it.
            inner.last_cross_injected_pq = Some(new_epoch);
            // As A.3 and A.4, whose `commit_pq_and_owe_bind` this shares: commit the PQ
            // half, owe the classical one, park NOTHING. The ack rides our next classical
            // COMMIT as an APQPrivateMessage staple, and the staple's re-send until
            // superseded heals a lost one.
            inner.commit_pq_and_owe_bind(&s)?;
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

#[uniffi::export]
impl TwoMlsPqSession {
    /// Whose move the PQ side-band is: true when this side owes the next operation.
    /// The initiator owes the A.4 bootstrap; completing an operation passes the turn.
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
    /// `*_begin` gates on it, so A.3, A.4 and A.5 are mutually exclusive. (A.4 was once
    /// absent from that, which let a ratchet round open beside a bootstrap and evict it —
    /// the reason A.4 is now a well-formed round.)
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
    /// takes `seal_side_band`'s classical fallback, the pre-A.4 `BOOTSTRAP_KP`, whose key
    /// tracks the CLASSICAL epoch that ordinary messaging advances: a `Stable` pass over that
    /// frame wants to finish inside the peer's classical header window. `Fresh` has no such
    /// constraint.
    pub fn pq_pending_outbound(&self, sealing: SideBandSealing) -> Option<Vec<u8>> {
        let mut inner = self.lock();
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
        let retained = inner.pending_side_band.take()?;
        // Side-band frames seal under the PQ family (the responder is post-establishment,
        // so its recv-PQ group exists); the classical fallback in `seal_side_band` is
        // never hit here.
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

    /// A.4 initiator — emit this side's PQ key package (tag 0x13) so the peer can stand
    /// up its deferred send-group PQ half. The key package's private material is retained
    /// in this client, so the returned welcome can be joined by `pq_bootstrap_bind`.
    ///
    /// `rotating` must name the session's CURRENT principal (like `pq_rekey_begin`); the KP'
    /// below is generated by that client, so the new leaf carries its credential without
    /// further work — the check is all a bootstrap-time handoff needs.
    pub fn pq_bootstrap_begin(&self, rotating: Option<ClientId>) -> Result<Vec<u8>> {
        // Guard-first (see `pq_ratchet_begin`): turn, the optional credential handoff, and the
        // "send exists, recv-PQ absent" readiness are all pure reads — check them before the
        // persist choke point so an ill-timed call is a no-op.
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
        }
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let kp = inner.client.combiner().generate_pq_key_package()?;
            let mut msg = vec![PQ_BOOTSTRAP_KP_TAG];
            msg.extend_from_slice(&kp);
            // Side-band frame. Pre-A.4 our recv-PQ (Group_B.pq) is the group the bootstrap
            // is creating, so `seal_side_band` falls back to the classical seal for exactly
            // this frame; the peer opens it from its classical window.
            let sealed = inner.seal_side_band(&msg)?;
            // Retain for re-send (see `pq_ratchet_begin`). A lost KP' is the worst of the
            // three to strand: without A.4 the session never reaches full establishment,
            // and this frame is what the peer's deferred send-PQ half is built around.
            inner.pending_side_band = Some(RetainedFrame::seeded(msg, &sealed));
            // Register the round. This is what stops A.3/A.5 opening beside a bootstrap —
            // every `*_begin` gates on `pq_inflight` being empty, and A.4's absence from it
            // is precisely why a ratchet round could evict this frame.
            inner.pq_inflight = Some(PqInflight::BootstrapInitiated);
            Ok(sealed)
        })
    }

    /// A.4 responder — stand up the deferred send-group PQ half around the peer's key
    /// package and return the bootstrap frame (tag 0x15) carrying its Welcome.
    /// PQ-groups-only: no classical commit rides here — the new half's APQ-PSK reaches
    /// the classical group at the next A.3 bind. Taking this turn makes the next
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
            // The bootstrap KP must name the established peer: the new PQ half's added leaf
            // becomes a sender identity this library reports, so an unexpected principal is
            // rejected before any group is stood up around it.
            if parse_mls_key_package(kp.to_vec())?.client_id != inner.their_state.client_id() {
                return Err(TwoMlsPqError::RemoteIdentityMismatch);
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
            // The new PQ half resolves PSKs from the CURRENT client's stores (A.4 runs on
            // the principal a Phase 8 rotation may have installed) — track them.
            inner.track_psk_stores(&client);
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
                // APQInfo (no classical commit rides A.4, so its classical epoch is the
                // deferred sentinel until the next A.3 bind attests both).
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
                // PQ-groups-only (spec A.4): no classical bind here. The new PQ half's
                // secrecy reaches ASG-cl at the next A.3 ratchet; until then ASG-cl keeps
                // the PQ-derived security chained in at establishment.
                send.set_pq(pq_group, client.combiner());
                encode_bootstrap_welcome(pq_welcome)
            };
            // The turn is NOT taken here. A.4 has a leg to apply now, so it passes on the
            // same rule A.3 and A.5 follow: we take it applying the stapled bind (the
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

    /// A.4 initiator, leg 3 — join the peer's new PQ group (our key package's private
    /// material is retained in this client), then CLOSE the round with a bind: export the
    /// cross-party secret from the group we just joined, inject it into our own send-PQ with
    /// a pathless commit, and chain the exported apq_psk into our classical half.
    ///
    /// This is A.3's bind (`bind_with_secret`) — the only difference is where the secret
    /// comes from: an exporter off the joined group rather than a KEM decapsulation. Two
    /// things fall out of that, and they are the reason the leg exists:
    ///
    /// - **The receipt is free.** The secret is derivable only from INSIDE the welcomed
    ///   group, so a bind that applies at all proves we joined. The peer re-derives it
    ///   rather than receiving it, so nothing about it goes on the wire.
    /// - **A.4 becomes a well-formed round** (initiator → responder → initiator, as A.3 and
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
            // Only the initiator of THIS bootstrap may close it.
            if !matches!(inner.pq_inflight, Some(PqInflight::BootstrapInitiated)) {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // An already-up recv-PQ means we joined and bound already — the peer is
            // re-sending its welcome until our bind lands. Discard: re-staple makes this
            // steady-state, and it is reached before anything is touched.
            if inner
                .recv_group
                .as_ref()
                .map(|g| g.pq.is_some())
                .unwrap_or(false)
            {
                return Err(TwoMlsPqError::DuplicateSideBand);
            }
            // Staple-stacking guard, as `pq_ratchet_bind` has: a prepared-but-unsent classical
            // commit is sitting in `current_staple` waiting for its `encrypt`, and the bind
            // commit below would replace it. A displaced commit never rides a frame again, so
            // the peer hits the epoch-ahead desync with zero loss on the wire. Retriable: bind
            // after `encrypt`.
            //
            // A.4 shares `bind_with_secret` with A.3, so it always had A.3's hazard — in a
            // sharper form. A.3's trigger is a CT the host asked for; A.4's is an INBOUND
            // welcome, so a host that prepares a round and then receives it before its
            // `encrypt` arrives here without having done anything wrong, and the ordering is
            // not its to control.
            //
            // Ordered after the duplicate check, where A.3 puts its guard first: a re-sent
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
                let pq = join_group_from_welcome(client.pq(), &pq_welcome)?;
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
            // The receipt, and the entropy, in one step: the cross-party secret off the
            // birth epoch of the group we just joined. Derivable only from inside it, and
            // the peer re-derives the same value from its own copy (same group, epoch and
            // domain), so it never goes on the wire.
            let (s, birth_epoch) = {
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let epoch = recv_pq.current_epoch();
                (
                    Zeroizing::new(
                        export_psk(recv_pq, PskDomain::CrossParty)?
                            .psk()
                            .raw_value()
                            .to_vec(),
                    ),
                    epoch,
                )
            };
            // The exporter leaf is consumed on first export, so record that we have spent
            // this epoch's — a later A.5 must not try to re-export it.
            inner.last_cross_injected_pq = Some(birth_epoch);

            // As A.3 (`pq_ratchet_bind`), which this shares `commit_pq_and_owe_bind` with:
            // commit the PQ half, owe the classical one, park NOTHING in `pending_side_band`.
            // The two commits ride our next classical COMMIT as an APQPrivateMessage staple —
            // the message path — and the staple's re-send until superseded heals a lost one.
            inner.commit_pq_and_owe_bind(&s)?;
            // A.4's round is over for us as far as the slot is concerned; the owed bind is
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
