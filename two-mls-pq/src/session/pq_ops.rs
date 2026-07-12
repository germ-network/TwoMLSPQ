//! PQ side-band operations: the A.3 ratchet (pq_ratchet_*), the A.4
//! bootstrap of the deferred send-group PQ half (pq_bootstrap_*), and the
//! A.5 PQ-only re-key (pq_rekey_*), plus the in-flight round state and the
//! pq turn/outbound accessors. Every method here operates on the PQ frames
//! classified in `frames` and is security-reviewed as a unit -- see
//! docs 08 A.3-A.5.

use super::*;

/// PQ ratchet round state carried between the messages of one exchange.
pub(in crate::session) enum PqInflight {
    /// Initiator holds the ephemeral (decapsulation key) until it receives the ciphertext.
    Initiating(apq::pq_ratchet::PqEphemeral),
    /// Responder holds the shared secret until it receives the stapled bind. `Zeroizing` wipes the
    /// secret from memory on drop, whether it is consumed by the bind or abandoned.
    Responding(Zeroizing<Vec<u8>>),
    /// A.5 initiator awaiting the responder's Commit' (+ counter-Upd'). `rotating`
    /// carries the credential-handoff ClientId from `pq_rekey_begin` so the final
    /// commit also hands our own send-PQ leaf to the new principal's signing key.
    RekeyInitiated { rotating: Option<ClientId> },
    /// A.5 responder awaiting the initiator's final Commit'.
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
    /// (tag 0x05). The decapsulation key is held until the ciphertext arrives.
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
            Ok(sealed)
        })
    }

    /// Responder — encapsulate a fresh secret to the initiator's EK, hold it, and return the
    /// ciphertext message (tag 0x07).
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
            if inner.pq_inflight.is_some() || inner.pending_pq_outbound.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            ek.to_vec()
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let (s, ct) = apq::pq_ratchet::encapsulate(&providers::pq_kem()?, &ek)?;
            inner.pq_inflight = Some(PqInflight::Responding(Zeroizing::new(s)));
            let mut msg = vec![PQ_CT_TAG];
            msg.extend_from_slice(&ct);
            inner.pending_pq_outbound = Some(msg);
            Ok(())
        })
    }

    /// Initiator step 2 — decapsulate S, inject it into the send group's PQ half via a pathless
    /// commit, bind the exported apq_psk into the classical half, and staple an app message.
    /// Returns the bind frame (tag 0x09).
    pub fn pq_ratchet_bind(&self, ct_msg: Vec<u8>, app: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): validate the frame and every turn/slot/staple
        // precondition before the persist choke point. The `pq_inflight` state is checked here
        // as a pure read; the closure below still `take`s it (guaranteed `Initiating`). A
        // displaced or ill-timed CT frame is then a no-op that neither bumps the seq nor pushes
        // a Checkpoint — and, crucially, never reaches the `take` that would consume a held
        // ephemeral or the `remember_send_psk` that mutates.
        let ct = {
            let inner = self.lock();
            let ct_msg = inner.open_or_raw(ct_msg);
            let (&tag, ct) = ct_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
            if tag != PQ_CT_TAG {
                return Err(TwoMlsPqError::Mls);
            }
            if inner.pending_pq_outbound.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Staple-stacking guard: a prepared-but-unsent classical commit is sitting in
            // `current_staple` waiting for its `encrypt`. The bind commit below would replace
            // it, and a displaced commit never rides a frame again — the peer would hit the
            // epoch-ahead desync with zero loss on the wire. Retriable: bind after `encrypt`.
            if inner.pending_proposal_hash.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            // Only an initiator holding the A.3 ephemeral can bind the ciphertext.
            if !matches!(inner.pq_inflight, Some(PqInflight::Initiating(_))) {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            ct.to_vec()
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            // Capture the departing epoch's PSK before the classical bind commit below.
            inner.remember_send_psk()?;
            let eph = match inner.pq_inflight.take() {
                Some(PqInflight::Initiating(eph)) => eph,
                _ => return Err(TwoMlsPqError::SessionNotReady),
            };
            let s = Zeroizing::new(apq::pq_ratchet::decapsulate(
                &providers::pq_kem()?,
                &eph,
                &ct,
            )?);
            let stores = inner.psk_stores.clone();
            let send = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let send_pq = send.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
            // The bind is a -02 FULL commit: both halves carry the AppDataUpdate attesting
            // the absolute post-commit epochs of both groups, computed before either commit.
            let attestation = ApqInfoUpdate {
                t_epoch: send.classical.current_epoch() + 1,
                pq_epoch: send_pq.current_epoch() + 1,
            };
            let (pq_commit, apq_psk) =
                apq::pq_ratchet::inject_and_commit(send_pq, &s, &stores, attestation)?;
            let cl_builder = send
                .classical
                .commit_builder()
                .custom_proposal(attestation.to_custom_proposal()?);
            let cl_out = apq_psk
                .add_to_commit(cl_builder)?
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?;
            send.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
            // The bind is a bare PSK commit (the queued peer proposal is not cached — it is
            // re-applied only at the routine fold), so the roster is unchanged; assert it.
            apq::ensure_two_party(&send.classical)?;
            // The bind consumed the one-shot apq PSK; drop it from every store it was
            // registered into (the session registry plus the group-captured handles).
            send.forget_psk(apq_psk.storage_id());
            apq::forget_psk_stores(&stores, apq_psk.storage_id());
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
            // This commit advanced our send-group epoch, so any queued or offered peer
            // proposal (an Update bound to the prior send epoch) is now stale and cannot be
            // committed — drop it. The peer re-proposes at the new epoch once it observes
            // this bind's staple (the receiver freely drops; the proposer re-sends).
            inner.queued_proposal = None;
            inner.offered_proposal = None;
            // Our send group advanced: record the new epoch's PSK in the session ledger.
            inner.remember_send_psk()?;
            // The bind's classical commit becomes the staple subsequent message frames
            // re-send — if the BIND frame itself is lost, the classical stream still heals.
            // (A message frame can overtake the BIND; the peer then lacks the APQ-PSK and the
            // staple fails retriably until the BIND lands — same as today's ordering.)
            inner.current_staple = cl_commit.clone();
            // The A.3 bind commit publishes new keys; tag the staple with the (already-bumped)
            // push seq for `depends_on_seq`.
            inner.current_staple_seq = inner.state_seq;
            // Our operation is complete once the peer applies; the turn passes.
            inner.pq_turn_mine = false;
            inner.pending_pq_outbound = Some(encode_pq_bind(pq_commit, cl_commit, app_ct));
            // The bind committed classically in our send group — capture the new
            // epoch's listen address — and advanced our send-PQ's pq_epoch — capture its
            // new header key.
            inner.record_listen_rendezvous()?;
            inner.record_pq_header_key()?;
            Ok(())
        })
    }

    /// Responder — apply the stapled bind: register the held secret, apply the PQ partial commit
    /// and classical commit on the recv group, and return the decrypted app message.
    pub fn pq_ratchet_apply(&self, bind_msg: Vec<u8>) -> Result<Vec<u8>> {
        // Guard-first (see `pq_ratchet_begin`): decode the frame and confirm we hold the
        // responder secret before the persist choke point, so a stray or ill-timed bind is a
        // no-op that neither `take`s the held secret nor pushes a Checkpoint. Frame validation
        // comes first, so a stranger's unparseable blob is rejected at the frame layer (`Mls`)
        // before any KEM/turn state is consulted; the closure still `take`s the (now guaranteed
        // `Responding`) inflight state.
        let (pq_commit, cl_commit, app_ct) = {
            let inner = self.lock();
            let bind_msg = inner.open_or_raw(bind_msg);
            let decoded = decode_pq_bind(&bind_msg)?;
            if !matches!(inner.pq_inflight, Some(PqInflight::Responding(_))) {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            decoded
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let s = match inner.pq_inflight.take() {
                Some(PqInflight::Responding(s)) => s,
                _ => return Err(TwoMlsPqError::SessionNotReady),
            };
            let stores = inner.psk_stores.clone();
            let recv = inner
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let recv_pq = recv.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
            let (apq_psk, pq_attestation) =
                apq::pq_ratchet::apply_injected_commit(recv_pq, &s, &pq_commit, &stores)?;
            let cl = MlsMessage::from_bytes(&cl_commit).map_err(|_| TwoMlsPqError::Mls)?;
            let cl_attestation = match recv
                .classical
                .process_incoming_message(cl)
                .map_err(|_| TwoMlsPqError::Mls)?
            {
                ReceivedMessage::Commit(desc) => {
                    commit_attestation(&desc)?.ok_or(TwoMlsPqError::ApqInfoMismatch)?
                }
                _ => return Err(TwoMlsPqError::ApqInfoMismatch),
            };
            // -02 FULL verification: both halves carried the AppDataUpdate, the two copies
            // agree, and they attest the actual post-apply epochs of both groups.
            //
            // Verify/apply boundary: per-half AppDataUpdate validity (correct proposal type,
            // committer-sent, and new-epoch == pre-commit context.epoch + 1) is enforced
            // PRE-apply by the MlsRules filter (see `apq::rules`), so a structurally bad
            // attestation is rejected before either group state moves. What remains here — the
            // CROSS-half agreement and the match against the actual post-apply epochs — is
            // necessarily post-apply, because comparing the two halves' epochs requires both
            // commits to have been applied (mls-rs `process_incoming_message` validates and
            // applies atomically; there is no inspect-without-apply short of a fork change).
            // That residual check still gates every observable effect: it runs BEFORE the
            // stapled app message is decrypted (line below), BEFORE the one-shot apq PSK is
            // forgotten, and BEFORE the turn passes — so on a bad attestation from our sole
            // counterparty no plaintext is released and no turn/PSK state is confirmed. The
            // only thing an attestation forgery can force is a self-inflicted epoch advance
            // that then errors out, which is within the two-party DoS threat model.
            if cl_attestation != pq_attestation
                || pq_attestation.pq_epoch != recv_pq.current_epoch()
                || cl_attestation.t_epoch != recv.classical.current_epoch()
            {
                return Err(TwoMlsPqError::ApqInfoMismatch);
            }
            // Peer commits (the PQ partial above is checked inside `apply_injected_commit`)
            // must never change the two-party shape.
            apq::ensure_two_party(&recv.classical)?;
            // The bind consumed the one-shot apq PSK; drop it from every store it was
            // registered into (the session registry plus the group-captured handles).
            recv.forget_psk(apq_psk.storage_id());
            apq::forget_psk_stores(&stores, apq_psk.storage_id());
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
        })
    }

    /// A.5 initiator — propose Upd'(self) into the peer's send-PQ (our recv mirror) and
    /// return the 0x0F frame. Requires both PQ halves live (post-A.4 only), the turn, and
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
            if !inner.pq_turn_mine
                || inner.pending_pq_outbound.is_some()
                || inner.pq_inflight.is_some()
            {
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
            inner.pq_inflight = Some(PqInflight::RekeyInitiated { rotating });
            Ok(sealed)
        })
    }

    /// A.5 responder — commit the initiator's Upd' on our own send-PQ with an updatePath
    /// and a PSK exported from our recv-PQ mirror (the initiator derives the same PSK from
    /// its send-PQ), then park the `[Commit'][counter-Upd'(self)]` frame (0x11) for pickup
    /// via `pq_take_pending_outbound`.
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
            if inner.pending_pq_outbound.is_some() || inner.pq_inflight.is_some() {
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
            // Snapshot of the peer's canonical history for the announced-id check below
            // (taken before the group borrow).
            let canonical_theirs = inner.with_auth(|core| core.theirs.to_parts().0);
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
                let builder = send_pq.commit_builder();
                let builder = match &cross_psk {
                    Some(psk) => psk.add_to_commit(builder)?,
                    None => builder,
                };
                let out = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
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
            // Counter-Upd'(self) for the initiator's send-PQ (our recv mirror).
            let counter = {
                let recv_pq = inner
                    .recv_group
                    .as_mut()
                    .and_then(|g| g.pq.as_mut())
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                recv_pq
                    .propose_update(Vec::new())
                    .map_err(|_| TwoMlsPqError::Mls)?
                    .to_bytes()
                    .map_err(|_| TwoMlsPqError::Mls)?
            };
            inner.pq_inflight = Some(PqInflight::RekeyResponded);
            inner.pending_pq_outbound = Some(encode_pq_rekey_commit(commit_bytes, counter));
            // Our send-PQ's pq_epoch advanced (updatePath commit) — capture its new key.
            inner.record_pq_header_key()?;
            Ok(rotated)
        })
    }

    /// Apply an A.5 rekey Commit' (0x11). As the initiator mid-operation (frame carries
    /// the counter-Upd'), apply the peer's commit to our recv mirror, commit the
    /// counter-Upd' on our own send-PQ with the freshly-exported cross-PSK, park the
    /// final 0x11, and return `true` (pick it up via `pq_take_pending_outbound`). As the
    /// responder (empty counter slot), apply the final commit, take the turn, and return
    /// `false` — the operation is complete.
    pub fn pq_rekey_apply(&self, msg: Vec<u8>) -> Result<bool> {
        // Guard-first (see `pq_ratchet_begin`): reject an unsolicited commit before the persist
        // choke point (a pure read of the inflight state) and decode the frame here. The closure
        // still `take`s the (now guaranteed rekey) inflight state below.
        let (commit_bytes, counter_bytes) = {
            let inner = self.lock();
            let msg = inner.open_or_raw(msg);
            let decoded = decode_pq_rekey_commit(&msg)?;
            if !matches!(
                inner.pq_inflight,
                Some(PqInflight::RekeyInitiated { .. }) | Some(PqInflight::RekeyResponded)
            ) {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            decoded
        };
        self.mutate_and_persist(crate::BlobKind::Checkpoint, |inner| {
            let commit_msg =
                MlsMessage::from_bytes(&commit_bytes).map_err(|_| TwoMlsPqError::Mls)?;
            let client = inner.client.clone();
            // Both roles pre-register their own send-PQ cross-party PSK so the peer's commit
            // (which cross-injects from its recv-PQ mirror = our send-PQ) can resolve it. Export
            // it at most once per send-PQ epoch (`last_send_pq_exported`): the value stays in the
            // store, and re-exporting a consumed leaf across two re-keys without our send-PQ
            // advancing would fail. (The send-PQ analogue of the classical `send_psk_ledger`.)
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
                    // Held so we can drop it once the peer's commit (below) has resolved it —
                    // it is consumed within this same call. When the export is skipped
                    // (watermark already at this epoch) the peer's commit skips referencing it
                    // too, so there is nothing new to forget.
                    Some(exported.storage_id().clone())
                } else {
                    None
                }
            };
            match inner.pq_inflight.take() {
                Some(PqInflight::RekeyInitiated { rotating }) => {
                    if counter_bytes.is_empty() {
                        return Err(TwoMlsPqError::SessionNotReady);
                    }
                    let counter_msg =
                        MlsMessage::from_bytes(&counter_bytes).map_err(|_| TwoMlsPqError::Mls)?;
                    // Apply the responder's Commit' to our recv mirror, then export the
                    // cross-PSK from its NEW epoch (§A.5: "Export PSK from [BSG-PQ]").
                    let exported = {
                        let inner: &mut SessionInner = &mut *inner;
                        let recv_pq = inner
                            .recv_group
                            .as_mut()
                            .and_then(|g| g.pq.as_mut())
                            .ok_or(TwoMlsPqError::SessionNotReady)?;
                        match recv_pq
                            .process_incoming_message(commit_msg)
                            .map_err(|_| TwoMlsPqError::Mls)?
                        {
                            // A.5 commits are PQ-group-only and carry no AppDataUpdate —
                            // the bumped pq_epoch reconciles at the next A.3 bind. An
                            // attestation smuggled in here is rejected.
                            ReceivedMessage::Commit(desc) => {
                                if commit_attestation(&desc)?.is_some() {
                                    return Err(TwoMlsPqError::ApqInfoMismatch);
                                }
                            }
                            _ => return Err(TwoMlsPqError::Mls),
                        }
                        // A peer commit must never change the two-party shape.
                        apq::ensure_two_party(&*recv_pq)?;
                        let recv_pq_epoch = recv_pq.current_epoch();
                        // The apply just advanced recv-PQ, so this is a fresh epoch — inject and
                        // bump the watermark (a later respond at this epoch skips). Guarded by
                        // the watermark for symmetry with the classical / respond paths.
                        if inner.last_cross_injected_pq == Some(recv_pq_epoch) {
                            None
                        } else {
                            let exported = export_psk(recv_pq, PskDomain::CrossParty)?;
                            inner.last_cross_injected_pq = Some(recv_pq_epoch);
                            Some(exported)
                        }
                    };
                    if let Some(psk) = &exported {
                        inner.register_psk(psk.storage_id(), psk.psk());
                    }
                    // The responder's Commit' we just applied to our recv-PQ mirror consumed the
                    // send-PQ cross-PSK we pre-registered above; drop it from the store.
                    if let Some(id) = &pre_registered_send_pq {
                        inner.forget_psk(id);
                    }
                    // Commit the counter-Upd' on our own send-PQ. If this rekey carries a
                    // credential handoff, the commit's updatePath also moves OUR committer
                    // leaf to the new principal's signing key (the Upd' in `pq_rekey_begin`
                    // covered our leaf in the peer's send-PQ; this covers the other group).
                    let handoff = match &rotating {
                        Some(new_id) => {
                            // The session client must not have changed mid-operation.
                            if client.client_id() != *new_id {
                                return Err(TwoMlsPqError::SessionNotReady);
                            }
                            Some(client.combiner().pq_signature_keypair())
                        }
                        None => None,
                    };
                    let commit2 = {
                        let send_pq = inner
                            .send_group
                            .as_mut()
                            .and_then(|g| g.pq.as_mut())
                            .ok_or(TwoMlsPqError::SessionNotReady)?;
                        let my_index = send_pq.current_member_index();
                        match send_pq
                            .process_incoming_message(counter_msg)
                            .map_err(map_credential_err)?
                        {
                            // The counter slot may only carry the peer's own-leaf Update.
                            ReceivedMessage::Proposal(desc) => {
                                require_peer_update(&desc, my_index)?
                            }
                            _ => return Err(TwoMlsPqError::Mls),
                        }
                        let handoff = match handoff {
                            Some((new_signer, new_public)) => {
                                // Catch-up: the moved leaf carries the canonical credential.
                                let identity = SigningIdentity::new(
                                    BasicCredential::new(client.client_id().bytes.clone())
                                        .into_credential(),
                                    new_public,
                                );
                                Some((new_signer, identity))
                            }
                            None => None,
                        };
                        let mut builder = send_pq.commit_builder();
                        if let Some(psk) = &exported {
                            builder = psk.add_to_commit(builder)?;
                        }
                        if let Some((new_signer, identity)) = handoff {
                            builder = builder.set_new_signing_identity(new_signer, identity);
                        }
                        let out = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
                        send_pq
                            .apply_pending_commit()
                            .map_err(|_| TwoMlsPqError::Mls)?;
                        // The commit folded the peer-supplied counter proposal: reject a
                        // roster change (only an Update is legitimate there).
                        apq::ensure_two_party(send_pq)?;
                        out.commit_message
                            .to_bytes()
                            .map_err(|_| TwoMlsPqError::Mls)?
                    };
                    // Our counter commit above consumed the recv-PQ cross-PSK we exported and
                    // registered for it; drop it now the commit is applied.
                    if let Some(psk) = &exported {
                        inner.forget_psk(psk.storage_id());
                    }
                    // Our operation completes once the peer applies; the turn passes.
                    inner.pq_turn_mine = false;
                    inner.pending_pq_outbound = Some(encode_pq_rekey_commit(commit2, Vec::new()));
                    // Our send-PQ's pq_epoch advanced (the counter-Upd' commit) — capture it.
                    inner.record_pq_header_key()?;
                    Ok(true)
                }
                Some(PqInflight::RekeyResponded) => {
                    if !counter_bytes.is_empty() {
                        return Err(TwoMlsPqError::SessionNotReady);
                    }
                    let recv_pq = inner
                        .recv_group
                        .as_mut()
                        .and_then(|g| g.pq.as_mut())
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    match recv_pq
                        .process_incoming_message(commit_msg)
                        .map_err(|_| TwoMlsPqError::Mls)?
                    {
                        // Like the responder's Commit' above: A.5 carries no AppDataUpdate.
                        ReceivedMessage::Commit(desc) => {
                            if commit_attestation(&desc)?.is_some() {
                                return Err(TwoMlsPqError::ApqInfoMismatch);
                            }
                        }
                        _ => return Err(TwoMlsPqError::Mls),
                    }
                    // A peer commit must never change the two-party shape.
                    apq::ensure_two_party(recv_pq)?;
                    // The initiator's final Commit' we just applied consumed the send-PQ
                    // cross-PSK we pre-registered above; drop it from the store.
                    if let Some(id) = &pre_registered_send_pq {
                        inner.forget_psk(id);
                    }
                    // We finished receiving this operation; the next one is ours to start.
                    inner.pq_turn_mine = true;
                    Ok(false)
                }
                // Unreachable: the guard at the top of this function admits only the two
                // rekey states. Kept (with the state restored) purely as exhaustiveness
                // defense should the guard and this match ever drift apart.
                other => {
                    inner.pq_inflight = other;
                    Err(TwoMlsPqError::SessionNotReady)
                }
            }
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

    /// Consume the side-band frame parked by the responder-side operations
    /// (`pq_ratchet_respond` / `pq_ratchet_bind` / `pq_bootstrap_respond`). Single slot,
    /// single delivery: those operations refuse to start while a frame is waiting.
    pub fn pq_take_pending_outbound(&self) -> Option<Vec<u8>> {
        let mut inner = self.lock();
        let frame = inner.pending_pq_outbound.take()?;
        // Side-band frames seal under the PQ family (the responder is post-establishment,
        // so its recv-PQ group exists); the classical fallback in `seal_side_band` is
        // never hit here.
        let out = inner.seal_side_band(&frame).ok();
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

    /// A.4 initiator — emit this side's PQ key package (tag 0x0B) so the peer can stand
    /// up its deferred send-group PQ half. The key package's private material is retained
    /// in this client, so the returned welcome can be joined by `pq_bootstrap_apply`.
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
            inner.seal_side_band(&msg)
        })
    }

    /// A.4 responder — stand up the deferred send-group PQ half around the peer's key
    /// package and return the bootstrap frame (tag 0x0D) carrying its Welcome.
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
            if inner.pending_pq_outbound.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
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
            if inner
                .send_group
                .as_ref()
                .map(|g| g.pq.is_some())
                .unwrap_or(false)
            {
                return Err(TwoMlsPqError::SessionNotReady);
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
                encode_bootstrap_bind(pq_welcome)
            };
            inner.pq_turn_mine = true;
            inner.pending_pq_outbound = Some(frame);
            // Our send-PQ half now exists (Group_B.pq) — capture its header key so we can
            // open side-band frames the peer seals to it.
            inner.record_pq_header_key()?;
            Ok(())
        })
    }

    /// A.4 initiator completion — join the peer's new PQ group (our key package's
    /// private material is retained in this client) and register its APQ-PSK.
    /// PQ-groups-only, like the responder side: no classical commit is applied here.
    /// The turn passes to the peer.
    pub fn pq_bootstrap_apply(&self, bind_msg: Vec<u8>) -> Result<()> {
        // Guard-first (see `pq_ratchet_begin`): confirm our recv-PQ half is not already up and
        // validate the welcome suite before the persist choke point, so a replayed or malformed
        // bootstrap bind is a no-op rather than a full-Checkpoint push.
        let pq_welcome = {
            let inner = self.lock();
            let bind_msg = inner.open_or_raw(bind_msg);
            let pq_welcome = decode_bootstrap_bind(&bind_msg)?;
            // Validate the peer's PQ welcome suite before joining — an early, clear
            // CipherSuiteMismatch rather than a late opaque mls-rs error (matches the
            // establishment welcome path).
            check_welcome_suite(&pq_welcome, inner.suite.pq)?;
            // Our recv-PQ half must not already be up (checked last, matching the original body
            // order); the guard-first position prevents a full-Checkpoint push on a replay.
            if inner
                .recv_group
                .as_ref()
                .map(|g| g.pq.is_some())
                .unwrap_or(false)
            {
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
                recv.set_pq(pq, client.combiner());
            }
            inner.pq_turn_mine = false;
            Ok(())
        })
    }
}
