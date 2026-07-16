//! Message path and frame sealing: rendezvous + header-key derivations, the
//! header seal/open helpers, the send-PSK ledger upkeep, the classical
//! ratchet commit (prepare_ratchet_commit), and the public
//! encrypt / open_incoming / process_incoming surface with its proposal /
//! rotation entry points.

use super::*;

// Rendezvous derivation, shared with the classical backend so both stacks address
// transport channels the same way: exportSecret(label, context, 32) on a group's
// classical half. Both members of a group derive identical values; outsiders cannot.
pub(in crate::session) const RENDEZVOUS_LABEL: &[u8] = b"rendezvous";
pub(in crate::session) const RENDEZVOUS_CONTEXT: &[u8] = b"TwoMLS";
pub(in crate::session) const RENDEZVOUS_LEN: usize = 32;

/// The rendezvous exporter both routing surfaces derive:
/// `exportSecret("rendezvous", "TwoMLS", 32)` on a group's classical (message) half.
/// Listen-side and post-side addresses align because they are this one derivation.
pub(in crate::session) fn rendezvous_secret(
    group: &crate::key_package_store::MlsGroup,
) -> Result<Vec<u8>> {
    group
        .export_secret(RENDEZVOUS_LABEL, RENDEZVOUS_CONTEXT, RENDEZVOUS_LEN)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

// Header encryption: the outer symmetric seal that turns every rendezvous-channel frame
// into one opaque blob (no plaintext tag, group id, epoch, or Welcome metadata). The key
// is an exporter of a group's half under a label distinct from the rendezvous and PSK
// exporters, so the derivations never collide. Both parties compute the same key on the
// same group at the same epoch; outsiders cannot.
//
// Two key families, one per stream, so each header key tracks the clock of the frames it
// protects (the classical and PQ ratchets run on independent, async cadences):
//   * message-path frames (0x01/0x03) seal under the CLASSICAL half's exporter, keyed by
//     the classical epoch — `header_key` / `recv_header_keys`;
//   * PQ side-band frames (0x13–0x1D) seal under the PQ half's exporter, keyed by
//     `pq_epoch` — `header_key_pq` / `recv_header_keys_pq`.
// The one exception is the pre-A.4 BOOTSTRAP_KP, whose recv-PQ group does not exist yet;
// it falls back to the classical seal (see `SessionInner::seal_side_band`).
//
// The two families only choose which group HALF derives the key; the AEAD that consumes
// it is a single configured choice (`providers::HEADER_AEAD_SUITE`), independent of the
// group suites, and the key length is that AEAD's key size (`header_key_len`) — so the
// header seal is crypto-agile as its own layer.
pub(in crate::session) const HEADER_KEY_LABEL: &[u8] = b"germ.network.twomlspq.headerKey.v1";
pub(in crate::session) const HEADER_KEY_PQ_LABEL: &[u8] = b"germ.network.twomlspq.headerKey.pq.v1";
/// Exporter label for the A.3 CT-seal PSK — the epoch-bound secret that keys the seal over
/// the round's injected secret (see `apq::pq_ratchet::seal_injected_secret`). The plain
/// REPEATABLE exporter, deliberately not `SafeExport`: both parties derive it independently
/// and a stale ciphertext must be able to fail its open without a one-shot leaf it could
/// otherwise burn. Its own label keeps it disjoint from the header-key exports above.
pub(in crate::session) const CT_SEAL_PSK_LABEL: &[u8] = b"germ.network.twomlspq.a3.ctSeal.psk.v1";
// PQ header window depth: the side-band is turn-based with one op in flight, so `pq_epoch`
// advances slowly; a few recent keys cover any lag. Session-owned secrets, so this is a
// plain "keep newest N", not tied to mls-rs retention or the (classical-only) rendezvous.
pub(in crate::session) const PQ_HEADER_WINDOW: usize = 4;

/// The header key length: the key size of the configured header AEAD
/// (`providers::HEADER_AEAD_SUITE`), so the exporter output always matches whatever cipher
/// seals the frame — no hardcoded assumption of a 32-byte (ChaCha) key.
pub(in crate::session) fn header_key_len() -> Result<usize> {
    use mls_rs::CipherSuiteProvider;
    Ok(providers::header_aead_suite()?.aead_key_size())
}

/// Derive the message-path header key for a group at its current classical epoch:
/// `exportSecret(label, group_id, header_key_len())` on the classical half. Context = the
/// group id (domain separation on top of the group-specific exporter, matching the
/// classical stack's convention).
pub(in crate::session) fn header_key(
    group: &crate::key_package_store::MlsGroup,
) -> Result<Vec<u8>> {
    group
        .export_secret(HEADER_KEY_LABEL, group.group_id(), header_key_len()?)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

/// Derive the PQ side-band header key for a group at its current `pq_epoch`:
/// `exportSecret(pq_label, group_id, header_key_len())` on the PQ half. Same exporter shape
/// as `header_key` (both halves are `Group<_>`), a distinct label, and keyed by the PQ
/// clock so the side-band's outer seal rotates with the PQ ratchet, not classical traffic.
pub(in crate::session) fn header_key_pq(
    group: &crate::key_package_store::PqMlsGroup,
) -> Result<Vec<u8>> {
    group
        .export_secret(HEADER_KEY_PQ_LABEL, group.group_id(), header_key_len()?)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

/// The A.3 CT-seal PSK for `group` at its CURRENT epoch: the repeatable exporter under
/// [`CT_SEAL_PSK_LABEL`]. Both parties call this on their own copy of the group the round's
/// secret is injected into (the initiator's send-PQ / the responder's recv-PQ mirror) — same
/// group, same epoch, same value — and each round is at a distinct epoch, so the PSK is the
/// round nonce with no state to track.
pub(in crate::session) fn ct_seal_psk(
    group: &crate::key_package_store::PqMlsGroup,
) -> Result<Vec<u8>> {
    group
        .export_secret(CT_SEAL_PSK_LABEL, group.group_id(), 32)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

impl SessionInner {
    /// Capture the send group's classical-half rendezvous exporter at its current epoch.
    /// Idempotent per epoch. Called wherever that epoch can advance — group creation,
    /// the A.2/rotation commits in `prepare_to_encrypt`, the A.3 bind — and from
    /// `should_listen_on` as a backstop.
    ///
    /// The listen window follows mls-rs's own epoch retention rather than a second,
    /// invented knob: on each new epoch the group is flushed (`write_to_storage`,
    /// which applies mls-rs's `max_epoch_retention` trim) and addresses whose epoch
    /// the injected group-state storage no longer retains are dropped with it.
    pub(in crate::session) fn record_listen_rendezvous(&mut self) -> Result<()> {
        let Some(send) = self.send_group.as_mut() else {
            return Ok(());
        };
        let group = send.message_group();
        let epoch = group.current_epoch();
        if self.listen_rendezvous.contains_key(&epoch) {
            return Ok(());
        }
        let secret = rendezvous_secret(group)?;
        // The header receive key for this epoch is captured in lockstep with the listen
        // address: both are send-group exporters only derivable while this epoch is live,
        // and retaining them together keeps "routable ⟺ openable" exact.
        let header = header_key(group)?;
        self.listen_rendezvous.insert(epoch, secret);
        self.recv_header_keys.insert(epoch, header);

        send.message_group_mut()
            .write_to_storage()
            .map_err(|_| TwoMlsPqError::Mls)?;
        let group_id = send.message_group().group_id().to_vec();
        // Probe the storage captured at session construction — the one the send group
        // actually flushes into. NOT `self.client`'s: after a Phase 8 rotation that is
        // the new principal's client with a fresh, empty storage, and probing it would
        // prune every prior epoch's listen address (dropping in-flight traffic).
        let storage = &self.send_group_storage;
        let retain = |e: u64| e == epoch || matches!(storage.epoch(&group_id, e), Ok(Some(_)));
        self.listen_rendezvous.retain(|&e, _| retain(e));
        self.recv_header_keys.retain(|&e, _| retain(e));
        Ok(())
    }

    /// Capture my send-PQ group's header key at its current `pq_epoch` into the PQ
    /// receive window. Idempotent per `pq_epoch`; a no-op until the send-PQ half exists
    /// (deferred on the acceptor until the A.4 bootstrap). Called wherever the send-PQ
    /// group is created or its `pq_epoch` advances — group creation (`initiate`,
    /// `pq_bootstrap_respond`), the A.3 bind (`pq_ratchet_bind`), and the A.5 commits
    /// (`pq_rekey_respond` / `pq_rekey_apply`). Retention is a plain keep-newest window
    /// (these are session-owned secrets; the PQ side-band has no rendezvous and no
    /// mls-rs-retention story to follow).
    pub(in crate::session) fn record_pq_header_key(&mut self) -> Result<()> {
        let Some(send) = self.send_group.as_ref() else {
            return Ok(());
        };
        let Some(send_pq) = send.pq.as_ref() else {
            return Ok(());
        };
        let epoch = send_pq.current_epoch();
        if self.recv_header_keys_pq.contains_key(&epoch) {
            return Ok(());
        }
        self.recv_header_keys_pq
            .insert(epoch, header_key_pq(send_pq)?);
        // Keep only the newest PQ_HEADER_WINDOW epochs.
        while self.recv_header_keys_pq.len() > PQ_HEADER_WINDOW {
            if let Some(&oldest) = self.recv_header_keys_pq.keys().next() {
                self.recv_header_keys_pq.remove(&oldest);
            }
        }
        Ok(())
    }

    /// Seal an outbound frame under the header key of MY recv group (the peer's send
    /// group) at its current classical epoch: `[random nonce][AEAD ct+tag]`, empty AAD.
    /// The peer opens it from its own send-group window (`recv_header_keys`). Requires a
    /// recv group — the one pre-establishment frame (the initiator's initial welcome on
    /// the invitation channel) has no symmetric key and is not sealed here.
    pub(in crate::session) fn seal(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let recv = self
            .recv_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?;
        self.seal_with(&header_key(&recv.classical)?, frame)
    }

    /// Seal a PQ side-band frame under the PQ family — `header_key_pq(recv_group.pq)` at
    /// its current `pq_epoch`, the peer opening it from its own send-PQ window. Falls back
    /// to the classical `seal` when the recv-PQ group does not exist yet: the only such
    /// frame is the pre-A.4 `BOOTSTRAP_KP` (its recv-PQ is the group the bootstrap is
    /// creating), a one-time establishment frame whose cadence is irrelevant, and the
    /// receiver opens it from its classical window via the dual-window `try_open`.
    pub(in crate::session) fn seal_side_band(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let recv = self
            .recv_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotEstablished)?;
        match recv.pq.as_ref() {
            Some(pq) => self.seal_with(&header_key_pq(pq)?, frame),
            None => self.seal(frame),
        }
    }

    /// Seal `frame` under `key`: `[random nonce][AEAD ct+tag]`, empty AAD.
    pub(in crate::session) fn seal_with(&self, key: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
        use mls_rs::CipherSuiteProvider;
        let cs = providers::header_aead_suite()?;
        let mut out = vec![0u8; cs.aead_nonce_size()];
        cs.random_bytes(&mut out).map_err(|_| TwoMlsPqError::Mls)?;
        let ct = cs
            .aead_seal(key, frame, None, &out)
            .map_err(|_| TwoMlsPqError::Mls)?;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Remove the header seal if this window can, else return the blob unchanged. Lets the
    /// receive entry points (`process_incoming`, the `pq_*` receivers) accept either the
    /// sealed blob straight off the wire OR the already-opened `frame` a host took from
    /// `open_incoming` — an honestly-sealed frame always opens, an already-plaintext frame
    /// fails AEAD auth under every key and passes through. (This is a receiver convenience;
    /// the metadata-hiding property is a sender guarantee — every outbound frame is sealed
    /// — so accepting an opened frame here downgrades nothing an observer can see. The
    /// initiator's unsealed initial welcome passes through the same way.)
    pub(in crate::session) fn open_or_raw(&self, blob: Vec<u8>) -> Vec<u8> {
        match self.try_open(&blob) {
            Ok(Some(pt)) => pt,
            _ => blob,
        }
    }

    /// Trial-decrypt an inbound blob against the header receive window, newest epoch
    /// first (the common case is the newest or second-newest key). `None` if no window
    /// key opens it — an out-of-window or garbage frame, indistinguishable by
    /// construction. Every candidate key is an honestly-derived secret, so trial
    /// decryption with a non-committing AEAD is safe here (no attacker-chosen keys, so no
    /// partitioning oracle).
    pub(in crate::session) fn try_open(&self, blob: &[u8]) -> Result<Option<Vec<u8>>> {
        use mls_rs::CipherSuiteProvider;
        let cs = providers::header_aead_suite()?;
        let nonce_size = cs.aead_nonce_size();
        if blob.len() < nonce_size {
            return Ok(None);
        }
        let (nonce, ct) = blob.split_at(nonce_size);
        // Both families use the same AEAD; only the key set differs. A message frame
        // authenticates only under a classical-window key and a side-band frame only
        // under a PQ-window key (the pre-A.4 BOOTSTRAP_KP under classical), so trying
        // both windows resolves either without ambiguity. Newest epoch first in each.
        let windows = [&self.recv_header_keys, &self.recv_header_keys_pq];
        for keys in windows {
            for key in keys.values().rev() {
                if let Ok(pt) = cs.aead_open(key, ct, None, nonce) {
                    return Ok(Some(pt.to_vec()));
                }
            }
        }
        Ok(None)
    }

    /// Record the cross-party TwoMLS-PSK for our send group's current epoch in the
    /// session-owned ledger. Called after every commit we apply on the send group (and
    /// lazily from `inject_send_psks`), so the ledger always covers the epochs the peer
    /// might still reference.
    pub(in crate::session) fn remember_send_psk(&mut self) -> Result<()> {
        let epoch = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .classical
            .current_epoch();
        // The -02 exporter tree consumes each component's leaf on first export, so a
        // given (send group, epoch) can be exported at most once: skip if this epoch is
        // already ledgered (this is called repeatedly per epoch, e.g. from every
        // `inject_send_psks`, and — after an archive/restore — for an epoch already
        // consumed and carried in the restored ledger).
        if self.send_psk_ledger.iter().any(|(e, _)| *e == epoch) {
            return Ok(());
        }
        let send = self
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let exported = export_psk(&mut send.classical, PskDomain::CrossParty)?;
        self.send_psk_ledger.push_back((epoch, exported));
        while self.send_psk_ledger.len() > SEND_PSK_WINDOW {
            if let Some((_, evicted)) = self.send_psk_ledger.pop_front() {
                self.retired_send_psks.push(evicted.storage_id().clone());
            }
        }
        Ok(())
    }

    /// Live-inject the session's PSK ledger, immediately before processing a frame whose
    /// commit may reference one of these PSKs. Injection targets the stores each live
    /// group actually resolves from (captured at the group's creation — the current
    /// client's stores are the wrong target after a principal rotation), plus the current
    /// client's stores for joins that are about to create a group. Retired ids are then
    /// deleted from the same targets, so the stores' contents stay bounded by the ledger
    /// and nothing remains resolvable that the session no longer vouches for.
    pub(in crate::session) fn inject_send_psks(&mut self) -> Result<()> {
        self.remember_send_psk()?;
        for (_, exported) in &self.send_psk_ledger {
            let (psk_id, psk) = (exported.storage_id(), exported.psk());
            register_psk(self.client.combiner(), psk_id, psk);
            if let Some(recv) = &self.recv_group {
                recv.register_psk(psk_id, psk);
            }
            if let Some(send) = &self.send_group {
                send.register_psk(psk_id, psk);
            }
        }
        for psk_id in self.retired_send_psks.drain(..) {
            forget_psk(self.client.combiner(), &psk_id);
            if let Some(recv) = &self.recv_group {
                recv.forget_psk(&psk_id);
            }
            if let Some(send) = &self.send_group {
                send.forget_psk(&psk_id);
            }
        }
        Ok(())
    }

    /// Validate that `proposal_bytes` is the peer's own-leaf Update carrying credential
    /// `proposing`, leaving the send group's proposal cache **untouched**. Only
    /// `process_incoming_message` authenticates the sender's signature and leaf, and it
    /// caches the proposal — so process to validate, then immediately `clear_proposal_cache`.
    /// This mutates no session state (the caller records the approval only on `Ok`), so a
    /// rejected `queue_proposal` is a pure no-op and there is nothing cached to poison the
    /// next commit; the approved proposal is re-applied to the group at commit time.
    /// The evidence-gating license: has the peer applied our send group's CURRENT epoch?
    ///
    /// True exactly when [`SessionInner::peer_applied_send_epoch`] has caught up to our send
    /// group — i.e. the peer has produced a proposal bound to the epoch we are sitting at, so
    /// nothing of ours is outstanding and a further commit cannot leave it more than one
    /// behind. The watermark can never exceed our own epoch (the peer cannot apply a commit we
    /// never made), so this is an equality test written as `>=` for its own safety.
    ///
    /// A fold does not consult this — see `prepare_ratchet_commit`.
    fn peer_applied_our_send_epoch(&self) -> Result<bool> {
        let send_epoch = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?
            .classical
            .current_epoch();
        Ok(self
            .peer_applied_send_epoch
            .is_some_and(|applied| applied >= send_epoch))
    }

    pub(in crate::session) fn validate_offered_update(
        &mut self,
        proposal_bytes: &[u8],
        proposing: &[u8],
    ) -> Result<()> {
        let msg = MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let send = self
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let my_index = send.classical.current_member_index();
        let processed = send.classical.process_incoming_message(msg);
        send.classical.clear_proposal_cache();
        let desc = match processed.map_err(map_credential_err)? {
            ReceivedMessage::Proposal(desc) => desc,
            _ => return Err(TwoMlsPqError::Mls),
        };
        require_peer_update(&desc, my_index)?;
        let leaf_id = match &desc.proposal {
            Proposal::Update(update) => match &update.signing_identity().credential {
                mls_rs::identity::Credential::Basic(basic) => basic.identifier.as_slice(),
                _ => return Err(TwoMlsPqError::ProposalRejected),
            },
            _ => return Err(TwoMlsPqError::ProposalRejected),
        };
        if leaf_id != proposing {
            return Err(TwoMlsPqError::ProposalRejected);
        }
        Ok(())
    }

    /// §A.1 pre-establishment round (initiated side, recv group absent): a NO-OP
    /// prepare — there is no recv group to stage an `Upd(self)` into and nothing to
    /// fold, exactly like a round right after one's own commit with nothing queued.
    /// Stages only the app-message AAD — `sha256(welcome)`, binding each
    /// pre-establishment app message to its establishment vector — and leaves
    /// `pending_proposal_message` empty, the marker the paired `encrypt` branches on
    /// to produce a §A.1 envelope instead of a 0x03 frame. `selected` cannot ride
    /// (no recv group carries an Upd) → `SessionNotReady`. Carve-out on the
    /// `PrepareEncryptResult` contract: here `proposal_message` is EMPTY and
    /// `proposal_hash` is the welcome digest, not sha256(proposal_message).
    pub(in crate::session) fn prepare_pre_establishment(
        &mut self,
        selected: Option<ClientId>,
    ) -> Result<crate::PrepareEncryptResult> {
        if selected.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // The paired encrypt must be able to seal (the retained KP′) and staple (the
        // birth welcome) — fail here, at prepare, if either is impossible.
        if self.initial_their_kp.is_none() || self.current_staple.first() != Some(&APQ_TAG) {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let proposal_hash = crate::sha256(&self.current_staple);
        self.pending_proposal_hash = Some(proposal_hash.clone());
        self.pending_proposal_message = None;
        Ok(crate::PrepareEncryptResult {
            proposal_message: Vec::new(),
            proposal_hash,
            committed_remote_client_id: None,
            did_commit: false,
        })
    }

    /// Routine round (A.2): commit in OUR OWN send group — only the owner commits — and
    /// stage an Upd(self) proposal for the peer's send group to staple alongside. With an
    /// app-approved queued proposal (already cached in the send group via `queue_proposal`),
    /// the commit consumes it and additionally refreshes the cross-party TwoMLS-PSK
    /// exported from the recv group (the peer derives the same PSK from its send group).
    /// `selected` names the staged rotation candidate whose credential this round's
    /// Upd(self) proposes (`prepare_to_encrypt(Some(id))`); `None` re-proposes the
    /// session's current identity. Different rounds may select different candidates —
    /// the peer's commit picks the winner.
    pub(in crate::session) fn prepare_ratchet_commit(
        &mut self,
        selected: Option<ClientId>,
    ) -> Result<crate::PrepareEncryptResult> {
        let folded = self.queued_proposal.take();
        // Two reasons to commit, and both are gated on the peer having applied our previous
        // commit — the evidence-gating license (book: Protocol Flows). One commit outstanding
        // at a time is what makes any single frame heal the peer, and what keeps a bind's
        // staple alive until it lands.
        //
        // 1. A FOLD, when the app approved the peer's Upd. Needs no license check: the offer
        //    is epoch-bound and `validate_offered_update` refused it against the live send
        //    group if it were stale, so holding it IS the evidence. Preferred when available
        //    — it refreshes BOTH leaves where an empty commit refreshes only ours.
        // 2. An owed BIND to discharge, license permitting. This is the case the fold cannot
        //    serve: rule 3 makes the bind wait for a classical commit, so an app that never
        //    approves would strand the PQ round at 2/1 forever — PQ liveness must not depend
        //    on app approval policy. RFC 9420 forces an updatePath onto a proposal-less
        //    commit, so the discharge still delivers both PCS sources (a fresh own leaf, plus
        //    the `apq_psk` chaining the PQ half's entropy in); it simply leaves the peer's
        //    leaf where it was — which is where it was staying regardless, precisely because
        //    the app did not approve the Upd that would have moved it.
        //
        // Only these two. A commit on cadence, whenever licensed, is deliberately NOT
        // offered: our commit invalidates whatever offer is in flight, so committing every
        // licensed round would kill each offer inside the window the peer's app has to
        // approve it — starving rotation (approval IS the AS authorization) for any host
        // that deliberates across a round trip. The bind's discharge bounds that churn to
        // the PQ cadence, which the host already chooses.
        let licensed = self.peer_applied_our_send_epoch()?;
        let did_commit = folded.is_some() || (self.owed_bind.is_some() && licensed);

        if did_commit {
            // Capture the departing epoch's PSK before committing past it: a peer frame in
            // flight may reference it, and mls-rs can only export the current epoch.
            self.remember_send_psk()?;

            // Cross-party TwoMLS-PSK from our recv group — but only when the peer's send
            // group has advanced since we last bound it (event-driven; see
            // `last_cross_injected`). If it is unchanged, the entanglement from our previous
            // injection still holds and re-deriving would consume the same exporter leaf for
            // no new entropy, so this commit carries no cross-party PSK (it still folds the
            // peer's Upd and refreshes our own leaf via the updatePath). The durable copy is
            // the peer's problem (it is THEIR send-group PSK, held in their ledger); we
            // derive and live-inject into the send group's stores just before the commit.
            let recv_epoch = self
                .recv_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .classical
                .current_epoch();
            let cross_psk = if self.last_cross_injected == Some(recv_epoch) {
                None
            } else {
                let recv = self
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let exported = export_psk(&mut recv.classical, PskDomain::CrossParty)?;
                let send = self
                    .send_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.register_psk(exported.storage_id(), exported.psk());
                // Advance the watermark now — deliberately BEFORE the build/apply below,
                // not after. `export_psk` has already consumed the recv exporter leaf, and
                // that consumption is irreversible (once per epoch, for FS). So this is not
                // a "commit succeeded" flag; it records "this leaf is spent." If build/apply
                // then fails, no commit reaches the peer (no divergence), and a retry at this
                // same `recv_epoch` MUST take the skip branch above — a second export of the
                // spent leaf would error. The prior binding's entanglement still holds and the
                // next peer advance re-triggers a fresh injection. The only observable cost of
                // a mid-commit failure is that this one recv-epoch's re-binding is skipped and
                // the folded peer proposal is dropped (the peer re-proposes on its next
                // advance) — both self-healing, neither a security property.
                self.last_cross_injected = Some(recv_epoch);
                Some(exported)
            };
            // Own-leaf catch-up: when the session's canonical identity has moved past
            // this send group's creator leaf (the peer's commit of our proposal is the
            // canonical step; our own groups lag), this commit's updatePath moves the
            // leaf to the current identity. A commit folding an Update always carries
            // a path (RFC 9420), so the handoff cannot be silently dropped.
            let current_id = self.client.client_id();
            let handoff = {
                let send = self
                    .send_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let mine = send.classical.current_member_index();
                if sender_client_id(&send.classical, mine)? != current_id.bytes {
                    let (signer, public) = self.client.combiner().classical_signature_keypair();
                    let identity = SigningIdentity::new(
                        BasicCredential::new(current_id.bytes.clone()).into_credential(),
                        public,
                    );
                    Some((signer, identity))
                } else {
                    None
                }
            };
            // Re-apply the one approved peer proposal (validated and un-cached at
            // `queue_proposal`), so the commit folds exactly it — build immediately, so
            // only ever one Update is cached at build time.
            if let Some((_, _, proposal_bytes)) = &folded {
                let msg = MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
                let send = self
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.classical
                    .process_incoming_message(msg)
                    .map_err(map_credential_err)?;
            }
            // From here the round turns destructive when a bind is owed: the discharge
            // consumes the reservation and spends the exporter leaf, and NO failure past
            // that point is recoverable — `mutate_and_persist` persists the half-committed
            // state even on Err, the leaf cannot be re-derived, and the peer waits in its
            // responded state for a staple that can never be rebuilt. None of it is
            // reachable from an honest flow (everything folded or handed off here was
            // validated when it was accepted), so a failure means an internal bug — and it
            // must wear a FATAL name, not the retriable error it would otherwise surface
            // as. The window is structural (one helper, one mapping) so a fallible line
            // added to the tail cannot silently escape it.
            let discharging = self.owed_bind.is_some();
            self.discharge_and_commit(&folded, &cross_psk, handoff)
                .map_err(|e| {
                    if discharging {
                        TwoMlsPqError::BindDischargeFailed
                    } else {
                        e
                    }
                })?;
        }

        // Upd(self) into the peer's send group — a proposal only; the peer commits it.
        // The proposal carries an identity: a selected staged candidate (the app's
        // offer for its next credential), or the session's current identity whenever
        // the recv-group leaf still lags it (converging e.g. the dedicated
        // establishment principal into the founding leaf); otherwise a plain key
        // refresh of the unchanged leaf.
        // Steer a deferred rotation onto this round: when the app did not explicitly
        // select a candidate and a slot has freed (a prior canonicalization cleared the
        // pool), promote the parked request — mint, admit, authorize — and propose it
        // this round in place of the default self-refresh.
        let selected = match selected {
            Some(id) => Some(id),
            None if self.staged_candidates.len() < CANDIDATE_WINDOW => {
                match self.deferred_candidate.take() {
                    Some(id) => {
                        let candidate = TwoMlsPqPrincipal::new(id.clone())?;
                        candidate.combiner().auth_view().rebind(&self.auth_core);
                        self.with_auth(|core| core.mine.authorize(id.clone()));
                        self.staged_candidates.push(candidate);
                        // A rotation to this candidate is now in flight (proposed this
                        // round, awaiting the peer's commit) — report it as `Pending`.
                        // A prior canonicalization set `Sync` when it committed an
                        // earlier candidate; without this, the promoted rotation would
                        // be invisible in `my_principal_state`.
                        self.my_state = PrincipalState::Pending {
                            old: self.client.client_id(),
                            new: ClientId { bytes: id.clone() },
                        };
                        Some(ClientId { bytes: id })
                    }
                    None => None,
                }
            }
            None => None,
        };
        let proposing_client = match &selected {
            Some(id) => Some(Arc::clone(
                self.staged_candidates
                    .iter()
                    .find(|c| c.client_id() == *id)
                    .ok_or(TwoMlsPqError::SessionNotReady)?,
            )),
            None => None,
        };
        let proposal_msg = {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let leaf_id = {
                let mine = recv.classical.current_member_index();
                sender_client_id(&recv.classical, mine)?
            };
            let identity_source = match &proposing_client {
                Some(candidate) => Some(Arc::clone(candidate)),
                None if leaf_id != self.client.client_id().bytes => Some(Arc::clone(&self.client)),
                None => None,
            };
            match identity_source {
                Some(source) => {
                    let (signer, public) = source.combiner().classical_signature_keypair();
                    let identity = SigningIdentity::new(
                        BasicCredential::new(source.client_id().bytes).into_credential(),
                        public,
                    );
                    recv.classical
                        .propose_update_with_identity(signer, identity, Vec::new())
                        .map_err(map_credential_err)?
                }
                None => recv
                    .classical
                    .propose_update(Vec::new())
                    .map_err(|_| TwoMlsPqError::Mls)?,
            }
        };
        let proposing = proposing_client
            .map(|c| c.client_id().bytes)
            .unwrap_or_else(|| self.client.client_id().bytes);
        let proposal_bytes = proposal_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
        // The binding value is the SHA-256 of the staged Upd(self) proposal — the same
        // value the receiver reports as `QueuedRemoteProposal.digest`, and the classical
        // backend's convention. `encrypt` carries it as the app message's authenticated
        // data, so the staple is verifiable against the frame it rides in.
        let proposal_hash = crate::sha256(&proposal_bytes);
        self.pending_proposal_message = Some((proposing, proposal_bytes.clone()));

        let their_id = self.their_state.client_id();
        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_message: proposal_bytes,
            proposal_hash,
            // What this commit CANONICALIZED of the peer's credential sequence — so it keys
            // off the fold, not off `did_commit`. The two were the same thing while a fold
            // was the only way to commit; a discharge riding a proposal-less commit
            // canonicalizes nothing of theirs, and reporting their unchanged id here would
            // be a canonicalization event a host could act on where none occurred.
            committed_remote_client_id: folded.as_ref().map(|_| their_id),
            did_commit,
        })
    }

    /// The destructive tail of a committing round: discharge any owed bind, build and
    /// apply the commit, canonicalize the folded credential, and set the staple. One
    /// helper so `prepare_ratchet_commit` can map ANY failure in it to the fatal
    /// [`TwoMlsPqError::BindDischargeFailed`] when a bind was being discharged — the
    /// window in which failure permanently strands the round (reservation consumed,
    /// exporter leaf spent, state persisted even on Err). Structural on purpose: a
    /// fallible line added here is inside the mapping by construction.
    fn discharge_and_commit(
        &mut self,
        folded: &Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
        cross_psk: &Option<apq::ExportedPsk>,
        handoff: Option<(mls_rs::crypto::SignatureSecretKey, SigningIdentity)>,
    ) -> Result<()> {
        // THIS is the commit an owed bind has been waiting for — rule 3: the next classical
        // COMMIT is the bind. Discharging here rather than at any send is what makes the
        // reserved `t_epoch` true, because nothing else may take this epoch. `None` on the
        // overwhelmingly common round, where no bind is owed.
        //
        // It spends the reserved PQ epoch's exporter leaf, so it must run exactly once per
        // owed bind, and only on a round that genuinely commits.
        let owed = self.discharge_owed_bind()?;
        let commit_output = {
            let send = self
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let mut builder = send.classical.commit_builder();
            if let Some(psk) = cross_psk {
                builder = psk.add_to_commit(builder)?;
            }
            // The bind's classical half: `apq_psk` chains the PQ entropy in, and the
            // attestation rides as the -02 AppDataUpdate — the same one already on the PQ
            // commit, which is what makes the two a single FULL commit.
            if let Some((_, apq_psk, attestation)) = &owed {
                builder = builder.custom_proposal(attestation.to_custom_proposal()?);
                builder = apq_psk.add_to_commit(builder)?;
            }
            if let Some((signer, identity)) = handoff {
                builder = builder.set_new_signing_identity(signer, identity);
            }
            builder.build().map_err(map_credential_err)?
        };
        {
            let send = self
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            send.classical
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
            // This commit folds the app-approved peer proposal from the cache: if
            // the peer smuggled anything but an Update there (an Add would grow the
            // roster through OUR commit), reject the result.
            apq::ensure_two_party(&send.classical)?;
            // The commit consumed the one-shot recv-group PSK (when one rode it); drop
            // it from the store.
            if let Some(psk) = cross_psk {
                send.forget_psk(psk.storage_id());
            }
            // Same for the bind's one-shot apq PSK, which this commit has now consumed.
            if let Some((_, apq_psk, _)) = &owed {
                send.forget_psk(apq_psk.storage_id());
            }
        }
        if let Some((_, apq_psk, _)) = &owed {
            apq::forget_psk_stores(&self.psk_stores, apq_psk.storage_id());
        }
        // OUR commit of the peer's approved Upd is the canonical step of THEIR
        // credential sequence: the committed credential defines their next identity.
        if let Some((_, proposing, _)) = folded {
            if *proposing != self.their_state.client_id().bytes {
                self.with_auth(|core| core.theirs.commit(proposing.clone()));
                self.their_state = PrincipalState::Sync {
                    client_id: ClientId {
                        bytes: proposing.clone(),
                    },
                };
            }
        }
        // Our send group advanced: record the new epoch's PSK in the session ledger.
        self.remember_send_psk()?;
        // The new commit becomes the staple every frame re-sends until superseded.
        let cl_commit = commit_output
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        self.current_staple = match &owed {
            // A bind discharged into this commit, so the staple is the draft-02 §7
            // APQPrivateMessage carrying BOTH halves. The PQ commit has to travel with its
            // classical partner and nowhere else: the peer cannot apply the classical half
            // without the `apq_psk` only the PQ half supplies, so a staple carrying one
            // alone is unusable. Riding the staple is also what heals a lost bind — it
            // re-sends on every frame until superseded, for free.
            Some((pq_commit, _, _)) => {
                apq::encode_apq_private_message(cl_commit, pq_commit.clone())
            }
            None => cl_commit,
        };
        // This commit publishes new leaf keys; the push about to persist it lands at the
        // (already-bumped) current `state_seq`, so tag the staple with it for `depends_on_seq`.
        self.current_staple_seq = self.state_seq;
        // This fold advanced our send epoch, so any still-unapproved offer is now
        // bound to the prior epoch — drop it (the queued one was consumed by the
        // caller's `take`). Mirrors the A.3 bind's clear; the peer re-proposes at the
        // new epoch once it sees this commit's staple.
        self.offered_proposal = None;
        Ok(())
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Prepare a pending proposal nonce and stage it for binding into the next outbound message.
    ///
    /// - `proposing: None` with a queued remote proposal → folding commit — folds the approved Upd (epoch advance + PSK refresh), `did_commit: true`
    /// - `proposing: Some(new_id)` → rotation commit with new leaf credential, `did_commit: true`
    /// - Otherwise → recv self-Update only, `did_commit: false`
    /// - Pre-establishment (initiated side, recv group absent) → a NO-OP prepare
    ///   (§A.1: the initiator sends app messages immediately, before the acceptor's
    ///   return welcome): nothing is staged (`proposal_message` empty; `proposal_hash`
    ///   is the WELCOME digest, the AAD binding each pre-establishment message to its
    ///   establishment vector), and the paired `encrypt` emits a §A.1 envelope
    ///   re-stapling the welcome. `proposing: Some` here → `SessionNotReady`.
    pub fn prepare_to_encrypt(&self, proposing: Option<ClientId>) -> Result<PrepareEncryptResult> {
        self.mutate_and_persist(crate::BlobKind::Core, |inner| {
            let result = if inner.recv_group.is_none() {
                inner.prepare_pre_establishment(proposing)?
            } else {
                inner.prepare_ratchet_commit(proposing)?
            };
            // A committing round advanced the send group's classical epoch — capture
            // the new epoch's listen address.
            inner.record_listen_rendezvous()?;
            Ok(result)
        })
    }

    /// Encrypt `app_message` using the PQ send group.
    /// Must be called after `prepare_to_encrypt`; the pending proposal hash is used as
    /// authenticated data and cleared on return.
    ///
    /// Post-establishment, the output is one message frame `[staple][proposal][app]`:
    /// the staple (our latest send-group commit, or our APQWelcome until the first
    /// commit) rides every frame, so a peer that missed a frame is healed by the next
    /// one. Pre-establishment (initiated side, no recv group — the marker is the empty
    /// staged-proposal slot a `prepare_pre_establishment` left), the output is instead
    /// a fresh §A.1 envelope HPKE-sealed to the peer's KP′, carrying the establishment
    /// sections plus this app message as its `[0x09]` staple — any single frame lets
    /// the invitation holder join and read it. `pending_outbound` is NOT consumed on
    /// either path — the frame itself carries the welcome; the standalone copy stays
    /// available for hosts that also deliver it separately (processing is idempotent).
    pub fn encrypt(&self, app_message: Vec<u8>) -> Result<EncryptResult> {
        self.mutate_and_persist(crate::BlobKind::Core, |inner| {
            let proposal_hash = inner
                .pending_proposal_hash
                .take()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            // Take the staged proposal BEFORE advancing the sender ratchet: an empty
            // slot is either the pre-establishment marker (valid only while the recv
            // group is still absent) or a prepare gone stale across the establishment
            // cutover — reject the stale case without burning a message generation.
            let staged = inner.pending_proposal_message.take();
            if staged.is_none() && inner.recv_group.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }

            let (app_bytes, epochs) = {
                let send = inner
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;

                let cipher_msg = send
                    .message_group_mut()
                    .encrypt_application_message(&app_message, proposal_hash)
                    .map_err(|_| TwoMlsPqError::Mls)?;

                let epochs = apq_epochs(send);
                let bytes = cipher_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
                (bytes, epochs)
            };

            let sender = inner.my_state.client_id();
            let recipient = inner.their_state.client_id();

            let cipher_text = match staged {
                Some((proposing, proposal)) => {
                    // The staple is set at construction — an empty slot means encrypt
                    // was reached outside the prepare contract.
                    if inner.current_staple.is_empty() {
                        return Err(TwoMlsPqError::SessionNotReady);
                    }
                    let frame = encode_message_frame(
                        &inner.current_staple,
                        encode_proposal_section(&proposing, &proposal),
                        app_bytes,
                    );
                    // Header encryption: seal the whole frame into one opaque blob
                    // before it leaves the library. This path only runs
                    // post-establishment (the prepare staged into the recv group), so
                    // the seal key is always available.
                    inner.seal(&frame)?
                }
                // Pre-establishment: no symmetric seal key exists — compose a fresh
                // §A.1 envelope (HPKE to the retained KP′) stapling this app message.
                None => inner
                    .compose_initial_envelope(Some(&encode_pre_establishment_app(&app_bytes)))?,
            };

            Ok(EncryptResult {
                cipher_text,
                sender,
                recipient,
                epochs,
                depends_on_seq: inner.current_staple_seq,
            })
        })
    }

    /// Remove the header seal from an inbound rendezvous-channel blob, returning the
    /// plaintext frame and its routing kind, or `None` if no key in the header receive
    /// window opens it (an out-of-window or garbage blob — indistinguishable by
    /// construction, the same "unknown, drop it" signal the reconnect path assigns).
    ///
    /// This is the single entry point for frames that arrive on a rendezvous address. The
    /// host dispatches on `OpenedFrame.kind`: `Message` → `process_incoming(frame)`;
    /// `PqSideBand { kind }` → the `pq_*` method that `kind` names. The old plaintext
    /// entry points keep their signatures and now take the opened `frame`.
    ///
    /// (The initiator's initial welcome does NOT come through here — it arrives on the
    /// invitation channel and goes to `TwoMlsPqInvitation::receive`.)
    ///
    /// Observability: an opened frame whose leading tag is unrecognized is
    /// `DecryptionFailed`, but a blob no window key opens is a silent `None`. Desyncs that
    /// mls-rs would once have surfaced loudly can therefore read as `None` here; a host
    /// tracking liveness should treat a run of `None`s on a live session as a reconnect
    /// signal.
    pub fn open_incoming(&self, blob: Vec<u8>) -> Result<Option<OpenedFrame>> {
        let inner = self.lock();
        let Some(frame) = inner.try_open(&blob)? else {
            return Ok(None);
        };
        let kind = frame
            .first()
            .copied()
            .and_then(opened_frame_kind)
            .ok_or(TwoMlsPqError::DecryptionFailed)?;
        Ok(Some(OpenedFrame { kind, frame }))
    }

    /// Process an incoming message.
    ///
    /// - APQWelcome (0x01) → join recv groups, idempotently (a re-delivered welcome is a
    ///   no-op); `Ok(None)`
    /// - Message frame (0x03) `[staple][proposal][app]` → apply the staple idempotently
    ///   (join from a welcome staple if this is its first delivery; apply a commit staple
    ///   at the recv group's current epoch, skip an older one), decrypt the app message,
    ///   and stage the stapled Upd(sender) for app approval; `DecryptResult`
    ///
    /// A commit staple *ahead* of the recv group's next epoch is `EpochDesync`: the
    /// bridging commit no longer rides any frame (only the sender's latest staples), so
    /// the direction needs the reconnect path — surfaced before the app ciphertext is
    /// touched, and distinguishable from a transient `DecryptionFailed`.
    ///
    /// PQ side-band frames (0x13–0x1D) are **not** handled here — the host routes them to
    /// the `pq_*` entry points by frame kind (`pq_frame_kind`). Passing one here returns
    /// `SessionNotReady` rather than attempting (and failing) MLS decryption. Anything
    /// else — including bare MLS ciphertext, which no longer occurs on the send path — is
    /// rejected as `DecryptionFailed`.
    pub fn process_incoming(&self, ciphertext: Vec<u8>) -> Result<Option<DecryptResult>> {
        // Snapshot the PQ-half epochs so the persist below can tell a classical-only frame
        // (Core) from one that created or advanced a PQ half. Only `process_welcome`'s
        // full-pair join does the latter today (a peer delivering a non-deferred welcome to
        // a recv-less session); a Core there would omit the new ML-KEM tree, and the next
        // restore would fail the epoch manifest closed. Deriving the kind from what actually
        // changed keeps the blob kind from ever disagreeing with the mutation.
        let pq_before = self.lock().pq_epochs();
        let r = self.process_incoming_inner(ciphertext);
        // Push on success only. A rejected (garbage / mis-routed) frame mutated nothing, and
        // pushing per garbage frame would be a DoS amplifier — a full core encode each; skipping
        // it there is the pure-guard rule. A processed frame (a real message or an idempotent
        // re-delivery) advanced or reaffirmed state, so persist it — as a Checkpoint if it
        // touched a PQ half, else a Core. mls-rs applies commits transactionally, so an `Err`
        // leaves no partial mutation to capture.
        if r.is_ok() {
            let kind = if self.lock().pq_epochs() == pq_before {
                crate::BlobKind::Core
            } else {
                crate::BlobKind::Checkpoint
            };
            self.persist_after(kind);
        }
        r
    }

    fn process_incoming_inner(&self, ciphertext: Vec<u8>) -> Result<Option<DecryptResult>> {
        // Receiving is broken: a prior bind staple failed to apply with its secret already
        // consumed, and the peer re-staples that same unappliable bind on every frame. Refuse
        // up front with the honest, queryable error rather than re-run the doomed apply per
        // frame — restoring from the last persisted state (which predates the failed take)
        // is the recovery. Sending is unaffected; this guards only the receive path.
        if self.lock().bind_apply_broken {
            return Err(TwoMlsPqError::BindApplyFailed);
        }
        // Header encryption: accept either the sealed blob off the wire or the frame a
        // host already took from `open_incoming` (see `open_or_raw`). The initiator's
        // initial welcome (invitation channel, unsealed) passes through untouched.
        let ciphertext = self.lock().open_or_raw(ciphertext);
        // Standalone APQWelcome: the initiator's welcome arrives this way over the
        // invitation channel, and hosts may also deliver the acceptor's return welcome
        // standalone. The same welcome also rides message-frame staples, so processing
        // must be (and is) idempotent — see `process_welcome`.
        if ciphertext.first() == Some(&APQ_TAG) {
            let mut inner = self.lock();
            let prior_their = inner.their_state.client_id();
            inner.process_welcome(&ciphertext)?;
            let adopted_their = inner.their_state.client_id();
            // A first-delivery join that adopts a different peer principal (the peer
            // established under a dedicated per-session principal) must be observable
            // on THIS delivery too, not only on the stapled one — otherwise which
            // signal the app gets would depend on which copy of the welcome arrived
            // first. Re-deliveries and unchanged-principal joins stay `None`.
            if adopted_their != prior_their {
                return Ok(Some(DecryptResult {
                    application_message: None,
                    proposal: None,
                    remote_commit: Some(CommitResult {
                        new_sender: Some(adopted_their),
                        new_recipient: inner.my_state.client_id(),
                    }),
                }));
            }
            return Ok(None);
        }

        // The message frame: the sender's latest send-group staple (commit-or-welcome) +
        // an Upd(sender) proposal addressed to OUR send group + the app message. Apply
        // the staple idempotently, decrypt the app message, and stage the proposal for
        // app approval — it enters our send group only via `queue_proposal`.
        if ciphertext.first() == Some(&MESSAGE_FRAME_TAG) {
            let (staple, proposal_bytes, app_bytes) = decode_message_frame(&ciphertext)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.lock();

            // The staple slot self-discriminates: an APQWelcome starts 0x01, an
            // MLSMessage 0x00. Track whether THIS frame advanced the recv group, and any
            // rotation handoff announced in the commit's authenticated_data.
            let mut staple_applied = false;
            let mut new_sender: Option<ClientId> = None;
            let mut canonicalized_own: Option<Vec<u8>> = None;

            if staple.first() == Some(&APQ_TAG) {
                // Welcome staple: joins on first delivery, skips repeats. The sender
                // re-staples its welcome until its first commit exists, so repeats are
                // the common case, not an anomaly. A first-delivery join adopts the
                // peer's principal from the creator leaf (see `process_welcome`); when
                // the peer established under a dedicated per-session principal, that id
                // differs from the invitation identity we initiated toward — surface it
                // like a rotation handoff so the app observes the change on this frame.
                let prior_their = inner.their_state.client_id();
                inner.process_welcome(&staple)?;
                let adopted_their = inner.their_state.client_id();
                if adopted_their != prior_their {
                    staple_applied = true;
                    new_sender = Some(adopted_their);
                }
            } else if staple.first() == Some(&apq::APQ_PRIVATE_MESSAGE_TAG) {
                // A BIND: the peer's A.3, A.4 or A.5 round closing. The staple is the
                // draft-02 §7 APQPrivateMessage carrying both halves of one FULL commit,
                // because the PQ commit cannot travel apart from its classical partner — we
                // could not apply the classical half without the `apq_psk` only the PQ half
                // supplies.
                //
                // The peer re-staples this on every frame until its next commit supersedes
                // it, so a repeat is the common case, not an anomaly: the epoch ordering (a
                // repeat skips, a gap desyncs) is `staple_epoch_action`, shared with the
                // plain commit arm below so the two cannot drift.
                let (t_message, pq_message) = apq::decode_apq_private_message(&staple)?;
                let t_msg = MlsMessage::from_bytes(&t_message)
                    .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
                match inner.staple_epoch_action(&t_msg)? {
                    StapleAction::Skip => {}
                    StapleAction::Apply => {
                        let stores = inner.psk_stores.clone();
                        // Where S comes from is the one thing the three rounds do not
                        // share. A.3's responder has held it since `encapsulate`; A.4's and
                        // A.5's re-derive it by exporting CrossParty from their OWN send-PQ
                        // at its current epoch — A.4 at the birth epoch of the group it
                        // created, A.5 at the epoch its own Commit' produced. Same group,
                        // epoch and domain as the initiator's export, so both sides get the
                        // same value and it never crosses the wire.
                        let s = match inner.pq_inflight.take() {
                            Some(PqInflight::Responding(s)) => s,
                            Some(PqInflight::BootstrapResponded)
                            | Some(PqInflight::RekeyResponded) => Zeroizing::new(
                                inner.export_cross_from_send_pq()?.psk().as_ref().to_vec(),
                            ),
                            // A current-epoch bind we are not the responder of — an
                            // ill-timed or forged staple; restore what we took.
                            other => {
                                inner.pq_inflight = other;
                                return Err(TwoMlsPqError::SessionNotReady);
                            }
                        };
                        // The bind's classical half is the peer's routine commit — when it
                        // folds our approved Upd it carries identity exactly as a plain
                        // commit staple does, so report what moved into the same bookkeeping
                        // the plain arm feeds (a proposal-less discharge simply moves
                        // nothing, and `LeafChanges` is empty).
                        //
                        // `s` was just consumed and the exporter leaf spent, so a failure
                        // here is unrecoverable in memory: the peer re-staples this bind on
                        // every frame (its next commit, which would supersede it, is what
                        // evidence-gating forbids while this one is unapplied), and each
                        // retry would re-enter with `pq_inflight` already taken and hit the
                        // `other` arm's `SessionNotReady` forever. Latch the break so the
                        // guard at the top of `process_incoming` refuses those retries with
                        // the honest `BindApplyFailed`, and so a host can ask. In-memory
                        // only: this closure persists on success, so the latch never reaches
                        // a blob and a restore predates the failed take.
                        let moved = match inner.apply_bind(&s, &stores, &pq_message, &t_message) {
                            Ok(moved) => moved,
                            Err(_) => {
                                // The specific reason (a torn PQ/classical apply, a rejected
                                // credential, an attestation mismatch) does not change the
                                // recovery — the secret is gone either way — so the breaking
                                // frame surfaces the same honest `BindApplyFailed` the latched
                                // guard gives every frame after it, not the raw error.
                                inner.bind_apply_broken = true;
                                return Err(TwoMlsPqError::BindApplyFailed);
                            }
                        };
                        new_sender = moved.new_sender;
                        canonicalized_own = moved.canonicalized_own;
                        staple_applied = true;
                        // The round is closed: the peer relinquished at its terminal send,
                        // and applying it is what takes the turn.
                        inner.pq_turn_mine = true;
                        // Our CT / Welcome' / Commit' is spent — the bind we just applied
                        // answered it. The ordinary "my part is done" clear (no retirement
                        // involved): the round is over on both sides, so the side-band
                        // falls silent until the next round's begin replaces the slot.
                        inner.pending_side_band = None;
                    }
                }
            } else {
                let commit_msg =
                    MlsMessage::from_bytes(&staple).map_err(|_| TwoMlsPqError::DecryptionFailed)?;
                match inner.staple_epoch_action(&commit_msg)? {
                    // Already applied off an earlier frame — the staple rides every
                    // frame precisely so repeats are cheap skips.
                    StapleAction::Skip => {}
                    StapleAction::Apply => {
                        // The commit may bind the cross-party TwoMLS-PSK of our send
                        // group — possibly at an epoch we've since moved past (their
                        // frame can cross one of our commits). Live-inject the
                        // session-held ledger before processing.
                        if inner.send_group.is_some() {
                            inner.inject_send_psks()?;
                        }
                        let recv = inner
                            .recv_group
                            .as_mut()
                            .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                        let mine = recv.classical.current_member_index();
                        let peer_index = if mine == 0 { 1 } else { 0 };
                        let prior_peer = sender_client_id(&recv.classical, peer_index)?;
                        let prior_own = sender_client_id(&recv.classical, mine)?;
                        let staple_attestation =
                            match recv.classical.process_incoming_message(commit_msg) {
                                Ok(ReceivedMessage::Commit(desc)) => commit_attestation(&desc)?,
                                Ok(_) => return Err(TwoMlsPqError::DecryptionFailed),
                                Err(e) => {
                                    return Err(match map_credential_err(e) {
                                        TwoMlsPqError::CredentialRejected => {
                                            TwoMlsPqError::CredentialRejected
                                        }
                                        // Preserve the transient, retriable semantics of a
                                        // staple that cannot process YET (e.g. a message
                                        // frame overtaking its A.3 BIND).
                                        _ => TwoMlsPqError::DecryptionFailed,
                                    });
                                }
                            };
                        // A staple commit is normally a PARTIAL (no AppDataUpdate); one
                        // that DOES attest (a bare attestation commit, or an A.3 bind
                        // classical half applied out of band) must attest truthfully:
                        // the actual post-apply classical epoch and the recv-PQ's actual
                        // current epoch.
                        if let Some(attestation) = staple_attestation {
                            let pq_epoch = recv
                                .pq
                                .as_ref()
                                .map(|pq| pq.current_epoch())
                                .ok_or(TwoMlsPqError::ApqInfoMismatch)?;
                            if attestation.t_epoch != recv.classical.current_epoch()
                                || attestation.pq_epoch != pq_epoch
                            {
                                return Err(TwoMlsPqError::ApqInfoMismatch);
                            }
                        }
                        // A peer commit must never change the two-party shape (an Add
                        // would plant a shadow member whose credential we would report
                        // as a sender identity).
                        apq::ensure_two_party(&recv.classical)?;
                        staple_applied = true;
                        // Identity changes travel IN the leaves now (the AS validated
                        // them during processing): the peer's own-leaf move is its
                        // catch-up to a credential our commit already canonicalized —
                        // surface it as `new_sender`; OUR leaf moving means the peer
                        // committed one of our candidate proposals — the canonical
                        // step of our own sequence (handled below, outside the borrow).
                        let new_peer = sender_client_id(&recv.classical, peer_index)?;
                        let new_own = sender_client_id(&recv.classical, mine)?;
                        if new_peer != prior_peer {
                            new_sender = Some(ClientId { bytes: new_peer });
                        }
                        if new_own != prior_own {
                            canonicalized_own = Some(new_own);
                        }
                    }
                }
            }

            if let Some(new_id) = &new_sender {
                inner.with_auth(|core| core.theirs.commit(new_id.bytes.clone()));
                inner.their_state = PrincipalState::Sync {
                    client_id: new_id.clone(),
                };
            }

            // The peer committed one of our candidate Upds: that commit DEFINES our
            // next canonical credential. Swap the session to the winning candidate's
            // principal; our own send-group leaf and the PQ leaves catch up on later
            // commits (the lag the AS's history window tolerates).
            if let Some(new_own) = canonicalized_own {
                if new_own == inner.client.client_id().bytes {
                    // The leaf converged to the identity the session already runs
                    // (e.g. the recv-group leaf catching up to the dedicated
                    // establishment principal): canonical state, no client swap.
                    inner.with_auth(|core| core.mine.commit(new_own));
                } else {
                    let winner = inner
                        .staged_candidates
                        .iter()
                        .find(|c| c.client_id().bytes == new_own)
                        .cloned()
                        .ok_or(TwoMlsPqError::CredentialRejected)?;
                    inner.with_auth(|core| core.mine.commit(new_own));
                    inner.track_psk_stores(&winner);
                    inner.client = winner;
                    inner.staged_candidates.clear();
                    inner.my_state = PrincipalState::Sync {
                        client_id: inner.client.client_id(),
                    };
                }
            }

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

            // The proposal's ordering context must equal the *sender's* `proposal_context`,
            // which is sha256 of THEIR recv group's classical id. Their recv group is our
            // send group (the reverse channel), so bind against our send group here — not
            // the recv group the message arrived on. The two endpoints' recv groups are
            // distinct MLS groups, so binding recv would never match the sender's value
            // and every cross-endpoint handoff signature would fail to validate.
            let group_id = inner
                .send_group
                .as_ref()
                .ok_or(TwoMlsPqError::SessionNotEstablished)?
                .classical
                .group_id()
                .to_vec();

            // Stage the stapled Upd(sender) proposal for app approval. The section is
            // self-describing — `[proposing][proposal message]` — so the candidate
            // credential is surfaced to the app BEFORE the proposal touches any group;
            // `queue_proposal` verifies the declared identity against the Update's
            // actual leaf.
            let (proposing, proposal_msg_bytes) = decode_proposal_section(&proposal_bytes)?;
            let digest = crate::sha256(&proposal_msg_bytes);
            // The evidence-gating watermark (see `peer_applied_send_epoch`). The peer staged
            // this Upd in its recv group — which IS our send group — so its epoch is the peer's
            // own view of our send group, and it could only have reached that view by applying
            // our commits up to it. Read here, off the raw section, so evidence accrues on
            // EVERY frame: approval is the app's to withhold, but the license is not the app's
            // to stall.
            //
            // Monotone, and it deliberately does not validate the offer (that is
            // `queue_proposal`'s job): a frame that crossed one of our commits carries a
            // now-stale epoch, and `max` simply ignores it rather than regressing the mark.
            if let Some(offer_epoch) = MlsMessage::from_bytes(&proposal_msg_bytes)
                .ok()
                .and_then(|m| m.epoch())
            {
                inner.peer_applied_send_epoch = Some(
                    inner
                        .peer_applied_send_epoch
                        .map_or(offer_epoch, |mark| mark.max(offer_epoch)),
                );
            }
            inner.offered_proposal = Some((digest.clone(), proposal_msg_bytes, proposing.clone()));
            let proposal = Some(crate::QueuedRemoteProposal {
                digest,
                sender: sender_id.clone(),
                proposing: ClientId { bytes: proposing },
                // The ordering context is the SHA-256 of our send group's (classical,
                // message-half) group id — which is the sender's recv group, matching
                // their `proposal_context` value (see the send_group binding above).
                context: crate::sha256(&group_id),
            });

            // Surfaced only on the frame whose staple was actually applied; repeats of
            // the same commit are silent skips. (Known edge, pre-existing: if the staple
            // applies but the app message fails in this same frame, `new_sender` is
            // never surfaced — the retry skips the already-applied staple. This covers
            // the welcome-join principal adoption above too: the event signal can be
            // lost, so treat `their_principal_state()` as the truth and `new_sender`
            // as a hint.)
            let remote_commit = if staple_applied {
                Some(CommitResult {
                    new_sender,
                    new_recipient: inner.my_state.client_id(),
                })
            } else {
                None
            };

            return Ok(Some(DecryptResult {
                application_message: Some(MlsSenderMessage {
                    app_message_data: app_data,
                    sender_client_id: sender_id,
                    epoch,
                }),
                proposal,
                remote_commit,
            }));
        }

        // Pre-establishment app staple ([0x09][BSG-cl PrivateMessage]): the peer's app
        // message extracted from a §A.1 envelope's `stapled_message` section (see
        // `InitialFrame`). The ciphertext rides the peer's send group — OUR recv group
        // — so it only decrypts after the join the same envelope's welcome produced;
        // hand it here AFTER `receive`. It carries no staple of its own and no
        // proposal (the sender had no recv group to propose into), so the result is
        // application-message-only. Replays are consumed-generation rejects
        // (`DecryptionFailed` — the host's fail-open staple handling drops them).
        if ciphertext.first() == Some(&PRE_ESTABLISHMENT_APP_TAG) {
            let app_msg = MlsMessage::from_bytes(&ciphertext[1..])
                .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
            let mut inner = self.lock();
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
            return Ok(Some(DecryptResult {
                application_message: Some(MlsSenderMessage {
                    app_message_data: app_data,
                    sender_client_id: sender_id,
                    epoch,
                }),
                proposal: None,
                remote_commit: None,
            }));
        }

        // PQ side-band frames are driven through the dedicated `pq_*` API, not this
        // method — they are stateful exchanges, not self-contained decryptable messages.
        // Reject every side-band tag explicitly (via the classifier, so this can never
        // drift from the allocation) so a host that misroutes one gets a clear signal
        // instead of an opaque `DecryptionFailed`.
        if ciphertext
            .first()
            .copied()
            .is_some_and(|b| pq_frame_kind(b).is_some())
        {
            return Err(TwoMlsPqError::SessionNotReady);
        }

        // Nothing else is a valid frame. Bare MLS ciphertext no longer occurs on the
        // send path (every outbound frame is a tagged message frame), so unrecognized
        // plaintext fails loudly here rather than being fed to the MLS parser.
        Err(TwoMlsPqError::DecryptionFailed)
    }

    /// The SHA-256 of the receive group's classical (message-half) group id — the
    /// binding context for identity introductions, matching the classical backend's
    /// convention and `QueuedRemoteProposal.context`. Always the classical half:
    /// message ordering rides it, and it exists from establishment (the PQ half may
    /// still be deferred pre-A.4).
    pub fn proposal_context(&self) -> Option<Vec<u8>> {
        let inner = self.lock();
        inner
            .recv_group
            .as_ref()
            .map(|rg| crate::sha256(rg.classical.group_id()))
    }

    /// Where to post outbound frames: the recv group's classical-half exporter at its
    /// current epoch. The recv group *is* the peer's send group, so this value appears
    /// in the peer's `should_listen_on` set. `None` until the recv group exists (the
    /// initiator pre-return-welcome delivers via the invitation channel instead).
    pub fn send_rendezvous(&self) -> Result<Option<RendezvousId>> {
        let inner = self.lock();
        let Some(recv) = inner.recv_group.as_ref() else {
            return Ok(None);
        };
        Ok(Some(RendezvousId {
            bytes: rendezvous_secret(recv.message_group())?,
        }))
    }

    /// Approve the peer's stapled Upd proposal (identified by its digest). Validated and
    /// stored in the session's single queued slot; the next `prepare_to_encrypt(None)`
    /// re-applies and commits it (with a cross-party PSK refresh). Single-occupancy,
    /// latest-wins; a rejected call is a no-op.
    pub fn queue_proposal(&self, digest: Vec<u8>) -> Result<()> {
        // Guard-first: approving with nothing offered mutates nothing, so reject it before the
        // persist choke point rather than bump the seq and push a Core for a no-op. (The
        // digest-mismatch and validation-failure paths below take-then-restore, so they stay in
        // the closure; both require a real pending offer to reach.)
        if self.lock().offered_proposal.is_none() {
            return Err(TwoMlsPqError::ProposalRejected);
        }
        self.mutate_and_persist(crate::BlobKind::Core, |inner| {
            let (offered, proposal_bytes, proposing) = inner
                .offered_proposal
                .take()
                .ok_or(TwoMlsPqError::ProposalRejected)?;
            // The offer's digest must match the value the app approved.
            if offered != digest {
                inner.offered_proposal = Some((offered, proposal_bytes, proposing));
                return Err(TwoMlsPqError::ProposalRejected);
            }
            // Validate without leaving the send group's cache touched (see
            // `validate_offered_update`). On success, record the authorization and the queued
            // proposal; on ANY rejection, restore the offer so the call is a pure no-op.
            match inner.validate_offered_update(&proposal_bytes, &proposing) {
                Ok(()) => {
                    // Approving the proposal IS the app's authorization of the credential it
                    // carries (the running tally — a later queue replaces both the
                    // authorization and the queued proposal while no commit has happened).
                    inner.with_auth(|core| core.theirs.authorize(proposing.clone()));
                    inner.queued_proposal = Some((digest, proposing, proposal_bytes));
                    Ok(())
                }
                Err(e) => {
                    inner.offered_proposal = Some((offered, proposal_bytes, proposing));
                    Err(e)
                }
            }
        })
    }

    /// The remote credential currently queued for the next commit (the app's running
    /// tally), or `None`. Lets the app decide whether a newly-received proposal should
    /// replace it (queue the newer one) or be kept (do nothing); the library's own
    /// policy is latest-wins, and the slot is cleared when the send epoch advances (a
    /// fold or an A.3 bind).
    pub fn queued_remote_successor(&self) -> Option<ClientId> {
        self.lock()
            .queued_proposal
            .as_ref()
            .map(|(_, proposing, _)| ClientId {
                bytes: proposing.clone(),
            })
    }

    /// Stage a new principal for the next rotation commit, minting its signing keys
    /// internally: the MLS signing keys are session-owned state, so the app supplies only
    /// the opaque ClientId. Call before `prepare_to_encrypt(Some(new_client_id))`, which
    /// commits the handoff.
    ///
    /// Idempotent-ish, matching the classical `propose`: staging the id already staged is
    /// a no-op (the existing staged identity — and its freshly minted keys — is kept); a
    /// different id replaces the staged identity.
    pub fn stage_rotation(&self, new_client_id: Vec<u8>) -> Result<()> {
        // Empty is reserved: the rotation commit announces the id in authenticated_data,
        // and empty AD is the "ratchet commit" discriminator — the handoff would be
        // structurally invisible to the peer.
        if new_client_id.is_empty() {
            return Err(TwoMlsPqError::InvalidClientId);
        }
        // Guard-first: staging an id already in flight (or already parked as the next request)
        // is an idempotent no-op — return before the persist choke point so it neither bumps the
        // seq nor pushes a Core for a state that did not change.
        {
            let inner = self.lock();
            if inner
                .staged_candidates
                .iter()
                .any(|staged| staged.client_id().bytes == new_client_id)
                || inner.deferred_candidate.as_deref() == Some(new_client_id.as_slice())
            {
                return Ok(());
            }
        }
        self.mutate_and_persist(crate::BlobKind::Core, |inner| {
            if inner.staged_candidates.len() < CANDIDATE_WINDOW {
                // Admit into the in-flight pool: mint, rebind the candidate's clients to the
                // session-canonical AS core, and authorize the id for OUR sequence (the peer's
                // provider learns it from the proposal we send; ours needs it for the local
                // commit apply). It is proposable this round via `prepare_to_encrypt(Some(id))`.
                let candidate = TwoMlsPqPrincipal::new(new_client_id.clone())?;
                candidate.combiner().auth_view().rebind(&inner.auth_core);
                inner.with_auth(|core| core.mine.authorize(new_client_id.clone()));
                inner.staged_candidates.push(candidate);
            } else {
                // Pool full — never evict a sent candidate. Park this request in the single
                // deferred slot; it is promoted and proposed on the next routine round once a
                // canonicalization frees a slot. Not authorized yet (it is not on the wire),
                // keeping `mine.authorized_next` aligned with the retained principals.
                inner.deferred_candidate = Some(new_client_id.clone());
            }
            let old = inner.my_state.client_id();
            inner.my_state = PrincipalState::Pending {
                old,
                new: ClientId {
                    bytes: new_client_id,
                },
            };
            Ok(())
        })
    }

    /// Acknowledge a re-delivered pre-establishment frame routed here by the
    /// invitation's forward table. `spawn_token` is the caller's opaque identifier for
    /// the frame (the same value it computes for
    /// `TwoMlsPqInvitation::forward_group_id`); it must equal the token this session
    /// was spawned under. Returns `Ok(None)` always: this call only validates the
    /// routing — since §A.1 replier-first sends (contract 16) every pre-establishment
    /// frame staples the sender's CURRENT app message, but the staple rides the
    /// envelope itself; the host parses it out (`decode_initial_plaintext`) and
    /// delivers it through `process_incoming` — nothing is parked here. A mismatched
    /// token is a mis-route (`DecryptionFailed`); initiator-side sessions have no
    /// spawn token and refuse (`SessionNotReady`).
    pub fn forwarded(&self, spawn_token: Vec<u8>) -> Result<Option<MlsSenderMessage>> {
        let inner = self.lock();
        let expected = inner
            .spawn_token
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        if *expected != spawn_token {
            return Err(TwoMlsPqError::DecryptionFailed);
        }
        Ok(None)
    }

    /// The combiner group ids and per-epoch rendezvous addresses the transport should
    /// listen on. Addresses derive from the send group's classical half, one per
    /// classical epoch, retained across epochs so traffic posted at a prior epoch's
    /// address still lands. The peer derives its post address from its recv group —
    /// the same MLS group — so the values align by construction.
    pub fn should_listen_on(&self) -> Result<ListenChannels> {
        let mut inner = self.lock();
        inner.record_listen_rendezvous()?;
        let send = inner
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_group = CombinerGroupId {
            classical: MlsGroupId {
                bytes: send.classical.group_id().to_vec(),
            },
            // Empty until the deferred PQ half is bootstrapped (A.4).
            pq: MlsGroupId {
                bytes: send
                    .pq
                    .as_ref()
                    .map(|pq| pq.group_id().to_vec())
                    .unwrap_or_default(),
            },
        };
        let rendezvous_by_epoch = inner
            .listen_rendezvous
            .iter()
            .map(|(epoch, bytes)| EpochRendezvous {
                epoch: *epoch,
                rendezvous_id: RendezvousId {
                    bytes: bytes.clone(),
                },
            })
            .collect();
        Ok(ListenChannels {
            send_group,
            rendezvous_by_epoch,
        })
    }
}
