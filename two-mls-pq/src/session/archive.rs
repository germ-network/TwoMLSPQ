//! Session archive (de)serialization: the versioned single-blob layout, the
//! `archive_wire` TLS structs, the state<->wire conversions, and the
//! `archive` / `from_archive` endpoints. The layout version is a whole-blob
//! compatibility gate (no migrations pre-release) -- see the note on
//! `SESSION_ARCHIVE_VERSION`.

use super::*;

// The session archive layout version. The byte covers the WHOLE layout. Still pre-release, so
// a layout change need not bump it — an archive from an older/other build simply fails to
// decode (`ArchiveInvalid`) and is regenerated; no migration.
// The header carries the concrete `ApqCipherSuite` pair (4 bytes, classical then pq,
// big-endian) in place of the old PQ-mode byte: the suite is a stored session property, and a
// restored archive whose pair differs from this build's pinned suite fails loudly.
//
// PRE-RELEASE FLOOR RESET (2026-07-13, with the §A.1 pre-establishment-sends layout
// change — the wire gained the initiator's retained envelope state `initial_their_kp` /
// `initial_app_payload` / `initial_return_kp`, so a session captured at birth restores
// send-ready; all three are None once established and on acceptors): the v1–v10 ladder
// this byte accumulated carried no compatibility value (every bump was a hard cut; the
// history stays in git), so the byte returns to the floor. Blobs from every prior cut
// wear bytes 2–10 and fail the header check; ancient v1-era layouts are additionally
// rejected structurally (the staple first-byte check in `session_from_wire`, whose
// fields pre-v2 bytes could otherwise alias into).
const SESSION_ARCHIVE_VERSION: u8 = 1;

// In its own module because the derive-generated impls reference the std `Result`, which
// the crate-local `Result` alias would shadow (same pattern as `invitation::wire`).
pub(crate) mod archive_wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use mls_rs::psk::{ExternalPskId, PreSharedKey};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// One exported mls-rs group snapshot (plaintext secret material — the enclosing
    /// archive carries the sealing obligation, see [`super::TwoMlsPqSession::archive`]).
    /// A one-field struct so `Option<GroupBlob>` composes with the `byte_vec` framing
    /// (the `with` module has no Option-awareness).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct GroupBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) bytes: Zeroizing<Vec<u8>>,
    }

    /// One Combiner group: the classical half's snapshot and, when live, the PQ half's.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct GroupEntry {
        pub(in crate::session) classical: GroupBlob,
        pub(in crate::session) pq: Option<GroupBlob>,
    }

    /// One session-owned cross-party PSK ledger entry: the send-group classical epoch it
    /// was exported at, and the application PSK's parts (`component_id`, `psk_id`, value).
    /// The store key is recomputed on restore via `ExportedPsk::from_parts`.
    /// `PreSharedKey`'s codec keeps the payload `Zeroizing` through decode.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct PskEntry {
        pub(in crate::session) epoch: u64,
        pub(in crate::session) component_id: u32,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) psk_id: Vec<u8>,
        pub(in crate::session) psk: PreSharedKey,
    }

    /// One per-epoch listen address (rendezvous exporter, captured at its live epoch).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct ListenEntry {
        pub(in crate::session) epoch: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) addr: Vec<u8>,
    }

    /// One per-epoch header receive key (header-encryption exporter of the send group,
    /// captured at its live epoch alongside the listen address).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct HeaderKeyEntry {
        pub(in crate::session) epoch: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) key: Vec<u8>,
    }

    /// `PrincipalState` on the wire: `Sync { client_id: active }` when `pending_new` is
    /// `None`, else `Pending { old: active, new: pending_new }`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WirePrincipalState {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) active: Vec<u8>,
        pub(in crate::session) pending_new: Option<Vec<u8>>,
    }

    /// The peer's stapled Upd awaiting app approval: (digest, proposal bytes).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct OfferedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) digest: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) proposal: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) proposing: Vec<u8>,
    }

    /// An opaque ClientId on the wire.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct IdBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) bytes: Vec<u8>,
    }

    /// A combiner key package pair on the wire (public material — the initiator's
    /// retained pre-establishment seal target / return key package).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WireCombinerKp {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) classical: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) pq: Vec<u8>,
    }

    /// One party's AS credential sequence (see `apq::authentication::PartySequence`).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WirePartySequence {
        pub(in crate::session) history: Vec<IdBlob>,
        pub(in crate::session) authorized_next: Vec<IdBlob>,
        /// Eviction-exempt credentials (a bootstrap leaf's frozen establishment id held
        /// admissible until A.5 catch-up) — see `apq::authentication::PartySequence`.
        pub(in crate::session) pinned: Vec<IdBlob>,
    }

    /// The staged Upd(self) with the identity it proposes.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WireStagedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) proposing: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) message: Vec<u8>,
    }

    /// The app-approved proposal awaiting our next commit (digest, proposing, and the
    /// proposal message bytes re-applied at commit).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WireQueuedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) digest: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) proposing: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) proposal: Vec<u8>,
    }

    /// A session-owned signing identity on the wire: the ClientId, each MLS half's signing
    /// key, and each half's retained key packages. Rebuilt via `apq::ArchivedIdentity` with
    /// the key-package stores preloaded from `*_kps` (the signing keys ARE the identity; the
    /// app owns only the opaque ClientId). The key packages carry any minted-but-unconsumed
    /// material — critically an initiator's return-group key package, which the peer's return
    /// welcome addresses; a bare identity (empty `*_kps`) could not join it after restore.
    /// Carries the session's current client and, when a rotation is staged, the successor
    /// (whose stores are empty). `Zeroizing` wipes the decoded keys on drop.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct SigningIdentityBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) client_id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) classical_signing_key: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) pq_signing_key: Zeroizing<Vec<u8>>,
        /// Retained key packages per half, `(storage id, KeyPackageData)`. Each half's
        /// `KeyPackageData` embeds via its own canonical MLS encoding (as in the invitation
        /// archive), so it stays correct if mls-rs evolves the (non_exhaustive) struct.
        pub(in crate::session) classical_kps: Vec<KeyPackageSecret>,
        pub(in crate::session) pq_kps: Vec<KeyPackageSecret>,
    }

    /// The initiator's held A.3 ephemeral (`PqInflight::Initiating`) on the wire: the
    /// decapsulation key (kept `Zeroizing`) and the encapsulation key. Round-trips via
    /// `apq::pq_ratchet::PqEphemeral`'s byte accessors.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct PqEphemeralBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) dk: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) ek: Vec<u8>,
    }

    /// The responder's held A.3 shared secret (`PqInflight::Responding`) on the wire.
    /// `Zeroizing` wipes it on drop; a one-field struct so `Option<SecretBlob>` composes
    /// with the byte_vec framing (the `with` module has no Option-awareness).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct SecretBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) bytes: Zeroizing<Vec<u8>>,
    }

    /// The archivable `PqInflight` round state, tag-dispatched by `kind` so all six
    /// variants share one optional-payload struct — the flat-struct style the rest of
    /// this module uses in place of codec enums. The A.4/A.5 markers carry no secrets
    /// (their round state lives in the group snapshots); the A.3 variants carry the
    /// round's KEM material (see [`super::TwoMlsPqSession::archive`] for why persisting
    /// it is sound).
    ///
    /// - `0` `Initiating`     — `ephemeral` set; `secret` absent.
    /// - `1` `Responding`     — `secret` set; `ephemeral` absent.
    /// - `2` `RekeyInitiated` — no payload.
    /// - `3` `RekeyResponded` — no payload.
    /// - `4` `BootstrapInitiated` — no payload (the welcome is self-sufficient).
    /// - `5` `BootstrapResponded` — no payload.
    ///
    /// `from_archive` rejects any other `kind`, or a payload that does not match `kind`,
    /// as `ArchiveInvalid`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WirePqInflight {
        pub(in crate::session) kind: u8,
        pub(in crate::session) ephemeral: Option<PqEphemeralBlob>,
        pub(in crate::session) secret: Option<SecretBlob>,
    }

    /// A PQ commit awaiting the classical commit that binds its entropy across — see
    /// `SessionInner::owed_bind`.
    ///
    /// Carries no key material, and needs none: `apq_psk` is exported at the commit that
    /// consumes it, so what waits here is a public commit message and the two epochs it
    /// reserved. That is the whole reason this can ride the archive as plain bytes while the
    /// round's secrets never do.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct WireOwedBind {
        pub(in crate::session) pq_commit: Vec<u8>,
        pub(in crate::session) t_epoch: u64,
        pub(in crate::session) pq_epoch: u64,
    }

    /// The persisted form of a `TwoMlsPqSession`. Everything a session needs to resume,
    /// self-contained (no restoring client is passed): the current signing identity,
    /// identity/turn state, both group snapshots, the cross-party PSK ledger, the
    /// per-epoch listen map, the spawn token, a staged-but-uncommitted rotation, the full
    /// PQ round state, and every parked one-shot frame (dropping a parked side-band frame
    /// whose turn already flipped would desync the side-band permanently).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(in crate::session) struct SessionArchive {
        /// Per-session monotonic mutation counter (see `SessionInner::state_seq`). Stamps
        /// this blob; `restore` compares a `core` blob's `state_seq` against the
        /// `checkpoint`'s to pick the newer non-PQ state.
        pub(in crate::session) state_seq: u64,
        /// PQ-epoch manifest: the current epoch of each PQ half at the time this blob was
        /// written (`None` when that half is absent). In a `checkpoint` these describe the
        /// PQ trees carried inline; in a `core` (PQ trees omitted) they are the epochs the
        /// core expects the reconciling checkpoint's PQ halves to be at — a mismatch means a
        /// PQ op advanced without emitting a checkpoint (forbidden), so restore fails closed.
        pub(in crate::session) send_pq_epoch: Option<u64>,
        pub(in crate::session) recv_pq_epoch: Option<u64>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) session_id: Vec<u8>,
        /// The session's current client signing identity, rebuilt byte-exact on restore
        /// so restore is self-contained (no client argument).
        pub(in crate::session) client: SigningIdentityBlob,
        pub(in crate::session) my_state: WirePrincipalState,
        pub(in crate::session) their_state: WirePrincipalState,
        pub(in crate::session) pq_turn_mine: bool,
        pub(in crate::session) spawn_token: Option<Vec<u8>>,
        /// Required: every constructor creates a send group, so its absence marks a
        /// forged or corrupt archive.
        pub(in crate::session) send_group: GroupEntry,
        pub(in crate::session) recv_group: Option<GroupEntry>,
        pub(in crate::session) send_psk_ledger: Vec<PskEntry>,
        pub(in crate::session) retired_send_psks: Vec<ExternalPskId>,
        pub(in crate::session) last_cross_injected: Option<u64>,
        /// The evidence-gating watermark (see `SessionInner::peer_applied_send_epoch`).
        /// Without it a restore would re-license a discharge the evidence no longer
        /// supports — the peer's proposal proving it is long gone from the wire.
        pub(in crate::session) peer_applied_send_epoch: Option<u64>,
        pub(in crate::session) last_cross_injected_pq: Option<u64>,
        pub(in crate::session) last_send_pq_exported: Option<u64>,
        pub(in crate::session) listen_rendezvous: Vec<ListenEntry>,
        pub(in crate::session) recv_header_keys: Vec<HeaderKeyEntry>,
        pub(in crate::session) recv_header_keys_pq: Vec<HeaderKeyEntry>,
        pub(in crate::session) pending_outbound: Option<Vec<u8>>,
        pub(in crate::session) pending_proposal_hash: Option<Vec<u8>>,
        /// The staple every outbound frame re-sends: a commit, a welcome, or an
        /// APQPrivateMessage (a discharged bind). Never empty on a valid archive
        /// (validated on restore: non-empty, first byte 0x00, 0x01 or 0x05).
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(in crate::session) current_staple: Vec<u8>,
        pub(in crate::session) pending_proposal_message: Option<WireStagedProposal>,
        pub(in crate::session) joined_welcome_digest: Option<Vec<u8>>,
        pub(in crate::session) offered_proposal: Option<OfferedProposal>,
        pub(in crate::session) queued_proposal: Option<WireQueuedProposal>,
        /// Rotation candidates staged by `stage_rotation` and not yet resolved: the
        /// minted successor identities, rebuilt on restore into `staged_candidates`.
        pub(in crate::session) staged_candidates: Vec<SigningIdentityBlob>,
        /// A parked next-rotation request (id only) not yet promoted to in-flight.
        pub(in crate::session) deferred_candidate: Option<Vec<u8>>,
        /// The Authentication Service state: both parties' credential sequences.
        pub(in crate::session) auth_mine: WirePartySequence,
        pub(in crate::session) auth_theirs: WirePartySequence,
        /// The retained side-band frame (plaintext), every one of which is answered by the
        /// round's next leg — no retirement stamp exists. Its `Stable` seal cache is
        /// live-only and deliberately absent here — see `RetainedFrame`.
        pub(in crate::session) pending_side_band: Option<Vec<u8>>,
        /// A landed PQ commit whose classical partner is owed. Public bytes and two
        /// reserved epochs — no key material, because `apq_psk` is exported at the commit
        /// that consumes it, not at the trigger. Without this a restore mid-hold would
        /// strand the round for good: the PQ leaf is spent, so the commit cannot be rebuilt
        /// and the classical half could never be bound.
        pub(in crate::session) owed_bind: Option<WireOwedBind>,
        pub(in crate::session) pq_inflight: Option<WirePqInflight>,
        /// The initiator's retained pre-establishment envelope state (v10): the peer
        /// key package pre-establishment frames are HPKE-sealed to, the host's
        /// self-sufficient app payload, and the bare-shape CLASSICAL return key package
        /// (a bare MLS KeyPackage message since v20). All `None` once established (the
        /// cutover clears them) and on acceptors.
        pub(in crate::session) initial_their_kp: Option<WireCombinerKp>,
        pub(in crate::session) initial_app_payload: Option<Vec<u8>>,
        pub(in crate::session) initial_return_kp: Option<Vec<u8>>,
        /// The initiator's pre-committed A.4 bootstrap key package (public bytes).
        /// Present from `initiate` until `pq_bootstrap_begin` consumes it, so a session
        /// restored between reply and A.4 still opens the round with the KP the
        /// establishment signature committed to. `None` on acceptors.
        pub(in crate::session) bootstrap_kp: Option<Vec<u8>>,
        /// The pre-committed KP's PRIVATE half — session-owned custody (per-client
        /// `SigningIdentityBlob.pq_kps` would be dropped by a Phase 8 client swap, and
        /// the signed commitment obligates this session to join the Welcome' built
        /// around the KP regardless of rotations). Present from `initiate` until the
        /// `pq_bootstrap_bind` join consumes it. `None` on acceptors. Secret material,
        /// like the group snapshots: the enclosing archive carries the sealing
        /// obligation.
        pub(in crate::session) bootstrap_kp_secret: Option<KeyPackageSecret>,
        /// The acceptor's pinned `H(initiator's PQ keyPackage)` from the signed
        /// establishment payload, enforced at `pq_bootstrap_respond`. `None` on
        /// initiators.
        pub(in crate::session) expected_bootstrap_kp_commitment: Option<Vec<u8>>,
    }
}

/// `PrincipalState` → its wire form.
fn wire_principal_state(state: &PrincipalState) -> archive_wire::WirePrincipalState {
    match state {
        PrincipalState::Sync { client_id } => archive_wire::WirePrincipalState {
            active: client_id.bytes.clone(),
            pending_new: None,
        },
        PrincipalState::Pending { old, new } => archive_wire::WirePrincipalState {
            active: old.bytes.clone(),
            pending_new: Some(new.bytes.clone()),
        },
    }
}

/// Wire form → `PrincipalState`.
fn principal_state_from_wire(wire: archive_wire::WirePrincipalState) -> PrincipalState {
    match wire.pending_new {
        None => PrincipalState::Sync {
            client_id: ClientId { bytes: wire.active },
        },
        Some(new) => PrincipalState::Pending {
            old: ClientId { bytes: wire.active },
            new: ClientId { bytes: new },
        },
    }
}

/// A client's signing identity → its wire form (ClientId + each half's signing key).
/// The signing keys are session-owned state; the archive rebuilds the client from them.
fn signing_identity_blob(identity: &TwoMlsPqPrincipal) -> archive_wire::SigningIdentityBlob {
    let client = identity.combiner();
    archive_wire::SigningIdentityBlob {
        client_id: client.client_id().to_vec(),
        classical_signing_key: Zeroizing::new(client.classical_signing_key().to_vec()),
        pq_signing_key: Zeroizing::new(client.pq_signing_key().to_vec()),
        // Carry the client's retained key packages so a restored initiator can still join
        // its return welcome (its return-group key package rides here).
        classical_kps: client.classical_kp_store().all_entries(),
        pq_kps: client.pq_kp_store().all_entries(),
    }
}

/// A signing-identity blob → a rebuilt session-owned `TwoMlsPqPrincipal` with its key-package
/// stores preloaded from the blob (empty for a bare identity, e.g. a staged successor).
fn principal_from_wire(blob: archive_wire::SigningIdentityBlob) -> Result<Arc<TwoMlsPqPrincipal>> {
    TwoMlsPqPrincipal::from_signing_keys(
        blob.client_id,
        blob.classical_signing_key,
        blob.classical_kps,
        blob.pq_signing_key,
        blob.pq_kps,
    )
}

/// Rebuild a retained frame. The `Stable` seal cache is live-only, so a restore starts
/// with none — a chunking pass restarts with a fresh base, which a host must already
/// tolerate.
fn retained_from_wire(frame: Option<Vec<u8>>) -> Option<RetainedFrame> {
    frame.map(RetainedFrame::unsealed)
}

/// `PqInflight` → its wire form. The A.3 variants carry the round's KEM material; the
/// A.4/A.5 markers carry only a discriminant.
fn wire_pq_inflight(inflight: &PqInflight) -> archive_wire::WirePqInflight {
    use archive_wire::{PqEphemeralBlob, SecretBlob, WirePqInflight};
    match inflight {
        PqInflight::Initiating(eph) => WirePqInflight {
            kind: 0,
            ephemeral: Some(PqEphemeralBlob {
                dk: eph.decapsulation_key(),
                ek: eph.encapsulation_key(),
            }),
            secret: None,
        },
        PqInflight::Responding(s) => WirePqInflight {
            kind: 1,
            ephemeral: None,
            secret: Some(SecretBlob { bytes: s.clone() }),
        },
        PqInflight::RekeyInitiated => WirePqInflight {
            kind: 2,
            ephemeral: None,
            secret: None,
        },
        PqInflight::RekeyResponded => WirePqInflight {
            kind: 3,
            ephemeral: None,
            secret: None,
        },
        PqInflight::BootstrapInitiated => WirePqInflight {
            kind: 4,
            ephemeral: None,
            secret: None,
        },
        PqInflight::BootstrapResponded => WirePqInflight {
            kind: 5,
            ephemeral: None,
            secret: None,
        },
    }
}

/// Wire form → `PqInflight`, rejecting an unknown `kind` or a payload that does not match
/// the discriminant (a forged or corrupt archive) as `ArchiveInvalid`.
fn pq_inflight_from_wire(wire: archive_wire::WirePqInflight) -> Result<PqInflight> {
    use archive_wire::WirePqInflight;
    match wire {
        WirePqInflight {
            kind: 0,
            ephemeral: Some(eph),
            secret: None,
        } => Ok(PqInflight::Initiating(
            apq::pq_ratchet::PqEphemeral::from_bytes(&eph.dk, &eph.ek),
        )),
        WirePqInflight {
            kind: 1,
            ephemeral: None,
            secret: Some(s),
        } => Ok(PqInflight::Responding(s.bytes)),
        WirePqInflight {
            kind: 2,
            ephemeral: None,
            secret: None,
        } => Ok(PqInflight::RekeyInitiated),
        WirePqInflight {
            kind: 3,
            ephemeral: None,
            secret: None,
        } => Ok(PqInflight::RekeyResponded),
        WirePqInflight {
            kind: 4,
            ephemeral: None,
            secret: None,
        } => Ok(PqInflight::BootstrapInitiated),
        WirePqInflight {
            kind: 5,
            ephemeral: None,
            secret: None,
        } => Ok(PqInflight::BootstrapResponded),
        _ => Err(TwoMlsPqError::ArchiveInvalid),
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Restore from the two pushed blobs (`ArchiveSink`): the last `core` and the last full
    /// `checkpoint`. Reconciles in one place — the PQ ratchet trees always come from the
    /// `checkpoint`; identity/classical/meta from whichever of the two has the higher
    /// `state_seq` (a `core` written after a checkpoint is always consistent with it, since
    /// the PQ trees never change between checkpoints). A `core` whose PQ-epoch manifest does
    /// not match the checkpoint's PQ halves (a PQ op that failed to checkpoint) is rejected
    /// as `ArchiveInvalid` — fail closed rather than restore a spliced state. Either slot may
    /// be absent (a session that only ever checkpointed has no `core`); at least the
    /// `checkpoint` must be present.
    #[uniffi::constructor]
    pub fn restore(core: Option<Archive>, checkpoint: Option<Archive>) -> Result<Arc<Self>> {
        session_from_wire(reconcile_persisted(core, checkpoint)?)
    }
}

/// Validate a decoded wire and rebuild the live session; shared by `from_archive` and
/// `restore`. The restored session starts with no sink — attach one with
/// `install_sink` (which pushes a fresh baseline checkpoint).
fn session_from_wire(wire: archive_wire::SessionArchive) -> Result<Arc<TwoMlsPqSession>> {
    // Structural invariants the live session maintains; reject blobs that violate
    // them rather than resurrecting an impossible state.
    if wire.send_psk_ledger.len() > SEND_PSK_WINDOW {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let digest_ok = |d: &[u8]| d.len() == 32;
    if wire
        .pending_proposal_hash
        .as_deref()
        .is_some_and(|d| !digest_ok(d))
        || wire
            .offered_proposal
            .as_ref()
            .is_some_and(|o| !digest_ok(&o.digest))
        || wire
            .queued_proposal
            .as_ref()
            .is_some_and(|q| !digest_ok(&q.digest))
        || wire
            .joined_welcome_digest
            .as_deref()
            .is_some_and(|d| !digest_ok(d))
    {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    if wire
        .listen_rendezvous
        .iter()
        .any(|e| e.addr.len() != RENDEZVOUS_LEN)
    {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let hk_len = header_key_len()?;
    if wire
        .recv_header_keys
        .iter()
        .chain(wire.recv_header_keys_pq.iter())
        .any(|e| e.key.len() != hk_len)
    {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    // The staple is never empty on a live session (set at construction), and its
    // first byte is one of the three staple forms: MLSMessage (0x00), APQWelcome
    // (0x01), or APQPrivateMessage (0x05 -- a discharged bind, the staple until the
    // next commit supersedes it). This check also structurally rejects pre-v2
    // archive layouts, whose bytes can otherwise alias into these fields (an
    // Option-None byte reads as an empty byte_vec).
    if !matches!(
        wire.current_staple.first(),
        Some(&0x00) | Some(&APQ_TAG) | Some(&apq::APQ_PRIVATE_MESSAGE_TAG)
    ) {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }

    let my_state = principal_state_from_wire(wire.my_state);
    let their_state = principal_state_from_wire(wire.their_state);

    // Rebuild the session's current client byte-exact from its archived signing
    // identity, and re-mint any staged-but-uncommitted rotation successor. All group
    // storage and PSK plumbing below re-homes onto this client.
    let client = principal_from_wire(wire.client)?;
    let staged_candidates = wire
        .staged_candidates
        .into_iter()
        .map(principal_from_wire)
        .collect::<Result<Vec<_>>>()?;
    // Rebuild the canonical AS core from the archived sequences onto the rebuilt
    // client's view, and point every candidate's view at it.
    let seq = |w: archive_wire::WirePartySequence| {
        apq::authentication::PartySequence::from_parts(
            w.history.into_iter().map(|b| b.bytes).collect(),
            w.authorized_next.into_iter().map(|b| b.bytes).collect(),
            w.pinned.into_iter().map(|b| b.bytes).collect(),
        )
    };
    let (auth_mine, auth_theirs) = (seq(wire.auth_mine), seq(wire.auth_theirs));
    client.combiner().auth_view().with(move |core| {
        core.mine = auth_mine;
        core.theirs = auth_theirs;
    });
    let auth_core_restored = client.combiner().auth_view().core();
    for candidate in &staged_candidates {
        candidate.combiner().auth_view().rebind(&auth_core_restored);
    }
    let pq_inflight = wire.pq_inflight.map(pq_inflight_from_wire).transpose()?;

    let group_state = |entry: archive_wire::GroupEntry| apq::CombinerGroupState {
        classical: entry.classical.bytes,
        pq: entry.pq.map(|blob| blob.bytes),
    };
    let send_group = apq::load_combiner_group(client.combiner(), &group_state(wire.send_group))?;
    let recv_group = match wire.recv_group {
        Some(entry) => Some(apq::load_combiner_group(
            client.combiner(),
            &group_state(entry),
        )?),
        None => None,
    };

    // The imports above re-homed every group's captured storage and PSK handles onto
    // `client`, so the plumbing collapses to `client`'s handles exactly as
    // `build_session` derives them — the multi-store history a rotation accumulated
    // existed only to serve groups born on pre-rotation clients, and those bindings
    // are dissolved by the import.
    let send_group_storage = client.combiner().classical_group_storage().clone();
    let suite = client.combiner().cipher_suite();
    let psk_stores = vec![
        client.combiner().classical().secret_store(),
        client.combiner().pq().secret_store(),
    ];
    let psk_stores_from = Arc::clone(&client);
    Ok(Arc::new(TwoMlsPqSession {
        inner: Mutex::new(SessionInner {
            client,
            suite,
            send_group: Some(send_group),
            recv_group,
            pending_outbound: wire.pending_outbound,
            pending_proposal_hash: wire.pending_proposal_hash,
            // Not serialized; the staple was persisted no later than the archived seq, so
            // using it is a safe (never-under) `depends_on_seq` for post-restore frames.
            current_staple_seq: wire.state_seq,
            current_staple: wire.current_staple,
            pending_proposal_message: wire
                .pending_proposal_message
                .map(|p| (p.proposing, p.message)),
            joined_welcome_digest: wire.joined_welcome_digest,
            offered_proposal: wire
                .offered_proposal
                .map(|o| (o.digest, o.proposal, o.proposing)),
            queued_proposal: wire
                .queued_proposal
                .map(|q| (q.digest, q.proposing, q.proposal)),
            staged_candidates,
            deferred_candidate: wire.deferred_candidate,
            auth_core: auth_core_restored,
            pq_inflight,
            session_id: SessionId {
                bytes: wire.session_id,
            },
            state_seq: wire.state_seq,
            my_state,
            their_state,
            pq_turn_mine: wire.pq_turn_mine,
            // Deliberately not archived and always restored clear: the wedge it marks is an
            // in-memory apply failure, and restoring predates the failed take — so a restore
            // IS the recovery (see `SessionInner::bind_apply_broken`).
            bind_apply_broken: false,
            // The seal cache is live-only, so a restore restarts any chunking pass with a
            // fresh base — the frames themselves ride the archive, so re-sending resumes.
            pending_side_band: retained_from_wire(wire.pending_side_band),
            owed_bind: wire.owed_bind.map(|o| super::OwedBind {
                pq_commit: o.pq_commit,
                t_epoch: o.t_epoch,
                pq_epoch: o.pq_epoch,
            }),
            send_psk_ledger: wire
                .send_psk_ledger
                .into_iter()
                .map(|entry| {
                    apq::ExportedPsk::from_parts(entry.component_id, entry.psk_id, entry.psk)
                        .map(|exported| (entry.epoch, exported))
                })
                .collect::<std::result::Result<_, _>>()?,
            retired_send_psks: wire.retired_send_psks,
            last_cross_injected: wire.last_cross_injected,
            peer_applied_send_epoch: wire.peer_applied_send_epoch,
            last_cross_injected_pq: wire.last_cross_injected_pq,
            last_send_pq_exported: wire.last_send_pq_exported,
            listen_rendezvous: wire
                .listen_rendezvous
                .into_iter()
                .map(|entry| (entry.epoch, entry.addr))
                .collect(),
            recv_header_keys: wire
                .recv_header_keys
                .into_iter()
                .map(|entry| (entry.epoch, entry.key))
                .collect(),
            recv_header_keys_pq: wire
                .recv_header_keys_pq
                .into_iter()
                .map(|entry| (entry.epoch, entry.key))
                .collect(),
            send_group_storage,
            psk_stores,
            psk_stores_from,
            spawn_token: wire.spawn_token,
            initial_their_kp: wire.initial_their_kp.map(combiner_kp_from_wire),
            initial_app_payload: wire.initial_app_payload,
            initial_return_kp: wire.initial_return_kp,
            bootstrap_kp: wire.bootstrap_kp,
            bootstrap_kp_secret: wire.bootstrap_kp_secret,
            expected_bootstrap_kp_commitment: wire.expected_bootstrap_kp_commitment,
            // Attached post-restore via `install_sink`.
            sink: None,
        }),
    }))
}

// Legacy whole-blob archive/restore — NOT on the FFI surface (push persistence via
// `ArchiveSink` + `restore` replaced it; the pull `archive()` was the root of H1). Kept
// `pub` for in-crate tests and the archive-decode fuzz target only.
impl TwoMlsPqSession {
    /// Restore from a single serialised archive (the legacy whole-blob path). Self-contained:
    /// the archive rebuilds the session's exact client internally.
    pub fn from_archive(archive: Archive) -> Result<Arc<Self>> {
        session_from_wire(decode_wire(&archive)?)
    }

    /// Serialise the session as one blob. NOT exported — this is the pull model push
    /// persistence replaced. Archive is **total** — a session is ALWAYS archivable.
    ///
    /// The bytes are **plaintext secret material** (the current signing identity, group
    /// snapshots including signing keys and epoch secrets, the PSK ledger, and any
    /// mid-round KEM material) — seal them before persisting (`apq::archive::seal` is the
    /// provided tool; the key belongs in the platform keystore). An archive is a **move,
    /// not a copy**: any further use of the live session (or of a second restore) rewinds
    /// the sender ratchet, which re-derives AEAD keys/nonces for new plaintexts. The
    /// caller owns single-use/latest-only discipline, as with invitation archives.
    ///
    /// A mid-A.3 PQ round is serialized whole (`Initiating` holds the decapsulation key,
    /// `Responding` the held shared secret). This does not weaken the ratchet in a way
    /// the archive doesn't already: the blob carries the PSK ledger, epoch secrets, and
    /// leaf signing keys, and the seal-before-persisting contract covers the round
    /// material alongside them; the marginal exposure is at most one round of PCS against
    /// an archive thief who already holds the epoch secrets. The alternative is unsound:
    /// a responder that discarded its held secret could never process the initiator's
    /// incoming bind (0x09) — a permanent side-band desync — so serialization is the only
    /// correct choice.
    pub fn archive(&self) -> Result<Archive> {
        let mut inner = self.lock();
        Ok(Archive {
            bytes: encode_checkpoint(&mut inner)?,
        })
    }
}

/// Build the archive wire struct from the live session. `include_pq = false` omits the two
/// ML-KEM ratchet trees (the `core` blob) — exporting only each half's cheap classical
/// snapshot — while recording their epochs in the manifest so a restore can splice them from a
/// `checkpoint`; `true` carries them inline (`checkpoint`).
fn build_archive_wire(
    inner: &mut SessionInner,
    include_pq: bool,
) -> Result<archive_wire::SessionArchive> {
    let pq_inflight = inner.pq_inflight.as_ref().map(wire_pq_inflight);
    let client = signing_identity_blob(&inner.client);
    let staged_candidates = inner
        .staged_candidates
        .iter()
        .map(|c| signing_identity_blob(c))
        .collect::<Vec<_>>();
    let (auth_mine, auth_theirs) = inner.with_auth(|core| {
        let seq = |s: &apq::authentication::PartySequence| {
            let (history, authorized_next, pinned) = s.to_parts();
            let blobs = |ids: Vec<Vec<u8>>| {
                ids.into_iter()
                    .map(|bytes| archive_wire::IdBlob { bytes })
                    .collect()
            };
            archive_wire::WirePartySequence {
                history: blobs(history),
                authorized_next: blobs(authorized_next),
                pinned: blobs(pinned),
            }
        };
        (seq(&core.mine), seq(&core.theirs))
    });

    // Prune the listen map against the same retention window whose epochs the
    // exported snapshots carry, so the archive is internally consistent.
    inner.record_listen_rendezvous()?;

    let group_entry = |state: apq::CombinerGroupState| archive_wire::GroupEntry {
        classical: archive_wire::GroupBlob {
            bytes: state.classical,
        },
        pq: state.pq.map(|bytes| archive_wire::GroupBlob { bytes }),
    };
    // For a `core` blob export only each half's classical snapshot (the ML-KEM tree is
    // omitted and spliced from the checkpoint at restore); for a `checkpoint` export both.
    let export = |g: &mut CombinerGroup| -> Result<apq::CombinerGroupState> {
        if include_pq {
            Ok(g.export_state()?)
        } else {
            Ok(apq::CombinerGroupState {
                classical: g.export_classical()?,
                pq: None,
            })
        }
    };
    let send_group = group_entry(export(
        inner
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?,
    )?);
    let recv_group = match inner.recv_group.as_mut() {
        Some(recv) => Some(group_entry(export(recv)?)),
        None => None,
    };

    // The PQ-epoch manifest: the current epoch of each PQ half (None when absent). Export
    // does not advance an epoch, so reading them after export is equivalent to before. The
    // same `pq_epochs` accessor gates `process_incoming`'s Core/Checkpoint choice, so the
    // manifest and that decision can never diverge on what counts as a PQ change.
    let (send_pq_epoch, recv_pq_epoch) = inner.pq_epochs();

    let archive =
        archive_wire::SessionArchive {
            state_seq: inner.state_seq,
            send_pq_epoch,
            recv_pq_epoch,
            session_id: inner.session_id.bytes.clone(),
            client,
            my_state: wire_principal_state(&inner.my_state),
            their_state: wire_principal_state(&inner.their_state),
            pq_turn_mine: inner.pq_turn_mine,
            spawn_token: inner.spawn_token.clone(),
            send_group,
            recv_group,
            send_psk_ledger: inner
                .send_psk_ledger
                .iter()
                .map(|(epoch, exported)| archive_wire::PskEntry {
                    epoch: *epoch,
                    component_id: exported.component_id(),
                    psk_id: exported.psk_id().to_vec(),
                    psk: exported.psk().clone(),
                })
                .collect(),
            retired_send_psks: inner.retired_send_psks.clone(),
            last_cross_injected: inner.last_cross_injected,
            peer_applied_send_epoch: inner.peer_applied_send_epoch,
            last_cross_injected_pq: inner.last_cross_injected_pq,
            last_send_pq_exported: inner.last_send_pq_exported,
            listen_rendezvous: inner
                .listen_rendezvous
                .iter()
                .map(|(&epoch, addr)| archive_wire::ListenEntry {
                    epoch,
                    addr: addr.clone(),
                })
                .collect(),
            recv_header_keys: inner
                .recv_header_keys
                .iter()
                .map(|(&epoch, key)| archive_wire::HeaderKeyEntry {
                    epoch,
                    key: key.clone(),
                })
                .collect(),
            recv_header_keys_pq: inner
                .recv_header_keys_pq
                .iter()
                .map(|(&epoch, key)| archive_wire::HeaderKeyEntry {
                    epoch,
                    key: key.clone(),
                })
                .collect(),
            pending_outbound: inner.pending_outbound.clone(),
            pending_proposal_hash: inner.pending_proposal_hash.clone(),
            current_staple: inner.current_staple.clone(),
            pending_proposal_message: inner.pending_proposal_message.as_ref().map(
                |(proposing, message)| archive_wire::WireStagedProposal {
                    proposing: proposing.clone(),
                    message: message.clone(),
                },
            ),
            joined_welcome_digest: inner.joined_welcome_digest.clone(),
            offered_proposal: inner.offered_proposal.as_ref().map(
                |(digest, proposal, proposing)| archive_wire::OfferedProposal {
                    digest: digest.clone(),
                    proposal: proposal.clone(),
                    proposing: proposing.clone(),
                },
            ),
            queued_proposal: inner
                .queued_proposal
                .as_ref()
                .map(
                    |(digest, proposing, proposal)| archive_wire::WireQueuedProposal {
                        digest: digest.clone(),
                        proposing: proposing.clone(),
                        proposal: proposal.clone(),
                    },
                ),
            staged_candidates,
            deferred_candidate: inner.deferred_candidate.clone(),
            auth_mine,
            auth_theirs,
            pending_side_band: inner.pending_side_band.as_ref().map(|r| r.frame.clone()),
            owed_bind: inner
                .owed_bind
                .as_ref()
                .map(|o| archive_wire::WireOwedBind {
                    pq_commit: o.pq_commit.clone(),
                    t_epoch: o.t_epoch,
                    pq_epoch: o.pq_epoch,
                }),
            pq_inflight,
            initial_their_kp: inner.initial_their_kp.as_ref().map(wire_combiner_kp),
            initial_app_payload: inner.initial_app_payload.clone(),
            initial_return_kp: inner.initial_return_kp.clone(),
            bootstrap_kp: inner.bootstrap_kp.clone(),
            bootstrap_kp_secret: inner.bootstrap_kp_secret.clone(),
            expected_bootstrap_kp_commitment: inner.expected_bootstrap_kp_commitment.clone(),
        };
    Ok(archive)
}

/// A retained combiner key package → its wire form.
fn wire_combiner_kp(kp: &CombinerKeyPackage) -> archive_wire::WireCombinerKp {
    archive_wire::WireCombinerKp {
        classical: kp.classical.clone(),
        pq: kp.pq.clone(),
    }
}

/// Wire form → the retained combiner key package.
fn combiner_kp_from_wire(wire: archive_wire::WireCombinerKp) -> CombinerKeyPackage {
    CombinerKeyPackage {
        classical: wire.classical,
        pq: wire.pq,
    }
}

/// Encode an archive wire struct to bytes: header `[version][suite pair]` + MLS body. Exact-
/// size `Zeroizing` prealloc so a growing Vec can't strand unwiped secret copies (the returned
/// Vec is itself unwiped — the `ArchiveSink` sealing obligation covers it).
fn encode_archive(
    suite: &apq::ApqCipherSuite,
    wire: &archive_wire::SessionArchive,
) -> Result<Vec<u8>> {
    use mls_rs::mls_rs_codec::{MlsEncode, MlsSize};
    let mut out = Zeroizing::new(Vec::with_capacity(5 + wire.mls_encoded_len()));
    out.push(SESSION_ARCHIVE_VERSION);
    // Header suite bytes: the declared suite's wire id (`TwoMlsSuite::to_wire`, the one
    // encoding authority `decode_wire` validates against). The session's stored pair is
    // definitionally the declared suite's pair (every session is constructed via
    // `crypto_config`); the debug_assert names that invariant rather than letting the
    // two silently diverge under a future multi-suite edit.
    debug_assert_eq!(suite.to_wire(), crate::suite::TwoMlsSuite::CURRENT.to_wire());
    out.extend_from_slice(&crate::suite::TwoMlsSuite::CURRENT.to_wire());
    wire.mls_encode(&mut out)
        .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    Ok(out.to_vec())
}

/// Encode the full session (checkpoint): identity + classical + meta + the ML-KEM trees.
pub(super) fn encode_checkpoint(inner: &mut SessionInner) -> Result<Vec<u8>> {
    let wire = build_archive_wire(inner, true)?;
    encode_archive(&inner.suite, &wire)
}

/// Encode the `core` blob: everything except the two ML-KEM ratchet trees.
pub(super) fn encode_core(inner: &mut SessionInner) -> Result<Vec<u8>> {
    let wire = build_archive_wire(inner, false)?;
    encode_archive(&inner.suite, &wire)
}

/// Decode + header-validate a single archive blob into its wire struct.
fn decode_wire(archive: &Archive) -> Result<archive_wire::SessionArchive> {
    use mls_rs::mls_rs_codec::MlsDecode;
    // Header: [version][classical u16 BE][pq u16 BE]. The archived suite pair must be this
    // build's declared suite — fail loudly across builds rather than misinterpret the group
    // snapshots (a recognized `TwoMlsSuite` variant is a coherent APQ pair by construction).
    let mut rest = match archive.bytes.as_slice() {
        [SESSION_ARCHIVE_VERSION, s0, s1, s2, s3, rest @ ..]
            if crate::suite::TwoMlsSuite::from_wire([*s0, *s1, *s2, *s3])
                == Some(crate::suite::TwoMlsSuite::CURRENT) =>
        {
            rest
        }
        _ => return Err(TwoMlsPqError::ArchiveInvalid),
    };
    let wire = archive_wire::SessionArchive::mls_decode(&mut rest)
        .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    if !rest.is_empty() {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    Ok(wire)
}

/// Reconcile the two pushed blobs into one wire struct (see `restore`). PQ trees come
/// from the checkpoint; the rest from whichever blob has the higher `state_seq`.
fn reconcile_persisted(
    core: Option<Archive>,
    checkpoint: Option<Archive>,
) -> Result<archive_wire::SessionArchive> {
    let checkpoint = checkpoint.ok_or(TwoMlsPqError::ArchiveInvalid)?;
    let ck = decode_wire(&checkpoint)?;
    let core = match core {
        Some(core) => decode_wire(&core)?,
        // No core: the session only ever checkpointed (or the core was lost) — the checkpoint
        // alone is a complete, consistent state.
        None => return Ok(ck),
    };
    // The checkpoint is at least as new: it already carries everything through its seq. The `>=`
    // (not `>`) is load-bearing: `install_sink` re-pushes a baseline checkpoint at the restored
    // seq WITHOUT bumping, so a checkpoint and a pre-restore core can share a seq — the tie must
    // break toward the checkpoint, which re-encodes the full reconciled state.
    if ck.state_seq >= core.state_seq {
        return Ok(ck);
    }
    // The core is newer. It shares the checkpoint's PQ halves (no PQ op happened since, or
    // there would be a newer checkpoint); validate that and splice them in. A mismatch means a
    // PQ op advanced without a checkpoint — fail closed.
    if core.send_pq_epoch != ck.send_pq_epoch || core.recv_pq_epoch != ck.recv_pq_epoch {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let mut merged = core;
    merged.send_group.pq = ck.send_group.pq;
    merged.recv_group = match (merged.recv_group, ck.recv_group) {
        (Some(mut rg), ck_rg) => {
            rg.pq = ck_rg.and_then(|c| c.pq);
            Some(rg)
        }
        // Core has no recv group and neither does the checkpoint (the epoch check above already
        // confirmed both recv_pq_epoch are None) — nothing to splice.
        (None, None) => None,
        // A newer core lacking a recv group the older checkpoint HAS would mean `recv_group`
        // regressed Some→None. That is impossible today — nothing clears it once set (no
        // in-library re-establish/reset exists) — so this pairs a passing PQ-epoch check (both None) with a
        // dropped recv group. Fail closed rather than silently discard the checkpoint's recv
        // group if a future change ever breaks that monotonicity.
        (None, Some(_)) => return Err(TwoMlsPqError::ArchiveInvalid),
    };
    Ok(merged)
}
