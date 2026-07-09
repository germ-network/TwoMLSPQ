use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use apq::storage::PersistableGroupStorage;
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    group::ReceivedMessage,
    psk::{ExternalPskId, PreSharedKey},
    storage_provider::in_memory::InMemoryPreSharedKeyStorage,
    GroupStateStorage, MlsMessage,
};

use apq::{
    create_bound_classical_send_group, create_combiner_send_group, create_group_with_member,
    decode_apq_welcome, encode_apq_welcome, export_psk, forget_psk, join_combiner_group,
    join_group_from_welcome, register_psk, sender_client_id, APQ_TAG,
};

use crate::key_package_store::CombinerGroup;

use crate::{
    key_packages::{
        ensure_pq_available, parse_mls_key_package, CombinerKeyPackage, TwoMlsPqPrincipal,
    },
    Archive, ClientId, CombinerGroupId, CommitResult, DecryptResult, EncryptResult,
    EpochRendezvous, ListenChannels, MlsGroupId, MlsSenderMessage, PrepareEncryptResult,
    PrincipalState, RendezvousId, Result, SessionId, TwoMlsPqError,
};

use zeroize::Zeroizing;

use crate::providers;

struct SessionInner {
    client: Arc<TwoMlsPqPrincipal>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    pending_proposal_hash: Option<Vec<u8>>,
    /// Send-group commit to bundle with the next outbound app message (rotation, or epoch advance).
    pending_commit_message: Option<Vec<u8>>,
    /// Upd(self) proposal for the peer's send group, stapled onto the next outbound frame.
    pending_proposal_message: Option<Vec<u8>>,
    /// The peer's stapled Upd proposal awaiting app approval (digest, proposal bytes). It
    /// enters our send group's proposal cache only via `queue_proposal`.
    offered_proposal: Option<(Vec<u8>, Vec<u8>)>,
    queued_proposal: Option<Vec<u8>>,
    pending_new_client: Option<Arc<TwoMlsPqPrincipal>>,
    pq_inflight: Option<PqInflight>,
    session_id: SessionId,
    my_state: PrincipalState,
    their_state: PrincipalState,
    /// Responder-side side-band frame awaiting pickup by `pq_take_pending_outbound`.
    /// Single slot: responder operations refuse to start while a frame is waiting.
    pending_pq_outbound: Option<Vec<u8>>,
    /// Whose move the PQ side-band is: the initiator owes the A.4 bootstrap; thereafter
    /// completing an operation passes the turn to the peer.
    pq_turn_mine: bool,
    /// Cross-party TwoMLS-PSKs of OUR send group's recent epochs, owned by the session
    /// (destined for the session archive; the mls-rs secret stores are ephemeral plumbing,
    /// filled just-in-time by `inject_send_psks`). The peer binds the PSK of our send
    /// group's epoch *as they last observed it*, so a frame that crossed one of our
    /// commits can reference an epoch mls-rs can no longer export — the ledger keeps a
    /// window instead of re-deriving at the current epoch only.
    send_psk_ledger: VecDeque<(ExternalPskId, PreSharedKey)>,
    /// PSK ids evicted from the ledger (or consumed one-shot) but possibly still present in
    /// the mls-rs secret stores from an earlier injection; the next `inject_send_psks`
    /// deletes them so the stores never resolve PSKs the session no longer vouches for.
    retired_send_psks: Vec<ExternalPskId>,
    /// Per-epoch listen addresses derived from the send group's classical half
    /// (`exportSecret("rendezvous", "TwoMLS", 32)` — the classical backend's convention).
    /// Exporters are only derivable at the current epoch, so each value is captured when
    /// its epoch is live: traffic posted at a prior epoch's address must still land.
    /// Keyed by classical epoch; the window follows mls-rs's own epoch retention (see
    /// `record_listen_rendezvous`) — current epoch + the prior epochs mls-rs retains.
    listen_rendezvous: BTreeMap<u64, Vec<u8>>,
    /// The group-state storage backing the send group's classical half, captured from
    /// the client that CONSTRUCTED the session. The retention probe must read this
    /// handle, not one reached through `self.client`: a Phase 8 rotation replaces
    /// `self.client` with the new principal's client (whose injected storage is a fresh,
    /// empty map), while the send group keeps flushing into the storage it was built
    /// with — probing the new client's handle would prune every prior epoch's listen
    /// address right after rotation.
    send_group_storage: PersistableGroupStorage,
    /// Every PSK store backing one of this session's group configs: the constructing
    /// client's stores, plus the stores of any later client that joins or stands up a
    /// group half (the A.4 bootstrap and the return-welcome join run on the CURRENT
    /// principal, which a Phase 8 rotation may have replaced since construction). External
    /// PSKs are registered into ALL of these (`register_psk`): an mls-rs group resolves
    /// PSKs from the store of the client that created it, so registering only through
    /// `self.client` would strand every group created before the latest rotation.
    psk_stores: Vec<InMemoryPreSharedKeyStorage>,
    /// The client whose PSK stores `psk_stores` last absorbed — the dedup key for
    /// `track_psk_stores` (compared by Arc identity, so re-tracking the same client
    /// is free and only a rotation-installed client grows the registry).
    psk_stores_from: Arc<TwoMlsPqPrincipal>,
    /// The opaque spawn token this acceptor session was created under (see
    /// `TwoMlsPqInvitation::receive`); `None` on initiator sessions. `forwarded`
    /// matches replayed initial frames against it. Opaque — this library never
    /// interprets the bytes. Must be serialized when `archive()` is implemented, or
    /// restored sessions stop acknowledging replayed initial frames.
    spawn_token: Option<Vec<u8>>,
}

/// Ledger depth for `send_psk_ledger`: one entry per send-group epoch. The peer references
/// the epoch it last observed, so the window must cover every unilateral send-group commit
/// (queued-proposal ratchet, principal rotation, PQ bind) that can cross one in-flight peer
/// frame. That count is protocol-unbounded in principle — a host looping rotations while a
/// peer frame is in transit can outrun any fixed window and permanently desync the
/// direction (the failed frame is a commit, so there is no recovery) — but each entry is
/// one 32-byte secret, so we keep a generous window and rely on hosts not committing
/// unboundedly between peer frames.
const SEND_PSK_WINDOW: usize = 8;

/// A TwoMLSPQ session holding two asymmetric Combiner send groups.
#[derive(uniffi::Object)]
pub struct TwoMlsPqSession {
    inner: Mutex<SessionInner>,
}

// APQWelcome wire format (0x01) + encode/decode live in the `apq` crate (imported above).
// Rotation commit+app: [0x03 tag][u32-LE commit-len][commit][u32-LE app-len][app]
// Used only for Phase 8 principal rotation (no PSK refresh).
const BUNDLED_TAG: u8 = 0x03;
// A.2 ratchet frame: [0x05 tag][send-commit][Upd(sender) proposal][app], each section
// u32-LE length-prefixed (see encode_ratchet; sections may be empty — routine rounds
// carry no commit). Per A.2 the sender commits in its OWN send group; the receiver
// applies that commit to its recv group and stages the stapled Upd for app approval.
const PARTIAL_TAG: u8 = 0x05;
// 0x07 was the pre-A.2 full-bundle frame (send + recv commits); retired — the tag
// stays reserved so old frames are rejected rather than misparsed.
// Stapled welcome: [0x09 tag][u32-LE welcome-len][APQWelcome bytes][inner frame bytes].
// The acceptor staples its return APQWelcome onto its first app frame; the inner frame is an
// ordinary tagged frame (0x05/0x03/raw). First round only — consumed after one send.
const STAPLED_WELCOME_TAG: u8 = 0x09;
// Rendezvous derivation, shared with the classical backend so both stacks address
// transport channels the same way: exportSecret(label, context, 32) on a group's
// classical half. Both members of a group derive identical values; outsiders cannot.
const RENDEZVOUS_LABEL: &[u8] = b"rendezvous";
const RENDEZVOUS_CONTEXT: &[u8] = b"TwoMLS";
const RENDEZVOUS_LEN: usize = 32;
// PQ ratchet (architecture-diagrams PR #2 §A.3), cryptokit only:
// 0x0B carries the initiator's ML-KEM encapsulation key, 0x0D the responder's ciphertext,
// 0x0F the bind = [pq partial-commit][classical commit][app], all length-prefixed.
const PQ_EK_TAG: u8 = 0x0B;
const PQ_CT_TAG: u8 = 0x0D;
const PQ_BIND_TAG: u8 = 0x0F;

/// A.4 bootstrap: this side's PQ key package, sent so the peer can stand up its deferred
/// send-group PQ half.
const PQ_BOOTSTRAP_KP_TAG: u8 = 0x11;

/// A.4 bootstrap reply: the new PQ group's welcome plus the classical APQ-PSK bind commit.
const PQ_BOOTSTRAP_BIND_TAG: u8 = 0x13;

// A.5 rekey (architecture-diagrams §A.5), cryptokit only — updatePath commits run on the
// PQ groups alone so the classical ratchet is never blocked behind a large ML-KEM
// updatePath. 0x15 carries the initiator's Upd' proposal for the responder's send-PQ;
// 0x17 = [Commit'][counter-Upd'-or-empty], length-prefixed — the responder's reply
// carries its counter-proposal, the initiator's final commit an empty slot. Each Commit'
// cross-injects a PSK exported from the opposite PQ send group; the bumped pq_epoch
// reconciles into APQInfo at the next A.3 bind (no AppDataUpdate rides these commits).
const PQ_REKEY_UPD_TAG: u8 = 0x15;
const PQ_REKEY_COMMIT_TAG: u8 = 0x17;

/// PQ ratchet round state carried between the messages of one exchange.
enum PqInflight {
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

// The session archive layout version. The byte covers the WHOLE layout. Pinned at 1 during
// pre-release development: format changes don't bump it, so an archive from an older/other
// build simply fails to decode (`ArchiveInvalid`) and is regenerated — no migration. Start
// incrementing on the first stable release.
const SESSION_ARCHIVE_VERSION: u8 = 1;
// Tags the PQ half as real ML-KEM, mirroring the invitation archive's header byte, so any
// future PQ-mode change (e.g. conf+auth) fails loudly across builds instead of
// misinterpreting group snapshots.
const SESSION_ARCHIVE_PQ_MODE: u8 = 1;

// In its own module because the derive-generated impls reference the std `Result`, which
// the crate-local `Result` alias would shadow (same pattern as `invitation::wire`).
mod archive_wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use mls_rs::psk::{ExternalPskId, PreSharedKey};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// One exported mls-rs group snapshot (plaintext secret material — the enclosing
    /// archive carries the sealing obligation, see [`super::TwoMlsPqSession::archive`]).
    /// A one-field struct so `Option<GroupBlob>` composes with the `byte_vec` framing
    /// (the `with` module has no Option-awareness).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct GroupBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) bytes: Zeroizing<Vec<u8>>,
    }

    /// One Combiner group: the classical half's snapshot and, when live, the PQ half's.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct GroupEntry {
        pub(super) classical: GroupBlob,
        pub(super) pq: Option<GroupBlob>,
    }

    /// One session-owned cross-party PSK ledger entry. `PreSharedKey`'s codec keeps the
    /// payload `Zeroizing` through decode.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct PskEntry {
        pub(super) id: ExternalPskId,
        pub(super) psk: PreSharedKey,
    }

    /// One per-epoch listen address (rendezvous exporter, captured at its live epoch).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct ListenEntry {
        pub(super) epoch: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) addr: Vec<u8>,
    }

    /// `PrincipalState` on the wire: `Sync { client_id: active }` when `pending_new` is
    /// `None`, else `Pending { old: active, new: pending_new }`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WirePrincipalState {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) active: Vec<u8>,
        pub(super) pending_new: Option<Vec<u8>>,
    }

    /// The peer's stapled Upd awaiting app approval: (digest, proposal bytes).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct OfferedProposal {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) digest: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) proposal: Vec<u8>,
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
    pub(super) struct SigningIdentityBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) client_id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) classical_signing_key: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) pq_signing_key: Zeroizing<Vec<u8>>,
        /// Retained key packages per half, `(storage id, KeyPackageData)`. Each half's
        /// `KeyPackageData` embeds via its own canonical MLS encoding (as in the invitation
        /// archive), so it stays correct if mls-rs evolves the (non_exhaustive) struct.
        pub(super) classical_kps: Vec<KeyPackageSecret>,
        pub(super) pq_kps: Vec<KeyPackageSecret>,
    }

    /// The initiator's held A.3 ephemeral (`PqInflight::Initiating`) on the wire: the
    /// decapsulation key (kept `Zeroizing`) and the encapsulation key. Round-trips via
    /// `apq::pq_ratchet::PqEphemeral`'s byte accessors.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct PqEphemeralBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) dk: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) ek: Vec<u8>,
    }

    /// The responder's held A.3 shared secret (`PqInflight::Responding`) on the wire.
    /// `Zeroizing` wipes it on drop; a one-field struct so `Option<SecretBlob>` composes
    /// with the byte_vec framing (the `with` module has no Option-awareness).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct SecretBlob {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) bytes: Zeroizing<Vec<u8>>,
    }

    /// The archivable `PqInflight` round state, tag-dispatched by `kind` so all four
    /// variants share one optional-payload struct — the flat-struct style the rest of
    /// this module uses in place of codec enums. The A.5 markers carry no secrets (their
    /// round state lives in the group snapshots); the A.3 variants carry the round's KEM
    /// material (see [`super::TwoMlsPqSession::archive`] for why persisting it is sound).
    ///
    /// - `0` `Initiating`     — `ephemeral` set; `secret`/`rotating` absent.
    /// - `1` `Responding`     — `secret` set; `ephemeral`/`rotating` absent.
    /// - `2` `RekeyInitiated` — `rotating` optional; no KEM payload.
    /// - `3` `RekeyResponded` — no payload.
    ///
    /// `from_archive` rejects any other `kind`, or a payload that does not match `kind`,
    /// as `ArchiveInvalid`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct WirePqInflight {
        pub(super) kind: u8,
        pub(super) ephemeral: Option<PqEphemeralBlob>,
        pub(super) secret: Option<SecretBlob>,
        pub(super) rotating: Option<Vec<u8>>,
    }

    /// The persisted form of a `TwoMlsPqSession`. Everything a session needs to resume,
    /// self-contained (no restoring client is passed): the current signing identity,
    /// identity/turn state, both group snapshots, the cross-party PSK ledger, the
    /// per-epoch listen map, the spawn token, a staged-but-uncommitted rotation, the full
    /// PQ round state, and every parked one-shot frame (dropping a parked side-band frame
    /// whose turn already flipped would desync the side-band permanently).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct SessionArchive {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) session_id: Vec<u8>,
        /// The session's current client signing identity, rebuilt byte-exact on restore
        /// so restore is self-contained (no client argument).
        pub(super) client: SigningIdentityBlob,
        pub(super) my_state: WirePrincipalState,
        pub(super) their_state: WirePrincipalState,
        pub(super) pq_turn_mine: bool,
        pub(super) spawn_token: Option<Vec<u8>>,
        /// Required: every constructor creates a send group, so its absence marks a
        /// forged or corrupt archive.
        pub(super) send_group: GroupEntry,
        pub(super) recv_group: Option<GroupEntry>,
        pub(super) send_psk_ledger: Vec<PskEntry>,
        pub(super) retired_send_psks: Vec<ExternalPskId>,
        pub(super) listen_rendezvous: Vec<ListenEntry>,
        pub(super) pending_outbound: Option<Vec<u8>>,
        pub(super) pending_proposal_hash: Option<Vec<u8>>,
        pub(super) pending_commit_message: Option<Vec<u8>>,
        pub(super) pending_proposal_message: Option<Vec<u8>>,
        pub(super) offered_proposal: Option<OfferedProposal>,
        pub(super) queued_proposal: Option<Vec<u8>>,
        /// A rotation staged by `stage_rotation` but not yet committed: the successor
        /// identity, rebuilt on restore into `pending_new_client`.
        pub(super) pending_new_client: Option<SigningIdentityBlob>,
        pub(super) pending_pq_outbound: Option<Vec<u8>>,
        pub(super) pq_inflight: Option<WirePqInflight>,
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

/// `PqInflight` → its wire form. The A.3 variants carry the round's KEM material; the
/// A.5 markers carry only a discriminant (and an optional rotation ClientId).
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
            rotating: None,
        },
        PqInflight::Responding(s) => WirePqInflight {
            kind: 1,
            ephemeral: None,
            secret: Some(SecretBlob { bytes: s.clone() }),
            rotating: None,
        },
        PqInflight::RekeyInitiated { rotating } => WirePqInflight {
            kind: 2,
            ephemeral: None,
            secret: None,
            rotating: rotating.as_ref().map(|id| id.bytes.clone()),
        },
        PqInflight::RekeyResponded => WirePqInflight {
            kind: 3,
            ephemeral: None,
            secret: None,
            rotating: None,
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
            rotating: None,
        } => Ok(PqInflight::Initiating(
            apq::pq_ratchet::PqEphemeral::from_bytes(&eph.dk, &eph.ek),
        )),
        WirePqInflight {
            kind: 1,
            ephemeral: None,
            secret: Some(s),
            rotating: None,
        } => Ok(PqInflight::Responding(s.bytes)),
        WirePqInflight {
            kind: 2,
            ephemeral: None,
            secret: None,
            rotating,
        } => Ok(PqInflight::RekeyInitiated {
            rotating: rotating.map(|bytes| ClientId { bytes }),
        }),
        WirePqInflight {
            kind: 3,
            ephemeral: None,
            secret: None,
            rotating: None,
        } => Ok(PqInflight::RekeyResponded),
        _ => Err(TwoMlsPqError::ArchiveInvalid),
    }
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

fn encode_pq_bind(pq_commit: Vec<u8>, classical_commit: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(1 + 4 + pq_commit.len() + 4 + classical_commit.len() + 4 + app.len());
    out.push(PQ_BIND_TAG);
    push_section(&mut out, &pq_commit);
    push_section(&mut out, &classical_commit);
    push_section(&mut out, &app);
    out
}

/// Encode the A.4 bootstrap reply: `[0x13][pq_welcome…]`. PQ-groups-only per the spec —
/// no classical commit rides along; ASG-PQ binds into ASG-cl at the next A.3 ratchet.
fn encode_bootstrap_bind(pq_welcome: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + pq_welcome.len());
    out.push(PQ_BOOTSTRAP_BIND_TAG);
    out.extend_from_slice(&pq_welcome);
    out
}

fn decode_bootstrap_bind(bytes: &[u8]) -> Result<Vec<u8>> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BOOTSTRAP_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    Ok(rest.to_vec())
}

fn decode_pq_bind(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [pq_commit, classical_commit, app] = read_sections::<3>(rest)?;
    Ok((pq_commit, classical_commit, app))
}

/// Encode an A.5 rekey Commit' frame: `[0x17][commit][counter-Upd'-or-empty]`.
fn encode_pq_rekey_commit(commit: Vec<u8>, counter_proposal: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + commit.len() + counter_proposal.len());
    out.push(PQ_REKEY_COMMIT_TAG);
    push_section(&mut out, &commit);
    push_section(&mut out, &counter_proposal);
    out
}

fn decode_pq_rekey_commit(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_REKEY_COMMIT_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [commit, counter_proposal] = read_sections::<2>(rest)?;
    Ok((commit, counter_proposal))
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Initiator step 1 — generate an ML-KEM ephemeral and return the encapsulation-key message
    /// (tag 0x0B). The decapsulation key is held until the ciphertext arrives.
    pub fn pq_ratchet_begin(&self) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        if inner.pq_inflight.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let eph = apq::pq_ratchet::generate_ephemeral(&providers::pq_kem()?)?;
        let mut msg = vec![PQ_EK_TAG];
        msg.extend_from_slice(&eph.encapsulation_key());
        inner.pq_inflight = Some(PqInflight::Initiating(eph));
        Ok(msg)
    }

    /// Responder — encapsulate a fresh secret to the initiator's EK, hold it, and return the
    /// ciphertext message (tag 0x0D).
    pub fn pq_ratchet_respond(&self, ek_msg: Vec<u8>) -> Result<()> {
        let (&tag, ek) = ek_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_EK_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pq_inflight.is_some() || inner.pending_pq_outbound.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let (s, ct) = apq::pq_ratchet::encapsulate(&providers::pq_kem()?, ek)?;
        inner.pq_inflight = Some(PqInflight::Responding(Zeroizing::new(s)));
        let mut msg = vec![PQ_CT_TAG];
        msg.extend_from_slice(&ct);
        inner.pending_pq_outbound = Some(msg);
        Ok(())
    }

    /// Initiator step 2 — decapsulate S, inject it into the send group's PQ half via a pathless
    /// commit, bind the exported apq_psk into the classical half, and staple an app message.
    /// Returns the bind frame (tag 0x0F).
    pub fn pq_ratchet_bind(&self, ct_msg: Vec<u8>, app: Vec<u8>) -> Result<()> {
        let (&tag, ct) = ct_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_CT_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pending_pq_outbound.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // Capture the departing epoch's PSK before the classical bind commit below.
        inner.remember_send_psk()?;
        let eph = match inner.pq_inflight.take() {
            Some(PqInflight::Initiating(eph)) => eph,
            _ => return Err(TwoMlsPqError::SessionNotReady),
        };
        let s = Zeroizing::new(apq::pq_ratchet::decapsulate(
            &providers::pq_kem()?,
            &eph,
            ct,
        )?);
        let stores = inner.psk_stores.clone();
        let send = inner
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let send_pq = send.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        let (pq_commit, apq_psk_id) = apq::pq_ratchet::inject_and_commit(send_pq, &s, &stores)?;
        let cl_out = send
            .classical
            .commit_builder()
            .add_external_psk(apq_psk_id.clone())
            .map_err(|_| TwoMlsPqError::Mls)?
            .build()
            .map_err(|_| TwoMlsPqError::Mls)?;
        send.classical
            .apply_pending_commit()
            .map_err(|_| TwoMlsPqError::Mls)?;
        // The bind consumed the one-shot apq PSK; drop it from every store it was
        // registered into (the session registry plus the group-captured handles).
        send.forget_psk(&apq_psk_id);
        apq::forget_psk_stores(&stores, &apq_psk_id);
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
        // Our send group advanced: record the new epoch's PSK in the session ledger.
        inner.remember_send_psk()?;
        // Our operation is complete once the peer applies; the turn passes.
        inner.pq_turn_mine = false;
        inner.pending_pq_outbound = Some(encode_pq_bind(pq_commit, cl_commit, app_ct));
        // The bind committed classically in our send group — capture the new
        // epoch's listen address.
        inner.record_listen_rendezvous()?;
        Ok(())
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
        let stores = inner.psk_stores.clone();
        let recv = inner
            .recv_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let recv_pq = recv.pq.as_mut().ok_or(TwoMlsPqError::SessionNotReady)?;
        let apq_psk_id = apq::pq_ratchet::apply_injected_commit(recv_pq, &s, &pq_commit, &stores)?;
        let cl = MlsMessage::from_bytes(&cl_commit).map_err(|_| TwoMlsPqError::Mls)?;
        recv.classical
            .process_incoming_message(cl)
            .map_err(|_| TwoMlsPqError::Mls)?;
        // The bind consumed the one-shot apq PSK; drop it from every store it was
        // registered into (the session registry plus the group-captured handles).
        recv.forget_psk(&apq_psk_id);
        apq::forget_psk_stores(&stores, &apq_psk_id);
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

    /// A.5 initiator — propose Upd'(self) into the peer's send-PQ (our recv mirror) and
    /// return the 0x15 frame. Requires both PQ halves live (post-A.4 only), the turn, and
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
        let mut inner = self.lock();
        if !inner.pq_turn_mine || inner.pending_pq_outbound.is_some() || inner.pq_inflight.is_some()
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
                let identity = SigningIdentity::new(
                    recv_pq
                        .current_member_signing_identity()
                        .map_err(|_| TwoMlsPqError::Mls)?
                        .credential
                        .clone(),
                    new_public,
                );
                recv_pq
                    .propose_update_with_identity(new_signer, identity, announced_id)
                    .map_err(|_| TwoMlsPqError::Mls)?
            }
            None => recv_pq
                .propose_update(Vec::new())
                .map_err(|_| TwoMlsPqError::Mls)?,
        };
        let mut msg = vec![PQ_REKEY_UPD_TAG];
        msg.extend_from_slice(&proposal.to_bytes().map_err(|_| TwoMlsPqError::Mls)?);
        inner.pq_inflight = Some(PqInflight::RekeyInitiated { rotating });
        Ok(msg)
    }

    /// A.5 responder — commit the initiator's Upd' on our own send-PQ with an updatePath
    /// and a PSK exported from our recv-PQ mirror (the initiator derives the same PSK from
    /// its send-PQ), then park the `[Commit'][counter-Upd'(self)]` frame (0x17) for pickup
    /// via `pq_take_pending_outbound`.
    ///
    /// Returns the ClientId the initiator announced in the Upd's authenticated_data when
    /// this rekey carries an A.5 credential handoff (see `pq_rekey_begin`), else `None`.
    /// By the time this returns, the initiator's leaf in our send-PQ has already moved
    /// to the new principal's signing key. The classical Phase 8 commit remains the
    /// authoritative identity-rotation channel — this reports the PQ half catching up
    /// and does not touch the session's principal state.
    pub fn pq_rekey_respond(&self, upd_msg: Vec<u8>) -> Result<Option<ClientId>> {
        let (&tag, proposal_bytes) = upd_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_REKEY_UPD_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let proposal_msg =
            MlsMessage::from_bytes(proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let mut inner = self.lock();
        if inner.pending_pq_outbound.is_some() || inner.pq_inflight.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        // Cross-PSK from our recv-PQ mirror (§A.5: "Export PSK from [ASG-PQ]") — the
        // initiator registers the same value from its own send-PQ at this epoch.
        let psk_id = {
            let recv_pq = inner
                .recv_group
                .as_ref()
                .and_then(|g| g.pq.as_ref())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let (psk_id, psk) = export_psk(recv_pq)?;
            inner.register_psk(&psk_id, &psk);
            psk_id
        };
        let rotated;
        let commit_bytes = {
            let send_pq = inner
                .send_group
                .as_mut()
                .and_then(|g| g.pq.as_mut())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            match send_pq
                .process_incoming_message(proposal_msg)
                .map_err(|_| TwoMlsPqError::Mls)?
            {
                ReceivedMessage::Proposal(desc) => {
                    rotated = (!desc.authenticated_data.is_empty()).then(|| ClientId {
                        bytes: desc.authenticated_data.clone(),
                    });
                }
                _ => return Err(TwoMlsPqError::Mls),
            }
            let out = send_pq
                .commit_builder()
                .add_external_psk(psk_id)
                .map_err(|_| TwoMlsPqError::Mls)?
                .build()
                .map_err(|_| TwoMlsPqError::Mls)?;
            send_pq
                .apply_pending_commit()
                .map_err(|_| TwoMlsPqError::Mls)?;
            out.commit_message
                .to_bytes()
                .map_err(|_| TwoMlsPqError::Mls)?
        };
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
        Ok(rotated)
    }

    /// Apply an A.5 rekey Commit' (0x17). As the initiator mid-operation (frame carries
    /// the counter-Upd'), apply the peer's commit to our recv mirror, commit the
    /// counter-Upd' on our own send-PQ with the freshly-exported cross-PSK, park the
    /// final 0x17, and return `true` (pick it up via `pq_take_pending_outbound`). As the
    /// responder (empty counter slot), apply the final commit, take the turn, and return
    /// `false` — the operation is complete.
    pub fn pq_rekey_apply(&self, msg: Vec<u8>) -> Result<bool> {
        let (commit_bytes, counter_bytes) = decode_pq_rekey_commit(&msg)?;
        let mut inner = self.lock();
        // Reject unsolicited commits before parsing or registering anything.
        if !matches!(
            inner.pq_inflight,
            Some(PqInflight::RekeyInitiated { .. }) | Some(PqInflight::RekeyResponded)
        ) {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let commit_msg = MlsMessage::from_bytes(&commit_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let client = inner.client.clone();
        // Both roles pre-register the peer's cross-injected PSK: it was exported from the
        // peer's recv-PQ mirror, which is our own send-PQ at its current state.
        {
            let send_pq = inner
                .send_group
                .as_ref()
                .and_then(|g| g.pq.as_ref())
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            let (psk_id, psk) = export_psk(send_pq)?;
            inner.register_psk(&psk_id, &psk);
        }
        match inner.pq_inflight.take() {
            Some(PqInflight::RekeyInitiated { rotating }) => {
                if counter_bytes.is_empty() {
                    return Err(TwoMlsPqError::SessionNotReady);
                }
                let counter_msg =
                    MlsMessage::from_bytes(&counter_bytes).map_err(|_| TwoMlsPqError::Mls)?;
                // Apply the responder's Commit' to our recv mirror, then export the
                // cross-PSK from its NEW epoch (§A.5: "Export PSK from [BSG-PQ]").
                let (psk_id, psk) = {
                    let recv_pq = inner
                        .recv_group
                        .as_mut()
                        .and_then(|g| g.pq.as_mut())
                        .ok_or(TwoMlsPqError::SessionNotReady)?;
                    match recv_pq
                        .process_incoming_message(commit_msg)
                        .map_err(|_| TwoMlsPqError::Mls)?
                    {
                        ReceivedMessage::Commit(_) => {}
                        _ => return Err(TwoMlsPqError::Mls),
                    }
                    export_psk(&*recv_pq)?
                };
                inner.register_psk(&psk_id, &psk);
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
                    match send_pq
                        .process_incoming_message(counter_msg)
                        .map_err(|_| TwoMlsPqError::Mls)?
                    {
                        ReceivedMessage::Proposal(_) => {}
                        _ => return Err(TwoMlsPqError::Mls),
                    }
                    let handoff = match handoff {
                        Some((new_signer, new_public)) => {
                            let identity = SigningIdentity::new(
                                send_pq
                                    .current_member_signing_identity()
                                    .map_err(|_| TwoMlsPqError::Mls)?
                                    .credential
                                    .clone(),
                                new_public,
                            );
                            Some((new_signer, identity))
                        }
                        None => None,
                    };
                    let mut builder = send_pq
                        .commit_builder()
                        .add_external_psk(psk_id)
                        .map_err(|_| TwoMlsPqError::Mls)?;
                    if let Some((new_signer, identity)) = handoff {
                        builder = builder.set_new_signing_identity(new_signer, identity);
                    }
                    let out = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
                    send_pq
                        .apply_pending_commit()
                        .map_err(|_| TwoMlsPqError::Mls)?;
                    out.commit_message
                        .to_bytes()
                        .map_err(|_| TwoMlsPqError::Mls)?
                };
                // Our operation completes once the peer applies; the turn passes.
                inner.pq_turn_mine = false;
                inner.pending_pq_outbound = Some(encode_pq_rekey_commit(commit2, Vec::new()));
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
                    ReceivedMessage::Commit(_) => {}
                    _ => return Err(TwoMlsPqError::Mls),
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

/// A.2 ratchet frame (0x05): own-send-group commit + Upd(self) proposal for the peer's
/// send group + app message. An empty section is permitted (e.g. rotation-less proposal).
fn encode_ratchet(commit: Vec<u8>, proposal: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 12 + commit.len() + proposal.len() + app.len());
    out.push(PARTIAL_TAG);
    push_section(&mut out, &commit);
    push_section(&mut out, &proposal);
    push_section(&mut out, &app);
    out
}

fn decode_ratchet(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PARTIAL_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [commit, proposal, app] = read_sections::<3>(rest)?;
    Ok((commit, proposal, app))
}

/// The rendezvous exporter both routing surfaces derive:
/// `exportSecret("rendezvous", "TwoMLS", 32)` on a group's classical (message) half.
/// Listen-side and post-side addresses align because they are this one derivation.
fn rendezvous_secret(group: &crate::key_package_store::MlsGroup) -> Result<Vec<u8>> {
    group
        .export_secret(RENDEZVOUS_LABEL, RENDEZVOUS_CONTEXT, RENDEZVOUS_LEN)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| TwoMlsPqError::Mls)
}

/// The APQ epoch pair for a combiner group: the PQ side-band epoch (0 while that
/// half is deferred) and the classical message epoch. Single home for the
/// pq-zero-when-deferred rule, shared by `epochs()` and `encrypt()`.
fn apq_epochs(group: &CombinerGroup) -> crate::ApqEpochs {
    crate::ApqEpochs {
        pq_epoch: group.pq.as_ref().map(|p| p.current_epoch()).unwrap_or(0),
        classical_epoch: group.classical.current_epoch(),
    }
}

impl SessionInner {
    /// Register an exported PSK into every store this session's groups resolve from.
    fn register_psk(&self, psk_id: &ExternalPskId, psk: &PreSharedKey) {
        apq::register_psk_stores(&self.psk_stores, psk_id, psk);
    }

    /// Track `client`'s PSK stores so future `register_psk` calls reach any group half
    /// this client creates or joins for the session (A.4 bootstrap, return-welcome join).
    /// Idempotent per client: the common paths re-track the construction client, and
    /// only a Phase 8 rotation actually introduces new stores.
    fn track_psk_stores(&mut self, client: &Arc<TwoMlsPqPrincipal>) {
        if Arc::ptr_eq(client, &self.psk_stores_from) {
            return;
        }
        self.psk_stores_from = Arc::clone(client);
        self.psk_stores
            .push(client.combiner().classical().secret_store());
        self.psk_stores.push(client.combiner().pq().secret_store());
    }

    /// Capture the send group's classical-half rendezvous exporter at its current epoch.
    /// Idempotent per epoch. Called wherever that epoch can advance — group creation,
    /// the A.2/rotation commits in `prepare_to_encrypt`, the A.3 bind — and from
    /// `should_listen_on` as a backstop.
    ///
    /// The listen window follows mls-rs's own epoch retention rather than a second,
    /// invented knob: on each new epoch the group is flushed (`write_to_storage`,
    /// which applies mls-rs's `max_epoch_retention` trim) and addresses whose epoch
    /// the injected group-state storage no longer retains are dropped with it.
    fn record_listen_rendezvous(&mut self) -> Result<()> {
        let Some(send) = self.send_group.as_mut() else {
            return Ok(());
        };
        let group = send.message_group();
        let epoch = group.current_epoch();
        if self.listen_rendezvous.contains_key(&epoch) {
            return Ok(());
        }
        let secret = rendezvous_secret(group)?;
        self.listen_rendezvous.insert(epoch, secret);

        send.message_group_mut()
            .write_to_storage()
            .map_err(|_| TwoMlsPqError::Mls)?;
        let group_id = send.message_group().group_id().to_vec();
        // Probe the storage captured at session construction — the one the send group
        // actually flushes into. NOT `self.client`'s: after a Phase 8 rotation that is
        // the new principal's client with a fresh, empty storage, and probing it would
        // prune every prior epoch's listen address (dropping in-flight traffic).
        let storage = &self.send_group_storage;
        self.listen_rendezvous
            .retain(|&e, _| e == epoch || matches!(storage.epoch(&group_id, e), Ok(Some(_))));
        Ok(())
    }

    /// Transition `my_state` from `Pending { old, new }` to `Sync { new }`.
    /// Called when any message is successfully decrypted from the recv group,
    /// confirming the peer has processed our rotation commit.
    fn resolve_pending_rotation(&mut self) {
        if let PrincipalState::Pending { new, .. } = &self.my_state {
            self.my_state = PrincipalState::Sync {
                client_id: new.clone(),
            };
        }
    }

    /// Record the cross-party TwoMLS-PSK for our send group's current epoch in the
    /// session-owned ledger. Called after every commit we apply on the send group (and
    /// lazily from `inject_send_psks`), so the ledger always covers the epochs the peer
    /// might still reference.
    fn remember_send_psk(&mut self) -> Result<()> {
        let send = self
            .send_group
            .as_ref()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        let (psk_id, psk) = export_psk(&send.classical)?;
        if !self
            .send_psk_ledger
            .iter()
            .any(|(known, _)| *known == psk_id)
        {
            self.send_psk_ledger.push_back((psk_id, psk));
            while self.send_psk_ledger.len() > SEND_PSK_WINDOW {
                if let Some((evicted, _)) = self.send_psk_ledger.pop_front() {
                    self.retired_send_psks.push(evicted);
                }
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
    fn inject_send_psks(&mut self) -> Result<()> {
        self.remember_send_psk()?;
        for (psk_id, psk) in &self.send_psk_ledger {
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

    /// Phase 8: encode a rotation commit on the CLASSICAL send group with `new_id` in
    /// authenticated_data (the PQ side-band is untouched; its epoch advances only on A.3/A.4
    /// rounds). This advances the classical send epoch, which is why the PSK ledger brackets
    /// the commit below.
    fn prepare_rotation(&mut self, new_id: ClientId) -> Result<crate::PrepareEncryptResult> {
        let new_client = self
            .pending_new_client
            .take()
            .ok_or(TwoMlsPqError::SessionNotReady)?;

        if new_client.client_id() != new_id {
            return Err(TwoMlsPqError::SessionNotReady);
        }

        // Capture the departing epoch's PSK before committing past it: a peer frame in
        // flight may reference it, and mls-rs can only export the current epoch.
        self.remember_send_psk()?;

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

        // Our send group advanced: record the new epoch's PSK in the session ledger.
        self.remember_send_psk()?;

        let commit_bytes = commit_output
            .commit_message
            .to_bytes()
            .map_err(|_| TwoMlsPqError::Mls)?;
        // The rotation stages a commit, not a proposal: the binding value is the
        // SHA-256 of the commit message itself (`encrypt` carries it as the app
        // message's authenticated data).
        let proposal_hash = crate::sha256(&commit_bytes);
        self.pending_commit_message = Some(commit_bytes);

        let old_id = self.my_state.client_id();
        self.my_state = PrincipalState::Pending {
            old: old_id,
            new: new_id,
        };
        self.client = new_client;

        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: None,
            did_commit: true,
        })
    }

    /// Routine round (A.2): commit in OUR OWN send group — only the owner commits — and
    /// stage an Upd(self) proposal for the peer's send group to staple alongside. With an
    /// app-approved queued proposal (already cached in the send group via `queue_proposal`),
    /// the commit consumes it and additionally refreshes the cross-party TwoMLS-PSK
    /// exported from the recv group (the peer derives the same PSK from its send group).
    fn prepare_ratchet_commit(&mut self) -> Result<crate::PrepareEncryptResult> {
        let did_commit = self.queued_proposal.take().is_some();

        // Commit our send group only when consuming the peer's approved Upd (cached via
        // `queue_proposal` in the current epoch — committing on routine rounds would
        // invalidate the peer's epoch-bound proposal). The commit also refreshes the
        // cross-party TwoMLS-PSK exported from the recv group.
        if did_commit {
            // Capture the departing epoch's PSK before committing past it: a peer frame in
            // flight may reference it, and mls-rs can only export the current epoch.
            self.remember_send_psk()?;

            // Cross-party TwoMLS-PSK from our recv group. The durable copy is the peer's
            // problem (it is THEIR send-group PSK, held in their ledger); we derive and
            // live-inject into the send group's stores (which the commit build resolves
            // from) immediately before the commit that references it.
            let psk_id = {
                let recv = self
                    .recv_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                let (psk_id, psk) = export_psk(&recv.classical)?;
                let send = self
                    .send_group
                    .as_ref()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.register_psk(&psk_id, &psk);
                psk_id
            };
            let commit_output = {
                let send = self
                    .send_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotReady)?;
                send.classical
                    .commit_builder()
                    .add_external_psk(psk_id.clone())
                    .map_err(|_| TwoMlsPqError::Mls)?
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
                // The commit consumed the one-shot recv-group PSK; drop it from the store.
                send.forget_psk(&psk_id);
            }
            // Our send group advanced: record the new epoch's PSK in the session ledger.
            self.remember_send_psk()?;
            self.pending_commit_message = Some(
                commit_output
                    .commit_message
                    .to_bytes()
                    .map_err(|_| TwoMlsPqError::Mls)?,
            );
        }

        // Upd(self) into the peer's send group — a proposal only; the peer commits it.
        let proposal_msg = {
            let recv = self
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            recv.classical
                .propose_update(Vec::new())
                .map_err(|_| TwoMlsPqError::Mls)?
        };
        let proposal_bytes = proposal_msg.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
        // The binding value is the SHA-256 of the staged Upd(self) proposal — the same
        // value the receiver reports as `QueuedRemoteProposal.digest`, and the classical
        // backend's convention. `encrypt` carries it as the app message's authenticated
        // data, so the staple is verifiable against the frame it rides in.
        let proposal_hash = crate::sha256(&proposal_bytes);
        self.pending_proposal_message = Some(proposal_bytes);

        let their_id = self.their_state.client_id();
        self.pending_proposal_hash = Some(proposal_hash.clone());

        Ok(crate::PrepareEncryptResult {
            proposal_hash,
            committed_remote_client_id: if did_commit { Some(their_id) } else { None },
            did_commit,
        })
    }
}

fn build_session(
    client: Arc<TwoMlsPqPrincipal>,
    send_group: Option<CombinerGroup>,
    recv_group: Option<CombinerGroup>,
    pending_outbound: Option<Vec<u8>>,
    session_id: SessionId,
    their_id: ClientId,
    initiated: bool,
) -> Arc<TwoMlsPqSession> {
    let my_id = client.client_id();
    let send_group_storage = client.combiner().classical_group_storage().clone();
    let psk_stores = vec![
        client.combiner().classical().secret_store(),
        client.combiner().pq().secret_store(),
    ];
    let psk_stores_from = Arc::clone(&client);
    Arc::new(TwoMlsPqSession {
        inner: Mutex::new(SessionInner {
            client,
            send_group,
            recv_group,
            pending_outbound,
            pending_proposal_hash: None,
            pending_commit_message: None,
            pending_proposal_message: None,
            offered_proposal: None,
            queued_proposal: None,
            pending_new_client: None,
            pq_inflight: None,
            session_id,
            my_state: PrincipalState::Sync { client_id: my_id },
            their_state: PrincipalState::Sync {
                client_id: their_id,
            },
            pq_turn_mine: initiated,
            pending_pq_outbound: None,
            send_psk_ledger: VecDeque::new(),
            retired_send_psks: Vec::new(),
            listen_rendezvous: BTreeMap::new(),
            send_group_storage,
            psk_stores,
            psk_stores_from,
            spawn_token: None,
        }),
    })
}

impl TwoMlsPqSession {
    /// Lock the session state, recovering from a poisoned mutex rather than propagating a panic.
    /// A poisoned lock means a prior holder panicked mid-update; we surface the inner state and let
    /// the normal `Option`/`PrincipalState` checks reject any half-applied operation. Used everywhere so
    /// the lock policy is uniform and panic-free (the crate denies `unwrap`/`expect`/`panic`).
    fn lock(&self) -> std::sync::MutexGuard<'_, SessionInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record the opaque spawn token this acceptor session was created under. Called by
    /// `TwoMlsPqInvitation::receive` right after a successful `accept`; `forwarded`
    /// matches replayed initial frames against it.
    pub(crate) fn set_spawn_token(&self, token: Vec<u8>) {
        self.lock().spawn_token = Some(token);
    }
}

#[uniffi::export]
impl TwoMlsPqSession {
    /// Create a session as the initiating party targeting `their_key_package`.
    /// Retrieve the outbound APQWelcome bytes via `pending_outbound`.
    #[uniffi::constructor]
    pub fn initiate(
        client: Arc<TwoMlsPqPrincipal>,
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

        let session = build_session(
            client,
            Some(send_group),
            None,
            Some(apq_welcome),
            session_id,
            their_id,
            true,
        );
        // Seed the PSK ledger with the send group's establishment epoch, and capture
        // the establishment epoch's listen address.
        session.lock().remember_send_psk()?;
        session.lock().record_listen_rendezvous()?;
        Ok(session)
    }

    /// Join a session from an APQWelcome produced by the remote `initiate`.
    /// Retrieve this party's return Welcome via `pending_outbound`.
    ///
    /// `client` must be dedicated to the acceptor role: `accept` clears its key-package store
    /// once the join has consumed the invitation key package (so nothing migrates into the
    /// session archive). Do NOT reuse one `TwoMlsPqPrincipal` for both `initiate` and a direct
    /// `accept` — `initiate` retains its return-group key package in that same store for the
    /// peer's return welcome, and this clear would drop it. The normal entry point,
    /// `TwoMlsPqInvitation::receive`, always builds a fresh invitation-derived client, so this
    /// only concerns direct callers of `accept`.
    #[uniffi::constructor]
    pub fn accept(
        client: Arc<TwoMlsPqPrincipal>,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<Self>> {
        ensure_pq_available(&their_key_package)?;
        let their_parsed = parse_mls_key_package(their_key_package.classical.clone())?;
        let their_id = their_parsed.client_id;
        let session_id = crate::derive_session_id(client.client_id(), their_id.clone())?;

        let recv_group = join_combiner_group(&welcome, client.combiner())?;
        // The invitation's key package has served its one purpose: mls-rs obtained it to join
        // the receive group. The store is only that serving interface, so drop the acceptor's
        // key-package material now — nothing migrates from the invitation into the session (or
        // its archive). This is what actually clears it: mls-rs's own post-join delete is
        // deferred to the group's next `write_to_storage`, which is after `accept` returns.
        // It clears the WHOLE store, which is why `client` must be dedicated to accepting (see
        // the fn docs); `initiate` deliberately does NOT purge, since it must retain its
        // return-group key package. Last-resort reuse is unaffected: it lives on the invitation,
        // which keeps its own captured material and rebuilds a fresh serving store per `receive`.
        client.combiner().classical_kp_store().purge_all();
        client.combiner().pq_kp_store().purge_all();
        // A.4: the send group's PQ half is deferred — classical only, bound to the
        // cross-party PSK. The bootstrap flow stands it up off the critical path, so the
        // return welcome carries an empty PQ slot.
        let (send_group, classical_welcome) = create_bound_classical_send_group(
            &their_key_package.classical,
            client.combiner(),
            &recv_group.classical,
        )?;
        let apq_welcome = encode_apq_welcome(classical_welcome, Vec::new());

        let session = build_session(
            client,
            Some(send_group),
            Some(recv_group),
            Some(apq_welcome),
            session_id,
            their_id,
            false,
        );
        // Seed the PSK ledger with the send group's establishment epoch, and capture
        // the establishment epoch's listen address.
        session.lock().remember_send_psk()?;
        session.lock().record_listen_rendezvous()?;
        Ok(session)
    }

    /// Restore a session from a serialised archive (see `archive` for the single-use
    /// contract). Self-contained: the archive carries the session's signing identity, so
    /// restore rebuilds the exact client internally — no client argument, matching the
    /// classical stack's fully-internalized MLS state. The rebuilt client is byte-exact
    /// (same ClientId and signing keys), giving continuity for any group or leaf created
    /// after the restore; the group snapshots supply their own signing keys as before.
    #[uniffi::constructor]
    pub fn from_archive(archive: Archive) -> Result<Arc<Self>> {
        use mls_rs::mls_rs_codec::MlsDecode;

        let mut rest = match archive.bytes.as_slice() {
            [SESSION_ARCHIVE_VERSION, SESSION_ARCHIVE_PQ_MODE, rest @ ..] => rest,
            _ => return Err(TwoMlsPqError::ArchiveInvalid),
        };
        let wire = archive_wire::SessionArchive::mls_decode(&mut rest)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        if !rest.is_empty() {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }

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

        let my_state = principal_state_from_wire(wire.my_state);
        let their_state = principal_state_from_wire(wire.their_state);

        // Rebuild the session's current client byte-exact from its archived signing
        // identity, and re-mint any staged-but-uncommitted rotation successor. All group
        // storage and PSK plumbing below re-homes onto this client.
        let client = principal_from_wire(wire.client)?;
        let pending_new_client = match wire.pending_new_client {
            Some(blob) => Some(principal_from_wire(blob)?),
            None => None,
        };
        let pq_inflight = wire.pq_inflight.map(pq_inflight_from_wire).transpose()?;

        let group_state = |entry: archive_wire::GroupEntry| apq::CombinerGroupState {
            classical: entry.classical.bytes,
            pq: entry.pq.map(|blob| blob.bytes),
        };
        let send_group =
            apq::load_combiner_group(client.combiner(), &group_state(wire.send_group))?;
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
        let psk_stores = vec![
            client.combiner().classical().secret_store(),
            client.combiner().pq().secret_store(),
        ];
        let psk_stores_from = Arc::clone(&client);
        Ok(Arc::new(TwoMlsPqSession {
            inner: Mutex::new(SessionInner {
                client,
                send_group: Some(send_group),
                recv_group,
                pending_outbound: wire.pending_outbound,
                pending_proposal_hash: wire.pending_proposal_hash,
                pending_commit_message: wire.pending_commit_message,
                pending_proposal_message: wire.pending_proposal_message,
                offered_proposal: wire.offered_proposal.map(|o| (o.digest, o.proposal)),
                queued_proposal: wire.queued_proposal,
                pending_new_client,
                pq_inflight,
                session_id: SessionId {
                    bytes: wire.session_id,
                },
                my_state,
                their_state,
                pq_turn_mine: wire.pq_turn_mine,
                pending_pq_outbound: wire.pending_pq_outbound,
                send_psk_ledger: wire
                    .send_psk_ledger
                    .into_iter()
                    .map(|entry| (entry.id, entry.psk))
                    .collect(),
                retired_send_psks: wire.retired_send_psks,
                listen_rendezvous: wire
                    .listen_rendezvous
                    .into_iter()
                    .map(|entry| (entry.epoch, entry.addr))
                    .collect(),
                send_group_storage,
                psk_stores,
                psk_stores_from,
                spawn_token: wire.spawn_token,
            }),
        }))
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

    /// Consume the side-band frame parked by the responder-side operations
    /// (`pq_ratchet_respond` / `pq_ratchet_bind` / `pq_bootstrap_respond`). Single slot,
    /// single delivery: those operations refuse to start while a frame is waiting.
    pub fn pq_take_pending_outbound(&self) -> Option<Vec<u8>> {
        self.lock().pending_pq_outbound.take()
    }

    /// The send group's APQ epoch pair (PQ side-band, classical message group).
    /// Zeros until the corresponding group exists.
    pub fn epochs(&self) -> crate::ApqEpochs {
        let inner = self.lock();
        inner
            .send_group
            .as_ref()
            .map(apq_epochs)
            .unwrap_or(crate::ApqEpochs {
                pq_epoch: 0,
                classical_epoch: 0,
            })
    }

    /// A.4 initiator — emit this side's PQ key package (tag 0x11) so the peer can stand
    /// up its deferred send-group PQ half. The key package's private material is retained
    /// in this client, so the returned welcome can be joined by `pq_bootstrap_apply`.
    ///
    /// `rotating` must name the session's CURRENT principal (like `pq_rekey_begin`); the KP'
    /// below is generated by that client, so the new leaf carries its credential without
    /// further work — the check is all a bootstrap-time handoff needs.
    pub fn pq_bootstrap_begin(&self, rotating: Option<ClientId>) -> Result<Vec<u8>> {
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
        let kp = inner.client.combiner().generate_pq_key_package()?;
        let mut msg = vec![PQ_BOOTSTRAP_KP_TAG];
        msg.extend_from_slice(&kp);
        Ok(msg)
    }

    /// A.4 responder — stand up the deferred send-group PQ half around the peer's key
    /// package, bind its exported APQ-PSK into the classical half, and return the
    /// bootstrap frame (tag 0x13). Taking this turn makes the next operation ours.
    pub fn pq_bootstrap_respond(&self, kp_msg: Vec<u8>) -> Result<()> {
        let (&tag, kp) = kp_msg.split_first().ok_or(TwoMlsPqError::Mls)?;
        if tag != PQ_BOOTSTRAP_KP_TAG {
            return Err(TwoMlsPqError::Mls);
        }
        let mut inner = self.lock();
        if inner.pending_pq_outbound.is_some() {
            return Err(TwoMlsPqError::SessionNotReady);
        }
        let client = inner.client.clone();
        // The new PQ half resolves PSKs from the CURRENT client's stores (A.4 runs on
        // the principal a Phase 8 rotation may have installed) — track them.
        inner.track_psk_stores(&client);
        let frame = {
            let send = inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if send.pq.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            let (pq_group, pq_welcome) = create_group_with_member(client.pq(), kp, &[])?;
            // PQ-groups-only (spec A.4): no classical bind here. The new PQ half's
            // secrecy reaches ASG-cl at the next A.3 ratchet; until then ASG-cl keeps
            // the PQ-derived security chained in at establishment.
            send.set_pq(pq_group, client.combiner());
            encode_bootstrap_bind(pq_welcome)
        };
        inner.pq_turn_mine = true;
        inner.pending_pq_outbound = Some(frame);
        Ok(())
    }

    /// A.4 initiator completion — join the peer's new PQ group (our key package's
    /// private material is retained in this client), register its APQ-PSK, and apply
    /// the classical bind on the recv group. The turn passes to the peer.
    pub fn pq_bootstrap_apply(&self, bind_msg: Vec<u8>) -> Result<()> {
        let pq_welcome = decode_bootstrap_bind(&bind_msg)?;
        let mut inner = self.lock();
        let client = inner.client.clone();
        // The joined PQ half resolves PSKs from the CURRENT client's stores — track them.
        inner.track_psk_stores(&client);
        {
            let recv = inner
                .recv_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?;
            if recv.pq.is_some() {
                return Err(TwoMlsPqError::SessionNotReady);
            }
            let pq = join_group_from_welcome(client.pq(), &pq_welcome)?;
            recv.set_pq(pq, client.combiner());
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

    pub fn my_principal_state(&self) -> PrincipalState {
        self.lock().my_state.clone()
    }

    pub fn their_principal_state(&self) -> PrincipalState {
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
        let result = match proposing {
            Some(new_id) => inner.prepare_rotation(new_id),
            None => inner.prepare_ratchet_commit(),
        }?;
        // A committing round advanced the send group's classical epoch — capture
        // the new epoch's listen address.
        inner.record_listen_rendezvous()?;
        Ok(result)
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

        let cipher_text = match (
            inner.pending_commit_message.take(),
            inner.pending_proposal_message.take(),
        ) {
            // A.2 ratchet round: own-send-group commit + Upd(self) proposal for the peer.
            (Some(commit), Some(proposal)) => encode_ratchet(commit, proposal, app_bytes),
            // Rotation commit only (credential handoff) → BUNDLED_TAG.
            (Some(commit), None) => encode_bundled(commit, app_bytes),
            // Proposal without a commit should not occur; carry it with an empty commit slot.
            (None, Some(proposal)) => encode_ratchet(Vec::new(), proposal, app_bytes),
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
            epochs,
        })
    }

    /// Process an incoming message.
    ///
    /// - APQWelcome (0x01) → join recv groups; `Ok(None)`
    /// - Rotation commit+app (0x03) → apply the peer's rotation commit to
    ///   `recv_group.classical`, then decrypt; `DecryptResult`
    /// - A.2 ratchet frame (0x05) → apply the commit (if any) to `recv_group.classical`,
    ///   stage the stapled Upd(sender) for app approval, decrypt; `DecryptResult`
    /// - 0x07 (pre-A.2 full bundle) → retired; rejected rather than misparsed
    /// - Stapled welcome (0x09) → join recv groups from the embedded APQWelcome, then
    ///   process the inner frame
    /// - Bare MLS ciphertext → decrypt on `recv_group.classical`; `DecryptResult`
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
            // The joins below resolve PSKs from the CURRENT client's stores (a Phase 8
            // rotation may have replaced the constructing client) — track them first.
            inner.track_psk_stores(&client);

            // Live-inject the session-held cross-party TwoMLS-PSKs (our send group's
            // recent epochs) before joining the peer's bound groups.
            if inner.send_group.is_some() {
                inner.inject_send_psks()?;
            }

            let (classical_welcome, pq_welcome) = decode_apq_welcome(&ciphertext)?;
            // An empty PQ slot is the acceptor's deferred (A.4) return welcome: join the
            // classical group only; the PQ half arrives with the bootstrap flow.
            if pq_welcome.is_empty() {
                let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
                inner.recv_group = Some(CombinerGroup::from_client(
                    client.combiner(),
                    classical,
                    None,
                ));
                return Ok(None);
            }
            // Join the PQ group first, then re-derive the intra-party APQ-PSK from it.
            let pq = join_group_from_welcome(client.pq(), &pq_welcome)?;
            let (psk_id, psk) = export_psk(&pq)?;
            inner.register_psk(&psk_id, &psk);
            // Join the classical group (bound with the cross-party + APQ PSKs).
            let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;

            inner.recv_group = Some(CombinerGroup::from_client(
                client.combiner(),
                classical,
                Some(pq),
            ));
            return Ok(None);
        }

        // A.2 ratchet frame: the sender committed in THEIR OWN send group (our recv
        // group) and stapled an Upd(sender) proposal addressed to OUR send group.
        // Apply the commit, decrypt the app message at the new epoch, and stage the
        // proposal for app approval — it enters our send group only via `queue_proposal`.
        if ciphertext.first() == Some(&PARTIAL_TAG) {
            let (commit_bytes, proposal_bytes, app_bytes) = decode_ratchet(&ciphertext)?;
            let app_msg =
                MlsMessage::from_bytes(&app_bytes).map_err(|_| TwoMlsPqError::DecryptionFailed)?;

            let mut inner = self.lock();

            // The sender's commit may bind the cross-party TwoMLS-PSK of our send group —
            // possibly at an epoch we've since moved past (their frame can cross one of
            // our commits). Live-inject the session-held ledger before processing.
            if inner.send_group.is_some() {
                inner.inject_send_psks()?;
            }

            let (app_data, sender_id, epoch, group_id) = {
                let recv = inner
                    .recv_group
                    .as_mut()
                    .ok_or(TwoMlsPqError::SessionNotEstablished)?;
                if !commit_bytes.is_empty() {
                    let commit_msg = MlsMessage::from_bytes(&commit_bytes)
                        .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
                    match recv
                        .classical
                        .process_incoming_message(commit_msg)
                        .map_err(|_| TwoMlsPqError::DecryptionFailed)?
                    {
                        ReceivedMessage::Commit(_) => {}
                        _ => return Err(TwoMlsPqError::DecryptionFailed),
                    }
                }
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
                        let gid = recv.classical.group_id().to_vec();
                        (desc.data().to_vec(), sender, ep, gid)
                    }
                    _ => return Err(TwoMlsPqError::DecryptionFailed),
                }
            };

            // Stage the stapled Upd(sender) proposal for app approval.
            let proposal = if proposal_bytes.is_empty() {
                None
            } else {
                let digest = crate::sha256(&proposal_bytes);
                inner.offered_proposal = Some((digest.clone(), proposal_bytes));
                Some(crate::QueuedRemoteProposal {
                    digest,
                    sender: sender_id.clone(),
                    proposing: sender_id.clone(),
                    // The ordering context is the SHA-256 of the receive group's
                    // (classical, message-half) group id — `proposal_context`'s value.
                    context: crate::sha256(&group_id),
                })
            };

            inner.resolve_pending_rotation();

            // A commit only rides a frame when it consumed our approved Upd proposal.
            let remote_commit = if commit_bytes.is_empty() {
                None
            } else {
                Some(CommitResult {
                    new_sender: None,
                    new_recipient: inner.my_state.client_id(),
                })
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
            // the new principal's ClientId bytes (set in prepare_to_encrypt Phase 8).
            let new_sender = if commit_auth_data.is_empty() {
                None
            } else {
                Some(ClientId {
                    bytes: commit_auth_data,
                })
            };

            if let Some(ref new_id) = new_sender {
                inner.their_state = PrincipalState::Sync {
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
                // Proposals travel as stapled messages (A.2), not authenticated_data.
                let proposal = None;
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

    /// Serialise the session for persistence; restore with `from_archive`. Archive is
    /// **total** — a session is ALWAYS archivable, in any state, so this never refuses.
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
    /// incoming bind (0x0F) — a permanent side-band desync — so serialization is the only
    /// correct choice.
    pub fn archive(&self) -> Result<Archive> {
        use mls_rs::mls_rs_codec::{MlsEncode, MlsSize};

        let mut inner = self.lock();
        let pq_inflight = inner.pq_inflight.as_ref().map(wire_pq_inflight);
        let client = signing_identity_blob(&inner.client);
        let pending_new_client = inner
            .pending_new_client
            .as_deref()
            .map(signing_identity_blob);

        // Prune the listen map against the same retention window whose epochs the
        // exported snapshots carry, so the archive is internally consistent.
        inner.record_listen_rendezvous()?;

        let group_entry = |state: apq::CombinerGroupState| archive_wire::GroupEntry {
            classical: archive_wire::GroupBlob {
                bytes: state.classical,
            },
            pq: state.pq.map(|bytes| archive_wire::GroupBlob { bytes }),
        };
        let send_group = group_entry(
            inner
                .send_group
                .as_mut()
                .ok_or(TwoMlsPqError::SessionNotReady)?
                .export_state()?,
        );
        let recv_group = match inner.recv_group.as_mut() {
            Some(recv) => Some(group_entry(recv.export_state()?)),
            None => None,
        };

        let archive = archive_wire::SessionArchive {
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
                .map(|(id, psk)| archive_wire::PskEntry {
                    id: id.clone(),
                    psk: psk.clone(),
                })
                .collect(),
            retired_send_psks: inner.retired_send_psks.clone(),
            listen_rendezvous: inner
                .listen_rendezvous
                .iter()
                .map(|(&epoch, addr)| archive_wire::ListenEntry {
                    epoch,
                    addr: addr.clone(),
                })
                .collect(),
            pending_outbound: inner.pending_outbound.clone(),
            pending_proposal_hash: inner.pending_proposal_hash.clone(),
            pending_commit_message: inner.pending_commit_message.clone(),
            pending_proposal_message: inner.pending_proposal_message.clone(),
            offered_proposal: inner.offered_proposal.as_ref().map(|(digest, proposal)| {
                archive_wire::OfferedProposal {
                    digest: digest.clone(),
                    proposal: proposal.clone(),
                }
            }),
            queued_proposal: inner.queued_proposal.clone(),
            pending_new_client,
            pending_pq_outbound: inner.pending_pq_outbound.clone(),
            pq_inflight,
        };

        // Exact-size preallocation: a growing Vec would strand unwiped partial copies of
        // the secrets in freed allocations. The final `Archive.bytes` handed across the
        // FFI is an unwiped copy regardless — hence the sealing obligation above.
        let mut out = Zeroizing::new(Vec::with_capacity(2 + archive.mls_encoded_len()));
        out.push(SESSION_ARCHIVE_VERSION);
        out.push(SESSION_ARCHIVE_PQ_MODE);
        archive
            .mls_encode(&mut out)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        Ok(Archive {
            bytes: out.to_vec(),
        })
    }

    /// Approve the peer's stapled Upd proposal (identified by its digest). The proposal
    /// message enters our send group's proposal cache, and the next
    /// `prepare_to_encrypt(None)` commits it (with a cross-party PSK refresh).
    pub fn queue_proposal(&self, digest: Vec<u8>) -> Result<()> {
        let mut inner = self.lock();
        let (offered, proposal_bytes) = inner
            .offered_proposal
            .take()
            .ok_or(TwoMlsPqError::ProposalRejected)?;
        if offered != digest {
            inner.offered_proposal = Some((offered, proposal_bytes));
            return Err(TwoMlsPqError::ProposalRejected);
        }
        let msg = MlsMessage::from_bytes(&proposal_bytes).map_err(|_| TwoMlsPqError::Mls)?;
        let send = inner
            .send_group
            .as_mut()
            .ok_or(TwoMlsPqError::SessionNotReady)?;
        match send
            .classical
            .process_incoming_message(msg)
            .map_err(|_| TwoMlsPqError::Mls)?
        {
            ReceivedMessage::Proposal(_) => {}
            _ => return Err(TwoMlsPqError::Mls),
        }
        inner.queued_proposal = Some(digest);
        Ok(())
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
        let mut inner = self.lock();
        if inner
            .pending_new_client
            .as_ref()
            .is_some_and(|staged| staged.client_id().bytes == new_client_id)
        {
            return Ok(());
        }
        inner.pending_new_client = Some(TwoMlsPqPrincipal::new(new_client_id)?);
        Ok(())
    }

    /// Acknowledge a replayed initial frame routed here by the invitation's forward
    /// table. `spawn_token` is the caller's opaque identifier for the frame (the same
    /// value it computes for `TwoMlsPqInvitation::forward_group_id`); it must equal the
    /// token this session was spawned under. Returns `Ok(None)`: a PQ initiator cannot
    /// staple a private message pre-establishment, so a replay of the initial frame
    /// never carries an undelivered payload. A mismatched token is a mis-route
    /// (`DecryptionFailed`); initiator-side sessions have no spawn token and refuse
    /// (`SessionNotReady`).
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::TwoMlsPqSession;
    use crate::{
        assert_err, assert_ok, assert_some,
        test_utils::{establish_sessions, make_client, make_combiner_kp},
        PrincipalState, TwoMlsPqError,
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

        let kp_msg = assert_ok!(alice.pq_bootstrap_begin(None));
        assert_ok!(bob.pq_bootstrap_respond(kp_msg));
        let bind = assert_some!(bob.pq_take_pending_outbound());
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
            bob.pq_bootstrap_begin(None),
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
    fn test_routing_available_from_birth_post_after_establishment() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        // Initiator: listening works immediately (send group @ classical epoch 1);
        // nowhere to post until the return welcome stands up the recv group.
        let alice_s = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let listen_a = assert_ok!(alice_s.should_listen_on());
        assert!(!listen_a.send_group.classical.bytes.is_empty());
        assert!(!listen_a.send_group.pq.bytes.is_empty());
        assert_eq!(listen_a.rendezvous_by_epoch.len(), 1);
        assert_eq!(listen_a.rendezvous_by_epoch[0].epoch, 1);
        assert_eq!(
            listen_a.rendezvous_by_epoch[0].rendezvous_id.bytes.len(),
            32
        );
        assert!(assert_ok!(alice_s.send_rendezvous()).is_none());

        // Acceptor: posts immediately — its recv group is the initiator's send
        // group, so its post address is the initiator's listen address verbatim.
        let welcome_a = assert_some!(alice_s.pending_outbound());
        let bob_s = assert_ok!(TwoMlsPqSession::accept(bob, welcome_a, alice_kp));
        let bob_post = assert_some!(assert_ok!(bob_s.send_rendezvous()));
        assert_eq!(
            bob_post.bytes,
            listen_a.rendezvous_by_epoch[0].rendezvous_id.bytes
        );
        // The acceptor's own send group listens too — classical-only pre-A.4.
        let listen_b = assert_ok!(bob_s.should_listen_on());
        assert!(!listen_b.send_group.classical.bytes.is_empty());
        assert!(listen_b.send_group.pq.bytes.is_empty());
        assert_eq!(listen_b.rendezvous_by_epoch.len(), 1);

        // Initiator joins in-band from the stapled return welcome and can post;
        // its address is in the acceptor's listen set.
        let welcome_b = assert_some!(bob_s.pending_outbound());
        assert_ok!(alice_s.process_incoming(welcome_b));
        let alice_post = assert_some!(assert_ok!(alice_s.send_rendezvous()));
        assert!(listen_b
            .rendezvous_by_epoch
            .iter()
            .any(|e| e.rendezvous_id.bytes == alice_post.bytes));
    }

    /// One approved A.2 round: `peer` staples an Upd(self); `committer` approves it and
    /// its next send commits — advancing the committer's send-group classical epoch.
    fn approved_commit_round(committer: &Arc<TwoMlsPqSession>, peer: &Arc<TwoMlsPqSession>) {
        assert_ok!(peer.prepare_to_encrypt(None));
        let upd = assert_ok!(peer.encrypt(b"upd".to_vec()));
        let got = assert_some!(assert_ok!(committer.process_incoming(upd.cipher_text)));
        let offered = assert_some!(got.proposal);
        assert_ok!(committer.queue_proposal(offered.digest));
        let prepared = assert_ok!(committer.prepare_to_encrypt(None));
        assert!(prepared.did_commit);
        let frame = assert_ok!(committer.encrypt(b"commit".to_vec()));
        assert_some!(assert_ok!(peer.process_incoming(frame.cipher_text)));
    }

    #[test]
    fn test_rotation_commit_mints_new_listen_address() {
        let (alice, bob) = establish_sessions();
        let before = assert_ok!(alice.should_listen_on());
        let bob_post_before = assert_some!(assert_ok!(bob.send_rendezvous()));

        // Phase 8 rotation: stage a new client and commit it on alice's send group.
        // The rotation branch shares the listen-address capture point with the
        // ratchet commit — this pins that it actually fires there too.
        let new_client = make_client();
        assert_ok!(alice.stage_rotation(new_client.client_id().bytes));
        let prepared = assert_ok!(alice.prepare_to_encrypt(Some(new_client.client_id())));
        assert!(prepared.did_commit);
        let after = assert_ok!(alice.should_listen_on());
        assert_eq!(
            after.rendezvous_by_epoch.len(),
            before.rendezvous_by_epoch.len() + 1
        );

        // Bob applies the rotation frame; his post address migrates to the new
        // epoch's channel, present in alice's listen set.
        let frame = assert_ok!(alice.encrypt(b"rotate".to_vec()));
        assert_some!(assert_ok!(bob.process_incoming(frame.cipher_text)));
        let bob_post_after = assert_some!(assert_ok!(bob.send_rendezvous()));
        assert_ne!(bob_post_after.bytes, bob_post_before.bytes);
        assert!(after
            .rendezvous_by_epoch
            .iter()
            .any(|e| e.rendezvous_id.bytes == bob_post_after.bytes));
    }

    #[test]
    fn test_rotation_preserves_listen_window_across_epochs() {
        // Regression check for the rotation × listen-window collapse: before
        // per-group persistence, `prepare_rotation`'s client swap left
        // `record_listen_rendezvous` probing the new client's empty storage, so
        // the window collapsed to the current epoch on every later commit
        // ([1,2] → rotate → [3] → [5], never recovering). With storage pulled
        // through the group objects, the swap must not touch the window.
        let epochs = |s: &Arc<TwoMlsPqSession>| -> Vec<u64> {
            assert_ok!(s.should_listen_on())
                .rendezvous_by_epoch
                .iter()
                .map(|e| e.epoch)
                .collect()
        };
        let (alice, bob) = establish_sessions();
        approved_commit_round(&alice, &bob);
        assert_eq!(epochs(&alice), vec![1, 2]);

        // Phase 8 rotation: commit the new principal on alice's send group. The
        // prior epochs must survive the client swap.
        let new_client = make_client();
        assert_ok!(alice.stage_rotation(new_client.client_id().bytes));
        let prepared = assert_ok!(alice.prepare_to_encrypt(Some(new_client.client_id())));
        assert!(prepared.did_commit);
        let frame = assert_ok!(alice.encrypt(b"rotate".to_vec()));
        assert_some!(assert_ok!(bob.process_incoming(frame.cipher_text)));
        assert_eq!(epochs(&alice), vec![1, 2, 3]);

        // And the window keeps growing on later rounds, up to mls-rs's
        // retention cap (current + 3 retained priors).
        approved_commit_round(&alice, &bob);
        assert_eq!(epochs(&alice), vec![1, 2, 3, 4]);
        approved_commit_round(&alice, &bob);
        assert_eq!(epochs(&alice), vec![2, 3, 4, 5]);
    }

    #[test]
    fn test_listen_window_follows_mls_rs_epoch_retention() {
        let (alice, bob) = establish_sessions();
        // Five committed rounds: alice's send group moves from epoch 1 to epoch 6.
        for _ in 0..5 {
            approved_commit_round(&alice, &bob);
        }
        let listen = assert_ok!(alice.should_listen_on());
        let epochs: Vec<u64> = listen.rendezvous_by_epoch.iter().map(|e| e.epoch).collect();
        // The window is NOT all six epochs — it follows the injected group-state
        // storage's retention: current + mls-rs's retained prior epochs (mls-rs
        // in-memory default max_epoch_retention = 3).
        assert_eq!(epochs, vec![3, 4, 5, 6]);
        // Bob's post address still lands inside the retained window.
        let post = assert_some!(assert_ok!(bob.send_rendezvous()));
        assert!(listen
            .rendezvous_by_epoch
            .iter()
            .any(|e| e.rendezvous_id.bytes == post.bytes));
    }

    #[test]
    fn test_encrypt_result_reports_apq_epoch_pair() {
        let (alice, bob) = establish_sessions();

        // Acceptor pre-A.4: classical-only send group — pq epoch 0, not a
        // duplicate of the classical epoch.
        assert_ok!(bob.prepare_to_encrypt(None));
        let upd = assert_ok!(bob.encrypt(b"upd".to_vec()));
        assert_eq!(upd.epochs.pq_epoch, 0);
        assert_eq!(upd.epochs.classical_epoch, 1);

        // Initiator commit round: full APQ pair from birth — pq stays 1 while
        // the commit advances classical to 2 — matching the session's own view.
        let got = assert_some!(assert_ok!(alice.process_incoming(upd.cipher_text)));
        assert_ok!(alice.queue_proposal(assert_some!(got.proposal).digest));
        assert_ok!(alice.prepare_to_encrypt(None));
        let committed = assert_ok!(alice.encrypt(b"commit".to_vec()));
        assert_eq!(committed.epochs.pq_epoch, 1);
        assert_eq!(committed.epochs.classical_epoch, 2);
        let session_view = alice.epochs();
        assert_eq!(committed.epochs.pq_epoch, session_view.pq_epoch);
        assert_eq!(
            committed.epochs.classical_epoch,
            session_view.classical_epoch
        );
    }

    #[test]
    fn test_encrypt_epochs_diverge_post_bootstrap() {
        let (alice, bob) = establish_full();
        // Post-A.4 the acceptor's send group has its PQ half (epoch 1); a commit
        // round moves classical to 2 while pq stays 1 — the pair diverges and
        // encrypt reports it faithfully.
        assert_ok!(alice.prepare_to_encrypt(None));
        let upd = assert_ok!(alice.encrypt(b"upd".to_vec()));
        let got = assert_some!(assert_ok!(bob.process_incoming(upd.cipher_text)));
        assert_ok!(bob.queue_proposal(assert_some!(got.proposal).digest));
        assert_ok!(bob.prepare_to_encrypt(None));
        let committed = assert_ok!(bob.encrypt(b"pq-live".to_vec()));
        assert_eq!(committed.epochs.pq_epoch, 1);
        assert_eq!(committed.epochs.classical_epoch, 2);
    }

    #[test]
    fn test_commit_round_mints_new_listen_address_and_retains_old() {
        let (alice, bob) = establish_sessions();
        let listen_a0 = assert_ok!(alice.should_listen_on());
        let bob_post0 = assert_some!(assert_ok!(bob.send_rendezvous()));

        // Routine (non-committing) rounds don't move epochs or addresses.
        assert_ok!(bob.prepare_to_encrypt(None));
        let upd_frame = assert_ok!(bob.encrypt(b"upd".to_vec()));
        let got = assert_some!(assert_ok!(alice.process_incoming(upd_frame.cipher_text)));
        assert_eq!(
            assert_ok!(alice.should_listen_on())
                .rendezvous_by_epoch
                .len(),
            listen_a0.rendezvous_by_epoch.len()
        );

        // Full A.2 round: alice approves bob's stapled Upd; her next send commits
        // it, advancing her send group's classical epoch and minting a new address.
        let offered = assert_some!(got.proposal);
        assert_ok!(alice.queue_proposal(offered.digest));
        let prepared = assert_ok!(alice.prepare_to_encrypt(None));
        assert!(prepared.did_commit);
        let commit_frame = assert_ok!(alice.encrypt(b"commit".to_vec()));

        let listen_a1 = assert_ok!(alice.should_listen_on());
        assert_eq!(
            listen_a1.rendezvous_by_epoch.len(),
            listen_a0.rendezvous_by_epoch.len() + 1
        );

        // Bob applies the commit: his post address migrates to the new epoch's
        // channel — present in alice's set — while the old address stays listed.
        assert_some!(assert_ok!(bob.process_incoming(commit_frame.cipher_text)));
        let bob_post1 = assert_some!(assert_ok!(bob.send_rendezvous()));
        assert_ne!(bob_post1.bytes, bob_post0.bytes);
        assert!(listen_a1
            .rendezvous_by_epoch
            .iter()
            .any(|e| e.rendezvous_id.bytes == bob_post1.bytes));
        assert!(listen_a1
            .rendezvous_by_epoch
            .iter()
            .any(|e| e.rendezvous_id.bytes == bob_post0.bytes));
    }

    #[test]
    fn test_pq_ratchet_bind_mints_new_listen_address() {
        let (alice, bob) = establish_sessions();
        let before = assert_ok!(alice.should_listen_on())
            .rendezvous_by_epoch
            .len();

        // A.3: the bind's classical commit advances alice's send-group epoch.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"bind".to_vec()));
        let listen_a = assert_ok!(alice.should_listen_on());
        assert_eq!(listen_a.rendezvous_by_epoch.len(), before + 1);

        // Bob applies the bind; his post address lands on the new epoch's channel.
        let bind = assert_some!(alice.pq_take_pending_outbound());
        assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"bind");
        let bob_post = assert_some!(assert_ok!(bob.send_rendezvous()));
        assert!(listen_a
            .rendezvous_by_epoch
            .iter()
            .any(|e| e.rendezvous_id.bytes == bob_post.bytes));
    }

    /// Drive one full A.5 rekey with `initiator` holding the turn. Returns after the
    /// responder applies the final commit (turn flipped to the responder).
    fn rekey_round(initiator: &Arc<TwoMlsPqSession>, responder: &Arc<TwoMlsPqSession>) {
        let upd = assert_ok!(initiator.pq_rekey_begin(None));
        assert_eq!(upd.first(), Some(&super::PQ_REKEY_UPD_TAG));
        // A rotation-less rekey announces no credential.
        assert!(assert_ok!(responder.pq_rekey_respond(upd)).is_none());
        let reply = assert_some!(responder.pq_take_pending_outbound());
        assert!(assert_ok!(initiator.pq_rekey_apply(reply)));
        let fin = assert_some!(initiator.pq_take_pending_outbound());
        assert!(!assert_ok!(responder.pq_rekey_apply(fin)));
    }

    #[test]
    fn test_pq_rekey_full_round() {
        let (alice, bob) = establish_full();
        // Bob holds the turn after Alice's bootstrap completed.
        assert!(bob.my_pq_turn());
        let alice_classical = alice.epochs().classical_epoch;
        let alice_listen = assert_ok!(alice.should_listen_on())
            .rendezvous_by_epoch
            .len();

        rekey_round(&bob, &alice);

        // Both send groups' PQ epochs advanced; classical and the listen map are
        // untouched (A.5 is PQ-groups-only); the turn flipped back to Alice.
        assert_eq!(alice.epochs().pq_epoch, 2);
        assert_eq!(bob.epochs().pq_epoch, 2);
        assert_eq!(alice.epochs().classical_epoch, alice_classical);
        assert_eq!(
            assert_ok!(alice.should_listen_on())
                .rendezvous_by_epoch
                .len(),
            alice_listen
        );
        assert!(alice.my_pq_turn());
        assert!(!bob.my_pq_turn());

        // Messaging still flows both ways on the rekeyed groups, and the next
        // encrypt reports the bumped pq epoch.
        assert_ok!(alice.prepare_to_encrypt(None));
        let a2b = assert_ok!(alice.encrypt(b"post-rekey".to_vec()));
        assert_eq!(a2b.epochs.pq_epoch, 2);
        let got = assert_ok!(bob.process_incoming(a2b.cipher_text));
        assert_eq!(
            assert_some!(assert_some!(got).application_message).app_message_data,
            b"post-rekey".to_vec()
        );

        // Consecutive rekeys work: the turn machine supports Alice going next.
        rekey_round(&alice, &bob);
        assert_eq!(alice.epochs().pq_epoch, 3);
        assert_eq!(bob.epochs().pq_epoch, 3);
    }

    #[test]
    fn test_pq_rekey_then_ratchet_still_works() {
        let (alice, bob) = establish_full();
        rekey_round(&bob, &alice);
        // A.3 ratchet after a rekey: Alice holds the turn.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"post-rekey-ratchet".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        assert_eq!(
            assert_ok!(bob.pq_ratchet_apply(bind)),
            b"post-rekey-ratchet"
        );
    }

    #[test]
    fn test_pq_rekey_requires_full_establishment() {
        // Pre-A.4 the acceptor's send-PQ (and the initiator's recv mirror) is missing.
        let (alice, _bob) = establish_sessions();
        assert!(alice.my_pq_turn());
        assert_err!(alice.pq_rekey_begin(None), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    fn test_pq_rekey_requires_turn_and_rejects_unsolicited() {
        let (alice, bob) = establish_full();
        // Alice's bootstrap completion passed the turn to Bob.
        assert_err!(alice.pq_rekey_begin(None), TwoMlsPqError::SessionNotReady);
        // An unsolicited final commit (no rekey in flight) is rejected.
        let bogus = super::encode_pq_rekey_commit(vec![0u8; 8], Vec::new());
        assert_err!(bob.pq_rekey_apply(bogus), TwoMlsPqError::SessionNotReady);
        // A second begin while one is in flight is rejected (single slot).
        let _upd = assert_ok!(bob.pq_rekey_begin(None));
        assert_err!(bob.pq_rekey_begin(None), TwoMlsPqError::SessionNotReady);
    }

    /// The session's own leaf signature public keys in (send-PQ, recv-PQ) — the two
    /// leaves an A.5 credential handoff must move to the new principal.
    fn own_pq_leaf_signature_keys(session: &Arc<TwoMlsPqSession>) -> (Vec<u8>, Vec<u8>) {
        let inner = session.lock();
        let send = inner
            .send_group
            .as_ref()
            .and_then(|g| g.pq.as_ref())
            .expect("send-PQ live")
            .current_member_signing_identity()
            .expect("send-PQ leaf")
            .signature_key
            .as_bytes()
            .to_vec();
        let recv = inner
            .recv_group
            .as_ref()
            .and_then(|g| g.pq.as_ref())
            .expect("recv-PQ live")
            .current_member_signing_identity()
            .expect("recv-PQ leaf")
            .signature_key
            .as_bytes()
            .to_vec();
        (send, recv)
    }

    #[test]
    fn test_pq_rekey_rotation_hands_pq_leaves_to_new_principal() {
        let (alice, bob) = establish_full();

        // Phase 8 first: the classical rotation swaps the session client to the new
        // principal (whose signing keys `stage_rotation` minted internally) and announces the
        // ClientId to the peer.
        let new_bob_id = make_client().client_id();
        assert_ok!(bob.stage_rotation(new_bob_id.bytes.clone()));
        assert!(assert_ok!(bob.prepare_to_encrypt(Some(new_bob_id.clone()))).did_commit);
        let enc = assert_ok!(bob.encrypt(b"rotate".to_vec()));
        assert_some!(assert_ok!(alice.process_incoming(enc.cipher_text)));

        // The successor's PQ signing key is now the session's current client — that is
        // what the A.5 handoff must install into both leaves.
        let new_key = {
            let inner = bob.lock();
            inner
                .client
                .combiner()
                .pq_signature_keypair()
                .1
                .as_bytes()
                .to_vec()
        };
        // The PQ leaves still sign as the old principal until the A.5 handoff.
        let before = own_pq_leaf_signature_keys(&bob);
        assert_ne!(before.0, new_key);
        assert_ne!(before.1, new_key);

        // A.5 with the credential handoff; the responder learns the announced id.
        let upd = assert_ok!(bob.pq_rekey_begin(Some(new_bob_id.clone())));
        assert_eq!(
            assert_some!(assert_ok!(alice.pq_rekey_respond(upd))),
            new_bob_id
        );
        let reply = assert_some!(alice.pq_take_pending_outbound());
        assert!(assert_ok!(bob.pq_rekey_apply(reply)));
        let fin = assert_some!(bob.pq_take_pending_outbound());
        assert!(!assert_ok!(alice.pq_rekey_apply(fin)));

        // Both of Bob's PQ leaves now sign with the new principal's key.
        let after = own_pq_leaf_signature_keys(&bob);
        assert_eq!(after.0, new_key);
        assert_eq!(after.1, new_key);

        // The rekeyed, rotated groups keep working: messaging flows and the next
        // rekey round (Alice's turn) proceeds — the new signer owns the leaves.
        assert_ok!(bob.prepare_to_encrypt(None));
        let msg = assert_ok!(bob.encrypt(b"post-handoff".to_vec()));
        let got = assert_ok!(alice.process_incoming(msg.cipher_text));
        assert_eq!(
            assert_some!(assert_some!(got).application_message).app_message_data,
            b"post-handoff".to_vec()
        );
        rekey_round(&alice, &bob);
    }

    /// Phase 8 swaps the session client, but the existing groups keep resolving
    /// external PSKs from the stores of the clients that created them. Every
    /// PSK-carrying flow must still work after a rotation — this pins the
    /// psk_stores registry (a plain rekey, an A.3 ratchet, and a full classical
    /// commit round, all post-rotation, no credential handoff involved).
    #[test]
    fn test_psk_flows_survive_rotation_without_handoff() {
        let (alice, bob) = establish_full();

        let new_bob = make_client();
        assert_ok!(bob.stage_rotation(new_bob.client_id().bytes));
        assert_ok!(bob.prepare_to_encrypt(Some(new_bob.client_id())));
        let enc = assert_ok!(bob.encrypt(b"rotate".to_vec()));
        assert_some!(assert_ok!(alice.process_incoming(enc.cipher_text)));

        // A.5 plain rekey, initiated by the rotated side (Bob holds the turn).
        rekey_round(&bob, &alice);

        // A.3 ratchet with the rotated side responding (Alice's turn now).
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"post-rotation-ratchet".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        assert_eq!(
            assert_ok!(bob.pq_ratchet_apply(bind)),
            b"post-rotation-ratchet"
        );

        // Full classical commit round from the rotated side: Alice staples an Upd
        // that Bob approves and commits with a cross-party PSK refresh.
        assert_ok!(alice.prepare_to_encrypt(None));
        let a2b = assert_ok!(alice.encrypt(b"staple".to_vec()));
        let got = assert_some!(assert_ok!(bob.process_incoming(a2b.cipher_text)));
        let offered = assert_some!(got.proposal);
        assert_ok!(bob.queue_proposal(offered.digest));
        assert!(assert_ok!(bob.prepare_to_encrypt(None)).did_commit);
        let b2a = assert_ok!(bob.encrypt(b"full-commit".to_vec()));
        assert_eq!(
            assert_some!(
                assert_some!(assert_ok!(alice.process_incoming(b2a.cipher_text)))
                    .application_message
            )
            .app_message_data,
            b"full-commit"
        );
    }

    #[test]
    fn test_pq_rekey_begin_rotating_requires_current_agent() {
        let (_alice, bob) = establish_full();
        // Bob holds the turn, but no Phase 8 rotation has run: a handoff to an
        // arbitrary principal is refused, and the slot stays free for a plain rekey.
        let stranger = make_client();
        assert_err!(
            bob.pq_rekey_begin(Some(stranger.client_id())),
            TwoMlsPqError::SessionNotReady
        );
        assert_ok!(bob.pq_rekey_begin(None));
    }

    #[test]
    fn test_pq_bootstrap_begin_rotating_requires_current_agent() {
        let (alice, bob) = establish_sessions();
        let stranger = make_client();
        assert_err!(
            alice.pq_bootstrap_begin(Some(stranger.client_id())),
            TwoMlsPqError::SessionNotReady
        );

        // After a Phase 8 rotation the bootstrap accepts the handoff id, and the
        // KP' it emits — generated by the new principal — completes A.4 as usual.
        let new_alice = make_client();
        let new_alice_id = new_alice.client_id();
        assert_ok!(alice.stage_rotation(new_alice.client_id().bytes));
        assert_ok!(alice.prepare_to_encrypt(Some(new_alice_id.clone())));
        let enc = assert_ok!(alice.encrypt(b"rotate".to_vec()));
        assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));

        let kp = assert_ok!(alice.pq_bootstrap_begin(Some(new_alice_id)));
        assert_ok!(bob.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_bootstrap_apply(bind));
        assert!(bob.my_pq_turn());
    }

    #[test]
    fn test_a4_bootstrap_mints_no_listen_addresses_but_advertises_pq_id() {
        let (alice, bob) = establish_sessions();
        let bob_before = assert_ok!(bob.should_listen_on());
        assert!(bob_before.send_group.pq.bytes.is_empty());

        let kp = assert_ok!(alice.pq_bootstrap_begin(None));
        assert_ok!(bob.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_bootstrap_apply(bind));

        // A.4 is PQ-groups-only: no classical commit, no new listen addresses —
        // but the acceptor's send group now advertises its PQ half.
        let bob_after = assert_ok!(bob.should_listen_on());
        assert_eq!(
            bob_after.rendezvous_by_epoch.len(),
            bob_before.rendezvous_by_epoch.len()
        );
        assert!(!bob_after.send_group.pq.bytes.is_empty());
    }

    #[test]
    fn test_pq_ratchet_round_trip_delivers_app_message() {
        let (alice, bob) = establish_sessions();
        // Alice initiates a PQ ratchet on her send group; Bob responds and applies.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"hello-pq".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        let got = assert_ok!(bob.pq_ratchet_apply(bind));
        assert_eq!(got, b"hello-pq");
    }

    /// The PQ side-band must survive a principal rotation: the injected-secret and apq PSKs
    /// have to land in the stores the group halves actually resolve from (captured at
    /// group creation), not the rotated-in client's stores — otherwise Alice's bind and
    /// Bob's apply both fail to find their PSKs after the client swap.
    #[test]
    fn test_pq_ratchet_completes_after_principal_rotation() {
        let (alice, bob) = establish_sessions();

        // Rotate both principals, delivering each rotation commit so the peer's recv group
        // tracks the new epoch.
        let new_alice = make_client();
        assert_ok!(alice.stage_rotation(new_alice.client_id().bytes));
        assert_ok!(alice.prepare_to_encrypt(Some(new_alice.client_id())));
        let enc = assert_ok!(alice.encrypt(b"alice-rotated".to_vec()));
        assert_some!(assert_ok!(bob.process_incoming(enc.cipher_text)));

        let new_bob = make_client();
        assert_ok!(bob.stage_rotation(new_bob.client_id().bytes));
        assert_ok!(bob.prepare_to_encrypt(Some(new_bob.client_id())));
        let enc = assert_ok!(bob.encrypt(b"bob-rotated".to_vec()));
        assert_some!(assert_ok!(alice.process_incoming(enc.cipher_text)));

        // A full A.3 round after both rotations: Alice injects on her send group's PQ half
        // and binds into its classical half; Bob applies on his recv halves.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"pq-after-rotation".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"pq-after-rotation");
    }

    /// Complete the A.4 bootstrap after establishment so both directions are full
    /// APQ — required before the deferred acceptor side can ratchet.
    fn establish_full() -> (Arc<TwoMlsPqSession>, Arc<TwoMlsPqSession>) {
        let (alice, bob) = establish_sessions();
        let kp = assert_ok!(alice.pq_bootstrap_begin(None));
        assert_ok!(bob.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_bootstrap_apply(bind));
        (alice, bob)
    }

    #[test]
    fn test_pq_ratchet_turn_flips_to_responder() {
        let (alice, bob) = establish_full();
        // Round 1: Alice initiates.
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"a1".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        assert_eq!(assert_ok!(bob.pq_ratchet_apply(bind)), b"a1");
        // Round 2: turn flips — Bob initiates on his send group, Alice applies.
        let ek2 = assert_ok!(bob.pq_ratchet_begin());
        assert_ok!(alice.pq_ratchet_respond(ek2));
        let ct2 = assert_some!(alice.pq_take_pending_outbound());
        assert_ok!(bob.pq_ratchet_bind(ct2, b"b1".to_vec()));
        let bind2 = assert_some!(bob.pq_take_pending_outbound());
        assert_eq!(assert_ok!(alice.pq_ratchet_apply(bind2)), b"b1");
    }

    #[test]
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
    fn test_classical_round_still_works_after_pq_ratchet() {
        let (alice, bob) = establish_sessions();
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"pq".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
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
    fn test_three_sequential_pq_ratchets_alternate_and_deliver() {
        let (alice, bob) = establish_full();
        for (i, (initiator, responder)) in [(&alice, &bob), (&bob, &alice), (&alice, &bob)]
            .iter()
            .enumerate()
        {
            let payload = vec![i as u8; 8];
            let ek = assert_ok!(initiator.pq_ratchet_begin());
            assert_ok!(responder.pq_ratchet_respond(ek));
            let ct = assert_some!(responder.pq_take_pending_outbound());
            assert_ok!(initiator.pq_ratchet_bind(ct, payload.clone()));
            let bind = assert_some!(initiator.pq_take_pending_outbound());
            assert_eq!(assert_ok!(responder.pq_ratchet_apply(bind)), payload);
        }
    }

    #[test]
    fn test_pq_ratchet_respond_rejects_wrong_tag() {
        let (_alice, bob) = establish_sessions();
        assert_err!(
            bob.pq_ratchet_respond(vec![0xAB, 1, 2, 3]),
            TwoMlsPqError::Mls
        );
    }

    #[test]
    fn test_pq_frame_routed_to_process_incoming_is_rejected() {
        let (_alice, bob) = establish_sessions();
        // A PQ-ratchet EK frame must never be silently swallowed as an MLS ciphertext.
        let mut ek = vec![super::PQ_EK_TAG];
        ek.extend_from_slice(&[0u8; 8]);
        assert_err!(bob.process_incoming(ek), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    fn test_pq_ratchet_apply_without_respond_is_rejected() {
        let (alice, bob) = establish_sessions();
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let ct = assert_some!(bob.pq_take_pending_outbound());
        assert_ok!(alice.pq_ratchet_bind(ct, b"x".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        // A different session that never responded has no held secret.
        let (_a2, b2) = establish_sessions();
        assert_err!(b2.pq_ratchet_apply(bind), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    fn test_pq_ratchet_double_begin_is_rejected() {
        let (alice, _bob) = establish_sessions();
        assert_ok!(alice.pq_ratchet_begin());
        assert_err!(alice.pq_ratchet_begin(), TwoMlsPqError::SessionNotReady);
    }

    #[test]
    fn test_pq_ratchet_tampered_ciphertext_fails_to_apply() {
        let (alice, bob) = establish_sessions();
        let ek = assert_ok!(alice.pq_ratchet_begin());
        assert_ok!(bob.pq_ratchet_respond(ek));
        let mut ct = assert_some!(bob.pq_take_pending_outbound());
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        // Alice binds a divergent S (ML-KEM implicit rejection); Bob holds the real S → apply fails.
        assert_ok!(alice.pq_ratchet_bind(ct, b"x".to_vec()));
        let bind = assert_some!(alice.pq_take_pending_outbound());
        assert_err!(bob.pq_ratchet_apply(bind), TwoMlsPqError::Mls);
    }

    #[test]
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
        assert!(!result.proposal_hash.is_empty());
        assert!(!result.did_commit);
    }

    #[test]
    fn test_encrypt_after_prepare_succeeds() {
        let (alice_session, _bob_session) = establish_sessions();
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let result = assert_ok!(alice_session.encrypt(b"hello world".to_vec()));
        assert!(!result.cipher_text.is_empty());
        assert_eq!(
            result.sender,
            alice_session.my_principal_state().client_id()
        );
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
            alice_session.my_principal_state().client_id()
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
    fn test_join_send_group_with_my_principal_succeeds() {
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
    fn test_create_bound_send_group_ml_kem_768_with_psk_succeeds() {
        let (alice_session, bob_session) = establish_sessions();
        assert!(alice_session.is_established());
        assert!(bob_session.is_established());
    }

    #[test]
    fn test_from_archive_returns_archive_invalid() {
        assert_err!(
            TwoMlsPqSession::from_archive(crate::Archive { bytes: vec![] }),
            TwoMlsPqError::ArchiveInvalid
        );
    }

    /// One plain application round: `sender` encrypts, `receiver` decrypts, payload matches.
    fn message_round(
        sender: &Arc<TwoMlsPqSession>,
        receiver: &Arc<TwoMlsPqSession>,
        payload: &[u8],
    ) {
        assert_ok!(sender.prepare_to_encrypt(None));
        let enc = assert_ok!(sender.encrypt(payload.to_vec()));
        let got = assert_some!(assert_ok!(receiver.process_incoming(enc.cipher_text)));
        assert_eq!(
            assert_some!(got.application_message).app_message_data,
            payload
        );
    }

    /// Archive `session` and restore it (self-contained — the archive rebuilds its own
    /// client, so no identity is passed).
    fn round_trip(session: &Arc<TwoMlsPqSession>) -> Arc<TwoMlsPqSession> {
        let archive = assert_ok!(session.archive());
        assert_ok!(TwoMlsPqSession::from_archive(archive))
    }

    #[test]
    fn test_archive_round_trips_session_state() {
        let (alice_session, bob_session) = establish_sessions();
        message_round(&alice_session, &bob_session, b"before");

        let session_id = alice_session.active_session_id();
        let restored = round_trip(&alice_session);
        assert_eq!(restored.active_session_id(), session_id);

        // Both directions keep flowing across the restore.
        message_round(&restored, &bob_session, b"restored->bob");
        message_round(&bob_session, &restored, b"bob->restored");
    }

    #[test]
    fn test_archive_before_return_welcome_join_restores_and_joins() {
        // The initiator archives right after `initiate` — before the peer's return welcome
        // exists — so its return-group key package is still pending in the client store and
        // the recv group is not yet joined. A self-contained restore must carry that key
        // package, or the return-welcome join below fails (an empty-store restore cannot
        // find the private material the welcome addresses). This is the archive-returning
        // `reply` path the Swift adapter drives.
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());

        // Archive and restore the initiator BEFORE it has joined the return welcome.
        let restored_alice = round_trip(&alice_session);
        assert!(restored_alice.receive_group_id().is_none());

        let bob_session = assert_ok!(TwoMlsPqSession::accept(
            Arc::clone(&bob),
            welcome_a,
            alice_kp
        ));
        let welcome_b = assert_some!(bob_session.pending_outbound());
        // The restored initiator joins the return welcome using its carried key package.
        assert_ok!(restored_alice.process_incoming(welcome_b));
        assert!(restored_alice.receive_group_id().is_some());

        // Both directions flow on the restored, now-established session.
        message_round(&restored_alice, &bob_session, b"restored-join");
        message_round(&bob_session, &restored_alice, b"back");
    }

    #[test]
    fn test_archive_round_trips_fully_established_session() {
        let (alice_session, bob_session) = establish_sessions();
        let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
        assert_ok!(bob_session.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_ok!(alice_session.pq_bootstrap_apply(bind));
        assert!(alice_session.is_fully_established());

        let restored = round_trip(&alice_session);
        assert!(restored.is_fully_established());

        // The PQ side-band still runs: a full A.3 ratchet round initiated by the
        // restored side (Bob holds the turn after the bootstrap, so pass it back first).
        let ek = assert_ok!(bob_session.pq_ratchet_begin());
        assert_ok!(restored.pq_ratchet_respond(ek));
        let ct = assert_some!(restored.pq_take_pending_outbound());
        assert_ok!(bob_session.pq_ratchet_bind(ct, b"pq-after-restore".to_vec()));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_eq!(
            assert_ok!(restored.pq_ratchet_apply(bind)),
            b"pq-after-restore"
        );
        message_round(&restored, &bob_session, b"classical-after-pq");
    }

    #[test]
    fn test_archive_preserves_listen_map() {
        let (alice_session, bob_session) = establish_sessions();
        // Advance the send epoch (full commit round) so the map holds several epochs.
        message_round(&alice_session, &bob_session, b"staple");
        message_round(&bob_session, &alice_session, b"staple-back");
        let offered = {
            assert_ok!(bob_session.prepare_to_encrypt(None));
            let enc = assert_ok!(bob_session.encrypt(b"upd".to_vec()));
            let got = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
            assert_some!(got.proposal)
        };
        assert_ok!(alice_session.queue_proposal(offered.digest));
        assert!(assert_ok!(alice_session.prepare_to_encrypt(None)).did_commit);
        let enc = assert_ok!(alice_session.encrypt(b"commit".to_vec()));
        assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

        let before = assert_ok!(alice_session.should_listen_on());
        assert!(before.rendezvous_by_epoch.len() > 1);

        let restored = round_trip(&alice_session);
        let after = assert_ok!(restored.should_listen_on());
        assert_eq!(
            before.send_group.classical.bytes,
            after.send_group.classical.bytes
        );
        let pairs = |chans: &crate::ListenChannels| {
            chans
                .rendezvous_by_epoch
                .iter()
                .map(|e| (e.epoch, e.rendezvous_id.bytes.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(pairs(&before), pairs(&after));
    }

    #[test]
    fn test_archive_preserves_spawn_token() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_inv = assert_ok!(crate::key_packages::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());
        let token = b"spawn-token".to_vec();
        let bob_session = assert_ok!(bob_inv.receive(welcome_a, alice_kp, token.clone()));

        let restored = round_trip(&bob_session);
        assert!(assert_ok!(restored.forwarded(token)).is_none());
        assert_err!(
            restored.forwarded(b"other".to_vec()),
            TwoMlsPqError::DecryptionFailed
        );
    }

    /// The restored PSK ledger — not the (empty) stores of the rebuilt client — must
    /// resolve the cross-party PSK a peer commit references: Bob's full commit binds the
    /// PSK of Alice's send group at the epoch he last observed, and the restored Alice
    /// runs on a rebuilt identity whose mls-rs secret stores hold nothing.
    #[test]
    fn test_archive_preserves_psk_ledger_for_peer_commit() {
        let (alice_session, bob_session) = establish_sessions();
        // Alice staples an Upd for Bob to approve.
        message_round(&alice_session, &bob_session, b"staple");
        let offered = {
            assert_ok!(alice_session.prepare_to_encrypt(None));
            let enc = assert_ok!(alice_session.encrypt(b"upd".to_vec()));
            let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
            assert_some!(got.proposal)
        };
        assert_ok!(bob_session.queue_proposal(offered.digest));
        assert!(assert_ok!(bob_session.prepare_to_encrypt(None)).did_commit);
        let crossing = assert_ok!(bob_session.encrypt(b"bound-commit".to_vec()));

        // Alice archives before Bob's bound frame arrives; the restore rebuilds her
        // client with empty PSK stores.
        let restored = round_trip(&alice_session);
        let got = assert_some!(assert_ok!(restored.process_incoming(crossing.cipher_text)));
        assert_eq!(
            assert_some!(got.application_message).app_message_data,
            b"bound-commit"
        );
    }

    /// Prepared-but-unsent state survives: the staged proposal/commit emit after restore
    /// and the peer accepts the frame.
    #[test]
    fn test_archive_preserves_prepared_encrypt_state() {
        let (alice_session, bob_session) = establish_sessions();
        assert_ok!(alice_session.prepare_to_encrypt(None));

        let restored = round_trip(&alice_session);
        let enc = assert_ok!(restored.encrypt(b"prepared-before-archive".to_vec()));
        let got = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
        assert_eq!(
            assert_some!(got.application_message).app_message_data,
            b"prepared-before-archive"
        );
    }

    /// A committed-but-unconfirmed rotation (`my_state == Pending`) archives, restores
    /// self-contained (the archive rebuilds the NEW principal's client — parameterless
    /// restore), and resolves to `Sync` once the peer's traffic confirms.
    #[test]
    fn test_archive_mid_rotation_restores_onto_new_client() {
        let (alice_session, bob_session) = establish_sessions();
        message_round(&alice_session, &bob_session, b"before");

        // A fresh opaque ClientId for the successor principal (the app owns only the id; the
        // signing keys are minted internally by `stage_rotation`).
        let new_id = make_client().client_id();
        assert_ok!(alice_session.stage_rotation(new_id.bytes.clone()));
        assert_ok!(alice_session.prepare_to_encrypt(Some(new_id.clone())));
        let rotation = assert_ok!(alice_session.encrypt(b"rotate".to_vec()));
        assert!(matches!(
            alice_session.my_principal_state(),
            PrincipalState::Pending { .. }
        ));

        let restored = round_trip(&alice_session);
        assert!(matches!(
            restored.my_principal_state(),
            PrincipalState::Pending { .. }
        ));

        // Peer processes the rotation commit, replies; the reply resolves Pending → Sync.
        assert_some!(assert_ok!(
            bob_session.process_incoming(rotation.cipher_text)
        ));
        message_round(&bob_session, &restored, b"confirm");
        assert!(matches!(
            restored.my_principal_state(),
            PrincipalState::Sync { .. }
        ));
    }

    /// A parked responder side-band frame (turn already flipped) survives the round trip;
    /// dropping it would desync the side-band permanently.
    #[test]
    fn test_archive_preserves_parked_pq_frame() {
        let (alice_session, bob_session) = establish_sessions();
        let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
        assert_ok!(bob_session.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_ok!(alice_session.pq_bootstrap_apply(bind));

        // Bob initiates a ratchet round; Alice responds and parks the ct frame.
        let ek = assert_ok!(bob_session.pq_ratchet_begin());
        assert_ok!(alice_session.pq_ratchet_respond(ek));
        let ct = assert_some!(alice_session.pq_take_pending_outbound());
        assert_ok!(bob_session.pq_ratchet_bind(ct.clone(), b"pq-msg".to_vec()));

        // Bob's bind is parked with his turn already flipped: archive him and make sure
        // the frame is still deliverable from the restored session.
        let restored_bob = round_trip(&bob_session);
        let bind = assert_some!(restored_bob.pq_take_pending_outbound());
        assert_eq!(assert_ok!(alice_session.pq_ratchet_apply(bind)), b"pq-msg");
    }

    /// A.5 rekey markers hold no secrets and archive on both sides mid-round.
    #[test]
    fn test_archive_mid_rekey_round_completes_after_restore() {
        let (alice_session, bob_session) = establish_sessions();
        let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
        assert_ok!(bob_session.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_ok!(alice_session.pq_bootstrap_apply(bind));

        // Bob holds the turn: he initiates the rekey, then archives mid-round.
        let upd = assert_ok!(bob_session.pq_rekey_begin(None));
        let restored_bob = round_trip(&bob_session);

        assert!(assert_ok!(alice_session.pq_rekey_respond(upd)).is_none());
        // Alice archives mid-round too (RekeyResponded, parked reply survives).
        let restored_alice = round_trip(&alice_session);

        let reply = assert_some!(restored_alice.pq_take_pending_outbound());
        assert!(assert_ok!(restored_bob.pq_rekey_apply(reply)));
        let fin = assert_some!(restored_bob.pq_take_pending_outbound());
        assert!(!assert_ok!(restored_alice.pq_rekey_apply(fin)));
    }

    /// Total archive #1: a staged-but-uncommitted rotation rides in the archive; after a
    /// self-contained restore, `prepare_to_encrypt(Some(new_id))` commits the rotation and
    /// the peer observes the new sender. (This path used to refuse `SessionNotReady`.)
    #[test]
    fn test_archive_with_staged_rotation_restores_and_commits() {
        let (alice_session, bob_session) = establish_sessions();
        message_round(&alice_session, &bob_session, b"before");

        // Stage a rotation but do NOT commit it — the archive must carry the staged
        // successor identity (minted internally by `stage_rotation`).
        let new_id = make_client().client_id();
        assert_ok!(alice_session.stage_rotation(new_id.bytes.clone()));
        assert!(matches!(
            alice_session.my_principal_state(),
            PrincipalState::Sync { .. }
        ));

        let restored = round_trip(&alice_session);
        // The restored session still holds the staged rotation: committing it succeeds.
        assert_ok!(restored.prepare_to_encrypt(Some(new_id.clone())));
        let rotation = assert_ok!(restored.encrypt(b"rotate-after-restore".to_vec()));

        // The peer processes the rotation commit and observes the new sender.
        let got = assert_some!(assert_ok!(
            bob_session.process_incoming(rotation.cipher_text)
        ));
        assert_eq!(
            assert_some!(got.application_message).app_message_data,
            b"rotate-after-restore"
        );
        assert_eq!(assert_some!(got.remote_commit).new_sender, Some(new_id));
    }

    /// `stage_rotation` is idempotent-ish (matching classical `propose`): staging the same
    /// id twice keeps the existing staged identity; a different id replaces it.
    #[test]
    fn test_stage_rotation_same_id_is_idempotent() {
        let (alice_session, _bob_session) = establish_sessions();
        let id = make_client().client_id();
        assert_ok!(alice_session.stage_rotation(id.bytes.clone()));
        // Staging the same id again is a no-op and does not error.
        assert_ok!(alice_session.stage_rotation(id.bytes.clone()));
        // A different id replaces it; the rotation still commits cleanly.
        let other = make_client().client_id();
        assert_ok!(alice_session.stage_rotation(other.bytes.clone()));
        assert_ok!(alice_session.prepare_to_encrypt(Some(other)));
    }

    /// Total archive #2: archive mid-A.3 as the INITIATOR (after `pq_ratchet_begin`,
    /// before the ciphertext arrives). The held ephemeral survives the jump, so the
    /// restored initiator binds the responder's ciphertext and the round completes.
    #[test]
    fn test_archive_mid_a3_as_initiator_completes_after_restore() {
        let (alice_session, bob_session) = establish_sessions();
        let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
        assert_ok!(bob_session.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_ok!(alice_session.pq_bootstrap_apply(bind));

        // Bob holds the turn after the bootstrap: he is the A.3 initiator.
        let ek = assert_ok!(bob_session.pq_ratchet_begin());
        // Archive Bob mid-round (Initiating, holding the ephemeral) before the ct arrives.
        let restored_bob = round_trip(&bob_session);

        // Alice responds; the restored Bob binds across the jump with his rebuilt ephemeral.
        assert_ok!(alice_session.pq_ratchet_respond(ek));
        let ct = assert_some!(alice_session.pq_take_pending_outbound());
        assert_ok!(restored_bob.pq_ratchet_bind(ct, b"initiator-jump".to_vec()));
        let bind = assert_some!(restored_bob.pq_take_pending_outbound());
        assert_eq!(
            assert_ok!(alice_session.pq_ratchet_apply(bind)),
            b"initiator-jump"
        );
        message_round(&restored_bob, &alice_session, b"classical-after-jump");
    }

    /// Total archive #3: archive mid-A.3 as the RESPONDER (after `pq_ratchet_respond`,
    /// holding the shared secret S). S survives the jump, so the restored responder
    /// applies the initiator's bind (0x0F) cleanly — the desync that discarding S would
    /// cause is exactly why S must be serialized.
    #[test]
    fn test_archive_mid_a3_as_responder_completes_after_restore() {
        let (alice_session, bob_session) = establish_sessions();
        let kp = assert_ok!(alice_session.pq_bootstrap_begin(None));
        assert_ok!(bob_session.pq_bootstrap_respond(kp));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_ok!(alice_session.pq_bootstrap_apply(bind));

        // Bob initiates; Alice responds and holds S (having emitted the ciphertext).
        let ek = assert_ok!(bob_session.pq_ratchet_begin());
        assert_ok!(alice_session.pq_ratchet_respond(ek));
        let ct = assert_some!(alice_session.pq_take_pending_outbound());
        // Archive Alice mid-round (Responding, holding S).
        let restored_alice = round_trip(&alice_session);

        // Bob binds; the restored Alice applies the incoming bind across the jump.
        assert_ok!(bob_session.pq_ratchet_bind(ct, b"responder-jump".to_vec()));
        let bind = assert_some!(bob_session.pq_take_pending_outbound());
        assert_eq!(
            assert_ok!(restored_alice.pq_ratchet_apply(bind)),
            b"responder-jump"
        );
        message_round(&restored_alice, &bob_session, b"classical-after-jump");
    }

    #[test]
    fn test_from_archive_rejects_malformed_bytes() {
        let (alice_session, _bob_session) = establish_sessions();
        let archive = assert_ok!(alice_session.archive());

        // Wrong version byte.
        let mut wrong_version = archive.bytes.clone();
        wrong_version[0] ^= 0xFF;
        assert_err!(
            TwoMlsPqSession::from_archive(crate::Archive {
                bytes: wrong_version
            }),
            TwoMlsPqError::ArchiveInvalid
        );

        // Truncated body.
        let truncated = archive.bytes[..archive.bytes.len() - 1].to_vec();
        assert_err!(
            TwoMlsPqSession::from_archive(crate::Archive { bytes: truncated }),
            TwoMlsPqError::ArchiveInvalid
        );

        // Trailing garbage.
        let mut trailing = archive.bytes.clone();
        trailing.push(0);
        assert_err!(
            TwoMlsPqSession::from_archive(crate::Archive { bytes: trailing }),
            TwoMlsPqError::ArchiveInvalid
        );
    }

    #[test]
    fn test_send_rendezvous_none_without_recv_group() {
        let alice = make_client();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        // Initiator pre-return-welcome: no recv group, nowhere to post.
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(assert_ok!(session.send_rendezvous()).is_none());
    }

    #[test]
    fn test_should_listen_on_derivation_is_shared_not_random() {
        // Both members of the same group derive the same address independently:
        // alice's listen address at epoch 1 equals bob's post address, computed
        // from each side's own group state.
        let (alice_session, bob_session) = establish_sessions();
        let listen = assert_ok!(alice_session.should_listen_on());
        let post = assert_some!(assert_ok!(bob_session.send_rendezvous()));
        assert_eq!(
            listen.rendezvous_by_epoch[0].rendezvous_id.bytes,
            post.bytes
        );
    }

    #[test]
    fn test_forwarded_refused_without_spawn_token() {
        // Initiator sessions (and acceptor sessions built directly via `accept`, not
        // through an invitation) carry no spawn token — nothing to match replays against.
        let (alice_session, bob_session) = establish_sessions();
        assert_err!(
            alice_session.forwarded(vec![]),
            TwoMlsPqError::SessionNotReady
        );
        assert_err!(
            bob_session.forwarded(b"anything".to_vec()),
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

    /// The binding values are honest digests with cross-side coherence: the sender's
    /// `proposal_hash` is the SHA-256 of the staged Upd(self) proposal, so the
    /// receiver's `QueuedRemoteProposal.digest` — derived independently from the
    /// received bytes — equals it; and the receiver's ordering `context` equals its own
    /// `proposal_context` (SHA-256 of its recv group's classical group id).
    #[test]
    fn test_proposal_hash_is_digest_of_the_staple_both_sides_agree_on() {
        let (alice_session, bob_session) = establish_sessions();

        let prep = assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"hello from bob".to_vec()));
        let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
        let proposal = assert_some!(result.proposal);

        // Sender's binding value == receiver's independently derived digest.
        assert_eq!(prep.proposal_hash, proposal.digest);
        assert_eq!(prep.proposal_hash.len(), 32);
        // Self-consistent across the receiver's two surfaces.
        assert_eq!(
            proposal.context,
            assert_some!(alice_session.proposal_context())
        );
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
            alice_session.my_principal_state().client_id()
        );
    }

    #[test]
    #[ignore = "concurrent-session dedup not yet implemented"]
    fn test_concurrent_sessions_same_did_pair_both_valid() {}

    #[test]
    fn test_principal_rotation_migrates_session_to_new_principal() {
        let (alice_session, bob_session) = establish_sessions();

        let new_alice = make_client();
        let new_alice_id = new_alice.client_id();

        assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
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
        assert_eq!(
            bob_session.their_principal_state().client_id(),
            new_alice_id
        );
    }

    #[test]
    fn test_principal_rotation_resolves_pending_state_after_peer_reply() {
        let (alice_session, bob_session) = establish_sessions();

        let new_alice = make_client();
        let new_alice_id = new_alice.client_id();

        assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
        assert_ok!(alice_session.prepare_to_encrypt(Some(new_alice_id.clone())));
        let enc = assert_ok!(alice_session.encrypt(b"rotation".to_vec()));
        assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

        // Alice's state is Pending until she receives a message from Bob.
        assert!(matches!(
            alice_session.my_principal_state(),
            PrincipalState::Pending { .. }
        ));

        // Bob replies; Alice's state must resolve to Sync { new }.
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let reply = assert_ok!(bob_session.encrypt(b"ack".to_vec()));
        assert_some!(assert_ok!(alice_session.process_incoming(reply.cipher_text)));

        assert!(
            matches!(
                alice_session.my_principal_state(),
                PrincipalState::Sync { .. }
            ),
            "Pending must resolve to Sync after peer reply"
        );
        assert_eq!(alice_session.my_principal_state().client_id(), new_alice_id);
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

    /// A frame that crossed one of our commits references our send group's *previous*
    /// epoch. The session's PSK ledger must still resolve it — live derivation cannot,
    /// because mls-rs only exports the current epoch. Choreography: alice's full-commit
    /// frame binds the PSK of bob's send group at epoch E; bob rotates (E → E+1) before
    /// processing alice's frame.
    #[test]
    fn test_psk_ledger_resolves_frame_that_crossed_a_commit() {
        let (alice_session, bob_session) = establish_sessions();

        // Bob opens a routine round whose stapled Upd alice approves.
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"proposal".to_vec()));
        let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
        assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));

        // Alice's full commit binds the PSK of bob's send group at its current epoch.
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let crossing = assert_ok!(alice_session.encrypt(b"crossed".to_vec()));

        // Before processing alice's frame, bob rotates — his send group leaves the epoch
        // alice's commit references.
        let new_bob = make_client();
        assert_ok!(bob_session.stage_rotation(new_bob.client_id().bytes));
        assert_ok!(bob_session.prepare_to_encrypt(Some(new_bob.client_id())));

        // The crossed frame still processes: the ledger held the departed epoch's PSK.
        let result = assert_some!(assert_ok!(
            bob_session.process_incoming(crossing.cipher_text)
        ));
        assert_eq!(
            assert_some!(result.application_message).app_message_data,
            b"crossed"
        );
    }

    /// One-shot PSKs (the recv-group export a full commit binds) are removed from the
    /// mls-rs secret stores once the commit is applied — the stores hold nothing the
    /// session doesn't currently vouch for.
    #[test]
    fn test_consumed_one_shot_psk_is_forgotten_from_stores() {
        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let bob_kp = make_combiner_kp(&bob);
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());
        let bob_session = assert_ok!(TwoMlsPqSession::accept(
            Arc::clone(&bob),
            welcome_a,
            alice_kp
        ));
        let welcome_b = assert_some!(bob_session.pending_outbound());
        assert_ok!(alice_session.process_incoming(welcome_b));

        // Full-commit round: bob proposes, alice queues and commits. Alice's commit binds
        // the one-shot PSK exported from her recv group (bob's send group) at its current
        // epoch (1: established, no commits on it yet).
        assert_ok!(bob_session.prepare_to_encrypt(None));
        let enc = assert_ok!(bob_session.encrypt(b"proposal".to_vec()));
        let result = assert_some!(assert_ok!(alice_session.process_incoming(enc.cipher_text)));
        assert_ok!(alice_session.queue_proposal(assert_some!(result.proposal).digest));
        let recv_gid = assert_some!(alice_session.receive_group_id())
            .classical
            .bytes;
        assert_ok!(alice_session.prepare_to_encrypt(None));

        let mut id_bytes = 1u64.to_le_bytes().to_vec();
        id_bytes.extend_from_slice(&recv_gid);
        let one_shot = mls_rs::psk::ExternalPskId::new(id_bytes);
        assert!(
            alice
                .combiner()
                .classical()
                .secret_store()
                .get(&one_shot)
                .is_none(),
            "one-shot recv-group PSK must be dropped after the commit is applied"
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
        assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
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
        assert!(!alice_ctx.is_empty());
        assert!(!bob_ctx.is_empty());
    }

    #[test]
    fn test_my_principal_state_initial_is_sync() {
        let alice = make_client();
        let alice_id = alice.client_id();
        let bob = make_client();
        let bob_kp = make_combiner_kp(&bob);
        let session = assert_ok!(TwoMlsPqSession::initiate(alice, bob_kp));
        assert!(matches!(
            session.my_principal_state(),
            PrincipalState::Sync { .. }
        ));
        assert_eq!(session.my_principal_state().client_id(), alice_id);
    }

    #[test]
    fn test_my_principal_state_becomes_pending_after_rotation_commit() {
        let (alice_session, _) = establish_sessions();
        let new_alice = make_client();
        let new_id = new_alice.client_id();
        assert_ok!(alice_session.stage_rotation(new_alice.client_id().bytes));
        assert_ok!(alice_session.prepare_to_encrypt(Some(new_id.clone())));
        assert!(matches!(
            alice_session.my_principal_state(),
            PrincipalState::Pending { .. }
        ));
    }

    #[test]
    fn test_partial_commit_surfaces_proposal_nonce() {
        let (alice_session, bob_session) = establish_sessions();

        assert_ok!(alice_session.prepare_to_encrypt(None));
        let enc = assert_ok!(alice_session.encrypt(b"with nonce".to_vec()));
        let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));

        let proposal = assert_some!(result.proposal);
        assert!(!proposal.digest.is_empty());
        assert_eq!(
            proposal.sender,
            alice_session.my_principal_state().client_id()
        );
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
            cl_recv_after, cl_recv_before,
            "a routine round is proposal-only (A.2) — no classical commit until the peer \
             queues and consumes our Upd"
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
            cl_recv_1, cl_recv_0,
            "the recv group is the peer's to commit (A.2) — cross-party PCS travels via \
             the PSK inside our send-group commit, not a recv commit"
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
    fn test_decode_ratchet_truncated_returns_error() {
        assert_err!(
            super::decode_ratchet(&[super::PARTIAL_TAG]),
            TwoMlsPqError::Mls
        );
    }

    #[test]
    fn test_decode_ratchet_trailing_bytes_returns_error() {
        let mut good = super::encode_ratchet(b"c".to_vec(), b"p".to_vec(), b"app".to_vec());
        good.push(0xFF);
        assert_err!(super::decode_ratchet(&good), TwoMlsPqError::Mls);
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
    fn test_encode_decode_ratchet_roundtrip() {
        let commit = b"send-commit".to_vec();
        let proposal = b"upd-proposal".to_vec();
        let app = b"app-data".to_vec();
        let encoded = super::encode_ratchet(commit.clone(), proposal.clone(), app.clone());
        let (dec_c, dec_p, dec_app) = assert_ok!(super::decode_ratchet(&encoded));
        assert_eq!(dec_c, commit);
        assert_eq!(dec_p, proposal);
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
