//! A self-contained combiner invitation, its opaque archive encoding, and the
//! generate/restore orchestration over the generic `apq` combiner. An invitation is the
//! signing identity (ClientId + per-half signing keys) paired with one combiner key
//! package's private material — everything needed to receive a welcome and HPKE-decrypt,
//! with no live client. It is the Rust analogue of the classical `MLSInvitationClientV2`.

use std::collections::{BTreeMap, BTreeSet};

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use zeroize::Zeroizing;

use crate::key_package_store::{CombinerClient, KeyPackageSecret, SyntheticKeyPackageStore};
use crate::{Result, TwoMlsPqError};

// The version byte covers the WHOLE archive layout, not just the invitation blob it sits in.
// Still pre-release, so a layout change need not bump it — there are no persisted invitations
// to reject; a mismatch just fails to decode (`ArchiveInvalid`) and is regenerated. The header
// also carries the concrete `ApqCipherSuite` pair (4 bytes, classical then pq, big-endian),
// matching the session archive; a pair differing from this build's pinned suite
// (`providers::APQ_SUITE`) is rejected — the suite is an explicit, checked property.
//
// PRE-RELEASE FLOOR RESET (2026-07-13, alongside SESSION_ARCHIVE_VERSION): the v1–v4
// ladder carried no compatibility value (every bump was a hard cut; the history stays in
// git — most recently v4, the AppBinding capability cut, whose rationale still applies:
// pre-AppBinding captured key packages can never join a binding-carrying group, so stale
// blobs reject at restore rather than deep inside the peer's `initiate`). The byte
// returns to the floor; blobs from every prior cut wear bytes 2–4 and fail the header
// check, and the layout is disjoint enough from the retired v1 shape that a decode
// cannot alias.
// v2 adds the bootstrap-commitment routing table (`bootstrap_commitments`) to the archive, so a
// v1 blob decodes short and fails — a pre-release hard cut, regenerate the invitation.
const INVITATION_VERSION: u8 = 2;

/// The spawned-group forward table: an opaque caller-supplied spawn token → the spawned
/// session's receive-group classical (message-half) id. The token is whatever the caller
/// passed to `receive` — this library never interprets it (the Swift adapter uses the
/// app's combined-welcome digest, but any replay-stable byte string works).
pub(crate) type SpawnedGroups = BTreeMap<Vec<u8>, Vec<u8>>;

/// The processed-welcome ledger: SHA-256 of the exact welcome bytes `receive` accepted →
/// the spawned session's receive-group classical (message-half) id. Welcomes cannot be
/// assumed to arrive exactly once — a re-delivered welcome resolves here (content-keyed,
/// no host token convention needed) instead of erroring or re-spawning.
pub(crate) type ProcessedWelcomes = BTreeMap<Vec<u8>, Vec<u8>>;

/// The bootstrap-commitment routing table: `H(initiator's PQ bootstrap key package)` — the same
/// 32-byte commitment `receive` was given and pinned — → the spawned session's receive-group
/// classical (message-half) id. Lets a KP′ that arrives as a §A.1 bootstrap envelope (contract 21,
/// carrying no session id) self-route to the session that owes A.4: `bootstrap_kp_group_id` hashes
/// the framed KP′ and resolves it here. Content-keyed like `processed`; distinct so the two
/// preimages (welcome bytes vs. bootstrap KP) never collide.
pub(crate) type BootstrapCommitments = BTreeMap<Vec<u8>, Vec<u8>>;

// In its own module because the derive-generated impls reference the std `Result`, which the
// crate-local `Result` alias imported above would shadow.
mod wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// A self-contained combiner invitation. Both halves' signing keys and (published) key
    /// packages are always present; the cipher-suite pair lives in the `encode`/`decode` header.
    ///
    /// `last_resort` records the caller-chosen key-package lifetime: a last-resort invitation
    /// may accept many welcomes (its captured material is retained), while a single-use one is
    /// consumed after the first accept — at which point `classical_kpd`/`pq_kpd` are set to
    /// `None` so the archive no longer carries the spent secret material. See
    /// `two-mls-pq/src/key_packages.rs` for the consume/retain logic.
    ///
    /// The derived codec embeds each `KeyPackageData` via its own canonical MLS encoding — no
    /// field-by-field surgery, so it stays correct if mls-rs evolves the (non_exhaustive) struct.
    #[derive(Clone, MlsSize, MlsEncode, MlsDecode)]
    pub(crate) struct CombinerInvitation {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub client_id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub classical_signing_key: Zeroizing<Vec<u8>>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub pq_signing_key: Zeroizing<Vec<u8>>,
        /// MLS-encoded (published) key package message for each half.
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub classical_public: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub pq_public: Vec<u8>,
        /// Whether this invitation's key package is last-resort (retained across welcomes)
        /// rather than single-use (consumed after the first accept).
        pub last_resort: bool,
        /// Captured private key-package material for each half: (storage id, KeyPackageData).
        /// `None` once a single-use invitation has been consumed.
        pub classical_kpd: Option<KeyPackageSecret>,
        pub pq_kpd: Option<KeyPackageSecret>,
    }

    /// The persisted form of a `TwoMlsPqInvitation`: the per-invitation mutation counter, the
    /// framed invitation blob (kept framed so the version/suite header stays where
    /// `CombinerInvitation::decode` expects it), the consumed-remote ids, the spawned-group
    /// forward table, and the processed-welcome ledger. The live `sink` is not persisted — it
    /// is plumbing supplied at each construction via `install_sink`.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct InvitationArchive {
        /// Per-invitation monotonic mutation counter (see `InvitationInner::state_seq`),
        /// stamped onto every pushed blob and carried across a restore.
        pub(super) state_seq: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) invitation: Vec<u8>,
        pub(super) consumed: Vec<Vec<u8>>,
        pub(super) spawned: Vec<SpawnedEntry>,
        pub(super) processed: Vec<ProcessedEntry>,
        pub(super) bootstrap_commitments: Vec<BootstrapCommitmentEntry>,
    }

    /// One spawned-group forward-table entry: an opaque spawn token → the spawned
    /// session's receive-group classical (message-half) id.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct SpawnedEntry {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) token: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) classical: Vec<u8>,
    }

    /// One processed-welcome ledger entry: SHA-256 of the accepted welcome bytes → the
    /// spawned session's receive-group classical (message-half) id.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct ProcessedEntry {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) digest: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) classical: Vec<u8>,
    }

    /// One bootstrap-commitment routing entry: `H(initiator's PQ bootstrap key package)` → the
    /// spawned session's receive-group classical (message-half) id.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct BootstrapCommitmentEntry {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) commitment: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) classical: Vec<u8>,
    }
}

pub(crate) use wire::CombinerInvitation;
use wire::{BootstrapCommitmentEntry, InvitationArchive, ProcessedEntry, SpawnedEntry};

/// The decoded parts of an invitation archive: the invitation, the consumed-remote set, the
/// spawned-group forward table, the processed-welcome ledger, and the per-invitation mutation
/// counter. Named (rather than a bare tuple) so `decode_archive`'s signature stays readable.
pub(crate) type DecodedArchive = (
    CombinerInvitation,
    BTreeSet<Vec<u8>>,
    SpawnedGroups,
    ProcessedWelcomes,
    BootstrapCommitments,
    u64,
);

impl CombinerInvitation {
    /// Encode to an opaque blob: `[version][classical u16 BE][pq u16 BE]` header, then the
    /// MLS-codec fields. The suite bytes come from the declared suite's wire encoding
    /// (`TwoMlsSuite::to_wire` — the one authority `decode` validates against).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![INVITATION_VERSION];
        out.extend_from_slice(&crate::suite::TwoMlsSuite::CURRENT.to_wire());
        self.mls_encode(&mut out)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        Ok(out)
    }

    /// Decode a blob produced by [`encode`](Self::encode). Rejects a wrong version or a
    /// cipher-suite pair that is not this build's declared suite (an archive from another
    /// build/suite).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        use crate::suite::TwoMlsSuite;
        let mut rest = match bytes {
            [INVITATION_VERSION, s0, s1, s2, s3, rest @ ..]
                if TwoMlsSuite::from_wire([*s0, *s1, *s2, *s3]) == Some(TwoMlsSuite::CURRENT) =>
            {
                rest
            }
            _ => return Err(TwoMlsPqError::ArchiveInvalid),
        };
        Self::mls_decode(&mut rest).map_err(|_| TwoMlsPqError::ArchiveInvalid)
    }
}

/// The single encoder for a `TwoMlsPqInvitation`'s persisted form ([`InvitationArchive`]):
/// the mutation counter, the framed invitation blob, the consumed-remote ids, the
/// spawned-group forward table, then the processed-welcome ledger. `BTreeSet`/`BTreeMap`
/// iteration gives a deterministic byte order. Used by both `generate_invitation`
/// (`state_seq = 0`, empty sets) and `archive`/the push path; `decode_archive` is the sole
/// reader, so the layout lives in exactly one place.
pub(crate) fn encode_archive(
    invitation: &CombinerInvitation,
    consumed: &BTreeSet<Vec<u8>>,
    spawned: &SpawnedGroups,
    processed: &ProcessedWelcomes,
    bootstrap_commitments: &BootstrapCommitments,
    state_seq: u64,
) -> Result<Vec<u8>> {
    InvitationArchive {
        state_seq,
        invitation: invitation.encode()?,
        consumed: consumed.iter().cloned().collect(),
        spawned: spawned
            .iter()
            .map(|(token, classical)| SpawnedEntry {
                token: token.clone(),
                classical: classical.clone(),
            })
            .collect(),
        processed: processed
            .iter()
            .map(|(digest, classical)| ProcessedEntry {
                digest: digest.clone(),
                classical: classical.clone(),
            })
            .collect(),
        bootstrap_commitments: bootstrap_commitments
            .iter()
            .map(|(commitment, classical)| BootstrapCommitmentEntry {
                commitment: commitment.clone(),
                classical: classical.clone(),
            })
            .collect(),
    }
    .mls_encode_to_vec()
    .map_err(|_| TwoMlsPqError::ArchiveInvalid)
}

pub(crate) fn decode_archive(bytes: &[u8]) -> Result<DecodedArchive> {
    let mut rest = bytes;
    let archive =
        InvitationArchive::mls_decode(&mut rest).map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    if !rest.is_empty() {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let invitation = CombinerInvitation::decode(&archive.invitation)?;
    let consumed = archive.consumed.into_iter().collect();
    let spawned = archive
        .spawned
        .into_iter()
        .map(|e| (e.token, e.classical))
        .collect();
    let processed = archive
        .processed
        .into_iter()
        .map(|e| (e.digest, e.classical))
        .collect();
    let bootstrap_commitments = archive
        .bootstrap_commitments
        .into_iter()
        .map(|e| (e.commitment, e.classical))
        .collect();
    Ok((
        invitation,
        consumed,
        spawned,
        processed,
        bootstrap_commitments,
        archive.state_seq,
    ))
}

/// Generate a combiner key package on `client` and capture its private material into a
/// self-contained [`CombinerInvitation`]. `last_resort` fixes the key package's lifetime
/// (retained across welcomes vs. consumed after the first accept). Afterwards the client
/// retains no key-package private data — its capture stores are purged.
pub(crate) fn generate_combiner_invitation(
    client: &CombinerClient,
    last_resort: bool,
) -> Result<CombinerInvitation> {
    let (classical_public, classical_kpd) = capture(client.classical_kp_store(), || {
        client.generate_classical_key_package()
    })?;

    let ((pq_public, pq_kpd), pq_signing_key) = (
        capture(client.pq_kp_store(), || client.generate_pq_key_package())?,
        Zeroizing::new(client.pq_signing_key().to_vec()),
    );

    client.classical_kp_store().purge_all();
    client.pq_kp_store().purge_all();

    Ok(CombinerInvitation {
        client_id: client.client_id().to_vec(),
        classical_signing_key: Zeroizing::new(client.classical_signing_key().to_vec()),
        pq_signing_key,
        classical_public,
        pq_public,
        last_resort,
        classical_kpd: Some(classical_kpd),
        pq_kpd: Some(pq_kpd),
    })
}

/// Rebuild a stateless combiner client from an invitation: restore the signing identity and
/// preload each half's key-package store with the invitation's captured `KeyPackageData` so
/// mls-rs can `get` it while joining the welcome. The store is only that serving interface —
/// `accept` clears it once the join has consumed the key package, so nothing migrates into the
/// session. Fails with `InvitationSpent` if the captured material has already been consumed (a
/// spent single-use invitation).
pub(crate) fn combiner_from_invitation(inv: &CombinerInvitation) -> Result<CombinerClient> {
    let classical_kpd = inv
        .classical_kpd
        .clone()
        .ok_or(TwoMlsPqError::InvitationSpent)?;
    let pq_kpd = inv.pq_kpd.clone().ok_or(TwoMlsPqError::InvitationSpent)?;
    apq::CombinerClient::from_key_packages(
        apq::ArchivedIdentity {
            client_id: inv.client_id.clone(),
            classical_signing_key: inv.classical_signing_key.clone(),
            classical_kp_store: SyntheticKeyPackageStore::for_invitation([classical_kpd]),
            pq_signing_key: inv.pq_signing_key.clone(),
            pq_kp_store: SyntheticKeyPackageStore::for_invitation([pq_kpd]),
        },
        crate::providers::crypto_config(),
    )
    .map_err(Into::into)
}

/// Run a key-package generation while capturing, returning the public bytes plus the single
/// captured `KeyPackageData`.
fn capture(
    store: &SyntheticKeyPackageStore,
    generate: impl FnOnce() -> std::result::Result<Vec<u8>, apq::CombinerError>,
) -> Result<(Vec<u8>, KeyPackageSecret)> {
    let (public, captured) = store.capture(generate);
    Ok((public?, single_captured(captured)?))
}

/// Exactly-one extraction: generating a key package inserts a single `KeyPackageData`.
fn single_captured(captured: Vec<KeyPackageSecret>) -> Result<KeyPackageSecret> {
    let mut it = captured.into_iter();
    match (it.next(), it.next()) {
        (Some(secret), None) => Ok(secret),
        _ => Err(TwoMlsPqError::Mls),
    }
}

#[cfg(test)]
mod tests {
    use mls_rs::mls_rs_codec::MlsEncode;

    use super::wire::InvitationArchive;
    use super::*;
    use crate::test_utils::make_client;
    use crate::{assert_err, assert_ok};

    /// The v4 prerelease hard cut (the AppBinding capability cut): a stale-version
    /// invitation blob must be rejected at restore — loudly, instead of resurfacing
    /// later as an opaque mls-rs error when a binding-carrying `initiate` cannot add its
    /// pre-AppBinding key package (whose republished blob would wear the current
    /// `COMBINER_KEY_PACKAGE_VERSION` byte). The layout is unchanged across v3 → v4, so
    /// only the version byte gates — this pins that it does. Companion of the combiner
    /// key package's version pin (`test_combiner_kp_v3_round_trips_and_rejects_prior_versions`).
    #[test]
    fn test_restore_rejects_stale_invitation_version() {
        let client = make_client();
        let inv = assert_ok!(generate_combiner_invitation(client.combiner(), true));
        let mut framed = assert_ok!(inv.encode());
        // Pin the current cut (update alongside the const's changelog comment):
        // v2 added the bootstrap-commitment routing table.
        assert_eq!(framed[0], 2);
        assert_eq!(framed[0], INVITATION_VERSION);

        // A pre-floor-reset blob (the v0.3.0-era AppBinding cut wore byte 4):
        // identical layout, stale version byte. The framed decoder is the choke
        // point every restore funnels through…
        framed[0] = 4;
        assert_err!(
            CombinerInvitation::decode(&framed),
            TwoMlsPqError::ArchiveInvalid
        );

        // …and through the public boundary: an otherwise-valid archive wrapping the
        // stale blob fails `TwoMlsPqInvitation::restore` the same way.
        let archive = assert_ok!(InvitationArchive {
            state_seq: 0,
            invitation: framed,
            consumed: Vec::new(),
            spawned: Vec::new(),
            processed: Vec::new(),
            bootstrap_commitments: Vec::new(),
        }
        .mls_encode_to_vec()
        .map_err(|_| TwoMlsPqError::ArchiveInvalid));
        assert_err!(
            crate::key_packages::TwoMlsPqInvitation::restore(archive),
            TwoMlsPqError::ArchiveInvalid
        );
    }
}
