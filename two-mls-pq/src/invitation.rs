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
// Pinned at 1 during pre-release development: format changes don't bump it, so an archive
// from an older/other build simply fails to decode (`ArchiveInvalid`) and is regenerated —
// no migration. Start incrementing on the first stable release.
const INVITATION_VERSION: u8 = 1;

/// The spawned-group forward table: an opaque caller-supplied spawn token → the spawned
/// session's receive-group classical (message-half) id. The token is whatever the caller
/// passed to `receive` — this library never interprets it (the Swift adapter uses the
/// app's combined-welcome digest, but any replay-stable byte string works).
pub(crate) type SpawnedGroups = BTreeMap<Vec<u8>, Vec<u8>>;

// Tags the PQ half as real ML-KEM. Mode 0 was the retired simulated-PQ build (classical
// placeholder half); its archives are rejected at decode. Kept as a header byte so any
// future PQ-mode change (e.g. conf+auth) still fails loudly across builds.
const PQ_MODE: u8 = 1;

// In its own module because the derive-generated impls reference the std `Result`, which the
// crate-local `Result` alias imported above would shadow.
mod wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// A self-contained combiner invitation. The two halves' signing keys and (published)
    /// key packages are always present (distinguished by the `PQ_MODE` header byte).
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

    /// The persisted form of a `TwoMlsPqInvitation`: the framed invitation blob (kept framed
    /// so the version/PQ-mode header stays where `CombinerInvitation::decode` expects it)
    /// followed by the consumed-remote ids and the spawned-group forward table.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct InvitationArchive {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) invitation: Vec<u8>,
        pub(super) consumed: Vec<Vec<u8>>,
        pub(super) spawned: Vec<SpawnedEntry>,
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
}

pub(crate) use wire::CombinerInvitation;
use wire::{InvitationArchive, SpawnedEntry};

impl CombinerInvitation {
    /// Encode to an opaque blob: `[version][pq_mode]` header, then the MLS-codec fields.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![INVITATION_VERSION, PQ_MODE];
        self.mls_encode(&mut out)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        Ok(out)
    }

    /// Decode a blob produced by [`encode`](Self::encode). Rejects a wrong version or a
    /// PQ-mode mismatch (an archive from the other build).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rest = match bytes {
            [INVITATION_VERSION, PQ_MODE, rest @ ..] => rest,
            _ => return Err(TwoMlsPqError::ArchiveInvalid),
        };
        Self::mls_decode(&mut rest).map_err(|_| TwoMlsPqError::ArchiveInvalid)
    }
}

/// The single encoder for a `TwoMlsPqInvitation`'s persisted form ([`InvitationArchive`]):
/// the framed invitation blob, the consumed-remote ids, then the spawned-group forward
/// table. `BTreeSet`/`BTreeMap` iteration gives a deterministic byte order. Used by both
/// `generate_invitation` (empty sets) and `archive`; `decode_archive` is the sole reader,
/// so the layout lives in exactly one place.
pub(crate) fn encode_archive(
    invitation: &CombinerInvitation,
    consumed: &BTreeSet<Vec<u8>>,
    spawned: &SpawnedGroups,
) -> Result<Vec<u8>> {
    InvitationArchive {
        invitation: invitation.encode()?,
        consumed: consumed.iter().cloned().collect(),
        spawned: spawned
            .iter()
            .map(|(token, classical)| SpawnedEntry {
                token: token.clone(),
                classical: classical.clone(),
            })
            .collect(),
    }
    .mls_encode_to_vec()
    .map_err(|_| TwoMlsPqError::ArchiveInvalid)
}

pub(crate) fn decode_archive(
    bytes: &[u8],
) -> Result<(CombinerInvitation, BTreeSet<Vec<u8>>, SpawnedGroups)> {
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
    Ok((invitation, consumed, spawned))
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
