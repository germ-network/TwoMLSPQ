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

// The version byte covers the WHOLE archive layout, not just the invitation blob it sits
// in. v2 (2026-07-07): field framing moved from bespoke u32-LE length prefixes to
// `mls_rs_codec`, and the archive gained the spawned-group forward table (increment C)
// after the consumed set; v1 archives are rejected as `ArchiveInvalid` — regenerate the
// invitation (pre-release, no migration).
// v3 (2026-07-08): the single PQ-mode byte became the concrete `ApqCipherSuite` pair (4 bytes,
// classical then pq, big-endian), matching the session archive; a pair differing from this
// build's pinned suite (`providers::APQ_SUITE`) is rejected — the suite is now an explicit,
// checked property rather than an opaque mode flag.
const INVITATION_VERSION: u8 = 3;

/// The spawned-group forward table: an opaque caller-supplied spawn token → the spawned
/// session's receive-group classical (message-half) id. The token is whatever the caller
/// passed to `receive` — this library never interprets it (the Swift adapter uses the
/// app's combined-welcome digest, but any replay-stable byte string works).
pub(crate) type SpawnedGroups = BTreeMap<Vec<u8>, Vec<u8>>;

// In its own module because the derive-generated impls reference the std `Result`, which the
// crate-local `Result` alias imported above would shadow.
mod wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// A self-contained combiner invitation. Both halves' signing keys and key packages are
    /// always present; the cipher-suite pair lives in the `encode`/`decode` header.
    ///
    /// The derived codec embeds each `KeyPackageData` via its own canonical MLS encoding — no
    /// field-by-field surgery, so it stays correct if mls-rs evolves the (non_exhaustive) struct.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
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
        /// Captured private key-package material for each half: (storage id, KeyPackageData).
        pub classical_kpd: KeyPackageSecret,
        pub pq_kpd: KeyPackageSecret,
    }

    /// The persisted form of a `TwoMlsPqInvitation`: the framed invitation blob (kept framed
    /// so the version/suite header stays where `CombinerInvitation::decode` expects it)
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
    /// Encode to an opaque blob: `[version][classical u16 BE][pq u16 BE]` header, then the
    /// MLS-codec fields.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![INVITATION_VERSION];
        out.extend_from_slice(&crate::providers::APQ_SUITE.to_wire());
        self.mls_encode(&mut out)
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
        Ok(out)
    }

    /// Decode a blob produced by [`encode`](Self::encode). Rejects a wrong version or a
    /// cipher-suite pair that differs from this build's pinned suite (an archive from another
    /// build/suite).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rest = match bytes {
            [INVITATION_VERSION, s0, s1, s2, s3, rest @ ..]
                if apq::ApqCipherSuite::from_wire([*s0, *s1, *s2, *s3])
                    == crate::providers::APQ_SUITE =>
            {
                rest
            }
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
/// self-contained [`CombinerInvitation`]. Afterwards the client retains no key-package
/// private data — its capture stores are purged.
pub(crate) fn generate_combiner_invitation(client: &CombinerClient) -> Result<CombinerInvitation> {
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
        classical_kpd,
        pq_kpd,
    })
}

/// Rebuild a stateless combiner client from an invitation: restore the signing identity and
/// preload each half's key-package store with the invitation's captured `KeyPackageData`,
/// so a subsequent join/`accept` finds it.
pub(crate) fn combiner_from_invitation(inv: &CombinerInvitation) -> Result<CombinerClient> {
    apq::CombinerClient::from_key_packages(
        apq::ArchivedIdentity {
            client_id: inv.client_id.clone(),
            classical_signing_key: inv.classical_signing_key.clone(),
            classical_kp_store: SyntheticKeyPackageStore::for_invitation([inv
                .classical_kpd
                .clone()]),
            pq_signing_key: inv.pq_signing_key.clone(),
            pq_kp_store: SyntheticKeyPackageStore::for_invitation([inv.pq_kpd.clone()]),
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
