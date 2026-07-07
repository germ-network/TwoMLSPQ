//! A self-contained combiner invitation, its opaque archive encoding, and the
//! generate/restore orchestration over the generic `apq` combiner. An invitation is the
//! signing identity (ClientId + per-half signing keys) paired with one combiner key
//! package's private material — everything needed to receive a welcome and HPKE-decrypt,
//! with no live client. It is the Rust analogue of the classical `MLSInvitationClientV2`.

use std::collections::BTreeSet;

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use zeroize::Zeroizing;

use crate::key_package_store::{CombinerClient, KeyPackageSecret, SyntheticKeyPackageStore};
use crate::{Result, TwoMlsPqError};

// v2: field framing moved from bespoke u32-LE length prefixes to `mls_rs_codec`; v1 archives
// are rejected as `ArchiveInvalid`.
const INVITATION_VERSION: u8 = 2;

// Tags whether the PQ half is real ML-KEM (`cryptokit`) or a classical simulation (default
// build). Baked into the archive so a mismatched build fails loudly at decode rather than
// silently misinterpreting the PQ signing key / key package.
#[cfg(feature = "cryptokit")]
const PQ_MODE: u8 = 1;
#[cfg(not(feature = "cryptokit"))]
const PQ_MODE: u8 = 0;

// In its own module because the derive-generated impls reference the std `Result`, which the
// crate-local `Result` alias imported above would shadow.
mod wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use zeroize::Zeroizing;

    use crate::key_package_store::KeyPackageSecret;

    /// A self-contained combiner invitation. The two halves' signing keys and key packages are
    /// always present; under the default build (no real PQ) the PQ half mirrors the classical
    /// one, so the archive shape is uniform across builds (distinguished by `PQ_MODE`).
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
    /// so the version/PQ-mode header stays where `CombinerInvitation::decode` expects it)
    /// followed by the consumed-remote ids.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct InvitationArchive {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) invitation: Vec<u8>,
        pub(super) consumed: Vec<Vec<u8>>,
    }
}

pub(crate) use wire::CombinerInvitation;
use wire::InvitationArchive;

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

/// The single encoder for a `TwoMlsPqInvitation`'s persisted form ([`InvitationArchive`]).
/// `BTreeSet` iteration gives a deterministic byte order. Used by both `generate_invitation`
/// (empty set) and `archive`; `decode_archive` is the sole reader, so the layout lives in
/// exactly one place.
pub(crate) fn encode_archive(
    invitation: &CombinerInvitation,
    consumed: &BTreeSet<Vec<u8>>,
) -> Result<Vec<u8>> {
    InvitationArchive {
        invitation: invitation.encode()?,
        consumed: consumed.iter().cloned().collect(),
    }
    .mls_encode_to_vec()
    .map_err(|_| TwoMlsPqError::ArchiveInvalid)
}

pub(crate) fn decode_archive(bytes: &[u8]) -> Result<(CombinerInvitation, BTreeSet<Vec<u8>>)> {
    let mut rest = bytes;
    let archive =
        InvitationArchive::mls_decode(&mut rest).map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    if !rest.is_empty() {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let invitation = CombinerInvitation::decode(&archive.invitation)?;
    Ok((invitation, archive.consumed.into_iter().collect()))
}

/// Generate a combiner key package on `client` and capture its private material into a
/// self-contained [`CombinerInvitation`]. Afterwards the client retains no key-package
/// private data — its capture stores are purged.
pub(crate) fn generate_combiner_invitation(client: &CombinerClient) -> Result<CombinerInvitation> {
    let (classical_public, classical_kpd) = capture(client.classical_kp_store(), || {
        client.generate_classical_key_package()
    })?;

    #[cfg(feature = "cryptokit")]
    let ((pq_public, pq_kpd), pq_signing_key) = (
        capture(client.pq_kp_store(), || client.generate_pq_key_package())?,
        Zeroizing::new(client.pq_signing_key().to_vec()),
    );
    // Without real PQ, the PQ half is a second classical key package on the classical
    // client, and the PQ signing key mirrors the classical one.
    #[cfg(not(feature = "cryptokit"))]
    let ((pq_public, pq_kpd), pq_signing_key) = (
        capture(client.classical_kp_store(), || {
            client.generate_classical_key_package()
        })?,
        Zeroizing::new(client.classical_signing_key().to_vec()),
    );

    client.classical_kp_store().purge_all();
    #[cfg(feature = "cryptokit")]
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
    // With real PQ each half serves its own KP; otherwise the classical store serves both
    // (the simulated PQ half is a classical key package on the classical client).
    #[cfg(feature = "cryptokit")]
    let client = apq::CombinerClient::from_key_packages(
        inv.client_id.clone(),
        inv.classical_signing_key.clone(),
        SyntheticKeyPackageStore::for_invitation([inv.classical_kpd.clone()]),
        inv.pq_signing_key.clone(),
        SyntheticKeyPackageStore::for_invitation([inv.pq_kpd.clone()]),
    )?;
    #[cfg(not(feature = "cryptokit"))]
    let client = apq::CombinerClient::from_key_packages(
        inv.client_id.clone(),
        inv.classical_signing_key.clone(),
        SyntheticKeyPackageStore::for_invitation([inv.classical_kpd.clone(), inv.pq_kpd.clone()]),
    )?;
    Ok(client)
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
