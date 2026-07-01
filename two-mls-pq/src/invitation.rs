//! A self-contained combiner invitation, its opaque archive encoding, and the
//! generate/restore orchestration over the generic `apq` combiner. An invitation is the
//! signing identity (ClientId + per-half signing keys) paired with one combiner key
//! package's private material — everything needed to receive a welcome and HPKE-decrypt,
//! with no live client. It is the Rust analogue of the classical `MLSInvitationClientV2`.

use std::collections::BTreeSet;

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::storage_provider::KeyPackageData;
use zeroize::Zeroizing;

use crate::key_package_store::{CombinerClient, KeyPackageSecret, SyntheticKeyPackageStore};
use crate::{Result, TwoMlsPqError};

const INVITATION_VERSION: u8 = 1;

// Tags whether the PQ half is real ML-KEM (`cryptokit`) or a classical simulation (default
// build). Baked into the archive so a mismatched build fails loudly at decode rather than
// silently misinterpreting the PQ signing key / key package.
#[cfg(feature = "cryptokit")]
const PQ_MODE: u8 = 1;
#[cfg(not(feature = "cryptokit"))]
const PQ_MODE: u8 = 0;

/// A self-contained combiner invitation. The two halves' signing keys and key packages are
/// always present; under the default build (no real PQ) the PQ half mirrors the classical
/// one, so the archive shape is uniform across builds (distinguished by `PQ_MODE`).
pub(crate) struct CombinerInvitation {
    pub client_id: Vec<u8>,
    pub classical_signing_key: Zeroizing<Vec<u8>>,
    pub pq_signing_key: Zeroizing<Vec<u8>>,
    /// MLS-encoded (published) key package message for each half.
    pub classical_public: Vec<u8>,
    pub pq_public: Vec<u8>,
    /// Captured private key-package material for each half: (storage id, KeyPackageData).
    pub classical_kpd: KeyPackageSecret,
    pub pq_kpd: KeyPackageSecret,
}

impl CombinerInvitation {
    /// Encode to an opaque, versioned, length-prefixed blob.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![INVITATION_VERSION, PQ_MODE];
        put_bytes(&mut out, &self.client_id)?;
        put_bytes(&mut out, &self.classical_signing_key)?;
        put_bytes(&mut out, &self.pq_signing_key)?;
        put_bytes(&mut out, &self.classical_public)?;
        put_bytes(&mut out, &self.pq_public)?;
        put_kpd(&mut out, &self.classical_kpd)?;
        put_kpd(&mut out, &self.pq_kpd)?;
        Ok(out)
    }

    /// Decode a blob produced by [`encode`](Self::encode). Rejects a wrong version or a
    /// PQ-mode mismatch (an archive from the other build).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes;
        if take_u8(&mut rest)? != INVITATION_VERSION || take_u8(&mut rest)? != PQ_MODE {
            return Err(TwoMlsPqError::ArchiveInvalid);
        }
        let client_id = take_bytes(&mut rest)?;
        let classical_signing_key = Zeroizing::new(take_bytes(&mut rest)?);
        let pq_signing_key = Zeroizing::new(take_bytes(&mut rest)?);
        let classical_public = take_bytes(&mut rest)?;
        let pq_public = take_bytes(&mut rest)?;
        let classical_kpd = take_kpd(&mut rest)?;
        let pq_kpd = take_kpd(&mut rest)?;
        Ok(Self {
            client_id,
            classical_signing_key,
            pq_signing_key,
            classical_public,
            pq_public,
            classical_kpd,
            pq_kpd,
        })
    }
}

/// The single encoder for a `TwoMlsPqInvitation`'s persisted form: the framed invitation
/// blob followed by the consumed-remote ids. `BTreeSet` gives a deterministic byte order.
/// Used by both `generate_invitation` (empty set) and `archive`; `decode_archive` is the
/// sole reader, so the layout lives in exactly one place.
pub(crate) fn encode_archive(
    invitation: &CombinerInvitation,
    consumed: &BTreeSet<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_bytes(&mut out, &invitation.encode()?)?;
    for id in consumed {
        put_bytes(&mut out, id)?;
    }
    Ok(out)
}

pub(crate) fn decode_archive(bytes: &[u8]) -> Result<(CombinerInvitation, BTreeSet<Vec<u8>>)> {
    let mut rest = bytes;
    let invitation = CombinerInvitation::decode(&take_bytes(&mut rest)?)?;
    let mut consumed = BTreeSet::new();
    while !rest.is_empty() {
        consumed.insert(take_bytes(&mut rest)?);
    }
    Ok((invitation, consumed))
}

/// Generate a combiner key package on `client` and capture its private material into a
/// self-contained [`CombinerInvitation`]. Afterwards the client retains no key-package
/// private data — its capture stores are purged.
pub(crate) fn generate_combiner_invitation(client: &CombinerClient) -> Result<CombinerInvitation> {
    let (classical_public, classical_kpd) =
        capture(client.classical_kp_store(), || client.generate_classical_key_package())?;

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
        SyntheticKeyPackageStore::for_invitation([
            inv.classical_kpd.clone(),
            inv.pq_kpd.clone(),
        ]),
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

pub(crate) fn put_bytes(out: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    let len = u32::try_from(v.len()).map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(v);
    Ok(())
}

pub(crate) fn take_bytes(rest: &mut &[u8]) -> Result<Vec<u8>> {
    if rest.len() < 4 {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    *rest = &rest[4..];
    if rest.len() < len {
        return Err(TwoMlsPqError::ArchiveInvalid);
    }
    let v = rest[..len].to_vec();
    *rest = &rest[len..];
    Ok(v)
}

fn take_u8(rest: &mut &[u8]) -> Result<u8> {
    let (&b, tail) = rest.split_first().ok_or(TwoMlsPqError::ArchiveInvalid)?;
    *rest = tail;
    Ok(b)
}

// KeyPackageData is (de)serialized via its own canonical MLS codec — no field-by-field
// surgery, so it stays correct if mls-rs evolves the (non_exhaustive) struct.
fn put_kpd(out: &mut Vec<u8>, (id, kpd): &KeyPackageSecret) -> Result<()> {
    put_bytes(out, id)?;
    put_bytes(
        out,
        &kpd.mls_encode_to_vec()
            .map_err(|_| TwoMlsPqError::ArchiveInvalid)?,
    )
}

fn take_kpd(rest: &mut &[u8]) -> Result<KeyPackageSecret> {
    let id = take_bytes(rest)?;
    let kpd_bytes = take_bytes(rest)?;
    let mut reader = kpd_bytes.as_slice();
    let kpd =
        KeyPackageData::mls_decode(&mut reader).map_err(|_| TwoMlsPqError::ArchiveInvalid)?;
    Ok((id, kpd))
}
