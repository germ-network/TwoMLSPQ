use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::invitation::{
    combiner_from_invitation, decode_archive, encode_archive, generate_combiner_invitation,
    CombinerInvitation, ProcessedWelcomes, SpawnedGroups,
};
use crate::key_package_store::{
    CombinerClient, KeyPackageSecret, MlsClient, PqMlsClient, SyntheticKeyPackageStore,
};
use crate::session::TwoMlsPqSession;
use crate::{ClientId, MlsCipherSuite, MlsGroupId, Result, TwoMlsPqError};

/// Holds a principal (ClientId) and mints MLS key packages and invitations for
/// publication. The ClientId is the Basic Credential that identifies this principal as a
/// leaf node in MLS groups; the MLS signing key is generated internally and is
/// independent of it.
///
/// Unlike mls-rs's monolithic per-credential `Client`, this object is *not* the hub
/// for group operations: `generate_invitation` captures key-package private material
/// into a self-contained `TwoMlsPqInvitation` and purges this identity's copies, and
/// group state lives inside `TwoMlsPqSession`s (which hold their own internal client
/// objects). See the book's Concepts chapter for the object model.
///
/// Thin UniFFI wrapper around `apq::CombinerClient`; the MLS plumbing lives in the
/// `apq` crate.
#[derive(uniffi::Object)]
pub struct TwoMlsPqPrincipal {
    inner: CombinerClient,
}

impl TwoMlsPqPrincipal {
    pub(crate) fn combiner(&self) -> &CombinerClient {
        &self.inner
    }

    /// Rebuild a stateless client from an invitation's captured signing identity + key
    /// package secrets (used by `TwoMlsPqInvitation::receive`).
    pub(crate) fn from_combiner_invitation(inv: &CombinerInvitation) -> Result<Arc<Self>> {
        let inner = combiner_from_invitation(inv)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Rebuild an identity from its archived signing keys (ClientId + each MLS half's
    /// signing key) and each half's retained key packages — a self-contained restore. Used
    /// by session archive/restore, where the MLS signing keys are session-owned state (the
    /// app owns only the opaque ClientId); the public halves are re-derived from the
    /// signing keys inside `from_key_packages`, giving byte-exact client continuity.
    ///
    /// The key-package stores carry any key package the client had minted but not yet
    /// consumed — critically the initiator's return-group key package, which the peer's
    /// return welcome addresses; without it a restored initiator could not join. Pass empty
    /// slices for a bare identity restore (e.g. a staged rotation successor).
    pub(crate) fn from_signing_keys(
        client_id: Vec<u8>,
        classical_signing_key: Zeroizing<Vec<u8>>,
        classical_key_packages: impl IntoIterator<Item = KeyPackageSecret>,
        pq_signing_key: Zeroizing<Vec<u8>>,
        pq_key_packages: impl IntoIterator<Item = KeyPackageSecret>,
    ) -> Result<Arc<Self>> {
        let inner = CombinerClient::from_key_packages(
            apq::ArchivedIdentity {
                client_id,
                classical_signing_key,
                classical_kp_store: SyntheticKeyPackageStore::preloaded(classical_key_packages),
                pq_signing_key,
                pq_kp_store: SyntheticKeyPackageStore::preloaded(pq_key_packages),
            },
            crate::providers::crypto_config(),
        )?;
        Ok(Arc::new(Self { inner }))
    }

    pub(crate) fn classical(&self) -> &MlsClient {
        self.inner.classical()
    }

    pub(crate) fn pq(&self) -> &PqMlsClient {
        self.inner.pq()
    }
}

#[uniffi::export]
impl TwoMlsPqPrincipal {
    /// Create a TwoMlsPqPrincipal for the given ClientId, generating a fresh signing
    /// key internally. `client_id` is opaque identity bytes, independent of any key.
    #[uniffi::constructor]
    pub fn new(client_id: Vec<u8>) -> Result<Arc<Self>> {
        let inner = CombinerClient::new(client_id, crate::providers::crypto_config())?;
        Ok(Arc::new(Self { inner }))
    }

    /// The ClientId (opaque identity bytes) for this principal.
    pub fn client_id(&self) -> ClientId {
        ClientId {
            bytes: self.inner.client_id().to_vec(),
        }
    }

    /// Generate a fresh KeyPackage for the given cipher suite.
    /// Returns MLS-encoded bytes suitable for publication.
    /// The corresponding HPKE private key is retained internally for group joins.
    pub fn generate_key_package(&self, suite: Arc<MlsCipherSuite>) -> Result<Vec<u8>> {
        match suite.value() {
            MlsCipherSuite::DHKEM_X25519_CHACHA => {
                Ok(self.inner.generate_classical_key_package()?)
            }
            MlsCipherSuite::ML_KEM_768 => Ok(self.inner.generate_pq_key_package()?),
            _ => Err(TwoMlsPqError::Mls),
        }
    }

    /// Generate a paired classical (0x0003) + PQ (0xFDEA) key package bundle
    /// for use in the APQ/Combiner construction.
    pub fn generate_combiner_key_package(&self) -> Result<CombinerKeyPackage> {
        let classical = self.generate_key_package(MlsCipherSuite::x25519_chacha())?;
        let pq = self.generate_key_package(MlsCipherSuite::ml_kem_768())?;
        Ok(CombinerKeyPackage { classical, pq })
    }

    /// Generate a combiner key package and capture it, with the signing identity, into a
    /// self-contained [`TwoMlsPqInvitation`] archive. The identity keeps no key-package
    /// private data — the Invitation owns it. Publish the invitation's `combinerKeyPackage`
    /// and reconstruct the receiving side with `TwoMlsPqInvitation(archive:)`.
    ///
    /// `last_resort` chooses the key package's lifetime, which TwoMLS manages itself rather
    /// than via mls-rs's on-the-wire last-resort extension: `true` retains the key package so
    /// the invitation can accept many welcomes; `false` makes it single-use (consumed, and its
    /// secret material dropped from the archive, after the first accepted session — a later
    /// `receive` then fails `InvitationSpent`).
    pub fn generate_invitation(&self, last_resort: bool) -> Result<Vec<u8>> {
        encode_archive(
            &generate_combiner_invitation(&self.inner, last_resort)?,
            &BTreeSet::new(),
            &SpawnedGroups::new(),
            &ProcessedWelcomes::new(),
        )
    }
}

/// Fields extracted from an MLS-encoded KeyPackage message.
#[derive(Debug, uniffi::Record)]
pub struct MlsKeyPackage {
    pub client_id: ClientId,
    pub cipher_suite: Arc<MlsCipherSuite>,
}

/// Paired key package bundle for the APQ/Combiner construction.
/// `classical` is MLS-encoded for suite 0x0003 (X25519+ChaCha20Poly1305);
/// `pq` is MLS-encoded for suite 0xFDEA (ML-KEM-768).
#[derive(Debug, Clone, uniffi::Record)]
pub struct CombinerKeyPackage {
    pub classical: Vec<u8>,
    pub pq: Vec<u8>,
}

/// Parsed identities from a `CombinerKeyPackage`.
/// Both components must share the same `client_id`; mismatched identities are rejected.
#[derive(Debug, uniffi::Record)]
pub struct ParsedCombinerKeyPackage {
    pub client_id: ClientId,
    pub classical_suite: Arc<MlsCipherSuite>,
    pub pq_suite: Arc<MlsCipherSuite>,
}

/// Parse an MLS-encoded KeyPackage and extract its client identity and cipher suite.
/// Use `is_combiner_pq` on the returned suite to decide which library should handle it.
#[uniffi::export]
pub fn parse_mls_key_package(bytes: Vec<u8>) -> Result<MlsKeyPackage> {
    let msg =
        mls_rs::MlsMessage::from_bytes(&bytes).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;

    let kp = msg
        .into_key_package()
        .ok_or(TwoMlsPqError::InvalidKeyPackage)?;

    let suite_value = u16::from(kp.cipher_suite);
    let cipher_suite = MlsCipherSuite::new(suite_value);

    let basic = kp
        .signing_identity()
        .credential
        .as_basic()
        .ok_or(TwoMlsPqError::InvalidKeyPackage)?;

    let client_id = ClientId {
        bytes: basic.identifier.clone(),
    };

    Ok(MlsKeyPackage {
        client_id,
        cipher_suite,
    })
}

/// Parse and validate a combiner key package pair.
/// Returns an error if the two components do not share the same client identity.
#[uniffi::export]
pub fn parse_combiner_key_package(kp: CombinerKeyPackage) -> Result<ParsedCombinerKeyPackage> {
    let classical = parse_mls_key_package(kp.classical)?;
    let pq = parse_mls_key_package(kp.pq)?;

    if classical.client_id != pq.client_id {
        return Err(TwoMlsPqError::InvalidKeyPackage);
    }

    Ok(ParsedCombinerKeyPackage {
        client_id: classical.client_id,
        classical_suite: classical.cipher_suite,
        pq_suite: pq.cipher_suite,
    })
}

/// Version tag for the opaque combiner key-package encoding.
const COMBINER_KEY_PACKAGE_VERSION: u8 = 1;

/// Encode a combiner key package pair into one opaque blob for publication. The
/// abstraction layer above carries the pair as a single `Data`; only TwoMLSPQ reads the
/// halves back out (see [`decode_combiner_key_package`]).
#[uniffi::export]
pub fn encode_combiner_key_package(key_package: CombinerKeyPackage) -> Vec<u8> {
    // Same framing style as the APQ welcome envelope: version byte, then u32-LE
    // length-prefixed halves. Key packages are a few KB, far below u32::MAX.
    let mut out =
        Vec::with_capacity(1 + 4 + key_package.classical.len() + 4 + key_package.pq.len());
    out.push(COMBINER_KEY_PACKAGE_VERSION);
    out.extend_from_slice(&(key_package.classical.len() as u32).to_le_bytes());
    out.extend_from_slice(&key_package.classical);
    out.extend_from_slice(&(key_package.pq.len() as u32).to_le_bytes());
    out.extend_from_slice(&key_package.pq);
    out
}

/// Decode an [`encode_combiner_key_package`] blob back into the key package pair.
#[uniffi::export]
pub fn decode_combiner_key_package(bytes: Vec<u8>) -> Result<CombinerKeyPackage> {
    let (&version, mut rest) = bytes
        .split_first()
        .ok_or(TwoMlsPqError::InvalidKeyPackage)?;
    if version != COMBINER_KEY_PACKAGE_VERSION {
        return Err(TwoMlsPqError::InvalidKeyPackage);
    }
    let classical = take_bytes(&mut rest).ok_or(TwoMlsPqError::InvalidKeyPackage)?;
    let pq = take_bytes(&mut rest).ok_or(TwoMlsPqError::InvalidKeyPackage)?;
    if !rest.is_empty() {
        return Err(TwoMlsPqError::InvalidKeyPackage);
    }
    Ok(CombinerKeyPackage { classical, pq })
}

/// Reader for the u32-LE framing above. This blob is published wire data, so it keeps its
/// byte-stable bespoke framing rather than the MLS codec used by the archive formats.
fn take_bytes(rest: &mut &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    *rest = &rest[4..];
    let v = rest.get(..len)?.to_vec();
    *rest = &rest[len..];
    Some(v)
}

/// The two components of an HPKE one-shot seal. Kept separate (like
/// `TwoMlsPqInvitation::hpke_open`'s inputs) so the outer wire framing stays with the
/// caller.
#[derive(Debug, uniffi::Record)]
pub struct HpkeSealed {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The opened initial frame: the composed `[app_payload ∥ APQWelcome_A]` after
/// `TwoMlsPqInvitation::open_initial` removes the §A.1 envelope. `app_payload` is the
/// host's app-layer welcome bytes it passed to `initiate` (`None` if it passed none);
/// `welcome` is the MLS `APQWelcome_A` to hand to `receive`.
#[derive(Debug, uniffi::Record)]
pub struct InitialFrame {
    pub app_payload: Option<Vec<u8>>,
    pub welcome: Vec<u8>,
}

/// Seal the initiator's first frame for the invitation channel: compose
/// `[app_payload][welcome]` and HPKE-seal it to the peer's published KP′ (PQ half),
/// returning the one opaque envelope blob `initiate` hands back via `pending_outbound`.
/// The counterpart is `TwoMlsPqInvitation::open_initial`.
///
/// Framing — composed plaintext: `[u32-LE app_len][app_payload][welcome]` (`welcome` is
/// the remainder; an empty app section means "no app payload"). Envelope blob:
/// `[u32-LE kem_output_len][kem_output][ciphertext]`.
pub(crate) fn seal_initial_envelope(
    their_key_package: &CombinerKeyPackage,
    app_payload: Option<&[u8]>,
    welcome: &[u8],
) -> Result<Vec<u8>> {
    let app = app_payload.unwrap_or(&[]);
    let mut plaintext = Vec::with_capacity(4 + app.len() + welcome.len());
    plaintext.extend_from_slice(&(app.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(app);
    plaintext.extend_from_slice(welcome);

    let sealed = hpke_seal_to_key_package(their_key_package.clone(), plaintext, None, None)?;

    let mut out = Vec::with_capacity(4 + sealed.kem_output.len() + sealed.ciphertext.len());
    out.extend_from_slice(&(sealed.kem_output.len() as u32).to_le_bytes());
    out.extend_from_slice(&sealed.kem_output);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
}

/// HPKE-seal `plaintext` to a published combiner key package's **PQ half** init key (spec
/// §A.1: the envelope is sealed to the PQ EK in KP′, under the PQ suite) — the sender side
/// of the initial routing-header pattern; the holder of the key package's invitation opens
/// it with `TwoMlsPqInvitation::hpke_open`. `info` defaults to the key package's credential
/// (the recipient's ClientId), matching `hpke_open`'s default.
#[uniffi::export]
pub fn hpke_seal_to_key_package(
    key_package: CombinerKeyPackage,
    plaintext: Vec<u8>,
    info: Option<Vec<u8>>,
    aad: Option<Vec<u8>>,
) -> Result<HpkeSealed> {
    let kp = mls_rs::MlsMessage::from_bytes(&key_package.pq)
        .map_err(|_| TwoMlsPqError::InvalidKeyPackage)?
        .into_key_package()
        .ok_or(TwoMlsPqError::InvalidKeyPackage)?;

    let info = match info {
        Some(info) => info,
        None => kp
            .signing_identity()
            .credential
            .as_basic()
            .ok_or(TwoMlsPqError::InvalidKeyPackage)?
            .identifier
            .clone(),
    };

    use mls_rs::CipherSuiteProvider;
    let cs = crate::providers::pq_envelope_suite()?;
    let sealed = cs
        .hpke_seal(&kp.hpke_init_key, &info, aad.as_deref(), &plaintext)
        .map_err(|_| TwoMlsPqError::Mls)?;
    Ok(HpkeSealed {
        kem_output: sealed.kem_output,
        ciphertext: sealed.ciphertext,
    })
}

/// Validate a peer's combiner key package against the session's fixed cipher-suite pair. The
/// observed `(classical, pq)` suites must equal `expected` exactly — which, since MLS suites are
/// monolithic, also fixes the KEM/AEAD/hash and signature scheme. A peer whose both halves are
/// classical (no PQ protection at all) keeps the specific `PqNotAvailable` diagnostic; any other
/// mismatch is `CipherSuiteMismatch`.
pub(crate) fn validate_combiner_kp(
    expected: apq::ApqCipherSuite,
    their_kp: &CombinerKeyPackage,
) -> Result<()> {
    let parsed = parse_combiner_key_package(their_kp.clone())?;
    // Compare the observed suite values directly against the session's pinned pair (rather than
    // constructing a checked `ApqCipherSuite`, which would reject an incoherent peer pair before
    // we can pick the right diagnostic).
    let classical = mls_rs::CipherSuite::new(parsed.classical_suite.value());
    let pq = mls_rs::CipherSuite::new(parsed.pq_suite.value());
    if classical == expected.classical && pq == expected.pq {
        return Ok(());
    }
    // Neither half is the post-quantum suite → the peer offers no PQ protection at all (any
    // classical suite, not just 0x0003) — the specific PqNotAvailable diagnostic.
    if !parsed.classical_suite.is_combiner_pq() && !parsed.pq_suite.is_combiner_pq() {
        return Err(TwoMlsPqError::PqNotAvailable);
    }
    Err(TwoMlsPqError::CipherSuiteMismatch)
}

/// The receiving/holding side of a published combiner key package: a self-contained
/// invitation that owns one key package's private material plus the signing identity, and
/// can turn a remote initiator's welcome into a session with no live `TwoMlsPqPrincipal`. The
/// Rust analogue of the classical `MLSInvitationClientV2`.
///
/// The private key-package material lives here (not in a `TwoMlsPqPrincipal`); each `receive`
/// rebuilds a stateless client from the archived invitation. A *last-resort* invitation can
/// service multiple welcomes (its key package is retained), bounded only by the per-remote
/// at-most-once guard; a *single-use* invitation accepts exactly one welcome, then drops its
/// key package (a later `receive` fails `InvitationSpent`). A remote whose welcome has
/// already been consumed is rejected with `DuplicateWelcome`.
#[derive(uniffi::Object)]
pub struct TwoMlsPqInvitation {
    // Behind a `Mutex` because a single-use invitation mutates it: the captured key package
    // is claimed at the start of `receive` and either kept consumed (success) or restored
    // (failure). A last-resort invitation never mutates the key-package material.
    invitation: Mutex<CombinerInvitation>,
    // Remote client ids already turned into a session — the transport at-most-once guard.
    // Persisted in `archive()` (a `BTreeSet` for deterministic encoding) so the guard
    // survives a restore.
    consumed: Mutex<BTreeSet<Vec<u8>>>,
    // The forward table: opaque spawn token → the spawned session's receive-group ids.
    // A replayed initial frame decodes to a token already in this table; the caller
    // routes it to the owning session instead of treating it as a fresh welcome.
    // Persisted in `archive()` so forwarding survives a restore.
    spawned: Mutex<SpawnedGroups>,
    // The processed-welcome ledger: SHA-256 of each accepted welcome's exact bytes → the
    // spawned session's receive-group classical id. Welcomes cannot be assumed to arrive
    // exactly once; a re-delivered welcome resolves here (content-keyed — no host token
    // convention required, unlike `spawned`) instead of erroring or re-spawning.
    // Persisted in `archive()`.
    processed: Mutex<ProcessedWelcomes>,
}

#[uniffi::export]
impl TwoMlsPqInvitation {
    /// Restore an invitation from its archive (from `TwoMlsPqPrincipal.generateInvitation` or
    /// `archive()`).
    #[uniffi::constructor]
    pub fn new(archive: Vec<u8>) -> Result<Arc<Self>> {
        let (invitation, consumed, spawned, processed) = decode_archive(&archive)?;
        Ok(Arc::new(Self {
            invitation: Mutex::new(invitation),
            consumed: Mutex::new(consumed),
            spawned: Mutex::new(spawned),
            processed: Mutex::new(processed),
        }))
    }

    /// Serialise the invitation's signing identity + key-package private material (or, once a
    /// single-use invitation is spent, the absence of it), plus the consumed-remote set and
    /// the spawned-group forward table so the transport dedup guard and replay routing survive
    /// a restore.
    ///
    /// Each field is cloned out under its own lock and released before encoding, so no two of
    /// the invitation's locks are ever held at once — this keeps a consistent global lock
    /// order with `receive` and rules out a lock-order inversion.
    pub fn archive(&self) -> Result<Vec<u8>> {
        let invitation = self.lock_invitation().clone();
        let consumed = self
            .consumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let spawned = self
            .spawned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let processed = self
            .processed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        encode_archive(&invitation, &consumed, &spawned, &processed)
    }

    /// The principal's ClientId.
    pub fn client_id(&self) -> ClientId {
        ClientId {
            bytes: self.lock_invitation().client_id.clone(),
        }
    }

    /// The published (public) combiner key package to hand to a remote initiator. Still
    /// available after a single-use invitation is spent (the published key package is public);
    /// only the private material is dropped on consume.
    pub fn combiner_key_package(&self) -> CombinerKeyPackage {
        let invitation = self.lock_invitation();
        CombinerKeyPackage {
            classical: invitation.classical_public.clone(),
            pq: invitation.pq_public.clone(),
        }
    }

    /// Receive a remote initiator's APQWelcome and establish the session using this
    /// invitation's captured key package. Rejects a second welcome from the same remote
    /// (`DuplicateWelcome`); a single-use invitation whose key package has already been
    /// consumed rejects every further welcome, from any remote (`InvitationSpent`).
    ///
    /// `spawn_token` is an opaque, caller-chosen, replay-stable identifier for the
    /// initial frame this welcome arrived in (the Swift adapter passes the app's
    /// combined-welcome digest; this library never interprets it). On success it keys
    /// the forward table: a replayed frame decodes to the same token, `forward_group_id`
    /// resolves it to the spawned session, and `TwoMlsPqSession::forwarded`
    /// acknowledges it there.
    pub fn receive(
        &self,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
        spawn_token: Vec<u8>,
    ) -> Result<Arc<TwoMlsPqSession>> {
        // Content-keyed idempotency, checked before anything is claimed or reserved: a
        // welcome these exact bytes already spawned a session from is a re-delivery, not
        // a fresh invite — the caller resolves it via `processed_welcome_group_id` and
        // routes to the owning session.
        let welcome_digest = crate::sha256(&welcome);
        if self
            .processed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&welcome_digest)
        {
            return Err(TwoMlsPqError::DuplicateWelcome);
        }

        let their_id = parse_mls_key_package(their_key_package.classical.clone())?.client_id;

        // Claim this invitation's captured key package for the attempt. This is the single-use
        // gate: under the lock we take a snapshot to build the client from, and for a
        // single-use invitation we null out the stored material *now* so a concurrent or later
        // `receive` (from any remote) sees it spent and cannot reuse the key package. A
        // last-resort invitation leaves the material in place (retained for reuse). A snapshot
        // whose material is already `None` means a single-use invitation was already consumed.
        let snapshot = {
            let mut invitation = self.lock_invitation();
            if invitation.classical_kpd.is_none() {
                return Err(TwoMlsPqError::InvitationSpent);
            }
            let snapshot = invitation.clone();
            if !invitation.last_resort {
                invitation.classical_kpd = None;
                invitation.pq_kpd = None;
            }
            snapshot
        };

        // Reserve this remote so two concurrent welcomes from it can't both establish;
        // `insert` returns false if it was already consumed (a replay). For a last-resort
        // invitation this is the reuse bound; for a single-use one the key-package claim above
        // is already decisive, but the reservation keeps the forward-table bookkeeping honest.
        if !self
            .consumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(their_id.bytes.clone())
        {
            self.restore_claim(&snapshot);
            return Err(TwoMlsPqError::DuplicateWelcome);
        }

        match TwoMlsPqPrincipal::from_combiner_invitation(&snapshot)
            .and_then(|client| TwoMlsPqSession::accept(client, welcome, their_key_package))
            .and_then(|session| {
                // Enter the spawn in the forward table and the welcome in the
                // processed ledger; the acceptor always has a receive group straight
                // out of `accept`, but any failure in this bookkeeping must release
                // the reservation like a failed accept.
                let gid = session.receive_group_id().ok_or(TwoMlsPqError::Mls)?;
                self.spawned
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(spawn_token.clone(), gid.classical.bytes.clone());
                self.processed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(welcome_digest.clone(), gid.classical.bytes);
                session.set_spawn_token(spawn_token);
                Ok(session)
            }) {
            Ok(session) => Ok(session),
            Err(e) => {
                // Establishment failed — release the remote reservation and, for a single-use
                // invitation, put the claimed key package back so a valid retry can proceed.
                self.consumed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&their_id.bytes);
                self.restore_claim(&snapshot);
                Err(e)
            }
        }
    }

    /// Resolve an initial frame's spawn token against the forward table: `Some` names
    /// the receive group (classical, message-half id) of the session this invitation
    /// already spawned from an identical frame (route the payload there — see
    /// `TwoMlsPqSession::forwarded`), `None` means the frame is fresh and should
    /// proceed through app validation to `receive`.
    pub fn forward_group_id(&self, spawn_token: Vec<u8>) -> Option<MlsGroupId> {
        self.spawned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&spawn_token)
            .map(|classical| MlsGroupId {
                bytes: classical.clone(),
            })
    }

    /// Resolve a welcome against the processed-welcome ledger: `Some` names the receive
    /// group (classical, message-half id) of the session this invitation already spawned
    /// from these exact welcome bytes — a re-delivery, to be routed to the owning session
    /// rather than passed to `receive` (which would reject it as `DuplicateWelcome`).
    /// `None` means the welcome is fresh. The content-keyed counterpart of
    /// `forward_group_id`: this one needs no host token convention, only the bytes.
    pub fn processed_welcome_group_id(&self, welcome: Vec<u8>) -> Option<MlsGroupId> {
        self.processed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&crate::sha256(&welcome))
            .map(|classical| MlsGroupId {
                bytes: classical.clone(),
            })
    }

    /// HPKE-decrypt data sealed to this invitation's **PQ half** key package init key (spec
    /// §A.1; counterpart of `hpke_seal_to_key_package`) — the initial routing-header pattern
    /// inherited from classical TwoMLS, which sealed to its classical init key. `info`
    /// defaults to the ClientId; `kem_output` and `ciphertext` are the two components of the
    /// HPKE ciphertext (kept separate so this stays agnostic to any outer wire framing).
    /// Fails with `InvitationSpent` once a single-use invitation has been consumed — its
    /// captured PQ key-package material, and thus the init key this opens with, is then gone.
    pub fn hpke_open(
        &self,
        kem_output: Vec<u8>,
        ciphertext: Vec<u8>,
        info: Option<Vec<u8>>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        use mls_rs::crypto::HpkeCiphertext;
        use mls_rs::CipherSuiteProvider;

        let invitation = self.lock_invitation();

        // Public init key: published in the PQ key package (spec A.1: the envelope is
        // sealed to the PQ EK in KP'). Matching secret: the invitation's captured PQ
        // KeyPackageData — absent once a single-use invitation has been consumed.
        let key_package = mls_rs::MlsMessage::from_bytes(&invitation.pq_public)
            .map_err(|_| TwoMlsPqError::InvalidKeyPackage)?
            .into_key_package()
            .ok_or(TwoMlsPqError::InvalidKeyPackage)?;
        let public = key_package.hpke_init_key;
        let pq_kpd = invitation
            .pq_kpd
            .as_ref()
            .ok_or(TwoMlsPqError::InvitationSpent)?;
        let secret = &pq_kpd.1.init_key;

        let cs = crate::providers::pq_envelope_suite()?;

        let info = info.unwrap_or_else(|| invitation.client_id.clone());
        let ciphertext = HpkeCiphertext {
            kem_output,
            ciphertext,
        };
        let plaintext = cs
            .hpke_open(&ciphertext, secret, &public, &info, aad.as_deref())
            .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
        Ok(plaintext.to_vec())
    }

    /// Open the initiator's first frame (the §A.1 envelope produced by `initiate`),
    /// returning the app-layer welcome the initiator passed as `app_payload` and the MLS
    /// `welcome` to hand to `receive`. Decrypt-only and **state-free** — it does NOT
    /// consume a single-use invitation's key package (consumption happens in `receive`),
    /// so a host can open a frame to validate it before deciding to join, and re-opens are
    /// harmless. Fails `InvitationSpent` once a single-use invitation is consumed (its KP′
    /// material, and thus the opener, is gone); `DecryptionFailed`/`Mls` on a malformed or
    /// wrong-key blob. The counterpart is the free function `seal_initial_envelope`
    /// (called inside `initiate`).
    ///
    /// The returned `welcome` is the plaintext both sides need for the spawn token: a
    /// re-sent envelope has a fresh HPKE ephemeral (different outer bytes, identical
    /// plaintext), so a replay-stable token must be computed over this decrypted frame,
    /// not the sealed bytes.
    pub fn open_initial(&self, blob: Vec<u8>) -> Result<InitialFrame> {
        // Split the envelope `[u32 kem_len][kem_output][ciphertext]`, then HPKE-open.
        let mut rest = blob.as_slice();
        let kem_output = take_bytes(&mut rest).ok_or(TwoMlsPqError::Mls)?;
        let ciphertext = rest.to_vec();
        let plaintext = self.hpke_open(kem_output, ciphertext, None, None)?;

        // Split the composed plaintext `[u32 app_len][app_payload][welcome]`.
        let mut rest = plaintext.as_slice();
        let app = take_bytes(&mut rest).ok_or(TwoMlsPqError::Mls)?;
        let welcome = rest.to_vec();
        Ok(InitialFrame {
            // An empty app section means the initiator passed no app payload.
            app_payload: (!app.is_empty()).then_some(app),
            welcome,
        })
    }
}

impl TwoMlsPqInvitation {
    /// Lock the invitation state, recovering from a poisoned mutex (the guarded data is plain
    /// records; a panic mid-update can't leave it torn).
    fn lock_invitation(&self) -> std::sync::MutexGuard<'_, CombinerInvitation> {
        self.invitation.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Put a single-use invitation's claimed key package back after a failed `receive`, so a
    /// valid retry can proceed. A no-op for a last-resort invitation (its material was never
    /// taken) and for the already-spent snapshot (its material is `None`).
    fn restore_claim(&self, snapshot: &CombinerInvitation) {
        if snapshot.last_resort {
            return;
        }
        let mut invitation = self.lock_invitation();
        invitation.classical_kpd = snapshot.classical_kpd.clone();
        invitation.pq_kpd = snapshot.pq_kpd.clone();
    }
}

#[cfg(test)]
mod tests {
    use mls_rs::{CipherSuiteProvider, CryptoProvider};

    use super::TwoMlsPqPrincipal;
    use crate::{assert_err, assert_ok, assert_some, MlsCipherSuite};

    /// A fresh, unique ClientId for tests (opaque random bytes, not a signing key).
    fn test_client_id() -> Vec<u8> {
        let crypto = crate::providers::classical();
        let cs = assert_some!(crypto.cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));
        let (secret, _) = assert_ok!(cs.signature_key_generate());
        secret.as_bytes().to_vec()
    }

    #[test]
    fn test_client_id_is_the_provided_bytes() {
        let id = test_client_id();
        let client = assert_ok!(TwoMlsPqPrincipal::new(id.clone()));
        // The ClientId is exactly the bytes provided — no longer derived from a key.
        assert_eq!(client.client_id().bytes, id);
    }

    #[test]
    fn test_generate_key_package_classical_succeeds() {
        let client = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_generate_key_package_ml_kem_768_succeeds() {
        let client = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::ml_kem_768()));
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_parse_mls_key_package_returns_correct_client_id_and_suite() {
        let client = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        let parsed = assert_ok!(super::parse_mls_key_package(bytes));
        assert_eq!(parsed.client_id, client.client_id());
        assert_eq!(
            parsed.cipher_suite.value(),
            MlsCipherSuite::DHKEM_X25519_CHACHA
        );
    }

    #[test]
    fn test_parse_mls_key_package_ml_kem_768_suite_value() {
        assert_eq!(
            MlsCipherSuite::ml_kem_768().value(),
            MlsCipherSuite::ML_KEM_768
        );
        assert_eq!(MlsCipherSuite::ML_KEM_768, 0xFDEA);
    }

    #[test]
    fn test_parse_mls_key_package_unknown_suite_returns_unknown_variant() {
        assert!(super::parse_mls_key_package(vec![0xAB, 0xCD, 0xEF]).is_err());
    }

    #[test]
    fn test_generate_combiner_key_package_produces_matching_client_ids() {
        let client = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let ckp = assert_ok!(client.generate_combiner_key_package());
        let parsed = assert_ok!(super::parse_combiner_key_package(ckp));
        assert_eq!(parsed.client_id, client.client_id());
    }

    #[test]
    fn test_parse_combiner_key_package_returns_correct_suites() {
        let client = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let ckp = assert_ok!(client.generate_combiner_key_package());
        let parsed = assert_ok!(super::parse_combiner_key_package(ckp));
        assert_eq!(
            parsed.classical_suite.value(),
            MlsCipherSuite::DHKEM_X25519_CHACHA
        );
        assert_eq!(parsed.pq_suite.value(), MlsCipherSuite::ML_KEM_768);
    }

    #[test]
    fn test_parse_combiner_key_package_mismatched_identities_returns_error() {
        let client_a = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let client_b = assert_ok!(TwoMlsPqPrincipal::new(test_client_id()));
        let classical = assert_ok!(client_a.generate_key_package(MlsCipherSuite::x25519_chacha()));
        let pq = assert_ok!(client_b.generate_key_package(MlsCipherSuite::x25519_chacha()));
        assert_err!(
            super::parse_combiner_key_package(crate::key_packages::CombinerKeyPackage {
                classical,
                pq,
            }),
            crate::TwoMlsPqError::InvalidKeyPackage
        );
    }

    #[test]
    fn test_invitation_receive_establishes_session() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        // Bob publishes an invitation instead of retaining key-package state on the client.
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        // Bob accepts through the invitation (no live client that generated the KP).
        let bob_session = assert_ok!(bob_inv.receive(welcome_a, alice_kp, b"token".to_vec()));
        let welcome_b = assert_some!(bob_session.pending_outbound());
        assert_ok!(alice_session.process_incoming(welcome_b));

        assert!(alice_session.is_established());
        assert!(bob_session.is_established());
    }

    #[test]
    fn test_invitation_receive_rejects_duplicate_remote() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        // First receive consumes Alice's identity.
        assert_ok!(bob_inv.receive(welcome_a.clone(), alice_kp.clone(), b"token".to_vec()));
        // A second welcome from the same remote is rejected as a replay.
        assert_err!(
            bob_inv.receive(welcome_a, alice_kp, b"token".to_vec()),
            crate::TwoMlsPqError::DuplicateWelcome
        );
    }

    #[test]
    fn test_invitation_processed_welcome_ledger_resolves_redelivery() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        // Fresh welcome: no ledger entry yet.
        assert!(bob_inv
            .processed_welcome_group_id(welcome_a.clone())
            .is_none());

        let bob_session =
            assert_ok!(bob_inv.receive(welcome_a.clone(), alice_kp.clone(), b"token".to_vec()));

        // A re-delivered welcome resolves — content-keyed, no host token convention —
        // to the spawned session's receive group…
        let gid = assert_some!(bob_inv.processed_welcome_group_id(welcome_a.clone()));
        assert_eq!(
            gid.bytes,
            assert_some!(bob_session.receive_group_id()).classical.bytes
        );
        // …and `receive` itself rejects it up front, before claiming or reserving
        // anything.
        assert_err!(
            bob_inv.receive(welcome_a.clone(), alice_kp, b"token2".to_vec()),
            crate::TwoMlsPqError::DuplicateWelcome
        );

        // The ledger survives the archive round-trip.
        let restored = assert_ok!(super::TwoMlsPqInvitation::new(
            assert_ok!(bob_inv.archive())
        ));
        assert_some!(restored.processed_welcome_group_id(welcome_a));
    }

    #[test]
    fn test_invitation_hpke_open_round_trips() {
        use crate::test_utils::make_client;

        let bob = make_client();
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));

        // Seal with an explicit info equal to the recipient's ClientId; opening with
        // `info = None` must agree (the default is the ClientId on both ends).
        let plaintext = b"routing-header".to_vec();
        let sealed = assert_ok!(super::hpke_seal_to_key_package(
            bob_inv.combiner_key_package(),
            plaintext.clone(),
            Some(bob_inv.client_id().bytes),
            None,
        ));

        let opened =
            assert_ok!(bob_inv.hpke_open(sealed.kem_output, sealed.ciphertext, None, None));
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_hpke_seal_to_key_package_opens_via_invitation() {
        use crate::test_utils::make_client;

        let bob = make_client();
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));

        // Sender side: seal to the published key package with the default info
        // (the recipient's ClientId, read from the credential).
        let sealed = assert_ok!(super::hpke_seal_to_key_package(
            bob_inv.combiner_key_package(),
            b"routing-header".to_vec(),
            None,
            None,
        ));

        // Recipient side: the invitation opens it with its captured init key.
        let opened =
            assert_ok!(bob_inv.hpke_open(sealed.kem_output, sealed.ciphertext, None, None));
        assert_eq!(opened, b"routing-header".to_vec());
    }

    #[test]
    fn test_invitation_archive_persists_consumed_set() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        // Consume Alice on the live invitation.
        assert_ok!(bob_inv.receive(welcome_a.clone(), alice_kp.clone(), b"token".to_vec()));

        // Archive + restore; the consumed set must survive so the replay is still rejected.
        let restored = assert_ok!(super::TwoMlsPqInvitation::new(
            assert_ok!(bob_inv.archive())
        ));
        assert_err!(
            restored.receive(welcome_a, alice_kp, b"token".to_vec()),
            crate::TwoMlsPqError::DuplicateWelcome
        );
    }

    #[test]
    fn test_invitation_new_rejects_malformed_archive() {
        assert_err!(
            super::TwoMlsPqInvitation::new(vec![0xFF, 0xFF, 0xFF]),
            crate::TwoMlsPqError::ArchiveInvalid
        );
    }

    /// Increment C — replay routing. A successful `receive` enters the spawn in the
    /// forward table under the caller's opaque token: the same token resolves to the
    /// spawned session's receive group, the session acknowledges the replay via
    /// `forwarded`, and a mis-routed token is refused.
    #[test]
    fn test_forward_table_routes_replayed_spawn_token() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        // Fresh frame: nothing to forward to yet.
        let token = b"spawn-token".to_vec();
        assert!(bob_inv.forward_group_id(token.clone()).is_none());

        let bob_session = assert_ok!(bob_inv.receive(welcome_a, alice_kp, token.clone()));

        // The replayed token now names the spawned session's receive group…
        let gid = assert_some!(bob_inv.forward_group_id(token.clone()));
        let recv = assert_some!(bob_session.receive_group_id());
        assert_eq!(gid.bytes, recv.classical.bytes);
        // …a different token still routes nowhere…
        assert!(bob_inv.forward_group_id(b"other".to_vec()).is_none());

        // …and the session acknowledges the replay: nothing new inside (the PQ
        // initiator cannot staple pre-establishment), a mis-route is refused.
        assert!(assert_ok!(bob_session.forwarded(token)).is_none());
        assert_err!(
            bob_session.forwarded(b"other".to_vec()),
            crate::TwoMlsPqError::DecryptionFailed
        );
    }

    /// The forward table survives archive/restore alongside the consumed set.
    #[test]
    fn test_invitation_archive_persists_forward_table() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        let token = b"spawn-token".to_vec();
        let bob_session = assert_ok!(bob_inv.receive(welcome_a, alice_kp, token.clone()));
        let recv = assert_some!(bob_session.receive_group_id());

        let restored = assert_ok!(super::TwoMlsPqInvitation::new(
            assert_ok!(bob_inv.archive())
        ));
        let gid = assert_some!(restored.forward_group_id(token));
        assert_eq!(gid.bytes, recv.classical.bytes);
        assert!(restored.forward_group_id(b"other".to_vec()).is_none());
    }

    #[test]
    fn test_combiner_key_package_codec_round_trips() {
        use crate::test_utils::{make_client, make_combiner_kp};

        let client = make_client();
        let kp = make_combiner_kp(&client);

        let encoded = super::encode_combiner_key_package(kp.clone());
        let decoded = assert_ok!(super::decode_combiner_key_package(encoded));
        assert_eq!(decoded.classical, kp.classical);
        assert_eq!(decoded.pq, kp.pq);
    }

    #[test]
    fn test_decode_combiner_key_package_rejects_malformed() {
        use crate::test_utils::{make_client, make_combiner_kp};

        // Empty and wrong-version inputs.
        assert_err!(
            super::decode_combiner_key_package(vec![]),
            crate::TwoMlsPqError::InvalidKeyPackage
        );
        assert_err!(
            super::decode_combiner_key_package(vec![0xFF, 0x00, 0x00, 0x00, 0x00]),
            crate::TwoMlsPqError::InvalidKeyPackage
        );

        // Truncated and trailing-garbage framings.
        let encoded = super::encode_combiner_key_package(make_combiner_kp(&make_client()));
        assert_err!(
            super::decode_combiner_key_package(encoded[..encoded.len() - 1].to_vec()),
            crate::TwoMlsPqError::InvalidKeyPackage
        );
        let mut trailing = encoded;
        trailing.push(0x00);
        assert_err!(
            super::decode_combiner_key_package(trailing),
            crate::TwoMlsPqError::InvalidKeyPackage
        );
    }

    #[test]
    fn test_invitation_receive_rollback_allows_retry() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        // A failed establishment must NOT consume the remote — the reservation is rolled
        // back, so a valid retry from the same remote still succeeds.
        assert!(bob_inv
            .receive(b"not-a-welcome".to_vec(), alice_kp.clone(), b"bad".to_vec())
            .is_err());
        // …and the failed spawn must not enter the forward table either.
        assert!(bob_inv.forward_group_id(b"bad".to_vec()).is_none());
        assert_ok!(bob_inv.receive(welcome_a, alice_kp, b"token".to_vec()));
    }

    /// A single-use (not last-resort) invitation accepts exactly one welcome; afterwards its
    /// key package is spent — a fresh remote is refused with `InvitationSpent`, proving the
    /// limit is on the key package itself, not merely a per-remote replay guard.
    #[test]
    fn test_invitation_single_use_consumes_key_package() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let carol = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let carol_kp = make_combiner_kp(&carol);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp.clone(),
            None,
        ));
        let welcome_a = alice_session.test_initial_welcome();
        assert_ok!(bob_inv.receive(welcome_a, alice_kp, b"token-a".to_vec()));

        let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
        let welcome_c = carol_session.test_initial_welcome();
        assert_err!(
            bob_inv.receive(welcome_c, carol_kp, b"token-c".to_vec()),
            crate::TwoMlsPqError::InvitationSpent
        );
    }

    /// A single-use invitation's spent state (its key package dropped from the archive)
    /// survives archive/restore: the restored invitation still refuses to accept and can no
    /// longer HPKE-open, because the private material is gone.
    #[test]
    fn test_invitation_single_use_archive_drops_key_package() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let carol = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let carol_kp = make_combiner_kp(&carol);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp.clone(),
            None,
        ));
        let welcome_a = alice_session.test_initial_welcome();
        assert_ok!(bob_inv.receive(welcome_a, alice_kp, b"token-a".to_vec()));

        let restored = assert_ok!(super::TwoMlsPqInvitation::new(
            assert_ok!(bob_inv.archive())
        ));
        let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
        let welcome_c = carol_session.test_initial_welcome();
        assert_err!(
            restored.receive(welcome_c, carol_kp, b"token-c".to_vec()),
            crate::TwoMlsPqError::InvitationSpent
        );
        assert_err!(
            restored.hpke_open(vec![0u8; 32], vec![0u8; 16], None, None),
            crate::TwoMlsPqError::InvitationSpent
        );
    }

    /// A failed accept on a single-use invitation must put the claimed key package back, so a
    /// subsequent valid welcome still establishes (the claim is rolled back like the remote
    /// reservation). If restoration were broken the retry would fail `InvitationSpent`.
    #[test]
    fn test_invitation_single_use_rollback_restores_key_package() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        assert!(bob_inv
            .receive(b"not-a-welcome".to_vec(), alice_kp.clone(), b"bad".to_vec())
            .is_err());
        // The key package was restored, so a valid welcome still establishes.
        assert_ok!(bob_inv.receive(welcome_a, alice_kp, b"token".to_vec()));
    }

    /// The defining last-resort behavior: the same published key package accepts welcomes from
    /// two *distinct* remotes (the material is retained across joins, bounded only by the
    /// per-remote guard).
    #[test]
    fn test_last_resort_invitation_reuses_across_distinct_remotes() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let carol = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);
        let carol_kp = make_combiner_kp(&carol);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp.clone(),
            None,
        ));
        let welcome_a = alice_session.test_initial_welcome();
        assert_ok!(bob_inv.receive(welcome_a, alice_kp, b"token-a".to_vec()));

        let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
        let welcome_c = carol_session.test_initial_welcome();
        assert_ok!(bob_inv.receive(welcome_c, carol_kp, b"token-c".to_vec()));
    }

    /// The key-package store is only a serving interface: once the acceptor's join has
    /// consumed the invitation key package, nothing of the invitation may remain in the
    /// session client (and thus its archive). Exercised for a last-resort invitation, the
    /// case that previously retained — and leaked — the shared key package.
    #[test]
    fn test_accept_leaves_no_key_package_in_acceptor_session() {
        use crate::invitation::generate_combiner_invitation;
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{make_client, make_combiner_kp};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_combiner_kp(&alice);

        let inv = assert_ok!(generate_combiner_invitation(bob.combiner(), true));
        let bob_kp = super::CombinerKeyPackage {
            classical: inv.classical_public.clone(),
            pq: inv.pq_public.clone(),
        };

        // Rebuild the acceptor client and keep handles on its (Arc-shared) serving stores.
        let bob_client = assert_ok!(super::TwoMlsPqPrincipal::from_combiner_invitation(&inv));
        let classical_store = bob_client.combiner().classical_kp_store().clone();
        let pq_store = bob_client.combiner().pq_kp_store().clone();
        assert!(
            !classical_store.all_entries().is_empty() && !pq_store.all_entries().is_empty(),
            "the serving store must hold the invitation key package before the join"
        );

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = alice_session.test_initial_welcome();

        let _bob_session = assert_ok!(TwoMlsPqSession::accept(bob_client, welcome_a, alice_kp));

        // After the join the acceptor retains nothing — nothing migrates into the session archive.
        assert!(
            classical_store.all_entries().is_empty(),
            "acceptor retains no classical key package after accept"
        );
        assert!(
            pq_store.all_entries().is_empty(),
            "acceptor retains no PQ key package after accept"
        );
    }

    #[test]
    fn test_invitation_rejects_wrong_suite() {
        use crate::test_utils::make_client;

        let bob = make_client();
        let mut archive = assert_ok!(bob.generate_invitation(true));
        // Layout: [varint len][version][classical u16 BE][pq u16 BE]…; the MLS varint's top two
        // bits give the header width. Flip a byte of the classical suite so the archived pair no
        // longer equals this build's pinned suite (mimicking an archive from another build/suite).
        let header = match archive[0] >> 6 {
            0 => 1,
            1 => 2,
            _ => 4,
        };
        archive[header + 1] ^= 1;
        assert_err!(
            super::TwoMlsPqInvitation::new(archive),
            crate::TwoMlsPqError::ArchiveInvalid
        );
    }
}
