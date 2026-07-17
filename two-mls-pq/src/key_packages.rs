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
            // A freshly generated invitation starts at seq 0 (no mutations yet); a sink is
            // attached later via `install_sink`, which pushes the baseline at this seq.
            0,
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
///
/// v1: bespoke u32-LE framing, classical then pq.
/// v2 (-02 conformance): the payload is the draft-02 §7 `APQKeyPackage`
/// TLS shape — `t_key_package` then `pq_key_package` as variable-length vectors
/// (MLS codec), each carrying the standard MLSMessage-encoded KeyPackage — enclosed in
/// Germ's version byte. v2 also marks the capability cut: leaves generated at v2
/// advertise the APQInfo extension and AppDataUpdate proposal types, which v1-era
/// leaves lack, so v1 blobs are rejected outright (prerelease hard-cut policy).
/// v3 (payload unchanged): the AppBinding capability cut. Leaves generated at v3
/// advertise the AppBinding GroupContext extension type (0xF0A2), which v2-era leaves
/// lack — a binding-carrying group can never admit one — so v2 blobs are rejected
/// outright (same prerelease hard-cut).
const COMBINER_KEY_PACKAGE_VERSION: u8 = 3;

// In its own module because the derive-generated impls reference the std `Result`,
// which the crate-local `Result` alias would shadow (same pattern as `archive_wire`).
mod kp_wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};

    /// draft-ietf-mls-combiner-02 §7 `APQKeyPackage`: the traditional half first, then
    /// the PQ half, as TLS variable-length vectors.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct ApqKeyPackageWire {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) t_key_package: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) pq_key_package: Vec<u8>,
    }
}

/// Encode a combiner key package pair into one opaque blob for publication: the -02 §7
/// `APQKeyPackage` TLS encoding inside Germ's version byte. The abstraction layer above
/// carries the pair as a single `Data`; only TwoMLSPQ reads the halves back out (see
/// [`decode_combiner_key_package`]).
#[uniffi::export]
pub fn encode_combiner_key_package(key_package: CombinerKeyPackage) -> Vec<u8> {
    use mls_rs::mls_rs_codec::MlsEncode;
    let wire = kp_wire::ApqKeyPackageWire {
        t_key_package: key_package.classical,
        pq_key_package: key_package.pq,
    };
    let mut out = vec![COMBINER_KEY_PACKAGE_VERSION];
    // Encoding two in-memory byte vectors is infallible in practice; an allocation
    // failure would abort long before this.
    out.extend_from_slice(&wire.mls_encode_to_vec().unwrap_or_default());
    out
}

/// Decode an [`encode_combiner_key_package`] blob back into the key package pair.
#[uniffi::export]
pub fn decode_combiner_key_package(bytes: Vec<u8>) -> Result<CombinerKeyPackage> {
    use mls_rs::mls_rs_codec::MlsDecode;
    let (&version, mut rest) = bytes
        .split_first()
        .ok_or(TwoMlsPqError::InvalidKeyPackage)?;
    if version != COMBINER_KEY_PACKAGE_VERSION {
        return Err(TwoMlsPqError::InvalidKeyPackage);
    }
    let wire = kp_wire::ApqKeyPackageWire::mls_decode(&mut rest)
        .map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    if !rest.is_empty() {
        return Err(TwoMlsPqError::InvalidKeyPackage);
    }
    Ok(CombinerKeyPackage {
        classical: wire.t_key_package,
        pq: wire.pq_key_package,
    })
}

/// Reader for the u32-LE framing used by the HPKE envelope below. Published wire data,
/// so it keeps its byte-stable bespoke framing rather than the MLS codec used by the
/// archive formats.
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

/// Inner authenticated leading tag of the §A.1 establishment vector — the FIRST BYTE OF THE
/// HPKE-SEALED PLAINTEXT, not an outer wire byte. Since contract 21 the envelope blob carries
/// no outer tag (`[u32-LE kem_len][kem_output][ciphertext]`); the establishment reply and the
/// parallel bootstrap-KP frame (Part 3) share that outer shape and are told apart only AFTER
/// HPKE-open, by this leading byte (0x07 = establishment vector) vs. `PQ_BOOTSTRAP_KP_TAG`
/// (0x13 = bootstrap KP), the way the 0x03 message frame's staple slot self-discriminates on
/// its first byte. The transport channel — invitation address → HPKE-open, session address →
/// session frame — already routes the blob to the right opener, so no observable OUTER
/// discriminator is needed or wanted (`frames.rs`: "header encryption seals every blob, so a
/// tag is never observed"; an outer tag would only fingerprint which frames carry PQ material).
///
/// Allocated out of the shared odd-tag space (it heads the A.1 band) but declared here rather
/// than in `session::frames`, because the establishment vector is not a session frame.
/// `frames::tests::BANDS` is where the whole space is visible at once and where the
/// distinctness this doc claims is actually enforced — asserting it in prose is how 0x15 got
/// claimed twice once already.
pub const ESTABLISHMENT_VECTOR_TAG: u8 = 0x07;

/// The establishment vector of a §A.1 envelope — the `OpenedInitial::Establishment` payload
/// after `TwoMlsPqInvitation::open_initial` (or `decode_initial_plaintext` on an
/// already-HPKE-opened plaintext whose inner leading tag is `ESTABLISHMENT_VECTOR_TAG`).
/// Every section is optional on the wire (empty = absent); which are populated follows the
/// either/or rule on `seal_initial_envelope`:
/// - `app_payload` — the host's app-layer welcome. When present it is establishment-
///   self-sufficient (carries the MLS welcome, the initiator's CLASSICAL return key
///   package, and the bootstrap KP commitment inside, e.g. a signed identity
///   envelope), and the bare sections below are absent.
/// - `welcome` — the bare MLS `APQWelcome_A` to hand to `receive` (no app payload).
/// - `return_key_package` — the initiator's CLASSICAL return key package, a bare MLS
///   KeyPackage message handed to `receive` as-is (§A.1: the return group starts
///   classical-only; the initiator's PQ key package travels in A.4, pinned by the
///   bootstrap KP commitment).
/// - `stapled_message` — a pre-establishment app message (`[0x09][ASG-cl ciphertext]` —
///   sealed in the initiator's send group),
///   re-stapled on every initiator frame until establishment; hand it to the spawned
///   session's `process_incoming` AFTER the join (fail-open: it is an optional early
///   delivery — the sender re-sends until its first commit).
#[derive(Debug, uniffi::Record)]
pub struct InitialFrame {
    pub app_payload: Option<Vec<u8>>,
    pub welcome: Option<Vec<u8>>,
    pub return_key_package: Option<Vec<u8>>,
    pub stapled_message: Option<Vec<u8>>,
}

/// The result of opening a §A.1 envelope blob (`TwoMlsPqInvitation::open_initial`, or
/// `decode_initial_plaintext` on an HPKE-opened plaintext). The envelope carries NO outer
/// wire tag (contract 21); the inner authenticated leading tag of the HPKE plaintext selects
/// the variant — the same channel-routes-then-inner-tag-dispatches pattern the whole tag
/// space follows (see [`ESTABLISHMENT_VECTOR_TAG`]).
#[derive(Debug, uniffi::Enum)]
pub enum OpenedInitial {
    /// Leading tag `ESTABLISHMENT_VECTOR_TAG` (0x07): the establishment reply's four optional
    /// sections (see [`InitialFrame`]).
    Establishment { frame: InitialFrame },
    /// Leading tag `PQ_BOOTSTRAP_KP_TAG` (0x13): the initiator's A.4 bootstrap frame delivered
    /// IN PARALLEL with the reply (Part 3). The pre-commitment fixed the KP bytes at
    /// `initiate`, so the initiator ships its A.4 KP′ alongside the establishment reply
    /// instead of waiting a round trip for A.4's first send. `frame` is the VERBATIM
    /// `[0x13][KP′ …]` side-band frame `pq_bootstrap_respond` consumes — only the OUTER
    /// framing differed (the §A.1 HPKE envelope here vs. the header-sealed side-band in
    /// steady state). The receiver holds it UNTIL the reply establishes the session, then
    /// feeds it to `pq_bootstrap_respond`, which enforces it against the anchor-signed
    /// commitment.
    BootstrapKp { frame: Vec<u8> },
}

/// HPKE-seal `plaintext` to a published combiner key package's **PQ half** and frame it as the
/// raw §A.1 envelope blob `[u32-LE kem_output_len][kem_output][ciphertext]` — NO outer tag
/// (retired at contract 21). Both §A.1 frame kinds use this identical outer shape: the
/// establishment reply (`seal_initial_envelope`, plaintext led by `ESTABLISHMENT_VECTOR_TAG`)
/// and the parallel bootstrap-KP frame (`pq_bootstrap_envelope`, plaintext = the verbatim
/// `[0x13][KP′]` side-band frame). They are told apart only AFTER HPKE-open, by the inner
/// authenticated leading tag. The fresh HPKE ephemeral per call makes each blob unlinkable
/// (uniform pre-establishment traffic — every re-send is a distinct envelope).
///
/// The AAD is the declared suite's envelope framing (contract 22) — [`envelope_framing_aad`],
/// the one exported derivation the opener and split-path hosts share; never transmitted.
///
/// Borrows both inputs: this runs per outbound frame pre-establishment (every `encrypt`
/// re-seal and every `pq_bootstrap_envelope` re-send), so it must not force the caller to
/// clone the KB-sized retained frame or the key package per send.
pub(crate) fn seal_hpke_blob(
    their_key_package: &CombinerKeyPackage,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let aad = envelope_framing_aad();
    let sealed = hpke_seal_to_key_package_ref(their_key_package, plaintext, None, Some(&aad))?;
    frame_hpke_blob(&sealed)
}

/// Seal a §A.1 establishment envelope for the invitation channel: compose the four optional
/// sections behind the inner `ESTABLISHMENT_VECTOR_TAG` and HPKE-seal them to the peer's
/// published KP′ (PQ half). Produced by `initiate` and by every pre-establishment `encrypt`
/// (which staples the current app message); the counterpart is
/// `TwoMlsPqInvitation::open_initial`.
///
/// Either/or rule (frame-size dedup): a host `app_payload` must be establishment-
/// self-sufficient (it carries the welcome, the classical return key package, and the
/// bootstrap KP commitment inside), so when one is present the bare
/// `welcome`/`return_key_package` sections are omitted by the composer — the caller
/// passes exactly one of the two shapes. All consequential state
/// keys off the signed, JOINED welcome (the invitation's `processed` ledger); sections
/// outside `app_payload` are unauthenticated routing/establishment hints.
///
/// Framing — HPKE plaintext: `[ESTABLISHMENT_VECTOR_TAG]` then four u32-LE length-prefixed
/// sections `[app_payload][welcome][return_key_package][stapled_message]`, empty = absent, no
/// trailing bytes. The leading tag is what tells this apart from the parallel bootstrap-KP
/// frame (`[0x13][KP′]`) once both are HPKE-opened — the two ride identical raw blobs
/// (`seal_hpke_blob`) with no outer distinguisher.
pub(crate) fn seal_initial_envelope(
    their_key_package: &CombinerKeyPackage,
    app_payload: Option<&[u8]>,
    welcome: Option<&[u8]>,
    return_key_package: Option<&[u8]>,
    stapled_message: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let sections = [app_payload, welcome, return_key_package, stapled_message];
    let mut plaintext = Vec::with_capacity(
        1 + sections
            .iter()
            .map(|s| 4 + s.map_or(0, <[u8]>::len))
            .sum::<usize>(),
    );
    plaintext.push(ESTABLISHMENT_VECTOR_TAG);
    for section in sections {
        let bytes = section.unwrap_or(&[]);
        plaintext.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(bytes);
    }
    seal_hpke_blob(their_key_package, &plaintext)
}

/// Dispatch an HPKE-opened §A.1 plaintext on its inner authenticated leading tag — the
/// attacker-facing decoder shared by `open_initial` and any host that HPKE-opens the envelope
/// itself (`hpke_open`). `ESTABLISHMENT_VECTOR_TAG` (0x07) → the four optional establishment
/// sections (see [`InitialFrame`]); `PQ_BOOTSTRAP_KP_TAG` (0x13) → the parallel bootstrap-KP
/// frame, returned VERBATIM (`[0x13][KP′]`, the exact bytes `pq_bootstrap_respond` consumes).
/// Any other leading byte is `Mls`.
///
/// For a replay-stable token, a host keys off the establishment vector's stable prefix:
/// `app_payload` when present, else `welcome` — the two sections identical across an
/// initiator's re-sealed/re-stapled envelopes (the bootstrap-KP frame is itself stable
/// per-round, but the fresh HPKE outer makes every emitted blob distinct). Rejects
/// truncation, trailing bytes, and an establishment vector carrying NOTHING (no `app_payload`
/// and no `welcome`).
#[uniffi::export]
pub fn decode_initial_plaintext(plaintext: Vec<u8>) -> Result<OpenedInitial> {
    let (&tag, body) = plaintext.split_first().ok_or(TwoMlsPqError::Mls)?;
    match tag {
        ESTABLISHMENT_VECTOR_TAG => {
            let mut rest = body;
            let mut sections: [Option<Vec<u8>>; 4] = [const { None }; 4];
            for slot in sections.iter_mut() {
                let bytes = take_bytes(&mut rest).ok_or(TwoMlsPqError::Mls)?;
                *slot = (!bytes.is_empty()).then_some(bytes);
            }
            if !rest.is_empty() {
                return Err(TwoMlsPqError::Mls);
            }
            let [app_payload, welcome, return_key_package, stapled_message] = sections;
            if app_payload.is_none() && welcome.is_none() {
                return Err(TwoMlsPqError::Mls);
            }
            Ok(OpenedInitial::Establishment {
                frame: InitialFrame {
                    app_payload,
                    welcome,
                    return_key_package,
                    stapled_message,
                },
            })
        }
        crate::session::frames::PQ_BOOTSTRAP_KP_TAG => {
            Ok(OpenedInitial::BootstrapKp { frame: plaintext })
        }
        _ => Err(TwoMlsPqError::Mls),
    }
}

/// The §A.1 envelope's HPKE AAD (contract 22): `[framing version (1)][classical u16 BE]
/// [pq u16 BE]` — the declared suite's envelope framing, **derived locally on both sides
/// and never transmitted** (RFC 9180 `aad` is a seal/open input, not part of the
/// ciphertext; only byte-equality matters). Binding it means a peer whose declared suite
/// pair or framing version differs fails the AEAD tag (`DecryptionFailed`) — downgrade
/// binding of the WHOLE pair, classical half included, at zero wire bytes. Exported so a
/// host driving the split path (`hpke_open` + `decode_initial_plaintext`) supplies the
/// same bytes without hardcoding them — the `pq_frame_kind` convention; `open_initial`
/// derives it internally.
#[uniffi::export]
pub fn envelope_framing_aad() -> Vec<u8> {
    crate::suite::framing_aad(crate::suite::TwoMlsSuite::CURRENT).to_vec()
}

/// HPKE-seal `plaintext` to a published combiner key package's **PQ half** init key (spec
/// §A.1: the envelope is sealed to the PQ EK in KP′, under the PQ suite) — the sender side
/// of the initial routing-header pattern; the holder of the key package's invitation opens
/// it with `TwoMlsPqInvitation::hpke_open`. `info` defaults to the key package's credential
/// (the recipient's ClientId), matching `hpke_open`'s default. A §A.1 envelope seal passes
/// [`envelope_framing_aad`] as `aad` (the crate's own seal paths do so via
/// `seal_hpke_blob`); the parameter stays open for non-envelope uses.
#[uniffi::export]
pub fn hpke_seal_to_key_package(
    key_package: CombinerKeyPackage,
    plaintext: Vec<u8>,
    info: Option<Vec<u8>>,
    aad: Option<Vec<u8>>,
) -> Result<HpkeSealed> {
    hpke_seal_to_key_package_ref(&key_package, &plaintext, info.as_deref(), aad.as_deref())
}

/// Borrowed-parameter body of [`hpke_seal_to_key_package`] — the owned-value signature is a
/// uniffi boundary requirement, but the in-crate per-send paths (`seal_hpke_blob`) must not
/// pay a `CombinerKeyPackage` clone and a plaintext copy per call to satisfy it.
fn hpke_seal_to_key_package_ref(
    key_package: &CombinerKeyPackage,
    plaintext: &[u8],
    info: Option<&[u8]>,
    aad: Option<&[u8]>,
) -> Result<HpkeSealed> {
    let kp = mls_rs::MlsMessage::from_bytes(&key_package.pq)
        .map_err(|_| TwoMlsPqError::InvalidKeyPackage)?
        .into_key_package()
        .ok_or(TwoMlsPqError::InvalidKeyPackage)?;

    let info = match info {
        Some(info) => info.to_vec(),
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
        .hpke_seal(&kp.hpke_init_key, &info, aad, plaintext)
        .map_err(|_| TwoMlsPqError::Mls)?;
    Ok(HpkeSealed {
        kem_output: sealed.kem_output,
        ciphertext: sealed.ciphertext,
    })
}

/// Frame an HPKE seal as the raw §A.1 envelope blob `[u32-LE kem_output_len][kem_output]
/// [ciphertext]` — the single writer of the outer framing `open_initial` parses. Split from
/// [`seal_hpke_blob`] so a test forcing a non-standard seal (e.g. the contract-22
/// `aad = None` compat cut) frames through the same code instead of a hand copy.
pub(crate) fn frame_hpke_blob(sealed: &HpkeSealed) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + sealed.kem_output.len() + sealed.ciphertext.len());
    out.extend_from_slice(&(sealed.kem_output.len() as u32).to_le_bytes());
    out.extend_from_slice(&sealed.kem_output);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
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
/// All of a `TwoMlsPqInvitation`'s mutable state, behind one lock so `receive` runs its
/// whole critical section (checks → join → commit) under a single acquisition — no
/// cross-lock ordering to reason about, and no rollback: every fallible step happens
/// before the first field is mutated, so an error path leaves this untouched.
struct InvitationInner {
    /// The self-contained invitation. A single-use invitation mutates it (the captured
    /// key package is dropped once consumed); a last-resort one never does.
    invitation: CombinerInvitation,
    /// Remote client ids already turned into a session — the transport at-most-once guard.
    /// A `BTreeSet` for deterministic encoding; persisted so the guard survives a restore.
    consumed: BTreeSet<Vec<u8>>,
    /// The forward table: opaque spawn token → the spawned session's receive-group ids. A
    /// replayed initial frame decodes to a token already here; the caller routes it to the
    /// owning session instead of treating it as a fresh welcome. Persisted.
    spawned: SpawnedGroups,
    /// The processed-welcome ledger: SHA-256 of each accepted welcome's exact bytes → the
    /// spawned session's receive-group classical id. Welcomes cannot be assumed to arrive
    /// exactly once; a re-delivered welcome resolves here (content-keyed — no host token
    /// convention required, unlike `spawned`) instead of erroring or re-spawning. Persisted.
    processed: ProcessedWelcomes,
    /// Per-invitation monotonic mutation counter, bumped once per state-advancing call (a
    /// successful `receive`). Serialized in the archive so it continues across a restore and
    /// stamps each pushed blob. `u64` so it cannot overflow; the bump is a `checked_add` that
    /// stops persisting rather than wrapping (the crate denies panic).
    state_seq: u64,
    /// The foreign persistence hook this invitation pushes to after every state-advancing
    /// mutation (see [`crate::ArchiveSink`]). `None` opts out (tests, benches). Not part of
    /// the archive — it is live plumbing supplied at construction via `install_sink`.
    sink: Option<Arc<dyn crate::ArchiveSink>>,
}

/// A checkpoint ready to push once the caller has dropped the lock: `(sink, seq, bytes)`.
type PendingCheckpointPush = (Arc<dyn crate::ArchiveSink>, u64, Vec<u8>);

impl InvitationInner {
    /// Encode this invitation's persisted form (everything but the live `sink`).
    fn encode(&self) -> Result<Vec<u8>> {
        encode_archive(
            &self.invitation,
            &self.consumed,
            &self.spawned,
            &self.processed,
            self.state_seq,
        )
    }

    /// Bump `state_seq` and, if a sink is installed, encode a fresh checkpoint UNDER the
    /// caller's lock — returning `(sink, seq, bytes)` for the caller to `persist` once the
    /// guard is dropped (encode inside the lock, push outside, mirroring the session).
    /// `Ok(None)` when there is no sink or the counter saturated (unreachable in practice); the
    /// bump still lands so `state_seq` counts mutations whether or not a sink is attached. An
    /// encode-after-mutation failure is SURFACED (`Err`) — mirroring the session's
    /// `mutate_and_persist` — so the caller reports it rather than silently returning a session
    /// whose state was mutated but never persisted.
    fn bump_and_encode(&mut self) -> Result<Option<PendingCheckpointPush>> {
        let Some(next) = self.state_seq.checked_add(1) else {
            return Ok(None);
        };
        self.state_seq = next;
        let Some(sink) = self.sink.clone() else {
            return Ok(None);
        };
        let bytes = self.encode()?;
        Ok(Some((sink, next, bytes)))
    }
}

#[derive(uniffi::Object)]
pub struct TwoMlsPqInvitation {
    // One lock over all mutable state (see `InvitationInner`): a single-use `receive`
    // mutates the captured key package, the consumed set, the forward table, and the
    // processed ledger together, so guarding them as one unit keeps the critical section
    // atomic and rollback-free. Persisted fields survive `archive()`/restore.
    inner: Mutex<InvitationInner>,
}

#[uniffi::export]
impl TwoMlsPqInvitation {
    /// Materialise a live invitation from its serialised bytes — the output of
    /// `TwoMlsPqPrincipal.generateInvitation` on first use, or a pushed checkpoint blob on
    /// restore. Named `restore`, not `new`: the state lives in the bytes and this mints none of
    /// it (mirrors the session's `restore`).
    #[uniffi::constructor]
    pub fn restore(archive: Vec<u8>) -> Result<Arc<Self>> {
        let (invitation, consumed, spawned, processed, state_seq) = decode_archive(&archive)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(InvitationInner {
                invitation,
                consumed,
                spawned,
                processed,
                state_seq,
                // Attached post-construction via `install_sink` (same as the session's
                // restore path); a fresh invitation starts with no persistence hook.
                sink: None,
            }),
        }))
    }

    /// Attach the persistence hook (see [`crate::ArchiveSink`]) this invitation pushes to
    /// after every state-advancing mutation, and immediately push a baseline `Checkpoint` at
    /// the current `state_seq` so the sink starts from a complete snapshot. Call once, right
    /// after construction and before use — mutations made before installing are not pushed (a
    /// fresh invitation has none; a restored one re-baselines here). Installing does not
    /// itself advance `state_seq`. The invitation is monolithic (no ML-KEM ratchet trees to
    /// split off), so it only ever pushes `Checkpoint`.
    pub fn install_sink(&self, sink: Arc<dyn crate::ArchiveSink>) -> Result<()> {
        let mut inner = self.lock();
        // Install exactly once (see `TwoMlsPqSession::install_sink`): a second call would
        // silently orphan the first sink, so reject it.
        if inner.sink.is_some() {
            return Err(TwoMlsPqError::SinkAlreadyInstalled);
        }
        inner.sink = Some(Arc::clone(&sink));
        let seq = inner.state_seq;
        let bytes = inner.encode()?;
        drop(inner);
        sink.persist(seq, crate::BlobKind::Checkpoint, bytes);
        Ok(())
    }

    /// The current per-invitation mutation counter (bumped once per successful `receive`),
    /// which stamps each pushed blob and feeds the app's `depends_on_seq` transmit gate.
    pub fn state_seq(&self) -> u64 {
        self.lock().state_seq
    }

    /// The principal's ClientId.
    pub fn client_id(&self) -> ClientId {
        ClientId {
            bytes: self.lock().invitation.client_id.clone(),
        }
    }

    /// The published (public) combiner key package to hand to a remote initiator. Still
    /// available after a single-use invitation is spent (the published key package is public);
    /// only the private material is dropped on consume.
    pub fn combiner_key_package(&self) -> CombinerKeyPackage {
        let inner = self.lock();
        CombinerKeyPackage {
            classical: inner.invitation.classical_public.clone(),
            pq: inner.invitation.pq_public.clone(),
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
    ///
    /// `new_client_id` is an optional dedicated per-session principal: when `Some`, the
    /// spawned session's send group is created under a freshly-minted principal carrying
    /// that ClientId (signing keys are session-owned, minted internally — the same
    /// convention as `stage_rotation`), so the initiator sees the dedicated principal
    /// from the very first frame and no rotation commit is needed. The receive-group
    /// join still uses this invitation's identity — the welcome was addressed to its key
    /// package. `None` keeps the session under the invitation identity.
    ///
    /// `their_classical_key_package` is the initiator's CLASSICAL return key package —
    /// a bare MLS KeyPackage message, not a combiner blob (§A.1: the send group this
    /// call creates starts classical-only, so classical is all it needs; the
    /// initiator's PQ key package arrives later, in the A.4 side-band).
    /// `bootstrap_kp_commitment` is `H(initiator's PQ keyPackage)` from the SIGNED
    /// establishment payload: `pq_bootstrap_respond` refuses to stand up the PQ half
    /// around a KP′ that hashes to anything else (`BootstrapKpMismatch`), anchoring the
    /// ML-KEM key material to the establishment signature. Exactly 32 bytes (SHA-256) —
    /// any other length is rejected up front, since it could never match.
    ///
    /// `expected_remote` is the identity the caller already expects this welcome to come
    /// from (the app validated it from the decrypted initial frame). When `Some`, a key
    /// package naming anyone else is rejected as `RemoteIdentityMismatch` — before any
    /// invitation state is claimed, so the invitation stays fully reusable. `None` skips
    /// the check (the welcome-creator ≡ key-package binding below still applies).
    ///
    /// `expected_app_binding` is the app-state binding this welcome must carry — the
    /// opaque bytes the initiator welded into its send group's GroupContext (see
    /// `TwoMlsPqSession::initiate`; a DIGEST of the app's immutable relationship
    /// identity, which this library never interprets). The check is an exact, symmetric
    /// match: `Some` requires the joined group's `AppBinding` extension to be byte-equal
    /// (absent or different — a stripped, downgraded, or wrong-relationship welcome — is
    /// `AppBindingMismatch`); `None` requires the welcome to carry none (a binding the
    /// caller did not state is rejected, never silently accepted — pass the binding you
    /// can verify). Unlike `expected_remote` this necessarily verifies after the join
    /// (GroupContext rides the encrypted welcome), but still BEFORE any invitation state
    /// is claimed: a rejected welcome consumes nothing, and the invitation stays fully
    /// usable for the genuine one. On success the spawned session's send group carries
    /// the same binding back to the initiator. An EMPTY expectation is rejected up
    /// front — empty is reserved (no group can carry an empty binding; `None` is the
    /// unbound state), so it could never match.
    //
    // Flat by design: this is the uniffi FFI surface, where a parameter struct would
    // trade one long-but-documented signature for an extra exported record type. Same
    // ruling as `build_session`.
    #[allow(clippy::too_many_arguments)]
    pub fn receive(
        &self,
        welcome: Vec<u8>,
        their_classical_key_package: Vec<u8>,
        bootstrap_kp_commitment: Vec<u8>,
        spawn_token: Vec<u8>,
        new_client_id: Option<Vec<u8>>,
        expected_remote: Option<Vec<u8>>,
        expected_app_binding: Option<Vec<u8>>,
    ) -> Result<Arc<TwoMlsPqSession>> {
        // --- Lock-free validations: pure, side-effect-free, so a rejection here touches
        // nothing and needs no lock. ---
        //
        // Empty ids are reserved (no leaf credential carries one, so no rotation
        // commit could ever announce it) — reject rather than mint an unannounceable
        // principal.
        if new_client_id.as_deref().is_some_and(<[u8]>::is_empty) {
            return Err(TwoMlsPqError::InvalidClientId);
        }
        // Empty bindings are likewise reserved (`AppBindingMismatch` documents the rule):
        // no group can carry one, so an empty expectation is unsatisfiable — reject it
        // here, lock-free, rather than let it surface as a confusing post-join mismatch.
        if expected_app_binding
            .as_deref()
            .is_some_and(<[u8]>::is_empty)
        {
            return Err(TwoMlsPqError::AppBindingMismatch);
        }
        // Parse the classical key package for its identity; compare it against the
        // caller's expectation for the early rejection. (`accept_with` re-validates the
        // suite and binds the welcome's creator leaf to this same identity.)
        let their_id = parse_mls_key_package(their_classical_key_package.clone())?.client_id;
        if expected_remote.is_some_and(|expected| expected != their_id.bytes) {
            return Err(TwoMlsPqError::RemoteIdentityMismatch);
        }
        let session_client = new_client_id.map(TwoMlsPqPrincipal::new).transpose()?;
        let welcome_digest = crate::sha256(&welcome);

        // --- One critical section: every check, the join, and the commit run under a single
        // lock acquisition. Crucially, none of the invitation's fields are mutated until the
        // commit point below, so any early return (a rejected check or a failed establishment)
        // drops the guard with the state exactly as it was — this is what replaces the old
        // claim/reserve-then-rollback dance. `accept_with` does not touch this invitation, so
        // running it under the lock is safe. ---
        let mut inner = self.lock();

        // Content-keyed idempotency: a welcome these exact bytes already spawned a session from
        // is a re-delivery, not a fresh invite — the caller resolves it via
        // `processed_welcome_group_id` and routes to the owning session.
        if inner.processed.contains_key(&welcome_digest) {
            return Err(TwoMlsPqError::DuplicateWelcome);
        }
        // Single-use gate: a spent single-use invitation has dropped its captured key-package
        // material, so it rejects every further welcome from any remote.
        if inner.invitation.classical_kpd.is_none() {
            return Err(TwoMlsPqError::InvitationSpent);
        }
        // Per-remote at-most-once guard (a replay from an already-established remote).
        if inner.consumed.contains(&their_id.bytes) {
            return Err(TwoMlsPqError::DuplicateWelcome);
        }

        // Build the stateless client from the still-present captured material and establish the
        // session. Both fallible steps happen before any mutation, so a failure here returns
        // without having claimed or reserved anything.
        let session =
            TwoMlsPqPrincipal::from_combiner_invitation(&inner.invitation).and_then(|client| {
                // R1: the spawn token is set inside `accept_with` before the birth checkpoint,
                // so it rides the persisted birth state (the old post-construction setter
                // would miss it).
                TwoMlsPqSession::accept_with(
                    client,
                    session_client,
                    welcome,
                    their_classical_key_package,
                    bootstrap_kp_commitment,
                    Some(spawn_token.clone()),
                    expected_app_binding,
                )
            })?;
        // The acceptor always has a receive group straight out of `accept`; its absence is a
        // library invariant violation. Resolved before the commit so this too is a clean
        // early return.
        let gid = session.receive_group_id().ok_or(TwoMlsPqError::Mls)?;

        // --- Commit point: all fallible work is done. From here nothing can fail out, so the
        // mutations below are the only writes and they are all-or-nothing. ---
        inner.consumed.insert(their_id.bytes);
        inner
            .spawned
            .insert(spawn_token, gid.classical.bytes.clone());
        inner.processed.insert(welcome_digest, gid.classical.bytes);
        // Single-use consume: drop the captured material so a later `receive` sees it spent. A
        // last-resort invitation retains it for reuse.
        if !inner.invitation.last_resort {
            inner.invitation.classical_kpd = None;
            inner.invitation.pq_kpd = None;
        }

        // A successful receive advanced state: bump the counter and (if a sink is installed)
        // encode the checkpoint under the lock, then push it once the guard is dropped. A
        // failed receive never reaches here, so it pushes nothing; a failed encode surfaces as
        // `Err` (state was mutated but not persisted — the caller must not treat it as durable).
        let push = inner.bump_and_encode()?;
        drop(inner);
        if let Some((sink, seq, bytes)) = push {
            sink.persist(seq, crate::BlobKind::Checkpoint, bytes);
        }
        Ok(session)
    }

    /// Resolve an initial frame's spawn token against the forward table: `Some` names
    /// the receive group (classical, message-half id) of the session this invitation
    /// already spawned from an identical frame (route the payload there — see
    /// `TwoMlsPqSession::forwarded`), `None` means the frame is fresh and should
    /// proceed through app validation to `receive`.
    pub fn forward_group_id(&self, spawn_token: Vec<u8>) -> Option<MlsGroupId> {
        self.lock()
            .spawned
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
        self.lock()
            .processed
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
    /// Opening a §A.1 envelope blob requires `aad = envelope_framing_aad()` (contract 22 —
    /// the suite binding `open_initial` derives internally; without it the tag fails).
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

        let inner = self.lock();
        let invitation = &inner.invitation;

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

    /// Open a §A.1 envelope blob (produced by `initiate`, by every pre-establishment
    /// `encrypt`, or by `pq_bootstrap_envelope`), dispatching on the inner authenticated
    /// leading tag into [`OpenedInitial`]. Decrypt-only and **state-free** — it does NOT
    /// consume a single-use invitation's key package (consumption happens in `receive`), so a
    /// host can open a frame to validate it before deciding to join, and re-opens are
    /// harmless. Fails `InvitationSpent` once a single-use invitation is consumed (its KP′
    /// material, and thus the opener, is gone); `DecryptionFailed`/`Mls` on a malformed or
    /// wrong-key blob. The counterpart is the free function `seal_hpke_blob`
    /// (via `seal_initial_envelope` / `pq_bootstrap_envelope`).
    ///
    /// The blob carries NO outer tag (`[u32-LE kem_len][kem_output][ciphertext]`); the host
    /// already knows to open it because it arrived on the invitation channel. Which §A.1 frame
    /// it is — establishment vector or parallel bootstrap KP — is decided only after
    /// HPKE-open, by the plaintext's leading byte.
    ///
    /// Every envelope from one initiator is freshly HPKE-sealed (different outer bytes)
    /// and — pre-establishment — may staple a different app message, so a replay-stable
    /// token must be computed over the decrypted STABLE PREFIX: the `app_payload`
    /// section when present, else the `welcome` section (see `decode_initial_plaintext`).
    pub fn open_initial(&self, blob: Vec<u8>) -> Result<OpenedInitial> {
        // The blob is `[u32-LE kem_len][kem_output][ciphertext]` — no outer tag (contract 21).
        // HPKE-open under the locally-derived envelope-framing AAD (contract 22: the declared
        // suite's bytes, never transmitted — a peer declaring a different suite or framing
        // version fails the tag as `DecryptionFailed`), then dispatch on the plaintext's
        // inner leading tag.
        let mut rest = blob.as_slice();
        let kem_output = take_bytes(&mut rest).ok_or(TwoMlsPqError::Mls)?;
        let ciphertext = rest.to_vec();
        let plaintext = self.hpke_open(kem_output, ciphertext, None, Some(envelope_framing_aad()))?;
        decode_initial_plaintext(plaintext)
    }
}

impl TwoMlsPqInvitation {
    /// Serialise the invitation as one blob — the legacy pull path, NOT on the FFI surface
    /// (push persistence via `ArchiveSink` + `install_sink` replaced it). Kept `pub` for
    /// in-crate tests only.
    pub fn archive(&self) -> Result<Vec<u8>> {
        self.lock().encode()
    }

    /// Lock the invitation's single state cell, recovering from a poisoned mutex (the guarded
    /// data is plain records; a panic mid-update can't leave it torn). Every method takes this
    /// one guard — `receive` holds it across its whole critical section, so there is no
    /// cross-lock ordering and no rollback to reason about.
    fn lock(&self) -> std::sync::MutexGuard<'_, InvitationInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Harness-only openers that flatten [`OpenedInitial`] to the variant a fixture expects, so
/// the crate's establishment tests and benches read the same whether or not Part 3's
/// inner-tag dispatch is in play. A wrong variant maps to `Err(Mls)` so the call site's
/// `assert_ok!`/`unwrap` surfaces it (the crate denies explicit `panic!`). Shared across
/// `test_utils`, the `key_packages`/`session` tests, and — via the `benchmark_util`
/// feature — `benches/common.rs`, so there is exactly ONE copy of this dispatch. NOT part
/// of the FFI surface.
#[cfg(any(test, feature = "benchmark_util"))]
impl TwoMlsPqInvitation {
    /// Open a §A.1 blob and require the establishment variant, returning its `InitialFrame`.
    pub fn open_establishment(&self, blob: Vec<u8>) -> Result<InitialFrame> {
        match self.open_initial(blob)? {
            OpenedInitial::Establishment { frame } => Ok(frame),
            OpenedInitial::BootstrapKp { .. } => Err(TwoMlsPqError::Mls),
        }
    }

    /// Open a §A.1 blob and require the parallel bootstrap-KP variant, returning the verbatim
    /// `[0x13][KP′]` frame.
    pub fn open_bootstrap_kp(&self, blob: Vec<u8>) -> Result<Vec<u8>> {
        match self.open_initial(blob)? {
            OpenedInitial::BootstrapKp { frame } => Ok(frame),
            OpenedInitial::Establishment { .. } => Err(TwoMlsPqError::Mls),
        }
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
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        // Bob publishes an invitation instead of retaining key-package state on the client.
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // Bob accepts through the invitation (no live client that generated the KP).
        let bob_session = assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
        let welcome_b = assert_some!(bob_session.pending_outbound());
        assert_ok!(alice_session.process_incoming(welcome_b));

        assert!(alice_session.is_established());
        assert!(bob_session.is_established());
    }

    #[test]
    fn test_invitation_receive_rejects_duplicate_remote() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // First receive consumes Alice's identity.
        assert_ok!(bob_inv.receive(
            welcome_a.clone(),
            alice_kp.clone(),
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
        // A second welcome from the same remote is rejected as a replay.
        assert_err!(
            bob_inv.receive(
                welcome_a,
                alice_kp,
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                None
            ),
            crate::TwoMlsPqError::DuplicateWelcome
        );
    }

    #[test]
    fn test_invitation_processed_welcome_ledger_resolves_redelivery() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // Fresh welcome: no ledger entry yet.
        assert!(bob_inv
            .processed_welcome_group_id(welcome_a.clone())
            .is_none());

        let bob_session = assert_ok!(bob_inv.receive(
            welcome_a.clone(),
            alice_kp.clone(),
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));

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
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp,
                commitment_of(&alice_session),
                b"token2".to_vec(),
                None,
                None,
                None
            ),
            crate::TwoMlsPqError::DuplicateWelcome
        );

        // The ledger survives the archive round-trip.
        let restored = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob_inv.archive()
        )));
        assert_some!(restored.processed_welcome_group_id(welcome_a));
    }

    #[test]
    fn test_invitation_hpke_open_round_trips() {
        use crate::test_utils::make_client;

        let bob = make_client();
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
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
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
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

    /// The exported §A.1 AAD is exactly the documented bytes: the framing version, then
    /// the DECLARED SUITE's wire encoding (`TwoMlsSuite::CURRENT.to_wire()` — the
    /// production authority, not a parallel constant). A host on the split `hpke_open`
    /// path derives its aad from this export, so the bytes are the contract; the layout
    /// itself is pinned by `suite::tests::framing_aad_is_version_then_pair`.
    #[test]
    fn test_envelope_framing_aad_is_version_then_suite_pair() {
        use crate::suite::{TwoMlsSuite, ENVELOPE_FRAMING_VERSION};
        let aad = super::envelope_framing_aad();
        let mut expected = vec![ENVELOPE_FRAMING_VERSION];
        expected.extend_from_slice(&TwoMlsSuite::CURRENT.to_wire());
        assert_eq!(aad, expected);
        assert_eq!(aad[0], 1, "contract 22 pins framing version 1");
    }

    /// The §A.1 envelope HPKE binds the declared suite via untransmitted AAD (contract
    /// 22): the split-open path succeeds only under `envelope_framing_aad()` — a v21-style
    /// `aad = None` open and a tampered-suite aad both fail the AEAD tag as
    /// `DecryptionFailed` (deliberately opaque: an incompatible peer build is
    /// indistinguishable from garbage by construction), while `open_initial` derives the
    /// aad internally and still round-trips.
    #[test]
    fn test_open_initial_binds_envelope_framing_aad() {
        use crate::test_utils::make_client;
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let alice_session = assert_ok!(crate::session::TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_inv.combiner_key_package(),
            None
        ));
        let blob = assert_some!(alice_session.pending_outbound());

        // Split the raw blob `[u32-LE kem_len][kem_output][ciphertext]` for the host path,
        // through the same cursor production `open_initial` parses with.
        let mut rest = blob.as_slice();
        let kem_output = assert_some!(super::take_bytes(&mut rest));
        let ciphertext = rest.to_vec();

        // A v21-style open (no aad) fails the tag: the compat cut is cryptographic, not
        // a blob-shape change.
        assert_err!(
            bob_inv.hpke_open(kem_output.clone(), ciphertext.clone(), None, None),
            crate::TwoMlsPqError::DecryptionFailed
        );

        // A tampered aad (wrong suite byte / wrong version) fails identically.
        let mut wrong_suite = super::envelope_framing_aad();
        *wrong_suite.last_mut().unwrap() ^= 0x01;
        assert_err!(
            bob_inv.hpke_open(
                kem_output.clone(),
                ciphertext.clone(),
                None,
                Some(wrong_suite)
            ),
            crate::TwoMlsPqError::DecryptionFailed
        );

        // The correct derived aad opens, and the plaintext dispatches as the
        // establishment vector — the split-open host path end to end.
        let plaintext = assert_ok!(bob_inv.hpke_open(
            kem_output,
            ciphertext,
            None,
            Some(super::envelope_framing_aad())
        ));
        assert!(matches!(
            assert_ok!(super::decode_initial_plaintext(plaintext)),
            super::OpenedInitial::Establishment { .. }
        ));

        // `open_initial` derives the same aad internally (state-free re-open).
        assert!(matches!(
            assert_ok!(bob_inv.open_initial(blob)),
            super::OpenedInitial::Establishment { .. }
        ));
    }

    /// The other direction of the contract-22 compat cut: a blob sealed WITHOUT the
    /// envelope-framing aad (a v21 build's seal) fails `open_initial`'s tag check — the
    /// suite binding is load-bearing on every §A.1 open, not advisory.
    #[test]
    fn test_open_initial_rejects_aad_none_seal() {
        use crate::test_utils::make_client;

        let bob = make_client();
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));

        // Seal a well-formed establishment-shaped plaintext the v21 way (aad = None),
        // framed by the production framer so only the missing aad differs.
        let sealed = assert_ok!(super::hpke_seal_to_key_package(
            bob_inv.combiner_key_package(),
            vec![super::ESTABLISHMENT_VECTOR_TAG],
            None,
            None,
        ));
        let blob = assert_ok!(super::frame_hpke_blob(&sealed));

        assert_err!(
            bob_inv.open_initial(blob),
            crate::TwoMlsPqError::DecryptionFailed
        );
    }

    #[test]
    fn test_invitation_archive_persists_consumed_set() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // Consume Alice on the live invitation.
        assert_ok!(bob_inv.receive(
            welcome_a.clone(),
            alice_kp.clone(),
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));

        // Archive + restore; the consumed set must survive so the replay is still rejected.
        let restored = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob_inv.archive()
        )));
        assert_err!(
            restored.receive(
                welcome_a,
                alice_kp,
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                None
            ),
            crate::TwoMlsPqError::DuplicateWelcome
        );
    }

    #[test]
    fn test_invitation_new_rejects_malformed_archive() {
        assert_err!(
            super::TwoMlsPqInvitation::restore(vec![0xFF, 0xFF, 0xFF]),
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
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // Fresh frame: nothing to forward to yet.
        let token = b"spawn-token".to_vec();
        assert!(bob_inv.forward_group_id(token.clone()).is_none());

        let bob_session = assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            token.clone(),
            None,
            None,
            None
        ));

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
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        let token = b"spawn-token".to_vec();
        let bob_session = assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            token.clone(),
            None,
            None,
            None
        ));
        let recv = assert_some!(bob_session.receive_group_id());

        let restored = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob_inv.archive()
        )));
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
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // A failed establishment must NOT consume the remote — the reservation is rolled
        // back, so a valid retry from the same remote still succeeds.
        assert!(bob_inv
            .receive(
                b"not-a-welcome".to_vec(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"bad".to_vec(),
                None,
                None,
                None
            )
            .is_err());
        // …and the failed spawn must not enter the forward table either.
        assert!(bob_inv.forward_group_id(b"bad".to_vec()).is_none());
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
    }

    /// A single-use (not last-resort) invitation accepts exactly one welcome; afterwards its
    /// key package is spent — a fresh remote is refused with `InvitationSpent`, proving the
    /// limit is on the key package itself, not merely a per-remote replay guard.
    #[test]
    fn test_invitation_single_use_consumes_key_package() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let carol = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let carol_kp = make_classical_kp(&carol);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp.clone(),
            None
        ));
        let welcome_a = assert_some!(alice_session.initial_welcome());
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token-a".to_vec(),
            None,
            None,
            None
        ));

        let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
        let welcome_c = assert_some!(carol_session.initial_welcome());
        assert_err!(
            bob_inv.receive(
                welcome_c,
                carol_kp,
                commitment_of(&carol_session),
                b"token-c".to_vec(),
                None,
                None,
                None
            ),
            crate::TwoMlsPqError::InvitationSpent
        );
    }

    /// A single-use invitation's spent state (its key package dropped from the archive)
    /// survives archive/restore: the restored invitation still refuses to accept and can no
    /// longer HPKE-open, because the private material is gone.
    #[test]
    fn test_invitation_single_use_archive_drops_key_package() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let carol = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let carol_kp = make_classical_kp(&carol);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp.clone(),
            None
        ));
        let welcome_a = assert_some!(alice_session.initial_welcome());
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token-a".to_vec(),
            None,
            None,
            None
        ));

        let restored = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob_inv.archive()
        )));
        let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
        let welcome_c = assert_some!(carol_session.initial_welcome());
        assert_err!(
            restored.receive(
                welcome_c,
                carol_kp,
                commitment_of(&carol_session),
                b"token-c".to_vec(),
                None,
                None,
                None
            ),
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
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        assert!(bob_inv
            .receive(
                b"not-a-welcome".to_vec(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"bad".to_vec(),
                None,
                None,
                None
            )
            .is_err());
        // The key package was restored, so a valid welcome still establishes.
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
    }

    /// The defining last-resort behavior: the same published key package accepts welcomes from
    /// two *distinct* remotes (the material is retained across joins, bounded only by the
    /// per-remote guard).
    #[test]
    fn test_last_resort_invitation_reuses_across_distinct_remotes() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let carol = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let carol_kp = make_classical_kp(&carol);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp.clone(),
            None
        ));
        let welcome_a = assert_some!(alice_session.initial_welcome());
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token-a".to_vec(),
            None,
            None,
            None
        ));

        let carol_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&carol), bob_kp, None));
        let welcome_c = assert_some!(carol_session.initial_welcome());
        assert_ok!(bob_inv.receive(
            welcome_c,
            carol_kp,
            commitment_of(&carol_session),
            b"token-c".to_vec(),
            None,
            None,
            None
        ));
    }

    /// The key-package store is only a serving interface: once the acceptor's join has
    /// consumed the invitation key package, nothing of the invitation may remain in the
    /// session client (and thus its archive). Exercised for a last-resort invitation, the
    /// case that previously retained — and leaked — the shared key package.
    #[test]
    fn test_accept_leaves_no_key_package_in_acceptor_session() {
        use crate::invitation::generate_combiner_invitation;
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

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
        let welcome_a = assert_some!(alice_session.initial_welcome());

        let _bob_session = assert_ok!(TwoMlsPqSession::accept(
            bob_client,
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            None
        ));

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
        // Layout: [state_seq u64 BE (8 bytes)][varint len][version][classical u16 BE][pq u16 BE]…
        // `state_seq` is a fixed 8-byte big-endian prefix (0 for a fresh invitation); the framed
        // invitation byte_vec follows it. The MLS varint's top two bits give the length width.
        // Flip a byte of the classical suite so the archived pair no longer equals this build's
        // pinned suite (mimicking an archive from another build/suite).
        const STATE_SEQ_LEN: usize = 8;
        let header = match archive[STATE_SEQ_LEN] >> 6 {
            0 => 1,
            1 => 2,
            _ => 4,
        };
        archive[STATE_SEQ_LEN + header + 1] ^= 1;
        assert_err!(
            super::TwoMlsPqInvitation::restore(archive),
            crate::TwoMlsPqError::ArchiveInvalid
        );
    }

    /// `expected_remote` early rejection: a key package naming anyone but the expected
    /// principal fails BEFORE any invitation state is claimed — the same welcome then
    /// establishes normally with the right expectation (and with `None`).
    #[test]
    fn test_receive_rejects_unexpected_remote() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{
            commitment_of, make_classical_kp, make_client, test_client_id as fresh_id,
        };
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // Wrong expectation → rejected, nothing consumed or recorded.
        assert_err!(
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                Some(fresh_id()),
                None
            ),
            crate::TwoMlsPqError::RemoteIdentityMismatch
        );
        assert!(bob_inv
            .processed_welcome_group_id(welcome_a.clone())
            .is_none());
        assert!(bob_inv.forward_group_id(b"token".to_vec()).is_none());

        // The correct expectation establishes from the very same welcome.
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            Some(alice.client_id().bytes),
            None
        ));
    }

    /// The welcome's creator leaf must match the supplied key package: a welcome from
    /// one principal handed in with another principal's key package is rejected instead
    /// of silently establishing against the wrong identity.
    #[test]
    fn test_receive_rejects_welcome_creator_kp_mismatch() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let mallory = make_client();
        let bob = make_client();
        let mallory_kp = make_classical_kp(&mallory);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();
        // The welcome really is Alice's…
        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // …but the caller attributes it to Mallory: the join-time creator≡KP binding
        // rejects it (before this check, the session would have established with
        // Mallory as `their_principal_state`).
        assert_err!(
            bob_inv.receive(
                welcome_a,
                mallory_kp,
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                None
            ),
            crate::TwoMlsPqError::RemoteIdentityMismatch
        );
    }

    /// Push-based persistence: `install_sink` pushes exactly one baseline `Checkpoint` at the
    /// current seq (no bump); a successful `receive` bumps the seq and pushes another
    /// `Checkpoint`; a failed (replayed) `receive` pushes nothing and leaves the seq alone;
    /// and restoring from the newest pushed blob carries the processed ledger and the advanced
    /// `state_seq` forward.
    #[test]
    fn test_invitation_push_persistence_smoke() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::{Arc, Mutex};

        /// Records every pushed blob — the test analogue of a persistence layer.
        #[derive(Default)]
        struct RecordingSink {
            pushes: Mutex<Vec<(u64, crate::BlobKind, Vec<u8>)>>,
        }
        impl crate::ArchiveSink for RecordingSink {
            fn persist(&self, seq: u64, kind: crate::BlobKind, archive: Vec<u8>) {
                self.pushes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((seq, kind, archive));
            }
        }
        impl RecordingSink {
            fn snapshot(&self) -> Vec<(u64, crate::BlobKind, Vec<u8>)> {
                self.pushes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            }
            /// The newest pushed blob (highest seq) — the newest-per-slot a real sink keeps.
            fn latest(&self) -> Vec<u8> {
                self.snapshot()
                    .into_iter()
                    .max_by_key(|(seq, _, _)| *seq)
                    .map(|(_, _, bytes)| bytes)
                    .unwrap_or_default()
            }
        }

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        // install_sink pushes exactly one baseline checkpoint at seq 0, without bumping.
        let sink = Arc::new(RecordingSink::default());
        assert_ok!(bob_inv.install_sink(sink.clone()));
        assert_eq!(bob_inv.state_seq(), 0);
        let baseline = sink.snapshot();
        assert_eq!(baseline.len(), 1);
        assert_eq!(baseline[0].0, 0);
        assert_eq!(baseline[0].1, crate::BlobKind::Checkpoint);

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        // A successful receive bumps the seq and pushes a fresh checkpoint.
        assert_ok!(bob_inv.receive(
            welcome_a.clone(),
            alice_kp.clone(),
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
        assert_eq!(bob_inv.state_seq(), 1);
        let after_receive = sink.snapshot();
        assert_eq!(after_receive.len(), 2);
        assert_eq!(after_receive[1].0, 1);
        assert_eq!(after_receive[1].1, crate::BlobKind::Checkpoint);

        // A failed (replayed) receive pushes nothing and does not advance the seq.
        assert_err!(
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp,
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                None
            ),
            crate::TwoMlsPqError::DuplicateWelcome
        );
        assert_eq!(bob_inv.state_seq(), 1);
        assert_eq!(sink.snapshot().len(), 2);

        // Restore from the newest pushed blob: the advanced seq and the processed ledger
        // survive, so the replay is still resolved to the spawned session.
        let restored = assert_ok!(super::TwoMlsPqInvitation::restore(sink.latest()));
        assert_eq!(restored.state_seq(), 1);
        assert_some!(restored.processed_welcome_group_id(welcome_a));
    }

    /// AppBinding round-trip through the production establishment path: the binding
    /// welded at `initiate` rides the §A.1 envelope and welcome, `receive` verifies it
    /// against the caller's expectation, the return group mirrors it (so the initiator's
    /// return-welcome join re-verifies equality with its own), and both sessions read
    /// back the same bytes.
    #[test]
    fn test_app_binding_round_trips_through_establishment() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let binding = b"relationship-digest".to_vec();

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp,
            Some(binding.clone())
        ));
        let envelope = assert_some!(alice_session.pending_outbound());
        let opened = assert_ok!(bob_inv.open_establishment(envelope));
        let bob_session = assert_ok!(bob_inv.receive(
            assert_some!(opened.welcome),
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            Some(binding.clone()),
        ));

        // The return welcome carries the mirrored binding; alice's join verifies it
        // against her own before adopting the receive group.
        let welcome_b = assert_some!(bob_session.pending_outbound());
        assert_ok!(alice_session.process_incoming(welcome_b));
        assert!(alice_session.is_established());
        assert!(bob_session.is_established());

        assert_eq!(
            assert_ok!(alice_session.app_binding()),
            Some(binding.clone())
        );
        assert_eq!(assert_ok!(bob_session.app_binding()), Some(binding));
    }

    /// AppBinding × §A.1 pre-establishment sends (v15 × v16): the binding welded at
    /// `initiate` rides the welcome that every pre-establishment app frame re-staples,
    /// so an acceptor joining from a RE-STAPLE (the initial envelope dropped) still
    /// verifies its expectation — and a wrong expectation still rejects before any
    /// invitation state is claimed.
    #[test]
    fn test_app_binding_verified_on_join_from_restaple() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let binding = b"relationship-digest".to_vec();

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp,
            Some(binding.clone()),
        ));
        assert_ok!(alice_session.set_initial_return_key_package(alice_kp.clone()));
        // Drop the initial envelope; send a pre-establishment app frame instead.
        assert_ok!(alice_session.prepare_to_encrypt(None));
        let frame = assert_ok!(alice_session.encrypt(b"bound-first".to_vec()));
        let opened = assert_ok!(bob_inv.open_establishment(frame.cipher_text));
        let welcome = assert_some!(opened.welcome);

        // Wrong expectation rejects without claiming anything…
        assert_err!(
            bob_inv.receive(
                welcome.clone(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"tok".to_vec(),
                None,
                None,
                Some(b"wrong-relationship".to_vec()),
            ),
            crate::TwoMlsPqError::AppBindingMismatch
        );
        // …and the right one joins from the re-staple, reads its stapled message,
        // and reads back the binding.
        let bob_session = assert_ok!(bob_inv.receive(
            welcome,
            alice_kp,
            commitment_of(&alice_session),
            b"tok".to_vec(),
            None,
            None,
            Some(binding.clone()),
        ));
        let got = assert_some!(assert_ok!(
            bob_session.process_incoming(assert_some!(opened.stapled_message))
        ));
        assert_eq!(
            assert_some!(got.application_message).app_message_data,
            b"bound-first"
        );
        assert_eq!(assert_ok!(bob_session.app_binding()), Some(binding));
    }

    /// A welcome whose binding does not match the caller's expectation is rejected
    /// BEFORE any invitation state is claimed — on a single-use invitation (the
    /// strictest case: consumption drops the captured key package), so the very same
    /// welcome is still accepted once the caller supplies the right expectation.
    #[test]
    fn test_receive_rejects_app_binding_mismatch_before_consumption() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(false)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp,
            Some(b"right-relationship".to_vec())
        ));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        assert_err!(
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                Some(b"wrong-relationship".to_vec()),
            ),
            crate::TwoMlsPqError::AppBindingMismatch
        );
        // Nothing was claimed: no ledger entry, no forward entry, and the single-use
        // key package is not consumed…
        assert!(bob_inv
            .processed_welcome_group_id(welcome_a.clone())
            .is_none());
        assert!(bob_inv.forward_group_id(b"token".to_vec()).is_none());
        // …so the genuine welcome still establishes with the correct expectation.
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            Some(b"right-relationship".to_vec()),
        ));
    }

    /// An UNBOUND welcome against a stated expectation is the strip/absence direction of
    /// the mismatch — rejected, and the invitation stays usable without the expectation.
    #[test]
    fn test_receive_rejects_missing_app_binding_when_expected() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        assert_err!(
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                Some(b"expected-relationship".to_vec()),
            ),
            crate::TwoMlsPqError::AppBindingMismatch
        );
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
    }

    /// A BOUND welcome against no expectation is never silently accepted — the caller
    /// must state the binding it can verify; with it, the same welcome establishes.
    #[test]
    fn test_receive_rejects_unexpected_app_binding() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);
        let binding = b"relationship-digest".to_vec();

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(
            Arc::clone(&alice),
            bob_kp,
            Some(binding.clone())
        ));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        assert_err!(
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                None,
            ),
            crate::TwoMlsPqError::AppBindingMismatch
        );
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            Some(binding),
        ));
    }

    /// An EMPTY expectation is reserved-invalid and rejected up front, lock-free —
    /// no group can carry an empty binding, so it could never match. The invitation
    /// is untouched: the same welcome establishes with the honest (None) expectation.
    #[test]
    fn test_receive_rejects_empty_expected_app_binding() {
        use crate::session::TwoMlsPqSession;
        use crate::test_utils::{commitment_of, make_classical_kp, make_client};
        use std::sync::Arc;

        let alice = make_client();
        let bob = make_client();
        let alice_kp = make_classical_kp(&alice);

        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::restore(assert_ok!(
            bob.generate_invitation(true)
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp, None));
        let welcome_a = assert_some!(alice_session.initial_welcome());

        assert_err!(
            bob_inv.receive(
                welcome_a.clone(),
                alice_kp.clone(),
                commitment_of(&alice_session),
                b"token".to_vec(),
                None,
                None,
                Some(Vec::new()),
            ),
            crate::TwoMlsPqError::AppBindingMismatch
        );
        assert_ok!(bob_inv.receive(
            welcome_a,
            alice_kp,
            commitment_of(&alice_session),
            b"token".to_vec(),
            None,
            None,
            None
        ));
    }
}
