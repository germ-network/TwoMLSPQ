use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::invitation::{
    combiner_from_invitation, decode_archive, encode_archive, generate_combiner_invitation,
    take_bytes, CombinerInvitation,
};
#[cfg(feature = "cryptokit")]
use crate::key_package_store::PqMlsClient;
use crate::key_package_store::{CombinerClient, MlsClient};
use crate::session::TwoMlsPqSession;
use crate::{ClientId, MlsCipherSuite, Result, TwoMlsPqError};

/// Holds an agent identity (ClientId) and manages MLS key packages for publication.
/// The ClientId is the Basic Credential that identifies this agent as a leaf node in
/// MLS groups; the MLS signing key is generated internally and is independent of it.
///
/// Thin UniFFI wrapper around `apq::CombinerClient`; the MLS plumbing lives in the
/// `apq` crate.
#[derive(uniffi::Object)]
pub struct TwoMlsPqClient {
    inner: CombinerClient,
}

impl TwoMlsPqClient {
    pub(crate) fn combiner(&self) -> &CombinerClient {
        &self.inner
    }

    /// Rebuild a stateless client from an invitation's captured signing identity + key
    /// package secrets (used by `TwoMlsPqInvitation::receive`).
    pub(crate) fn from_combiner_invitation(inv: &CombinerInvitation) -> Result<Arc<Self>> {
        let inner = combiner_from_invitation(inv)?;
        Ok(Arc::new(Self { inner }))
    }

    pub(crate) fn classical(&self) -> &MlsClient {
        self.inner.classical()
    }

    #[cfg(feature = "cryptokit")]
    pub(crate) fn pq(&self) -> &PqMlsClient {
        self.inner.pq()
    }
}

#[uniffi::export]
impl TwoMlsPqClient {
    /// Create a TwoMlsPqClient for the given ClientId, generating a fresh agent signing
    /// key internally. `client_id` is opaque identity bytes, independent of any key.
    #[uniffi::constructor]
    pub fn new(client_id: Vec<u8>) -> Result<Arc<Self>> {
        let inner = CombinerClient::new(client_id)?;
        Ok(Arc::new(Self { inner }))
    }

    /// The ClientId (opaque identity bytes) for this agent.
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
            #[cfg(feature = "cryptokit")]
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
    /// self-contained [`TwoMlsPqInvitation`] archive. The client keeps no key-package
    /// private data — the Invitation owns it. Publish the invitation's `combinerKeyPackage`
    /// and reconstruct the receiving side with `TwoMlsPqInvitation(archive:)`.
    pub fn generate_invitation(&self) -> Result<Vec<u8>> {
        encode_archive(
            &generate_combiner_invitation(&self.inner)?,
            &BTreeSet::new(),
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
/// Use `is_supported` on the returned suite to decide which library should handle it.
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
    let classical = take_bytes(&mut rest).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    let pq = take_bytes(&mut rest).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    if !rest.is_empty() {
        return Err(TwoMlsPqError::InvalidKeyPackage);
    }
    Ok(CombinerKeyPackage { classical, pq })
}

/// Reject a peer combiner whose both halves are classical (no PQ protection).
///
/// No-op without `cryptokit`: there the PQ half is deliberately classical
/// (ML-KEM is simulated), so the check would reject every session.
#[cfg(feature = "cryptokit")]
pub(crate) fn ensure_pq_available(their_kp: &CombinerKeyPackage) -> Result<()> {
    let classical = parse_mls_key_package(their_kp.classical.clone())?;
    let pq = parse_mls_key_package(their_kp.pq.clone())?;
    if !classical.cipher_suite.is_supported() && !pq.cipher_suite.is_supported() {
        return Err(TwoMlsPqError::PqNotAvailable);
    }
    Ok(())
}

#[cfg(not(feature = "cryptokit"))]
pub(crate) fn ensure_pq_available(_their_kp: &CombinerKeyPackage) -> Result<()> {
    Ok(())
}

/// The receiving/holding side of a published combiner key package: a self-contained
/// invitation that owns one key package's private material plus the signing identity, and
/// can turn a remote initiator's welcome into a session with no live `TwoMlsPqClient`. The
/// Rust analogue of the classical `MLSInvitationClientV2`.
///
/// The private key-package material lives here (not in a `TwoMlsPqClient`); each `receive`
/// rebuilds a stateless client from the archived invitation, so one invitation can service
/// multiple welcomes. A remote whose welcome has already been consumed is rejected.
#[derive(uniffi::Object)]
pub struct TwoMlsPqInvitation {
    invitation: CombinerInvitation,
    // Remote client ids already turned into a session — the transport at-most-once guard.
    // Persisted in `archive()` (a `BTreeSet` for deterministic encoding) so the guard
    // survives a restore.
    consumed: Mutex<BTreeSet<Vec<u8>>>,
}

#[uniffi::export]
impl TwoMlsPqInvitation {
    /// Restore an invitation from its archive (from `TwoMlsPqClient.generateInvitation` or
    /// `archive()`).
    #[uniffi::constructor]
    pub fn new(archive: Vec<u8>) -> Result<Arc<Self>> {
        let (invitation, consumed) = decode_archive(&archive)?;
        Ok(Arc::new(Self {
            invitation,
            consumed: Mutex::new(consumed),
        }))
    }

    /// Serialise the invitation's signing identity + key-package private material, plus the
    /// consumed-remote set so the transport dedup guard survives a restore.
    pub fn archive(&self) -> Result<Vec<u8>> {
        let consumed = self.consumed.lock().unwrap_or_else(|e| e.into_inner());
        encode_archive(&self.invitation, &consumed)
    }

    /// The agent's ClientId.
    pub fn client_id(&self) -> ClientId {
        ClientId {
            bytes: self.invitation.client_id.clone(),
        }
    }

    /// The published (public) combiner key package to hand to a remote initiator.
    pub fn combiner_key_package(&self) -> CombinerKeyPackage {
        CombinerKeyPackage {
            classical: self.invitation.classical_public.clone(),
            pq: self.invitation.pq_public.clone(),
        }
    }

    /// Receive a remote initiator's APQWelcome and establish the session using this
    /// invitation's captured key package. Rejects a second welcome from the same remote
    /// (`DuplicateWelcome`).
    pub fn receive(
        &self,
        welcome: Vec<u8>,
        their_key_package: CombinerKeyPackage,
    ) -> Result<Arc<TwoMlsPqSession>> {
        let their_id = parse_mls_key_package(their_key_package.classical.clone())?.client_id;

        // Atomically reserve this remote up front so two concurrent welcomes from it can't
        // both establish; `insert` returns false if it was already consumed (a replay).
        if !self
            .consumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(their_id.bytes.clone())
        {
            return Err(TwoMlsPqError::DuplicateWelcome);
        }

        match TwoMlsPqClient::from_combiner_invitation(&self.invitation)
            .and_then(|client| TwoMlsPqSession::accept(client, welcome, their_key_package))
        {
            Ok(session) => Ok(session),
            Err(e) => {
                // Establishment failed — release the reservation so a valid retry can proceed.
                self.consumed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&their_id.bytes);
                Err(e)
            }
        }
    }

    /// HPKE-decrypt data sealed to this invitation's (classical) key package init key — the
    /// initial routing-header pattern from classical TwoMLS. `info` defaults to the
    /// ClientId; `kem_output` and `ciphertext` are the two components of the HPKE ciphertext
    /// (kept separate so this stays agnostic to any outer wire framing).
    pub fn hpke_open(
        &self,
        kem_output: Vec<u8>,
        ciphertext: Vec<u8>,
        info: Option<Vec<u8>>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        use mls_rs::crypto::HpkeCiphertext;
        use mls_rs::{CipherSuiteProvider, CryptoProvider};
        use mls_rs_crypto_rustcrypto::RustCryptoProvider;

        // Public init key: published in the classical key package. Matching secret: the
        // invitation's captured classical KeyPackageData.
        let key_package = mls_rs::MlsMessage::from_bytes(&self.invitation.classical_public)
            .map_err(|_| TwoMlsPqError::InvalidKeyPackage)?
            .into_key_package()
            .ok_or(TwoMlsPqError::InvalidKeyPackage)?;
        let public = key_package.hpke_init_key;
        let secret = &self.invitation.classical_kpd.1.init_key;

        let cs = RustCryptoProvider::new()
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .ok_or(TwoMlsPqError::Mls)?;

        let info = info.unwrap_or_else(|| self.invitation.client_id.clone());
        let ciphertext = HpkeCiphertext {
            kem_output,
            ciphertext,
        };
        let plaintext = cs
            .hpke_open(&ciphertext, secret, &public, &info, aad.as_deref())
            .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    use super::TwoMlsPqClient;
    use crate::{assert_err, assert_ok, assert_some, MlsCipherSuite};

    /// A fresh, unique ClientId for tests (opaque random bytes, not a signing key).
    fn test_client_id() -> Vec<u8> {
        let crypto = RustCryptoProvider::new();
        let cs = assert_some!(crypto.cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));
        let (secret, _) = assert_ok!(cs.signature_key_generate());
        secret.as_bytes().to_vec()
    }

    #[test]
    fn test_client_id_is_the_provided_bytes() {
        let id = test_client_id();
        let client = assert_ok!(TwoMlsPqClient::new(id.clone()));
        // The ClientId is exactly the bytes provided — no longer derived from a key.
        assert_eq!(client.client_id().bytes, id);
    }

    #[test]
    fn test_generate_key_package_classical_succeeds() {
        let client = assert_ok!(TwoMlsPqClient::new(test_client_id()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        assert!(!bytes.is_empty());
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_generate_key_package_ml_kem_768_succeeds() {
        let client = assert_ok!(TwoMlsPqClient::new(test_client_id()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::ml_kem_768()));
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_parse_mls_key_package_returns_correct_client_id_and_suite() {
        let client = assert_ok!(TwoMlsPqClient::new(test_client_id()));
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
    #[cfg(feature = "cryptokit")]
    fn test_generate_combiner_key_package_produces_matching_client_ids() {
        let client = assert_ok!(TwoMlsPqClient::new(test_client_id()));
        let ckp = assert_ok!(client.generate_combiner_key_package());
        let parsed = assert_ok!(super::parse_combiner_key_package(ckp));
        assert_eq!(parsed.client_id, client.client_id());
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_parse_combiner_key_package_returns_correct_suites() {
        let client = assert_ok!(TwoMlsPqClient::new(test_client_id()));
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
        let client_a = assert_ok!(TwoMlsPqClient::new(test_client_id()));
        let client_b = assert_ok!(TwoMlsPqClient::new(test_client_id()));
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
            bob.generate_invitation()
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());

        // Bob accepts through the invitation (no live client that generated the KP).
        let bob_session = assert_ok!(bob_inv.receive(welcome_a, alice_kp));
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
            bob.generate_invitation()
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());

        // First receive consumes Alice's identity.
        assert_ok!(bob_inv.receive(welcome_a.clone(), alice_kp.clone()));
        // A second welcome from the same remote is rejected as a replay.
        assert_err!(
            bob_inv.receive(welcome_a, alice_kp),
            crate::TwoMlsPqError::DuplicateWelcome
        );
    }

    #[test]
    fn test_invitation_hpke_open_round_trips() {
        use crate::test_utils::make_client;
        use mls_rs::{CipherSuiteProvider, CryptoProvider};
        use mls_rs_crypto_rustcrypto::RustCryptoProvider;

        let bob = make_client();
        let bob_inv = assert_ok!(super::TwoMlsPqInvitation::new(assert_ok!(
            bob.generate_invitation()
        )));

        // Seal a header to the public init key from Bob's published classical key package.
        let key_package = assert_some!(assert_ok!(mls_rs::MlsMessage::from_bytes(
            &bob_inv.combiner_key_package().classical
        ))
        .into_key_package());
        let cs =
            assert_some!(RustCryptoProvider::new()
                .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));

        let info = bob_inv.client_id().bytes;
        let plaintext = b"routing-header".to_vec();
        let sealed = assert_ok!(cs.hpke_seal(&key_package.hpke_init_key, &info, None, &plaintext));

        // `info = None` exercises the ClientId default, which matches the seal above.
        let opened =
            assert_ok!(bob_inv.hpke_open(sealed.kem_output, sealed.ciphertext, None, None));
        assert_eq!(opened, plaintext);
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
            bob.generate_invitation()
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());

        // Consume Alice on the live invitation.
        assert_ok!(bob_inv.receive(welcome_a.clone(), alice_kp.clone()));

        // Archive + restore; the consumed set must survive so the replay is still rejected.
        let restored = assert_ok!(super::TwoMlsPqInvitation::new(
            assert_ok!(bob_inv.archive())
        ));
        assert_err!(
            restored.receive(welcome_a, alice_kp),
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
            bob.generate_invitation()
        )));
        let bob_kp = bob_inv.combiner_key_package();

        let alice_session = assert_ok!(TwoMlsPqSession::initiate(Arc::clone(&alice), bob_kp));
        let welcome_a = assert_some!(alice_session.pending_outbound());

        // A failed establishment must NOT consume the remote — the reservation is rolled
        // back, so a valid retry from the same remote still succeeds.
        assert!(bob_inv
            .receive(b"not-a-welcome".to_vec(), alice_kp.clone())
            .is_err());
        assert_ok!(bob_inv.receive(welcome_a, alice_kp));
    }

    #[test]
    fn test_invitation_rejects_wrong_pq_mode() {
        use crate::test_utils::make_client;

        let bob = make_client();
        let mut archive = assert_ok!(bob.generate_invitation());
        // Layout: [u32 len][version][PQ_MODE]…; flip the PQ_MODE byte to mimic an archive
        // produced by the other build.
        archive[5] ^= 1;
        assert_err!(
            super::TwoMlsPqInvitation::new(archive),
            crate::TwoMlsPqError::ArchiveInvalid
        );
    }
}
