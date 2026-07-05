use std::sync::Arc;

use crate::{ClientId, MlsCipherSuite, Result, TwoMlsPqError};

/// Holds an agent signing key and manages MLS key packages for publication.
/// The signing key's public component is the ClientId — the Basic Credential
/// that identifies this agent as a leaf node in MLS groups.
///
/// Thin UniFFI wrapper around `apq::CombinerClient`; the MLS plumbing lives in the
/// `apq` crate.
#[derive(uniffi::Object)]
pub struct TwoMlsPqClient {
    inner: apq::CombinerClient,
}

impl TwoMlsPqClient {
    pub(crate) fn combiner(&self) -> &apq::CombinerClient {
        &self.inner
    }

    pub(crate) fn classical(&self) -> &apq::MlsClient {
        self.inner.classical()
    }

    #[cfg(feature = "cryptokit")]
    pub(crate) fn pq(&self) -> &apq::PqMlsClient {
        self.inner.pq()
    }
}

#[uniffi::export]
impl TwoMlsPqClient {
    /// Create a TwoMlsPqClient from an existing agent signing key.
    #[uniffi::constructor]
    pub fn new(signing_key: Vec<u8>) -> Result<Arc<Self>> {
        let inner = apq::CombinerClient::new(signing_key)?;
        Ok(Arc::new(Self { inner }))
    }

    /// The ClientId (public signing key) for this agent.
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

#[cfg(test)]
mod tests {
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    use super::TwoMlsPqClient;
    use crate::{assert_err, assert_ok, assert_some, MlsCipherSuite};

    fn test_signing_key() -> Vec<u8> {
        let crypto = RustCryptoProvider::new();
        let cs = assert_some!(crypto.cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));
        let (secret, _) = assert_ok!(cs.signature_key_generate());
        secret.as_bytes().to_vec()
    }

    #[test]
    fn test_local_agent_client_id_matches_signing_key() {
        let key = test_signing_key();
        let client = assert_ok!(TwoMlsPqClient::new(key.clone()));

        let crypto = RustCryptoProvider::new();
        let cs = assert_some!(crypto.cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA));
        let secret = mls_rs::crypto::SignatureSecretKey::new(key);
        let expected_pub = assert_ok!(cs.signature_key_derive_public(&secret));

        assert_eq!(client.client_id().bytes, expected_pub.as_ref().to_vec());
    }

    #[test]
    fn test_generate_key_package_classical_succeeds() {
        let client = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::x25519_chacha()));
        assert!(!bytes.is_empty());
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_generate_key_package_ml_kem_768_succeeds() {
        let client = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
        let bytes = assert_ok!(client.generate_key_package(MlsCipherSuite::ml_kem_768()));
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_parse_mls_key_package_returns_correct_client_id_and_suite() {
        let client = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
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
        let client = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
        let ckp = assert_ok!(client.generate_combiner_key_package());
        let parsed = assert_ok!(super::parse_combiner_key_package(ckp));
        assert_eq!(parsed.client_id, client.client_id());
    }

    #[test]
    #[cfg(feature = "cryptokit")]
    fn test_parse_combiner_key_package_returns_correct_suites() {
        let client = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
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
        let client_a = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
        let client_b = assert_ok!(TwoMlsPqClient::new(test_signing_key()));
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
}
