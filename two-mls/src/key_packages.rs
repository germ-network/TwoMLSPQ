use std::sync::Arc;

use crate::{ClientId, MlsCipherSuite, Result};

/// Holds an agent signing key and manages MLS key packages for publication.
/// The signing key's public component is the ClientId — the Basic Credential
/// that identifies this agent as a leaf node in MLS groups.
#[derive(uniffi::Object)]
pub struct TwoMlsClient;

#[uniffi::export]
impl TwoMlsClient {
    /// Create a TwoMlsClient from an existing agent signing key.
    #[uniffi::constructor]
    pub fn new(_signing_key: Vec<u8>) -> Result<Arc<Self>> {
        todo!()
    }

    /// The ClientId (public signing key) for this agent.
    pub fn client_id(&self) -> ClientId {
        todo!()
    }

    /// Generate a fresh KeyPackage for the given cipher suite.
    /// Returns MLS-encoded bytes suitable for publication.
    /// The corresponding HPKE private key is retained internally for group joins.
    pub fn generate_key_package(&self, _suite: Arc<MlsCipherSuite>) -> Result<Vec<u8>> {
        todo!()
    }

    /// Generate a paired classical (0x0003) + PQ (0xFE4C) key package bundle
    /// for use in the APQ/Combiner construction.
    pub fn generate_combiner_key_package(&self) -> Result<CombinerKeyPackage> {
        todo!()
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
/// `pq` is MLS-encoded for suite 0xFE4C (XWing).
#[derive(Debug, uniffi::Record)]
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
pub fn parse_mls_key_package(_bytes: Vec<u8>) -> Result<MlsKeyPackage> {
    todo!()
}

/// Parse and validate a combiner key package pair.
/// Returns an error if the two components do not share the same client identity.
#[uniffi::export]
pub fn parse_combiner_key_package(_kp: CombinerKeyPackage) -> Result<ParsedCombinerKeyPackage> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "not yet implemented"]
    fn test_local_agent_client_id_matches_signing_key() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_generate_key_package_xwing_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_generate_key_package_classical_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_parse_mls_key_package_returns_correct_client_id_and_suite() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_parse_mls_key_package_unknown_suite_returns_unknown_variant() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_generate_combiner_key_package_produces_matching_client_ids() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_parse_combiner_key_package_returns_correct_suites() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_parse_combiner_key_package_mismatched_identities_returns_error() {}
}
