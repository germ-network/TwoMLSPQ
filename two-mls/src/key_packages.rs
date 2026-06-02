use crate::{PqCapability, Result};

/// A KeyPackage for Alice's Hello Agent, signed by her Anchor Key over her
/// ATProto DID. Published as a `com.germnetwork.keypackage` record in her PDS.
/// Alice publishes a second AnchorHello with the X-Wing ciphersuite to
/// advertise PQ capability.
#[derive(Debug, uniffi::Record)]
pub struct AnchorHello {
    pub key_package: Vec<u8>,
    pub anchor_signature: Vec<u8>,
    pub did: String,
    pub pq: PqCapability,
}

/// Sign the Hello Agent's KeyPackage with the Anchor Key over the DID,
/// producing the record Alice publishes to her PDS.
#[uniffi::export]
pub fn generate_anchor_hello(
    _anchor_key: Vec<u8>,
    _signing_key: Vec<u8>,
    _did: String,
    _pq: PqCapability,
) -> Result<AnchorHello> {
    todo!()
}

/// Verify that an AnchorHello's anchor signature is valid for the stated DID.
#[uniffi::export]
pub fn verify_anchor_hello(_anchor_hello: AnchorHello) -> Result<()> {
    todo!()
}

/// Return the highest PQ capability advertised across a set of AnchorHellos.
/// Returns `Classical` if none use X-Wing.
#[uniffi::export]
pub fn detect_pq_capability(anchor_hellos: Vec<AnchorHello>) -> PqCapability {
    if anchor_hellos.iter().any(|h| h.pq == PqCapability::XWing) {
        PqCapability::XWing
    } else {
        PqCapability::Classical
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "not yet implemented"]
    fn test_generate_anchor_hello_classical_produces_valid_record() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_generate_anchor_hello_xwing_produces_valid_record() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_verify_anchor_hello_valid_signature_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_verify_anchor_hello_tampered_signature_fails() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_verify_anchor_hello_wrong_did_fails() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_detect_pq_capability_with_xwing_record_returns_xwing() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_detect_pq_capability_classical_only_returns_classical() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_detect_pq_capability_empty_records_returns_classical() {}
}
