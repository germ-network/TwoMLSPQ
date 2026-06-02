use zeroize::Zeroizing;

use crate::Result;

/// PSK identifier structured as `LinearEncode(epoch, groupId)`.
/// Both parties can reconstruct it from group state without extra coordination.
pub struct PskId {
    pub epoch: u64,
    pub group_id: Vec<u8>,
}

/// PSK exported from a send group, ready to inject into the opposing group.
/// Holds both the secret bytes (zeroed on drop) and the ID that must be
/// registered with `PreSharedKeyStorage` before calling
/// `CommitBuilder::addExternalPsk(pskId:)`.
pub struct BoundPsk {
    bytes: Zeroizing<Vec<u8>>,
    pub id: PskId,
}

impl BoundPsk {
    pub fn new(bytes: Vec<u8>, id: PskId) -> Self {
        Self { bytes: Zeroizing::new(bytes), id }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Export a 32-byte PSK from `send_group` for injection into the opposing group.
/// Uses `exportSecret(label="exportSecret", context="derive", len=32)`.
/// PSK ID: `LinearEncode(currentEpoch(), groupId())`.
pub fn export_psk(_send_group: &[u8]) -> Result<BoundPsk> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "not yet implemented"]
    fn test_export_psk_from_established_group_succeeds() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_export_psk_uses_export_secret_label_and_context() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_export_psk_id_is_linear_encode_epoch_group_id() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_export_psk_bytes_are_zeroized_on_drop() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_bound_send_group_rejects_wrong_psk() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_bound_send_group_rejects_wrong_psk_id() {}

    #[test]
    #[ignore = "not yet implemented"]
    fn test_psk_binding_ties_alice_group_to_bob_group() {}
}
