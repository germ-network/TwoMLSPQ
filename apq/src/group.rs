//! The `{classical, pq}` group pair, the APQ-PSK binding, establishment, and APQ welcome framing.

use mls_rs::{
    psk::{ExternalPskId, PreSharedKey},
    ExtensionList, Group, MlsMessage,
};

use crate::client::{CombinerClient, MlsClient, OurConfig};
use crate::{CombinerError, Result};

#[cfg(feature = "cryptokit")]
use crate::client::{PqConfig, PqMlsClient};

/// APQ welcome envelope tag: [0x01][u32-LE classical-len][classical][u32-LE pq-len][pq].
pub const APQ_TAG: u8 = 0x01;

pub type MlsGroup = Group<OurConfig>;

#[cfg(feature = "cryptokit")]
pub type PqMlsGroup = Group<PqConfig>;
#[cfg(not(feature = "cryptokit"))]
pub type PqMlsGroup = MlsGroup;

pub struct CombinerGroup {
    pub classical: MlsGroup,
    pub pq: PqMlsGroup,
}

impl CombinerGroup {
    // Application messages ride the classical group; the pq group is the side channel that
    // injects PQ secrecy via the APQ-PSK and only ratchets on a full (queued-proposal) round.
    pub fn message_group(&self) -> &MlsGroup {
        &self.classical
    }
    pub fn message_group_mut(&mut self) -> &mut MlsGroup {
        &mut self.classical
    }
}

/// Encode the two-welcome APQ envelope (classical + pq).
pub fn encode_apq_welcome(classical: Vec<u8>, pq: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + classical.len() + 4 + pq.len());
    out.push(APQ_TAG);
    out.extend_from_slice(&(classical.len() as u32).to_le_bytes());
    out.extend_from_slice(&classical);
    out.extend_from_slice(&(pq.len() as u32).to_le_bytes());
    out.extend_from_slice(&pq);
    out
}

/// Decode the two-welcome APQ envelope into (classical, pq) welcome bytes.
pub fn decode_apq_welcome(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(CombinerError::Mls)?;
    if tag != APQ_TAG {
        return Err(CombinerError::Mls);
    }
    if rest.len() < 4 {
        return Err(CombinerError::Mls);
    }
    let c_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() < c_len + 4 {
        return Err(CombinerError::Mls);
    }
    let classical = rest[..c_len].to_vec();
    let rest = &rest[c_len..];
    let p_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let rest = &rest[4..];
    if rest.len() != p_len {
        return Err(CombinerError::Mls);
    }
    Ok((classical, rest.to_vec()))
}

/// Construct the PSK identifier: 8-byte LE epoch || group_id bytes.
fn make_psk_id(epoch: u64, group_id: &[u8]) -> ExternalPskId {
    let mut id = epoch.to_le_bytes().to_vec();
    id.extend_from_slice(group_id);
    ExternalPskId::new(id)
}

/// Export 32 bytes from `group` via exportSecret and register them in the client's PSK store.
/// Both parties derive the same value from the same epoch, enabling independent PSK registration.
/// Registers in both classical and PQ stores so both halves can use the PSK for group binding.
pub fn export_and_register_psk(group: &MlsGroup, client: &CombinerClient) -> Result<ExternalPskId> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| CombinerError::Mls)?;
    let psk_id = make_psk_id(group.current_epoch(), group.group_id());
    let psk = PreSharedKey::new(secret.as_bytes().to_vec());
    let mut store = client.classical().secret_store();
    store.insert(psk_id.clone(), psk.clone());
    #[cfg(feature = "cryptokit")]
    {
        let mut pq_store = client.pq().secret_store();
        pq_store.insert(psk_id.clone(), psk);
    }
    Ok(psk_id)
}

/// Export and register PSK from a PQ group. Identical to `export_and_register_psk` but
/// accepts `PqMlsGroup`, which differs from `MlsGroup` when the `cryptokit` feature is on.
#[cfg(feature = "cryptokit")]
pub fn export_and_register_psk_pq(
    group: &PqMlsGroup,
    client: &CombinerClient,
) -> Result<ExternalPskId> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| CombinerError::Mls)?;
    let psk_id = make_psk_id(group.current_epoch(), group.group_id());
    let psk = PreSharedKey::new(secret.as_bytes().to_vec());
    let mut store = client.classical().secret_store();
    store.insert(psk_id.clone(), psk.clone());
    {
        let mut pq_store = client.pq().secret_store();
        pq_store.insert(psk_id.clone(), psk);
    }
    Ok(psk_id)
}

/// Create a group and commit the given key package in as the first member.
/// Each id in `psk_ids` is injected as an external PSK binding on the member-add commit.
/// Returns (group-at-epoch-1, MLS-encoded Welcome bytes).
pub fn create_group_with_member(
    mls_client: &MlsClient,
    their_kp_bytes: &[u8],
    psk_ids: &[ExternalPskId],
) -> Result<(MlsGroup, Vec<u8>)> {
    let mut group = mls_client
        .create_group(ExtensionList::new(), ExtensionList::new(), None)
        .map_err(|_| CombinerError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| CombinerError::InvalidKeyPackage)?;
    let mut builder = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| CombinerError::Mls)?;
    for psk in psk_ids {
        builder = builder
            .add_external_psk(psk.clone())
            .map_err(|_| CombinerError::Mls)?;
    }
    let commit_output = builder.build().map_err(|_| CombinerError::Mls)?;
    group
        .apply_pending_commit()
        .map_err(|_| CombinerError::Mls)?;
    let welcome = commit_output
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(CombinerError::MissingWelcome)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| CombinerError::Mls)?;
    Ok((group, welcome_bytes))
}

/// Join a group from an MLS-encoded Welcome message.
pub fn join_group_from_welcome(mls_client: &MlsClient, welcome_bytes: &[u8]) -> Result<MlsGroup> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| CombinerError::Mls)?;
    let (group, _) = mls_client
        .join_group(None, &welcome, None)
        .map_err(|_| CombinerError::Mls)?;
    Ok(group)
}

/// Create a PQ group, adding the member and binding each id in `psk_ids` as an external PSK.
#[cfg(feature = "cryptokit")]
pub(crate) fn pq_create_group_with_member(
    pq_client: &PqMlsClient,
    their_kp_bytes: &[u8],
    psk_ids: &[ExternalPskId],
) -> Result<(PqMlsGroup, Vec<u8>)> {
    let mut group = pq_client
        .create_group(ExtensionList::new(), ExtensionList::new(), None)
        .map_err(|_| CombinerError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| CombinerError::InvalidKeyPackage)?;
    let mut builder = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| CombinerError::Mls)?;
    for psk in psk_ids {
        builder = builder
            .add_external_psk(psk.clone())
            .map_err(|_| CombinerError::Mls)?;
    }
    let commit_output = builder.build().map_err(|_| CombinerError::Mls)?;
    group
        .apply_pending_commit()
        .map_err(|_| CombinerError::Mls)?;
    let welcome = commit_output
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(CombinerError::MissingWelcome)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| CombinerError::Mls)?;
    Ok((group, welcome_bytes))
}

/// Join a PQ group from an MLS-encoded Welcome message.
#[cfg(feature = "cryptokit")]
pub fn pq_join_group_from_welcome(
    pq_client: &PqMlsClient,
    welcome_bytes: &[u8],
) -> Result<PqMlsGroup> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| CombinerError::Mls)?;
    let (group, _) = pq_client
        .join_group(None, &welcome, None)
        .map_err(|_| CombinerError::Mls)?;
    Ok(group)
}

/// Create the initiator's Combiner send group (Group_A) from the remote's key-package bytes.
/// APQ-PSK chain: PQ Group_A → PSK → classical Group_A — the classical message group absorbs
/// PQ secrecy, so messages on it are quantum-safe even though the PQ group ratchets rarely.
/// Returns (send_group, APQWelcome_A bytes).
pub fn create_combiner_send_group(
    classical_kp: &[u8],
    pq_kp: &[u8],
    client: &CombinerClient,
) -> Result<(CombinerGroup, Vec<u8>)> {
    // PQ side group first, unbound.
    #[cfg(feature = "cryptokit")]
    let (pq_group, pq_welcome) = pq_create_group_with_member(client.pq(), pq_kp, &[])?;
    #[cfg(not(feature = "cryptokit"))]
    let (pq_group, pq_welcome) = create_group_with_member(client.classical(), pq_kp, &[])?;
    // APQ-PSK: export from the PQ group, inject into the classical message group.
    #[cfg(feature = "cryptokit")]
    let apq_psk = export_and_register_psk_pq(&pq_group, client)?;
    #[cfg(not(feature = "cryptokit"))]
    let apq_psk = export_and_register_psk(&pq_group, client)?;
    let (classical_group, classical_welcome) =
        create_group_with_member(client.classical(), classical_kp, &[apq_psk])?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup {
            classical: classical_group,
            pq: pq_group,
        },
        apq,
    ))
}

/// Join both halves of a Combiner group from an APQWelcome.
/// The joiner joins the PQ group first, re-derives the APQ-PSK from it, and registers it before
/// joining the classical group (which is bound with that PSK).
pub fn join_combiner_group(apq_welcome: &[u8], client: &CombinerClient) -> Result<CombinerGroup> {
    let (classical_welcome, pq_welcome) = decode_apq_welcome(apq_welcome)?;
    #[cfg(feature = "cryptokit")]
    let pq = pq_join_group_from_welcome(client.pq(), &pq_welcome)?;
    #[cfg(not(feature = "cryptokit"))]
    let pq = join_group_from_welcome(client.classical(), &pq_welcome)?;
    // Re-derive the same APQ-PSK the creator used to bind the classical group.
    #[cfg(feature = "cryptokit")]
    export_and_register_psk_pq(&pq, client)?;
    #[cfg(not(feature = "cryptokit"))]
    export_and_register_psk(&pq, client)?;
    let classical = join_group_from_welcome(client.classical(), &classical_welcome)?;
    Ok(CombinerGroup { classical, pq })
}

/// Create the acceptor's bound Combiner send group (Group_B). The classical message group binds
/// to two PSKs: the cross-party TwoMLS-PSK (from the recv group's classical half, Group_A) and
/// the intra-party APQ-PSK (from Group_B's PQ side group).
/// Returns (send_group, APQWelcome_B bytes).
pub fn create_bound_combiner_send_group(
    classical_kp: &[u8],
    pq_kp: &[u8],
    client: &CombinerClient,
    recv_classical: &MlsGroup,
) -> Result<(CombinerGroup, Vec<u8>)> {
    // Cross-party TwoMLS-PSK from the recv group (Group_A classical).
    let psk_cross = export_and_register_psk(recv_classical, client)?;
    // PQ side group first, unbound.
    #[cfg(feature = "cryptokit")]
    let (pq_group, pq_welcome) = pq_create_group_with_member(client.pq(), pq_kp, &[])?;
    #[cfg(not(feature = "cryptokit"))]
    let (pq_group, pq_welcome) = create_group_with_member(client.classical(), pq_kp, &[])?;
    // Intra-party APQ-PSK from Group_B's PQ group.
    #[cfg(feature = "cryptokit")]
    let psk_apq = export_and_register_psk_pq(&pq_group, client)?;
    #[cfg(not(feature = "cryptokit"))]
    let psk_apq = export_and_register_psk(&pq_group, client)?;
    let (classical_group, classical_welcome) =
        create_group_with_member(client.classical(), classical_kp, &[psk_cross, psk_apq])?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup {
            classical: classical_group,
            pq: pq_group,
        },
        apq,
    ))
}

/// Extract the ClientId bytes of the member at `leaf_index` in `group` (Basic credential).
pub fn sender_client_id(group: &MlsGroup, leaf_index: u32) -> Result<Vec<u8>> {
    let member = group
        .roster()
        .member_with_index(leaf_index)
        .map_err(|_| CombinerError::DecryptionFailed)?;
    let basic = member
        .signing_identity
        .credential
        .as_basic()
        .ok_or(CombinerError::DecryptionFailed)?;
    Ok(basic.identifier.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CombinerClient;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    fn signing_key() -> Vec<u8> {
        let crypto = RustCryptoProvider::new();
        let cs = crypto
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let (secret, _) = cs.signature_key_generate().unwrap();
        secret.as_bytes().to_vec()
    }

    fn client() -> CombinerClient {
        CombinerClient::new(signing_key()).unwrap()
    }

    // Without `cryptokit` the PQ half is a simulated classical group, so its key package is
    // a classical one; with `cryptokit` it is a real ML-KEM-768 key package.
    fn pq_kp(c: &CombinerClient) -> Vec<u8> {
        #[cfg(feature = "cryptokit")]
        {
            c.generate_pq_key_package().unwrap()
        }
        #[cfg(not(feature = "cryptokit"))]
        {
            c.generate_classical_key_package().unwrap()
        }
    }

    #[test]
    fn test_create_then_join_combiner_group_shares_both_groups() {
        let alice = client();
        let bob = client();

        let (alice_send, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &pq_kp(&bob),
            &alice,
        )
        .unwrap();
        let bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        assert_eq!(
            alice_send.classical.group_id(),
            bob_recv.classical.group_id()
        );
        assert_eq!(alice_send.pq.group_id(), bob_recv.pq.group_id());
    }

    #[test]
    fn test_bound_send_group_is_live_at_epoch_one() {
        let alice = client();
        let bob = client();
        let (_alice_send, welcome_a) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &pq_kp(&bob),
            &alice,
        )
        .unwrap();
        let bob_recv = join_combiner_group(&welcome_a, &bob).unwrap();

        let (bob_send, _welcome_b) = create_bound_combiner_send_group(
            &alice.generate_classical_key_package().unwrap(),
            &pq_kp(&alice),
            &bob,
            &bob_recv.classical,
        )
        .unwrap();

        assert_eq!(bob_send.classical.current_epoch(), 1);
        assert_eq!(bob_send.pq.current_epoch(), 1);
    }

    #[test]
    fn test_export_and_register_psk_is_deterministic_and_le_epoch_group_id() {
        let alice = client();
        let bob = client();
        let (group, _) = create_group_with_member(
            alice.classical(),
            &bob.generate_classical_key_package().unwrap(),
            &[],
        )
        .unwrap();

        let id1 = export_and_register_psk(&group, &alice).unwrap();
        let id2 = export_and_register_psk(&group, &alice).unwrap();
        assert_eq!(id1, id2);

        let mut expected = group.current_epoch().to_le_bytes().to_vec();
        expected.extend_from_slice(group.group_id());
        let id_bytes: &[u8] = &id1;
        assert_eq!(id_bytes, expected.as_slice());
    }

    #[test]
    fn test_sender_client_id_returns_group_creator() {
        let alice = client();
        let bob = client();
        let (group, _) = create_group_with_member(
            alice.classical(),
            &bob.generate_classical_key_package().unwrap(),
            &[],
        )
        .unwrap();
        // Leaf 0 is the creating client.
        assert_eq!(sender_client_id(&group, 0).unwrap(), alice.client_id());
    }

    #[test]
    fn test_encode_decode_apq_welcome_round_trips() {
        let classical = b"classical-welcome".to_vec();
        let pq = b"pq-welcome".to_vec();
        let encoded = encode_apq_welcome(classical.clone(), pq.clone());
        assert_eq!(encoded[0], APQ_TAG);
        let (dc, dp) = decode_apq_welcome(&encoded).unwrap();
        assert_eq!(dc, classical);
        assert_eq!(dp, pq);
    }

    #[test]
    fn test_decode_apq_welcome_truncated_is_err() {
        assert!(decode_apq_welcome(&[APQ_TAG]).is_err());
    }

    #[test]
    fn test_decode_apq_welcome_wrong_tag_is_err() {
        let mut encoded = encode_apq_welcome(b"c".to_vec(), b"p".to_vec());
        encoded[0] = 0xFF;
        assert!(decode_apq_welcome(&encoded).is_err());
    }
}
