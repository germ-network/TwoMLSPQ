//! The APQ Combiner layer: the `{classical, pq}` group pair and its construction.
//!
//! This is the "separate APQ from TwoMLS" boundary. Everything here is the combiner
//! construction (draft-ietf-mls-combiner + our deviation): the two MLS groups, the
//! **APQ-PSK** (PQ → classical, intra-party), and establishment. The two-mls layer
//! (`session.rs`) owns session orchestration, the cross-party TwoMLS-PSK, wire framing,
//! and the UniFFI surface, and drives this layer through `CombinerGroup`.

use std::sync::Arc;

use mls_rs::{
    psk::{ExternalPskId, PreSharedKey},
    ExtensionList, Group, MlsMessage,
};

use crate::{
    key_packages::{CombinerKeyPackage, MlsClient, OurConfig, TwoMlsPqClient},
    session::{decode_apq_welcome, encode_apq_welcome},
    ClientId, Result, TwoMlsPqError,
};

#[cfg(feature = "cryptokit")]
use crate::key_packages::{PqConfig, PqMlsClient};

pub(crate) type MlsGroup = Group<OurConfig>;

#[cfg(feature = "cryptokit")]
pub(crate) type PqMlsGroup = Group<PqConfig>;
#[cfg(not(feature = "cryptokit"))]
pub(crate) type PqMlsGroup = MlsGroup;

pub(crate) struct CombinerGroup {
    pub(crate) classical: MlsGroup,
    pub(crate) pq: PqMlsGroup,
}

impl CombinerGroup {
    // The "message group" carries application messages and the per-round (routine) ratchet;
    // the "side group" (`pq`) injects PQ secrecy via the APQ-PSK. Post-rework: message =
    // `classical`, side = `pq` (see ROADMAP / MECHANICS-AND-INTERFACE). Routine rounds are
    // classical-only; the PQ group ratchets only on the queued-proposal (full) round.
    pub(crate) fn message_group(&self) -> &MlsGroup {
        &self.classical
    }
    pub(crate) fn message_group_mut(&mut self) -> &mut MlsGroup {
        &mut self.classical
    }
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
pub(crate) fn export_and_register_psk(
    group: &MlsGroup,
    client: &TwoMlsPqClient,
) -> Result<ExternalPskId> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| TwoMlsPqError::Mls)?;
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
pub(crate) fn export_and_register_psk_pq(
    group: &PqMlsGroup,
    client: &TwoMlsPqClient,
) -> Result<ExternalPskId> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| TwoMlsPqError::Mls)?;
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
pub(crate) fn create_group_with_member(
    mls_client: &MlsClient,
    their_kp_bytes: &[u8],
    psk_ids: &[ExternalPskId],
) -> Result<(MlsGroup, Vec<u8>)> {
    let mut group = mls_client
        .create_group(ExtensionList::new(), ExtensionList::new(), None)
        .map_err(|_| TwoMlsPqError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    let mut builder = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| TwoMlsPqError::Mls)?;
    for psk in psk_ids {
        builder = builder
            .add_external_psk(psk.clone())
            .map_err(|_| TwoMlsPqError::Mls)?;
    }
    let commit_output = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
    group
        .apply_pending_commit()
        .map_err(|_| TwoMlsPqError::Mls)?;
    let welcome = commit_output
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(TwoMlsPqError::MissingWelcome)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
    Ok((group, welcome_bytes))
}

/// Join a group from an MLS-encoded Welcome message.
pub(crate) fn join_group_from_welcome(
    mls_client: &MlsClient,
    welcome_bytes: &[u8],
) -> Result<MlsGroup> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| TwoMlsPqError::Mls)?;
    let (group, _) = mls_client
        .join_group(None, &welcome, None)
        .map_err(|_| TwoMlsPqError::Mls)?;
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
        .map_err(|_| TwoMlsPqError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| TwoMlsPqError::InvalidKeyPackage)?;
    let mut builder = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| TwoMlsPqError::Mls)?;
    for psk in psk_ids {
        builder = builder
            .add_external_psk(psk.clone())
            .map_err(|_| TwoMlsPqError::Mls)?;
    }
    let commit_output = builder.build().map_err(|_| TwoMlsPqError::Mls)?;
    group
        .apply_pending_commit()
        .map_err(|_| TwoMlsPqError::Mls)?;
    let welcome = commit_output
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(TwoMlsPqError::MissingWelcome)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| TwoMlsPqError::Mls)?;
    Ok((group, welcome_bytes))
}

/// Join a PQ group from an MLS-encoded Welcome message.
#[cfg(feature = "cryptokit")]
pub(crate) fn pq_join_group_from_welcome(
    pq_client: &PqMlsClient,
    welcome_bytes: &[u8],
) -> Result<PqMlsGroup> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| TwoMlsPqError::Mls)?;
    let (group, _) = pq_client
        .join_group(None, &welcome, None)
        .map_err(|_| TwoMlsPqError::Mls)?;
    Ok(group)
}

/// Create the initiator's Combiner send group (Group_A) from the remote's CombinerKeyPackage.
/// APQ-PSK chain: PQ Group_A → PSK → classical Group_A — the classical message group absorbs
/// PQ secrecy, so messages on it are quantum-safe even though the PQ group ratchets rarely.
/// Returns (send_group, APQWelcome_A bytes).
pub(crate) fn create_combiner_send_group(
    their_kp: &CombinerKeyPackage,
    client: &Arc<TwoMlsPqClient>,
) -> Result<(CombinerGroup, Vec<u8>)> {
    // PQ side group first, unbound.
    #[cfg(feature = "cryptokit")]
    let (pq_group, pq_welcome) = pq_create_group_with_member(client.pq(), &their_kp.pq, &[])?;
    #[cfg(not(feature = "cryptokit"))]
    let (pq_group, pq_welcome) = create_group_with_member(client.classical(), &their_kp.pq, &[])?;
    // APQ-PSK: export from the PQ group, inject into the classical message group.
    #[cfg(feature = "cryptokit")]
    let apq_psk = export_and_register_psk_pq(&pq_group, client)?;
    #[cfg(not(feature = "cryptokit"))]
    let apq_psk = export_and_register_psk(&pq_group, client)?;
    let (classical_group, classical_welcome) =
        create_group_with_member(client.classical(), &their_kp.classical, &[apq_psk])?;
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
pub(crate) fn join_combiner_group(
    apq_welcome: &[u8],
    client: &Arc<TwoMlsPqClient>,
) -> Result<CombinerGroup> {
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
pub(crate) fn create_bound_combiner_send_group(
    their_kp: &CombinerKeyPackage,
    client: &Arc<TwoMlsPqClient>,
    recv_classical: &MlsGroup,
) -> Result<(CombinerGroup, Vec<u8>)> {
    // Cross-party TwoMLS-PSK from the recv group (Group_A classical).
    let psk_cross = export_and_register_psk(recv_classical, client)?;
    // PQ side group first, unbound.
    #[cfg(feature = "cryptokit")]
    let (pq_group, pq_welcome) = pq_create_group_with_member(client.pq(), &their_kp.pq, &[])?;
    #[cfg(not(feature = "cryptokit"))]
    let (pq_group, pq_welcome) = create_group_with_member(client.classical(), &their_kp.pq, &[])?;
    // Intra-party APQ-PSK from Group_B's PQ group.
    #[cfg(feature = "cryptokit")]
    let psk_apq = export_and_register_psk_pq(&pq_group, client)?;
    #[cfg(not(feature = "cryptokit"))]
    let psk_apq = export_and_register_psk(&pq_group, client)?;
    let (classical_group, classical_welcome) = create_group_with_member(
        client.classical(),
        &their_kp.classical,
        &[psk_cross, psk_apq],
    )?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup {
            classical: classical_group,
            pq: pq_group,
        },
        apq,
    ))
}

/// Extract the `ClientId` of the member at `leaf_index` in `group` using the Basic credential.
pub(crate) fn sender_client_id(group: &MlsGroup, leaf_index: u32) -> Result<ClientId> {
    let member = group
        .roster()
        .member_with_index(leaf_index)
        .map_err(|_| TwoMlsPqError::DecryptionFailed)?;
    let basic = member
        .signing_identity
        .credential
        .as_basic()
        .ok_or(TwoMlsPqError::DecryptionFailed)?;
    Ok(ClientId {
        bytes: basic.identifier.clone(),
    })
}
