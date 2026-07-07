//! The `{classical, pq}` group pair, the APQ-PSK binding, establishment, and APQ welcome framing.

use mls_rs::{
    psk::{ExternalPskId, PreSharedKey},
    storage_provider::in_memory::InMemoryPreSharedKeyStorage,
    ExtensionList, Group, KeyPackageStorage, MlsMessage,
};
use zeroize::Zeroizing;

use crate::client::{CombinerClient, MlsClient, OurConfig};
use crate::storage::PersistableGroupStorage;
use crate::{CombinerError, Result};

#[cfg(feature = "cryptokit")]
use crate::client::{PqConfig, PqMlsClient};

/// APQ welcome envelope tag: [0x01][u32-LE classical-len][classical][u32-LE pq-len][pq].
pub const APQ_TAG: u8 = 0x01;

pub type MlsGroup<S> = Group<OurConfig<S>>;

#[cfg(feature = "cryptokit")]
pub type PqMlsGroup<S> = Group<PqConfig<S>>;
#[cfg(not(feature = "cryptokit"))]
pub type PqMlsGroup<S> = MlsGroup<S>;

pub struct CombinerGroup<S: KeyPackageStorage + Clone> {
    pub classical: MlsGroup<S>,
    /// `None` while the PQ half is deferred: an acceptor's send group before the A.4
    /// bootstrap, and the initiator's recv group mirroring it.
    pub pq: Option<PqMlsGroup<S>>,
    // Group-state and PSK storage handles of the client that created/joined each half. An
    // mls-rs group reads and writes through the config of its originating client, so
    // archival pulls (and PSK injection lands) through these captured handles — a later
    // client swap (agent rotation) must not redirect where an existing group's state or
    // PSK lookups resolve.
    classical_storage: PersistableGroupStorage,
    pq_storage: PersistableGroupStorage,
    classical_psks: InMemoryPreSharedKeyStorage,
    pq_psks: InMemoryPreSharedKeyStorage,
}

/// One Combiner group's exported state: a per-group blob per half, produced by
/// [`CombinerGroup::export_state`] and consumed by [`load_combiner_group`]. The blobs are
/// plaintext secret material (see `storage::PersistableGroupStorage::export_group`); callers
/// must seal them (e.g. with [`crate::archive::seal`]) before persisting.
pub struct CombinerGroupState {
    pub classical: Zeroizing<Vec<u8>>,
    pub pq: Option<Zeroizing<Vec<u8>>>,
}

impl<S: KeyPackageStorage + Clone> CombinerGroup<S> {
    /// Assemble a Combiner group from halves that were created/joined by `client`, capturing
    /// the client's storage handles for later per-group archival.
    pub fn from_client(
        client: &CombinerClient<S>,
        classical: MlsGroup<S>,
        pq: Option<PqMlsGroup<S>>,
    ) -> Self {
        Self {
            classical,
            pq,
            classical_storage: client.classical_group_storage().clone(),
            pq_storage: pq_storage_of(client).clone(),
            classical_psks: client.classical().secret_store(),
            pq_psks: pq_psks_of(client),
        }
    }

    /// Attach a deferred (A.4) PQ half that was created/joined by `client`, capturing the
    /// storage handles it resolves through. The classical half's handles are untouched —
    /// they stay with the client that originally produced that half.
    pub fn set_pq(&mut self, pq: PqMlsGroup<S>, client: &CombinerClient<S>) {
        self.pq = Some(pq);
        self.pq_storage = pq_storage_of(client).clone();
        self.pq_psks = pq_psks_of(client);
    }

    /// Inject a PSK into the secret stores this group's halves resolve from (the
    /// originating client's), immediately before building or processing a commit that
    /// references it. Injecting via the current session client instead would miss after an
    /// agent rotation — the group keeps reading the store it was born with.
    pub fn register_psk(&self, psk_id: &ExternalPskId, psk: &PreSharedKey) {
        let mut classical = self.classical_psks.clone();
        classical.insert(psk_id.clone(), psk.clone());
        let mut pq = self.pq_psks.clone();
        pq.insert(psk_id.clone(), psk.clone());
    }

    /// Remove a PSK from the stores this group's halves resolve from, once the commit that
    /// referenced it has been applied/processed (or the session has retired it). Keeps the
    /// stores' contents bounded by what the caller still vouches for.
    pub fn forget_psk(&self, psk_id: &ExternalPskId) {
        let mut classical = self.classical_psks.clone();
        classical.delete(psk_id);
        let mut pq = self.pq_psks.clone();
        pq.delete(psk_id);
    }

    /// Flush both halves and export each half's state + retained epoch secrets, pulled
    /// through the storage handles captured at construction (so this works regardless of
    /// which client the session currently holds).
    pub fn export_state(&mut self) -> Result<CombinerGroupState> {
        self.classical
            .write_to_storage()
            .map_err(|_| CombinerError::Mls)?;
        let classical = self
            .classical_storage
            .export_group(self.classical.group_id())?;
        let pq = match self.pq.as_mut() {
            Some(pq) => {
                pq.write_to_storage().map_err(|_| CombinerError::Mls)?;
                Some(self.pq_storage.export_group(pq.group_id())?)
            }
            None => None,
        };
        Ok(CombinerGroupState { classical, pq })
    }

    // Application messages ride the classical group; the pq group is the side channel that
    // injects PQ secrecy via the APQ-PSK and only ratchets on a full (queued-proposal) round.
    pub fn message_group(&self) -> &MlsGroup<S> {
        &self.classical
    }
    pub fn message_group_mut(&mut self) -> &mut MlsGroup<S> {
        &mut self.classical
    }
}

/// The storage the PQ half writes through: the PQ client's under `cryptokit`, otherwise the
/// classical client's (the simulated PQ half is a classical group on the classical client).
fn pq_storage_of<S: KeyPackageStorage + Clone>(
    client: &CombinerClient<S>,
) -> &PersistableGroupStorage {
    #[cfg(feature = "cryptokit")]
    {
        client.pq_group_storage()
    }
    #[cfg(not(feature = "cryptokit"))]
    {
        client.classical_group_storage()
    }
}

/// The secret store the PQ half resolves PSKs from (see [`pq_storage_of`]).
fn pq_psks_of<S: KeyPackageStorage + Clone>(
    client: &CombinerClient<S>,
) -> InMemoryPreSharedKeyStorage {
    #[cfg(feature = "cryptokit")]
    {
        client.pq().secret_store()
    }
    #[cfg(not(feature = "cryptokit"))]
    {
        client.classical().secret_store()
    }
}

/// Rebuild a [`CombinerGroup`] on `client` from exported state: import each half's record
/// into the client's storage, then load the group from it. The loaded groups write through
/// `client`'s storage from here on.
pub fn load_combiner_group<S: KeyPackageStorage + Clone>(
    client: &CombinerClient<S>,
    state: &CombinerGroupState,
) -> Result<CombinerGroup<S>> {
    let classical_id = client
        .classical_group_storage()
        .import_group(&state.classical)?;
    let classical = client
        .classical()
        .load_group(&classical_id)
        .map_err(|_| CombinerError::Mls)?;
    let pq = match &state.pq {
        Some(bytes) => {
            let pq_id = pq_storage_of(client).import_group(bytes)?;
            #[cfg(feature = "cryptokit")]
            let pq = client.pq().load_group(&pq_id);
            #[cfg(not(feature = "cryptokit"))]
            let pq = client.classical().load_group(&pq_id);
            Some(pq.map_err(|_| CombinerError::Mls)?)
        }
        None => None,
    };
    Ok(CombinerGroup::from_client(client, classical, pq))
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

/// Trailing domain byte that distinguishes a PQ-ratchet *injected-secret* PSK id from an
/// *exported* (apq / cross-party) PSK id. Injected ids carry this byte and are therefore always
/// exactly one byte longer than an exported id, so the two families can never collide even at the
/// same epoch. See `pq_ratchet` for the injection path.
#[cfg(feature = "cryptokit")]
pub(crate) const PSK_DOMAIN_INJECTED: u8 = 0x52;

/// Raw PSK-id bytes: 8-byte little-endian epoch || group_id. The single source of truth for the
/// id layout; all PSK ids in this crate are derived from this.
fn psk_id_bytes(epoch: u64, group_id: &[u8]) -> Vec<u8> {
    let mut id = epoch.to_le_bytes().to_vec();
    id.extend_from_slice(group_id);
    id
}

/// PSK identifier for an *exported* secret (apq-PSK or cross-party TwoMLS-PSK): LE epoch || group_id.
fn make_psk_id(epoch: u64, group_id: &[u8]) -> ExternalPskId {
    ExternalPskId::new(psk_id_bytes(epoch, group_id))
}

/// PSK identifier for a PQ-ratchet *injected* secret: LE epoch || group_id || `PSK_DOMAIN_INJECTED`.
#[cfg(feature = "cryptokit")]
pub(crate) fn injected_secret_psk_id(epoch: u64, group_id: &[u8]) -> ExternalPskId {
    let mut id = psk_id_bytes(epoch, group_id);
    id.push(PSK_DOMAIN_INJECTED);
    ExternalPskId::new(id)
}

/// Derive the exportable PSK for `group`'s current epoch: 32 bytes via exportSecret, with
/// id = LE epoch || group_id. Pure derivation — no store side-effect. Both parties derive
/// the same value from the same epoch. Durable PSK material belongs to the caller (session
/// orchestration), which registers the pair into every PSK store its groups resolve from
/// just-in-time before the commit that references it — an mls-rs group reads the store of
/// the client that created it, which a session's current client may no longer be after an
/// agent rotation. See [`register_psk`] / [`register_psk_stores`].
pub fn export_psk<S: KeyPackageStorage + Clone>(
    group: &MlsGroup<S>,
) -> Result<(ExternalPskId, PreSharedKey)> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| CombinerError::Mls)?;
    Ok((
        make_psk_id(group.current_epoch(), group.group_id()),
        PreSharedKey::new(secret.as_bytes().to_vec()),
    ))
}

/// Register an exported PSK into every store in `stores` — the caller's registry of
/// every store its groups resolve PSKs from. The single fan-out loop shared by the
/// session layer and the PQ ratchet.
pub fn register_psk_stores(
    stores: &[mls_rs::storage_provider::in_memory::InMemoryPreSharedKeyStorage],
    psk_id: &ExternalPskId,
    psk: &PreSharedKey,
) {
    for store in stores {
        store.clone().insert(psk_id.clone(), psk.clone());
    }
}

/// Remove a PSK from every store in `stores` — the counterpart of [`register_psk_stores`],
/// for one-shot entries the caller has retired.
pub fn forget_psk_stores(
    stores: &[mls_rs::storage_provider::in_memory::InMemoryPreSharedKeyStorage],
    psk_id: &ExternalPskId,
) {
    for store in stores {
        store.clone().delete(psk_id);
    }
}

/// Inject a PSK into the client's secret store(s) — both halves, so either can resolve it —
/// immediately before building or processing the commit that references it. The stores are
/// ephemeral plumbing; they are not archived and hold nothing the caller doesn't.
pub fn register_psk<S: KeyPackageStorage + Clone>(
    client: &CombinerClient<S>,
    psk_id: &ExternalPskId,
    psk: &PreSharedKey,
) {
    let mut store = client.classical().secret_store();
    store.insert(psk_id.clone(), psk.clone());
    #[cfg(feature = "cryptokit")]
    {
        let mut pq_store = client.pq().secret_store();
        pq_store.insert(psk_id.clone(), psk.clone());
    }
}

/// Remove a PSK from a client's secret store(s) — the counterpart of [`register_psk`], for
/// entries the caller has retired.
pub fn forget_psk<S: KeyPackageStorage + Clone>(
    client: &CombinerClient<S>,
    psk_id: &ExternalPskId,
) {
    let mut store = client.classical().secret_store();
    store.delete(psk_id);
    #[cfg(feature = "cryptokit")]
    {
        let mut pq_store = client.pq().secret_store();
        pq_store.delete(psk_id);
    }
}

/// [`export_psk`] + [`register_psk`] for derive-and-use-immediately sites (establishment,
/// where the PSK is consumed by a join/commit in the same call).
pub fn export_and_register_psk<S: KeyPackageStorage + Clone>(
    group: &MlsGroup<S>,
    client: &CombinerClient<S>,
) -> Result<ExternalPskId> {
    let (psk_id, psk) = export_psk(group)?;
    register_psk(client, &psk_id, &psk);
    Ok(psk_id)
}

/// [`export_psk`] for a PQ group, which is a distinct type when `cryptokit` is on.
#[cfg(feature = "cryptokit")]
pub fn export_psk_pq<S: KeyPackageStorage + Clone>(
    group: &PqMlsGroup<S>,
) -> Result<(ExternalPskId, PreSharedKey)> {
    let secret = group
        .export_secret(b"exportSecret", b"derive", 32)
        .map_err(|_| CombinerError::Mls)?;
    Ok((
        make_psk_id(group.current_epoch(), group.group_id()),
        PreSharedKey::new(secret.as_bytes().to_vec()),
    ))
}

/// Export and register PSK from a PQ group. Identical to `export_and_register_psk` but
/// accepts `PqMlsGroup`, which differs from `MlsGroup` when the `cryptokit` feature is on.
#[cfg(feature = "cryptokit")]
pub fn export_and_register_psk_pq<S: KeyPackageStorage + Clone>(
    group: &PqMlsGroup<S>,
    client: &CombinerClient<S>,
) -> Result<ExternalPskId> {
    let (psk_id, psk) = export_psk_pq(group)?;
    register_psk(client, &psk_id, &psk);
    Ok(psk_id)
}

/// Create a group and commit the given key package in as the first member.
/// Each id in `psk_ids` is injected as an external PSK binding on the member-add commit.
/// Returns (group-at-epoch-1, MLS-encoded Welcome bytes).
pub fn create_group_with_member<S: KeyPackageStorage + Clone>(
    mls_client: &MlsClient<S>,
    their_kp_bytes: &[u8],
    psk_ids: &[ExternalPskId],
) -> Result<(MlsGroup<S>, Vec<u8>)> {
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
pub fn join_group_from_welcome<S: KeyPackageStorage + Clone>(
    mls_client: &MlsClient<S>,
    welcome_bytes: &[u8],
) -> Result<MlsGroup<S>> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| CombinerError::Mls)?;
    let (group, _) = mls_client
        .join_group(None, &welcome, None)
        .map_err(|_| CombinerError::Mls)?;
    Ok(group)
}

/// Create a PQ group, adding the member and binding each id in `psk_ids` as an external PSK.
#[cfg(feature = "cryptokit")]
pub fn pq_create_group_with_member<S: KeyPackageStorage + Clone>(
    pq_client: &PqMlsClient<S>,
    their_kp_bytes: &[u8],
    psk_ids: &[ExternalPskId],
) -> Result<(PqMlsGroup<S>, Vec<u8>)> {
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
pub fn pq_join_group_from_welcome<S: KeyPackageStorage + Clone>(
    pq_client: &PqMlsClient<S>,
    welcome_bytes: &[u8],
) -> Result<PqMlsGroup<S>> {
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
pub fn create_combiner_send_group<S: KeyPackageStorage + Clone>(
    classical_kp: &[u8],
    pq_kp: &[u8],
    client: &CombinerClient<S>,
) -> Result<(CombinerGroup<S>, Vec<u8>)> {
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
        CombinerGroup::from_client(client, classical_group, Some(pq_group)),
        apq,
    ))
}

/// Join both halves of a Combiner group from an APQWelcome.
/// The joiner joins the PQ group first, re-derives the APQ-PSK from it, and registers it before
/// joining the classical group (which is bound with that PSK).
pub fn join_combiner_group<S: KeyPackageStorage + Clone>(
    apq_welcome: &[u8],
    client: &CombinerClient<S>,
) -> Result<CombinerGroup<S>> {
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
    Ok(CombinerGroup::from_client(client, classical, Some(pq)))
}

/// Create the acceptor's bound send group (Group_B) with the PQ half deferred (A.4):
/// classical only, bound to the cross-party TwoMLS-PSK from the recv group. The heavy PQ
/// half is stood up later by the bootstrap flow, off the handshake critical path.
pub fn create_bound_classical_send_group<S: KeyPackageStorage + Clone>(
    classical_kp: &[u8],
    client: &CombinerClient<S>,
    recv_classical: &MlsGroup<S>,
) -> Result<(CombinerGroup<S>, Vec<u8>)> {
    let psk_cross = export_and_register_psk(recv_classical, client)?;
    let (classical_group, classical_welcome) =
        create_group_with_member(client.classical(), classical_kp, &[psk_cross])?;
    Ok((
        CombinerGroup::from_client(client, classical_group, None),
        classical_welcome,
    ))
}

/// Create the acceptor's bound Combiner send group (Group_B). The classical message group binds
/// to two PSKs: the cross-party TwoMLS-PSK (from the recv group's classical half, Group_A) and
/// the intra-party APQ-PSK (from Group_B's PQ side group).
/// Returns (send_group, APQWelcome_B bytes).
pub fn create_bound_combiner_send_group<S: KeyPackageStorage + Clone>(
    classical_kp: &[u8],
    pq_kp: &[u8],
    client: &CombinerClient<S>,
    recv_classical: &MlsGroup<S>,
) -> Result<(CombinerGroup<S>, Vec<u8>)> {
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
        CombinerGroup::from_client(client, classical_group, Some(pq_group)),
        apq,
    ))
}

/// Extract the ClientId bytes of the member at `leaf_index` in `group` (Basic credential).
pub fn sender_client_id<S: KeyPackageStorage + Clone>(
    group: &MlsGroup<S>,
    leaf_index: u32,
) -> Result<Vec<u8>> {
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
    use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    // apq's tests exercise the generic combiner with mls-rs's default in-memory store; the
    // capture/serve store used for real invitations lives in the `two-mls-pq` crate.
    type TestClient = CombinerClient<InMemoryKeyPackageStorage>;

    /// A fresh, unique ClientId for tests (opaque random bytes, not a signing key).
    fn client_id() -> Vec<u8> {
        let crypto = RustCryptoProvider::new();
        let cs = crypto
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let (secret, _) = cs.signature_key_generate().unwrap();
        secret.as_bytes().to_vec()
    }

    fn client() -> TestClient {
        CombinerClient::new(client_id()).unwrap()
    }

    // Without `cryptokit` the PQ half is a simulated classical group, so its key package is
    // a classical one; with `cryptokit` it is a real ML-KEM-768 key package.
    fn pq_kp(c: &TestClient) -> Vec<u8> {
        #[cfg(feature = "cryptokit")]
        {
            c.generate_pq_key_package().unwrap()
        }
        #[cfg(not(feature = "cryptokit"))]
        {
            c.generate_classical_key_package().unwrap()
        }
    }

    /// The adopted persistence pattern end-to-end: archive per group through the group
    /// objects, restore onto a client rebuilt from the archived signing identity, and keep
    /// messaging. The restored side must decrypt both a pre-archive in-flight message and
    /// messages sent after the restore.
    #[test]
    fn test_combiner_group_state_survives_client_rebuild() {
        use mls_rs::group::ReceivedMessage;
        use zeroize::Zeroizing;

        let alice = client();
        let bob_id = client_id();
        let bob = TestClient::new(bob_id.clone()).unwrap();
        // The archivable signing identity, captured as an invitation-style archive would.
        let bob_classical_key = Zeroizing::new(bob.classical_signing_key().to_vec());
        #[cfg(feature = "cryptokit")]
        let bob_pq_key = Zeroizing::new(bob.pq_signing_key().to_vec());

        let (mut alice_send, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &pq_kp(&bob),
            &alice,
        )
        .unwrap();
        let mut bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        // A message decrypted before archival, and one still in flight across the restart.
        let m1 = alice_send
            .classical
            .encrypt_application_message(b"before archive", vec![])
            .unwrap()
            .to_bytes()
            .unwrap();
        bob_recv
            .classical
            .process_incoming_message(MlsMessage::from_bytes(&m1).unwrap())
            .unwrap();
        let in_flight = alice_send
            .classical
            .encrypt_application_message(b"in flight", vec![])
            .unwrap()
            .to_bytes()
            .unwrap();

        // Bob archives his recv group and "restarts": a fresh CombinerClient rebuilt from
        // the archived signing identity, with empty stores.
        let state = bob_recv.export_state().unwrap();
        let classical_gid = bob_recv.classical.group_id().to_vec();
        drop(bob_recv);
        drop(bob);

        #[cfg(feature = "cryptokit")]
        let bob2 = TestClient::from_key_packages(
            bob_id,
            bob_classical_key,
            Default::default(),
            bob_pq_key,
            Default::default(),
        )
        .unwrap();
        #[cfg(not(feature = "cryptokit"))]
        let bob2 =
            TestClient::from_key_packages(bob_id, bob_classical_key, Default::default()).unwrap();

        let mut restored = load_combiner_group(&bob2, &state).unwrap();
        assert_eq!(restored.classical.group_id(), classical_gid.as_slice());
        assert!(restored.pq.is_some());

        let decrypt = |restored: &mut CombinerGroup<_>, bytes: &[u8]| match restored
            .classical
            .process_incoming_message(MlsMessage::from_bytes(bytes).unwrap())
            .unwrap()
        {
            ReceivedMessage::ApplicationMessage(m) => m.data().to_vec(),
            _ => Vec::new(),
        };

        // The in-flight message decrypts after the restore…
        assert_eq!(decrypt(&mut restored, &in_flight), b"in flight");

        // …and so do messages sent afterwards.
        let m3 = alice_send
            .classical
            .encrypt_application_message(b"after restore", vec![])
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(decrypt(&mut restored, &m3), b"after restore");
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
        assert_eq!(
            alice_send.pq.as_ref().unwrap().group_id(),
            bob_recv.pq.as_ref().unwrap().group_id()
        );
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
        assert_eq!(bob_send.pq.as_ref().unwrap().current_epoch(), 1);
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
