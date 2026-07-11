//! The `{classical, pq}` group pair, the APQ-PSK binding, establishment, and APQ welcome framing.

use mls_rs::{
    client::Client,
    client_builder::MlsConfig,
    psk::{ExternalPskId, PreSharedKey},
    storage_provider::in_memory::InMemoryPreSharedKeyStorage,
    CryptoProvider, ExtensionList, Group, KeyPackageStorage, MlsMessage,
};
use zeroize::Zeroizing;

use crate::client::{CombinerClient, OurConfig, PqConfig};
use crate::component::{
    apq_info_extensions, ensure_membership_consistent, verify_apqinfo_pair, ApqInfo, ApqInfoUpdate,
    EPOCH_UNBOUND,
};
use crate::storage::PersistableGroupStorage;
use crate::{CombinerError, Result};

/// APQ welcome envelope tag: [0x01][u32-LE classical-len][classical][u32-LE pq-len][pq].
pub const APQ_TAG: u8 = 0x01;

pub type MlsGroup<S, C> = Group<OurConfig<S, C>>;
pub type PqMlsGroup<S, P> = Group<PqConfig<S, P>>;

pub struct CombinerGroup<S, C, P>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    pub classical: MlsGroup<S, C>,
    /// `None` while the PQ half is deferred: an acceptor's send group before the A.4
    /// bootstrap, and the initiator's recv group mirroring it.
    pub pq: Option<PqMlsGroup<S, P>>,
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

impl<S, C, P> CombinerGroup<S, C, P>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    /// Assemble a Combiner group from halves that were created/joined by `client`, capturing
    /// the client's storage handles for later per-group archival.
    pub fn from_client(
        client: &CombinerClient<S, C, P>,
        classical: MlsGroup<S, C>,
        pq: Option<PqMlsGroup<S, P>>,
    ) -> Self {
        Self {
            classical,
            pq,
            classical_storage: client.classical_group_storage().clone(),
            pq_storage: client.pq_group_storage().clone(),
            classical_psks: client.classical().secret_store(),
            pq_psks: client.pq().secret_store(),
        }
    }

    /// Attach a deferred (A.4) PQ half that was created/joined by `client`, capturing the
    /// storage handles it resolves through. The classical half's handles are untouched —
    /// they stay with the client that originally produced that half.
    pub fn set_pq(&mut self, pq: PqMlsGroup<S, P>, client: &CombinerClient<S, C, P>) {
        self.pq = Some(pq);
        self.pq_storage = client.pq_group_storage().clone();
        self.pq_psks = client.pq().secret_store();
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
    pub fn message_group(&self) -> &MlsGroup<S, C> {
        &self.classical
    }
    pub fn message_group_mut(&mut self) -> &mut MlsGroup<S, C> {
        &mut self.classical
    }
}

/// Rebuild a [`CombinerGroup`] on `client` from exported state: import each half's record
/// into the client's storage, then load the group from it. The loaded groups write through
/// `client`'s storage from here on.
pub fn load_combiner_group<S, C, P>(
    client: &CombinerClient<S, C, P>,
    state: &CombinerGroupState,
) -> Result<CombinerGroup<S, C, P>>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let classical_id = client
        .classical_group_storage()
        .import_group(&state.classical)?;
    let classical = client
        .classical()
        .load_group(&classical_id)
        .map_err(|_| CombinerError::Mls)?;
    let pq = match &state.pq {
        Some(bytes) => {
            let pq_id = client.pq_group_storage().import_group(bytes)?;
            Some(
                client
                    .pq()
                    .load_group(&pq_id)
                    .map_err(|_| CombinerError::Mls)?,
            )
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
/// *exported* (apq / cross-party) application-PSK id. An injected id is an *external* PSK id
/// of `8 + group_id + 1` bytes (41 with this crate's 32-byte group ids) ending in this byte,
/// whereas an exported id is a 38-byte *application* storage id
/// `0x03 ‖ component_id ‖ len ‖ psk_id` (see [`export_psk`] / `ExportedPsk::storage_id`). The
/// two families are disjoint both by length (41 ≠ 38) and by the leading application
/// discriminant. See `pq_ratchet` for the injection path.
pub(crate) const PSK_DOMAIN_INJECTED: u8 = 0x52;

/// PSK identifier for a PQ-ratchet *injected* secret: LE epoch || group_id || `PSK_DOMAIN_INJECTED`.
/// The injected secret S is externally-sourced ML-KEM entropy, not an exporter-derived value,
/// so it keeps this structural id (and stays an *external* PSK) in both recipe phases — it is
/// Germ's extension, not draft-02's `apq_psk`.
pub(crate) fn injected_secret_psk_id(epoch: u64, group_id: &[u8]) -> ExternalPskId {
    let mut id = epoch.to_le_bytes().to_vec();
    id.extend_from_slice(group_id);
    id.push(PSK_DOMAIN_INJECTED);
    ExternalPskId::new(id)
}

/// Which exported-PSK family a derivation belongs to. Both parties on a given binding MUST
/// pass the same domain: the domain selects the component id and the exporter labels, so a
/// mismatch would derive different id/value pairs and the PSK would never resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskDomain {
    /// draft-02's `apq_psk`: exported from a PQ group, imported into its paired classical
    /// group (intra-party PQ→classical binding).
    Apq,
    /// Germ's cross-party TwoMLS-PSK: exported from one party's send group and imported into
    /// the other party's send group (classical↔classical at establishment / the routine
    /// ratchet, PQ↔PQ at an A.5 re-key).
    CrossParty,
}

impl PskDomain {
    /// The mls-extensions component id this domain exports its `SafeExportSecret` leaf from.
    /// Domain separation is the component id (distinct exporter-tree leaves); the
    /// `DeriveSecret` labels (`"psk_id"` / `"psk"`) are fixed across domains.
    fn component_id(self) -> u32 {
        match self {
            PskDomain::Apq => crate::component::APQ_COMPONENT_ID,
            PskDomain::CrossParty => crate::component::TWOMLS_COMPONENT_ID,
        }
    }
}

/// A draft-02 `application` PSK derived from a group's exporter tree: the component id and
/// `psk_id` that name it in a commit (via [`CommitBuilder::add_application_psk`]), the
/// `storage_id` its value is looked up under in the group's PSK store, and the value itself.
/// Produced by [`export_psk`]; consumed by the commit builders (which reference it) and by
/// [`register_psk`] / [`register_psk_stores`] (which install the value under `storage_id`).
#[derive(Clone)]
pub struct ExportedPsk {
    component_id: u32,
    psk_id: Vec<u8>,
    storage_id: ExternalPskId,
    psk: PreSharedKey,
}

impl ExportedPsk {
    /// The component id naming this application PSK in a commit.
    pub fn component_id(&self) -> u32 {
        self.component_id
    }
    /// The opaque `psk_id` naming this application PSK in a commit.
    pub fn psk_id(&self) -> &[u8] {
        &self.psk_id
    }
    /// The store key the PSK value is installed under (`0x03 ‖ component_id ‖ psk_id`).
    pub fn storage_id(&self) -> &ExternalPskId {
        &self.storage_id
    }
    /// The PSK value.
    pub fn psk(&self) -> &PreSharedKey {
        &self.psk
    }

    /// Reconstruct an `ExportedPsk` from its archived parts, recomputing the store key.
    /// The value is not re-derived from any group (the exporter leaf is long consumed);
    /// this is how a restored session recovers a ledgered cross-party PSK.
    pub fn from_parts(component_id: u32, psk_id: Vec<u8>, psk: PreSharedKey) -> Result<Self> {
        let storage_id = mls_rs::psk::ApplicationPsk::new(component_id, psk_id.clone())
            .storage_id()
            .map_err(|_| CombinerError::Mls)?;
        Ok(Self {
            component_id,
            psk_id,
            storage_id,
            psk,
        })
    }

    /// Add this application PSK to a commit under construction.
    pub fn add_to_commit<'a, Cfg: MlsConfig>(
        &self,
        builder: mls_rs::group::CommitBuilder<'a, Cfg>,
    ) -> Result<mls_rs::group::CommitBuilder<'a, Cfg>> {
        builder
            .add_application_psk(self.component_id, self.psk_id.clone())
            .map_err(|_| CombinerError::Mls)
    }
}

/// Derive the draft-02 `apq_psk` (or Germ cross-party PSK) for `group`'s current epoch in the
/// given [`PskDomain`] — the conformant recipe (mls-extensions-08 §4.4): a single
/// `SafeExportSecret(component_id)` off the epoch's exporter tree, then
/// `DeriveSecret(apq_exporter, "psk_id")` and `DeriveSecret(apq_exporter, "psk")`. The
/// exporter leaf is rooted in the epoch's start secret (forward secrecy) and is **consumed**:
/// `safe_export_secret` deletes the leaf, so a given (group, epoch, component) can be exported
/// **at most once** — hence `&mut group`, and callers that may need the value again must
/// memoize it (see the session's PSK ledger). Both parties derive the same [`ExportedPsk`]
/// from the same epoch and domain.
///
/// Generic over the group's config, so it serves both the classical and the PQ half.
pub fn export_psk<Cfg: MlsConfig>(
    group: &mut Group<Cfg>,
    domain: PskDomain,
) -> Result<ExportedPsk> {
    let exporter = group
        .safe_export_secret(domain.component_id())
        .map_err(|_| CombinerError::Mls)?;
    let psk_id = group
        .derive_secret(exporter.as_bytes(), b"psk_id")
        .map_err(|_| CombinerError::Mls)?
        .as_bytes()
        .to_vec();
    let psk = group
        .derive_secret(exporter.as_bytes(), b"psk")
        .map_err(|_| CombinerError::Mls)?;
    let application = mls_rs::psk::ApplicationPsk::new(domain.component_id(), psk_id.clone());
    let storage_id = application.storage_id().map_err(|_| CombinerError::Mls)?;
    Ok(ExportedPsk {
        component_id: domain.component_id(),
        psk_id,
        storage_id,
        psk: PreSharedKey::new(psk.as_bytes().to_vec()),
    })
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
pub fn register_psk<S, C, P>(
    client: &CombinerClient<S, C, P>,
    psk_id: &ExternalPskId,
    psk: &PreSharedKey,
) where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let mut store = client.classical().secret_store();
    store.insert(psk_id.clone(), psk.clone());
    let mut pq_store = client.pq().secret_store();
    pq_store.insert(psk_id.clone(), psk.clone());
}

/// Remove a PSK from a client's secret store(s) — the counterpart of [`register_psk`], for
/// entries the caller has retired.
pub fn forget_psk<S, C, P>(client: &CombinerClient<S, C, P>, psk_id: &ExternalPskId)
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let mut store = client.classical().secret_store();
    store.delete(psk_id);
    let mut pq_store = client.pq().secret_store();
    pq_store.delete(psk_id);
}

/// [`export_psk`] + [`register_psk`] for derive-and-use-immediately sites (establishment,
/// where the PSK is consumed by a join/commit in the same call): derives the application PSK,
/// installs its value under the store key, and returns the descriptor so the caller can also
/// reference it in a commit. Generic over the group's config, so it serves both halves.
pub fn export_and_register_psk<Cfg, S, C, P>(
    group: &mut Group<Cfg>,
    client: &CombinerClient<S, C, P>,
    domain: PskDomain,
) -> Result<ExportedPsk>
where
    Cfg: MlsConfig,
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let exported = export_psk(group, domain)?;
    register_psk(client, exported.storage_id(), exported.psk());
    Ok(exported)
}

/// Creation-time parameters for one half of a combiner group: the pre-generated group id
/// (a group's own id must appear inside its creation-time `APQInfo`, so it exists before
/// `create_group`), the GroupContext extensions (carrying the `APQInfo`), and — when the
/// creation commit is one half of a -02 FULL — the `AppDataUpdate` epoch attestation to
/// ride it.
pub struct GroupCreation {
    pub group_id: Vec<u8>,
    pub extensions: ExtensionList,
    pub app_data_update: Option<ApqInfoUpdate>,
}

impl GroupCreation {
    /// Creation parameters carrying the given `APQInfo` (the production shape).
    pub fn new(
        group_id: Vec<u8>,
        info: &ApqInfo,
        app_data_update: Option<ApqInfoUpdate>,
    ) -> Result<Self> {
        Ok(Self {
            group_id,
            extensions: apq_info_extensions(info)?,
            app_data_update,
        })
    }

    /// Creation parameters with no extensions and no attestation — for tests exercising
    /// the raw primitive below the combiner builders.
    pub fn bare(group_id: Vec<u8>) -> Self {
        Self {
            group_id,
            extensions: ExtensionList::new(),
            app_data_update: None,
        }
    }
}

/// Create a group and commit the given key package in as the first member.
/// Each id in `psk_ids` is injected as an external PSK binding on the member-add commit.
/// Returns (group-at-epoch-1, MLS-encoded Welcome bytes).
///
/// Generic over the client's config, so it serves both the classical and the PQ half.
pub fn create_group_with_member<Cfg: MlsConfig>(
    mls_client: &Client<Cfg>,
    their_kp_bytes: &[u8],
    psks: &[ExportedPsk],
    creation: GroupCreation,
) -> Result<(Group<Cfg>, Vec<u8>)> {
    let mut group = mls_client
        .create_group_with_id(
            creation.group_id,
            creation.extensions,
            ExtensionList::new(),
            None,
        )
        .map_err(|_| CombinerError::Mls)?;
    let their_kp =
        MlsMessage::from_bytes(their_kp_bytes).map_err(|_| CombinerError::InvalidKeyPackage)?;
    let mut builder = group
        .commit_builder()
        .add_member(their_kp)
        .map_err(|_| CombinerError::Mls)?;
    for psk in psks {
        builder = psk.add_to_commit(builder)?;
    }
    if let Some(update) = creation.app_data_update {
        builder = builder.custom_proposal(update.to_custom_proposal()?);
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

/// The ClientId (basic-credential identifier) a key package names. Used to admit the
/// peer into the AS state before a group is built around its key package.
pub fn key_package_client_id(kp_bytes: &[u8]) -> Result<Vec<u8>> {
    let msg = MlsMessage::from_bytes(kp_bytes).map_err(|_| CombinerError::InvalidKeyPackage)?;
    let kp = msg
        .into_key_package()
        .ok_or(CombinerError::InvalidKeyPackage)?;
    let basic = kp
        .signing_identity()
        .credential
        .as_basic()
        .ok_or(CombinerError::InvalidKeyPackage)?;
    Ok(basic.identifier.clone())
}

/// Every group in this protocol is a 1:1 pair — exactly two leaves, the creator and the
/// added member. Enforce that shape wherever a group's roster is set or changed by peer
/// input (joins, and applied peer commits): a crafted welcome or commit carrying extra
/// leaves would otherwise plant shadow members whose credentials this library reports as
/// sender identities, letting the peer make per-message attribution and the adopted
/// principal state diverge. MLS authenticates that roster changes came from the peer —
/// it cannot know the peer was never allowed to make them.
pub fn ensure_two_party<Cfg: MlsConfig>(group: &Group<Cfg>) -> Result<()> {
    if group.roster().members_iter().count() == 2 {
        Ok(())
    } else {
        Err(CombinerError::Mls)
    }
}

/// Join a group from an MLS-encoded Welcome message. Generic over the client's config, so
/// it serves both the classical and the PQ half. Rejects a welcome whose tree is not the
/// protocol's two-party shape (see [`ensure_two_party`]).
pub fn join_group_from_welcome<Cfg: MlsConfig>(
    mls_client: &Client<Cfg>,
    welcome_bytes: &[u8],
) -> Result<Group<Cfg>> {
    let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|_| CombinerError::Mls)?;
    let (group, _) = mls_client
        .join_group(None, &welcome, None)
        .map_err(|_| CombinerError::Mls)?;
    ensure_two_party(&group)?;
    Ok(group)
}

/// Create the initiator's Combiner send group (Group_A) from the remote's key-package bytes.
/// APQ-PSK chain: PQ Group_A → PSK → classical Group_A — the classical message group absorbs
/// PQ secrecy, so messages on it are quantum-safe even though the PQ group ratchets rarely.
/// Returns (send_group, APQWelcome_A bytes).
pub fn create_combiner_send_group<S, C, P>(
    classical_kp: &[u8],
    pq_kp: &[u8],
    client: &CombinerClient<S, C, P>,
) -> Result<(CombinerGroup<S, C, P>, Vec<u8>)>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    // The caller passing the peer's key package IS the app's authorization: admit its
    // identity into the AS state so the added leaves validate.
    let peer_id = key_package_client_id(pq_kp)?;
    client.auth_view().with(|core| core.theirs.commit(peer_id));
    // Pre-generate both halves' group ids so each half's creation-time APQInfo can name
    // the full pair. Both halves land at epoch 1 after their creation commit, and the
    // pair is created together — a structurally FULL creation, so both commits carry the
    // {1, 1} AppDataUpdate attestation.
    let suite = client.cipher_suite();
    let t_gid = client.random_group_id()?;
    let pq_gid = client.random_group_id()?;
    let info = ApqInfo::new(suite, t_gid.clone(), pq_gid.clone(), 1, 1);
    let attestation = ApqInfoUpdate {
        t_epoch: 1,
        pq_epoch: 1,
    };
    // PQ side group first, unbound.
    let (mut pq_group, pq_welcome) = create_group_with_member(
        client.pq(),
        pq_kp,
        &[],
        GroupCreation::new(pq_gid, &info, Some(attestation))?,
    )?;
    // APQ-PSK: export from the PQ group, inject into the classical message group.
    let apq_psk = export_and_register_psk(&mut pq_group, client, PskDomain::Apq)?;
    let (classical_group, classical_welcome) = create_group_with_member(
        client.classical(),
        classical_kp,
        &[apq_psk],
        GroupCreation::new(t_gid, &info, Some(attestation))?,
    )?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup::from_client(client, classical_group, Some(pq_group)),
        apq,
    ))
}

/// Join both halves of a Combiner group from an APQWelcome.
/// The joiner joins the PQ group first, re-derives the APQ-PSK from it, and registers it before
/// joining the classical group (which is bound with that PSK).
pub fn join_combiner_group<S, C, P>(
    apq_welcome: &[u8],
    client: &CombinerClient<S, C, P>,
) -> Result<CombinerGroup<S, C, P>>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let (classical_welcome, pq_welcome) = decode_apq_welcome(apq_welcome)?;
    join_combiner_group_from_halves(&classical_welcome, &pq_welcome, client)
}

/// Join both halves of a Combiner group from the already-decoded APQWelcome halves — for callers
/// that have decoded (and validated) the envelope, so it is not decoded a second time.
pub fn join_combiner_group_from_halves<S, C, P>(
    classical_welcome: &[u8],
    pq_welcome: &[u8],
    client: &CombinerClient<S, C, P>,
) -> Result<CombinerGroup<S, C, P>>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    // The joins validate every leaf in the received trees, including a creator this
    // client may not know yet (e.g. a dedicated per-session principal): open the
    // adoption window for the joins, then record the creator as the peer's canonical
    // identity. Authenticity rides the PSKs bound into the welcome.
    client.auth_view().with(|core| core.adopting = true);
    let joined = (|| {
        let mut pq = join_group_from_welcome(client.pq(), pq_welcome)?;
        // Re-derive the same APQ-PSK the creator used to bind the classical group.
        export_and_register_psk(&mut pq, client, PskDomain::Apq)?;
        let classical = join_group_from_welcome(client.classical(), classical_welcome)?;
        Ok(CombinerGroup::from_client(client, classical, Some(pq)))
    })();
    client.auth_view().with(|core| core.adopting = false);
    let group: CombinerGroup<S, C, P> = joined?;
    // -02 joiner verification: both halves carry a coherent, mutually consistent APQInfo
    // naming exactly these groups, and both rosters hold the same two identities.
    {
        let pq = group.pq.as_ref().ok_or(CombinerError::Mls)?;
        verify_apqinfo_pair(&group.classical, pq, client.cipher_suite())?;
        ensure_membership_consistent(&group.classical, pq)?;
    }
    let mine = group.classical.current_member_index();
    let creator = sender_client_id(&group.classical, if mine == 0 { 1 } else { 0 })?;
    client.auth_view().with(|core| core.theirs.commit(creator));
    Ok(group)
}

/// Create the acceptor's bound send group (Group_B) with the PQ half deferred (A.4):
/// classical only, bound to the cross-party TwoMLS-PSK from the recv group — the sole path
/// by which this classical-only send group inherits post-quantum protection before A.4 (the
/// recv group's classical half is PQ-seeded via its own `apq_psk`). The heavy PQ half is
/// stood up later by the bootstrap flow, off the handshake critical path.
pub fn create_bound_classical_send_group<S, C, P>(
    classical_kp: &[u8],
    client: &CombinerClient<S, C, P>,
    recv_classical: &mut MlsGroup<S, C>,
) -> Result<(CombinerGroup<S, C, P>, Vec<u8>)>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let peer_id = key_package_client_id(classical_kp)?;
    client.auth_view().with(|core| core.theirs.commit(peer_id));
    let psk_cross = export_and_register_psk(recv_classical, client, PskDomain::CrossParty)?;
    // Pre-allocate the deferred PQ half's group id now: it is pinned inside the
    // classical half's APQInfo (durable in GroupContext, riding the Welcome), and the
    // A.4 bootstrap must later create the PQ group under exactly this id. The PQ epoch
    // is the deferred sentinel; this classical-only creation is a -02 PARTIAL, so no
    // AppDataUpdate rides it.
    let suite = client.cipher_suite();
    let t_gid = client.random_group_id()?;
    let pq_gid = client.random_group_id()?;
    let info = ApqInfo::new(suite, t_gid.clone(), pq_gid, 1, EPOCH_UNBOUND);
    let (classical_group, classical_welcome) = create_group_with_member(
        client.classical(),
        classical_kp,
        std::slice::from_ref(&psk_cross),
        GroupCreation::new(t_gid, &info, None)?,
    )?;
    Ok((
        CombinerGroup::from_client(client, classical_group, None),
        classical_welcome,
    ))
}

/// Create the acceptor's bound Combiner send group (Group_B). The classical message group binds
/// to two PSKs: the cross-party TwoMLS-PSK (from the recv group's classical half, Group_A) and
/// the intra-party APQ-PSK (from Group_B's PQ side group).
/// Returns (send_group, APQWelcome_B bytes).
pub fn create_bound_combiner_send_group<S, C, P>(
    classical_kp: &[u8],
    pq_kp: &[u8],
    client: &CombinerClient<S, C, P>,
    recv_classical: &mut MlsGroup<S, C>,
) -> Result<(CombinerGroup<S, C, P>, Vec<u8>)>
where
    S: KeyPackageStorage + Clone,
    C: CryptoProvider + Clone,
    P: CryptoProvider + Clone,
{
    let peer_id = key_package_client_id(classical_kp)?;
    client.auth_view().with(|core| core.theirs.commit(peer_id));
    // Cross-party TwoMLS-PSK from the recv group (Group_A classical).
    let psk_cross = export_and_register_psk(recv_classical, client, PskDomain::CrossParty)?;
    // Pre-generated ids + APQInfo in both halves; both creation commits carry the
    // {1, 1} attestation (the pair is created together — structurally FULL).
    let suite = client.cipher_suite();
    let t_gid = client.random_group_id()?;
    let pq_gid = client.random_group_id()?;
    let info = ApqInfo::new(suite, t_gid.clone(), pq_gid.clone(), 1, 1);
    let attestation = ApqInfoUpdate {
        t_epoch: 1,
        pq_epoch: 1,
    };
    // PQ side group first, unbound.
    let (mut pq_group, pq_welcome) = create_group_with_member(
        client.pq(),
        pq_kp,
        &[],
        GroupCreation::new(pq_gid, &info, Some(attestation))?,
    )?;
    // Intra-party APQ-PSK from Group_B's PQ group.
    let psk_apq = export_and_register_psk(&mut pq_group, client, PskDomain::Apq)?;
    let (classical_group, classical_welcome) = create_group_with_member(
        client.classical(),
        classical_kp,
        &[psk_cross, psk_apq],
        GroupCreation::new(t_gid, &info, Some(attestation))?,
    )?;
    let apq = encode_apq_welcome(classical_welcome, pq_welcome);
    Ok((
        CombinerGroup::from_client(client, classical_group, Some(pq_group)),
        apq,
    ))
}

/// Extract the ClientId bytes of the member at `leaf_index` in `group` (Basic credential).
pub fn sender_client_id<Cfg: MlsConfig>(group: &Group<Cfg>, leaf_index: u32) -> Result<Vec<u8>> {
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
    use crate::{CombinerClient, CryptoConfig};
    use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;

    // apq's tests exercise the generic combiner with mls-rs's default in-memory store and
    // aws-lc backing both halves (portable: identical on Linux and macOS); the capture/serve
    // store used for real invitations lives in the `two-mls-pq` crate.
    type TestClient =
        CombinerClient<InMemoryKeyPackageStorage, AwsLcCryptoProvider, AwsLcCryptoProvider>;

    fn crypto() -> CryptoConfig<AwsLcCryptoProvider, AwsLcCryptoProvider> {
        CryptoConfig::default()
    }

    /// A fresh, unique ClientId for tests (opaque random bytes, not a signing key).
    fn client_id() -> Vec<u8> {
        let cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let (secret, _) = cs.signature_key_generate().unwrap();
        secret.as_bytes().to_vec()
    }

    fn client() -> TestClient {
        CombinerClient::new(client_id(), crypto()).unwrap()
    }

    /// Admit `peer` into `me`'s AS view — the authorization the combiner-level
    /// builders perform internally; tests driving `create_group_with_member` /
    /// `join_group_from_welcome` directly do it explicitly.
    fn admit(me: &TestClient, peer: &[u8]) {
        let peer = peer.to_vec();
        me.auth_view().with(|core| core.theirs.commit(peer));
    }

    /// A rules-free mls-rs client (default `MlsRules`, plain basic identity provider,
    /// same crypto) for crafting protocol-violating artifacts that a wired client can
    /// no longer even build — the adversary's toolbox for the tests below.
    fn rogue_client(id: Vec<u8>) -> mls_rs::Client<impl mls_rs::client_builder::MlsConfig> {
        use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
        use mls_rs::identity::SigningIdentity;
        let provider = AwsLcCryptoProvider::new();
        let cs = provider
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let (secret, public) = cs.signature_key_generate().unwrap();
        let identity = SigningIdentity::new(BasicCredential::new(id).into_credential(), public);
        mls_rs::client_builder::ClientBuilder::new()
            .crypto_provider(provider)
            .identity_provider(BasicIdentityProvider::new())
            .signing_identity(identity, secret, mls_rs::CipherSuite::CURVE25519_CHACHA)
            .build()
    }

    /// Every group in this protocol is a 1:1 pair: a welcome whose tree carries more
    /// than two leaves (a shadow member planted at creation, whose credential would
    /// otherwise be reportable as a sender identity) is rejected at join. The crafting
    /// needs a rules-free client — a wired client can no longer even BUILD the
    /// two-Add creation commit (see `test_rules_reject_malformed_creation`).
    #[test]
    fn test_join_rejects_three_member_welcome() {
        let rogue = rogue_client(client_id());
        let bob = client();
        let carol = client();

        let mut group = rogue
            .create_group(ExtensionList::new(), ExtensionList::new(), None)
            .unwrap();
        let bob_kp =
            MlsMessage::from_bytes(&bob.generate_classical_key_package().unwrap()).unwrap();
        let carol_kp =
            MlsMessage::from_bytes(&carol.generate_classical_key_package().unwrap()).unwrap();
        let commit = group
            .commit_builder()
            .add_member(bob_kp)
            .unwrap()
            .add_member(carol_kp)
            .unwrap()
            .build()
            .unwrap();
        group.apply_pending_commit().unwrap();
        let welcome = commit.welcome_messages.first().unwrap().to_bytes().unwrap();

        assert!(join_group_from_welcome(bob.classical(), &welcome).is_err());
    }

    /// The rules make the same malformation unbuildable on a wired client: the
    /// creation commit must be exactly one Add.
    #[test]
    fn test_rules_reject_malformed_creation() {
        let alice = client();
        let bob = client();
        let carol = client();

        let mut group = alice
            .classical()
            .create_group(ExtensionList::new(), ExtensionList::new(), None)
            .unwrap();
        let bob_kp =
            MlsMessage::from_bytes(&bob.generate_classical_key_package().unwrap()).unwrap();
        let carol_kp =
            MlsMessage::from_bytes(&carol.generate_classical_key_package().unwrap()).unwrap();
        assert!(group
            .commit_builder()
            .add_member(bob_kp)
            .unwrap()
            .add_member(carol_kp)
            .unwrap()
            .build()
            .is_err());
    }

    /// Steady state forbids growth through EITHER side's commit: a peer commit
    /// smuggling an Add is vetoed on receive BEFORE it is applied, and a wired
    /// client cannot build one.
    #[test]
    fn test_rules_reject_add_in_steady_state() {
        let alice = client();
        let bob = client();
        let carol = client();

        // Honest pair (mutual admissions — the step the combiner-level builders and
        // the session layer perform).
        admit(&alice, bob.client_id());
        admit(&bob, alice.client_id());
        let (mut alice_send, welcome) = create_group_with_member(
            alice.classical(),
            &bob.generate_classical_key_package().unwrap(),
            &[],
            GroupCreation::bare(alice.random_group_id().unwrap()),
        )
        .unwrap();
        let mut bob_recv = join_group_from_welcome(bob.classical(), &welcome).unwrap();

        // A wired client cannot even build the growth commit.
        let carol_kp =
            MlsMessage::from_bytes(&carol.generate_classical_key_package().unwrap()).unwrap();
        assert!(alice_send
            .commit_builder()
            .add_member(carol_kp)
            .unwrap()
            .build()
            .is_err());

        // A rogue creator CAN build it — the victim must veto it on receive, before
        // application (the roster still reads 2 afterwards).
        let rogue_id = client_id();
        let rogue = rogue_client(rogue_id.clone());
        let victim = client();
        admit(&victim, &rogue_id);
        let mut rogue_group = rogue
            .create_group(ExtensionList::new(), ExtensionList::new(), None)
            .unwrap();
        let victim_kp =
            MlsMessage::from_bytes(&victim.generate_classical_key_package().unwrap()).unwrap();
        let creation = rogue_group
            .commit_builder()
            .add_member(victim_kp)
            .unwrap()
            .build()
            .unwrap();
        rogue_group.apply_pending_commit().unwrap();
        let welcome = creation
            .welcome_messages
            .first()
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut victim_recv = join_group_from_welcome(victim.classical(), &welcome).unwrap();

        let carol_kp2 =
            MlsMessage::from_bytes(&carol.generate_classical_key_package().unwrap()).unwrap();
        let growth = rogue_group
            .commit_builder()
            .add_member(carol_kp2)
            .unwrap()
            .build()
            .unwrap();
        rogue_group.apply_pending_commit().unwrap();
        let growth_bytes = growth.commit_message.to_bytes().unwrap();

        assert!(victim_recv
            .process_incoming_message(MlsMessage::from_bytes(&growth_bytes).unwrap())
            .is_err());
        assert!(ensure_two_party(&victim_recv).is_ok());

        // The honest pair still works.
        let msg = alice_send
            .encrypt_application_message(b"still-fine", vec![])
            .unwrap()
            .to_bytes()
            .unwrap();
        bob_recv
            .process_incoming_message(MlsMessage::from_bytes(&msg).unwrap())
            .unwrap();
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
        let bob = TestClient::new(bob_id.clone(), crypto()).unwrap();
        // The archivable signing identity, captured as an invitation-style archive would.
        let bob_classical_key = Zeroizing::new(bob.classical_signing_key().to_vec());
        let bob_pq_key = Zeroizing::new(bob.pq_signing_key().to_vec());

        let (mut alice_send, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
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

        let bob2 = TestClient::from_key_packages(
            crate::ArchivedIdentity {
                client_id: bob_id,
                classical_signing_key: bob_classical_key,
                classical_kp_store: Default::default(),
                pq_signing_key: bob_pq_key,
                pq_kp_store: Default::default(),
            },
            crypto(),
        )
        .unwrap();

        let mut restored = load_combiner_group(&bob2, &state).unwrap();
        assert_eq!(restored.classical.group_id(), classical_gid.as_slice());
        assert!(restored.pq.is_some());

        let decrypt = |restored: &mut CombinerGroup<_, _, _>, bytes: &[u8]| match restored
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
            &bob.generate_pq_key_package().unwrap(),
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
            &bob.generate_pq_key_package().unwrap(),
            &alice,
        )
        .unwrap();
        let mut bob_recv = join_combiner_group(&welcome_a, &bob).unwrap();

        let (bob_send, _welcome_b) = create_bound_combiner_send_group(
            &alice.generate_classical_key_package().unwrap(),
            &alice.generate_pq_key_package().unwrap(),
            &bob,
            &mut bob_recv.classical,
        )
        .unwrap();

        assert_eq!(bob_send.classical.current_epoch(), 1);
        assert_eq!(bob_send.pq.as_ref().unwrap().current_epoch(), 1);
    }

    /// Deterministic across parties, domain-separated, and consumed once per epoch. Two
    /// independent group instances at the same epoch (the two parties' copies) each export
    /// once and agree; the two domains are distinct exporter-tree leaves; and a second
    /// export of the same (group, epoch, component) is rejected (`SafeExportSecret` consumes
    /// the leaf — the FS property the session's ledger memoization is built around).
    #[test]
    fn test_export_psk_agrees_across_parties_and_consumes_once() {
        let alice = client();
        let bob = client();

        let (mut send, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
            &alice,
        )
        .unwrap();
        let mut recv = join_combiner_group(&welcome, &bob).unwrap();

        // Cross-party from each party's copy of the classical group: same store key +
        // value (the CrossParty leaf is untouched by establishment, which consumes only
        // the Apq leaves to bind the pair).
        let a = export_psk(&mut send.classical, PskDomain::CrossParty).unwrap();
        let b = export_psk(&mut recv.classical, PskDomain::CrossParty).unwrap();
        assert_eq!(a.storage_id(), b.storage_id());
        assert_eq!(a.psk().raw_value(), b.psk().raw_value());

        // Re-exporting the same (group, epoch, component) is rejected: the leaf is consumed.
        assert!(export_psk(&mut send.classical, PskDomain::CrossParty).is_err());

        // Establishment already consumed the Apq leaf of both PQ halves (pq -> classical
        // bind), so re-exporting it at the same epoch is likewise rejected.
        assert!(export_psk(send.pq.as_mut().unwrap(), PskDomain::Apq).is_err());
    }

    #[test]
    fn test_sender_client_id_returns_group_creator() {
        let alice = client();
        let bob = client();
        admit(&alice, bob.client_id());
        let (group, _) = create_group_with_member(
            alice.classical(),
            &bob.generate_classical_key_package().unwrap(),
            &[],
            GroupCreation::bare(alice.random_group_id().unwrap()),
        )
        .unwrap();
        // Leaf 0 is the creating client.
        assert_eq!(sender_client_id(&group, 0).unwrap(), alice.client_id());
    }

    #[test]
    fn test_client_construction_fails_on_provider_without_pq_suite() {
        // A provider that cannot supply the PQ suite cannot back the PQ half: construction
        // fails up front with UnsupportedCipherSuite instead of deep in a session.
        #[derive(Clone, Default)]
        struct ClassicalOnly(AwsLcCryptoProvider);
        impl CryptoProvider for ClassicalOnly {
            type CipherSuiteProvider = <AwsLcCryptoProvider as CryptoProvider>::CipherSuiteProvider;
            fn supported_cipher_suites(&self) -> Vec<mls_rs::CipherSuite> {
                vec![mls_rs::CipherSuite::CURVE25519_CHACHA]
            }
            fn cipher_suite_provider(
                &self,
                suite: mls_rs::CipherSuite,
            ) -> Option<Self::CipherSuiteProvider> {
                (suite == mls_rs::CipherSuite::CURVE25519_CHACHA)
                    .then(|| self.0.cipher_suite_provider(suite))
                    .flatten()
            }
        }

        let result = CombinerClient::<InMemoryKeyPackageStorage, _, _>::new(
            client_id(),
            CryptoConfig {
                classical: AwsLcCryptoProvider::new(),
                pq: ClassicalOnly::default(),
                suite: Default::default(),
            },
        );
        assert!(matches!(
            result,
            Err(crate::CombinerError::UnsupportedCipherSuite)
        ));
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
