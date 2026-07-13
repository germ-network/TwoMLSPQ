//! draft-ietf-mls-combiner-02 component machinery: the `APQInfo` GroupContext extension,
//! the `AppDataUpdate` (mls-extensions, 0x0008) epoch-attestation proposal, and the
//! verification helpers joins and FULL commits run against them.
//!
//! Conformance shape (see the book's psk-binding / group-rules chapters):
//! - `APQInfo` is written **once, at group creation**, into both halves' GroupContext and
//!   rides Welcomes automatically. It is never rewritten — a GroupContextExtensions
//!   proposal would force an updatePath onto the deliberately pathless A.3 bind — so its
//!   two epoch fields are creation-time values. Epoch *freshness* is attested per FULL
//!   commit by the `AppDataUpdate` proposal instead, which receivers verify against the
//!   actual post-commit epochs of both halves.
//! - A deferred half (the acceptor's PQ side before the A.4 bootstrap) is recorded with
//!   its epoch field set to [`EPOCH_UNBOUND`] and its group id **pre-allocated**, so the
//!   id a later A.4 must use is pinned inside the classical half's GroupContext from
//!   creation.

use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::ExtensionType;
use mls_rs::group::proposal::{CustomProposal, Proposal, ProposalType};
use mls_rs::group::{CommitEffect, CommitMessageDescription};
use mls_rs::mls_rules::ProposalInfo;
use mls_rs::{ExtensionList, Group};

use crate::client::{ApqCipherSuite, ApqMode};
use crate::{CombinerError, Result};

pub use wire::{AppBinding, ApqInfo, ApqInfoUpdate};

/// The combiner component id. The draft's id awaits IANA assignment; this is a high,
/// uncommon value. It MUST fit the 16-bit Exporter Tree that `SafeExportSecret` walks:
/// draft-ietf-mls-extensions-08 types `ComponentID` as `uint32` but gives the tree only
/// `2^16` leaves (draft -09 resolves this by narrowing `ComponentID` to `uint16`), and the
/// fork rejects out-of-range ids rather than truncating — so combiner component ids live in
/// `[0, 0x10000)`.
pub const APQ_COMPONENT_ID: u32 = 0xFF01;

/// Germ's cross-party TwoMLS-PSK domain, kept disjoint from the combiner component so the
/// two exported-PSK families can never collide (distinct Exporter Tree leaves). Also 16-bit
/// (see [`APQ_COMPONENT_ID`]).
pub const TWOMLS_COMPONENT_ID: u32 = 0xFF02;

/// The `APQInfo` GroupContext extension type (RFC 9420 private-use extension range).
pub const APQINFO_EXTENSION_TYPE: ExtensionType = ExtensionType::new(0xF0A1);

/// The `AppBinding` GroupContext extension type (RFC 9420 private-use range, next after
/// [`APQINFO_EXTENSION_TYPE`]).
pub const APP_BINDING_EXTENSION_TYPE: ExtensionType = ExtensionType::new(0xF0A2);

/// The mls-extensions `AppDataUpdate` proposal type (suggested IANA code point 0x0008).
pub const APP_DATA_UPDATE: ProposalType = ProposalType::new(0x0008);

/// Epoch sentinel for a half whose binding into its sibling is still pending: the
/// acceptor's PQ side before A.4 (as seen from the classical half), and the classical
/// side as recorded by the A.4-created PQ group. Unreachable as a real MLS epoch.
pub const EPOCH_UNBOUND: u64 = u64::MAX;

/// `AppDataUpdateOperation.update` (mls-extensions §AppDataUpdate).
const APP_DATA_OP_UPDATE: u8 = 1;

// In its own module because the derive-generated impls reference the std `Result`,
// which the crate-local `Result` alias would shadow (same pattern as the session's
// `archive_wire`).
mod wire {
    use mls_rs::extension::{ExtensionType, MlsCodecExtension};
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};

    /// The `APQInfo` struct per draft-ietf-mls-combiner-02 §6, carried as a GroupContext
    /// extension in both halves. Field order follows the draft's TLS presentation
    /// (`mode` as a one-byte bool, suites as u16).
    #[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
    pub struct ApqInfo {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub t_session_group_id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub pq_session_group_id: Vec<u8>,
        /// 0 = PQ/T Confidentiality-Only, 1 = Confidentiality + Authenticity.
        pub mode: u8,
        pub t_cipher_suite: u16,
        pub pq_cipher_suite: u16,
        /// Classical epoch as of this extension's write (= the join point, epoch 1), or
        /// [`super::EPOCH_UNBOUND`]. Fresh epochs are attested by [`ApqInfoUpdate`], not here.
        pub t_epoch: u64,
        /// PQ epoch as of this extension's write, or [`super::EPOCH_UNBOUND`] while deferred.
        pub pq_epoch: u64,
    }

    impl MlsCodecExtension for ApqInfo {
        fn extension_type() -> ExtensionType {
            super::APQINFO_EXTENSION_TYPE
        }
    }

    /// The `AppBinding` GroupContext extension: opaque app-supplied bytes binding the
    /// session to the app's immutable relationship identity — the piece the two mutable
    /// agents (see the rotation lifecycle) cannot carry. Like `APQInfo`, it is written
    /// **once, at group creation**, rides Welcomes automatically, and is never rewritten
    /// (GroupContextExtensions proposals are outside the TwoMLS operation whitelist), so
    /// it is immutable for the session's lifetime; joiners verify it against the binding
    /// they expect.
    ///
    /// The payload should be a DIGEST of the app's identifiers, not the identifiers
    /// themselves (the first adopter binds `H(domain-tag ‖ role-ordered did:did)`, with
    /// the same canonicalization its delegation binding uses, so the two cannot drift).
    /// This crate never interprets the bytes — the adopter owns the digest and wire
    /// format.
    #[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
    pub struct AppBinding {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub data: Vec<u8>,
    }

    impl MlsCodecExtension for AppBinding {
        fn extension_type() -> ExtensionType {
            super::APP_BINDING_EXTENSION_TYPE
        }
    }

    /// The combiner's `AppDataUpdate` payload: the absolute epochs of both halves after a
    /// FULL commit ("the epochs of both groups", -02 §6.1). Receivers verify equality
    /// against the actual post-apply epochs — absolute values, so any number of intervening
    /// PARTIALs or A.5 re-keys reconciles with no extra machinery.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
    pub struct ApqInfoUpdate {
        pub t_epoch: u64,
        pub pq_epoch: u64,
    }

    /// The mls-extensions `AppDataUpdate` wire shape (op is always `update`; a `remove`
    /// for the combiner component is never legitimate and fails strict decode).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct AppDataUpdateWire {
        pub(super) component_id: u32,
        pub(super) op: u8,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) update: Vec<u8>,
    }
}

use wire::AppDataUpdateWire;

impl ApqInfo {
    /// Assemble an `ApqInfo` for a group pair: ids as pre-allocated, mode and suite
    /// values read off the validated [`ApqCipherSuite`].
    pub fn new(
        suite: ApqCipherSuite,
        t_session_group_id: Vec<u8>,
        pq_session_group_id: Vec<u8>,
        t_epoch: u64,
        pq_epoch: u64,
    ) -> Self {
        Self {
            t_session_group_id,
            pq_session_group_id,
            mode: mode_byte(suite.mode()),
            t_cipher_suite: u16::from(suite.classical),
            pq_cipher_suite: u16::from(suite.pq),
            t_epoch,
            pq_epoch,
        }
    }

    /// The identity fields both halves must agree on (everything but the per-half
    /// creation-time epoch fields, which legitimately differ across a deferred A.4).
    fn identity_fields_match(&self, other: &Self) -> bool {
        self.t_session_group_id == other.t_session_group_id
            && self.pq_session_group_id == other.pq_session_group_id
            && self.mode == other.mode
            && self.t_cipher_suite == other.t_cipher_suite
            && self.pq_cipher_suite == other.pq_cipher_suite
    }

    /// Validate this extension's suite pair against the pinned [`ApqCipherSuite`]:
    /// the recorded values must equal the expected pair, the pair must be a coherent
    /// APQ combination (rejecting duplicate or invalid suites per -02), and the mode
    /// must be the one the pair derives.
    fn check_suites(&self, expected: ApqCipherSuite) -> Result<()> {
        if self.t_cipher_suite != u16::from(expected.classical)
            || self.pq_cipher_suite != u16::from(expected.pq)
        {
            return Err(CombinerError::CipherSuiteMismatch);
        }
        // Re-validate coherence from the recorded values (duplicate/invalid suites).
        let recorded = ApqCipherSuite::new(
            mls_rs::CipherSuite::new(self.t_cipher_suite),
            mls_rs::CipherSuite::new(self.pq_cipher_suite),
        )?;
        if self.mode != mode_byte(recorded.mode()) {
            return Err(CombinerError::ApqInfoMismatch);
        }
        Ok(())
    }
}

fn mode_byte(mode: ApqMode) -> u8 {
    match mode {
        ApqMode::ConfidentialityOnly => 0,
        ApqMode::ConfidentialityAndAuthenticity => 1,
    }
}

/// Decode a value and require the input to be fully consumed.
fn decode_all<T: mls_rs::mls_rs_codec::MlsDecode>(mut bytes: &[u8]) -> Result<T> {
    let value = T::mls_decode(&mut bytes).map_err(|_| CombinerError::Mls)?;
    if !bytes.is_empty() {
        return Err(CombinerError::Mls);
    }
    Ok(value)
}

fn encode<T: mls_rs::mls_rs_codec::MlsEncode>(value: &T) -> Result<Vec<u8>> {
    value.mls_encode_to_vec().map_err(|_| CombinerError::Mls)
}

impl ApqInfoUpdate {
    /// Encode as an `AppDataUpdate(op=update)` custom proposal for the combiner component.
    pub fn to_custom_proposal(self) -> Result<CustomProposal> {
        let wire = AppDataUpdateWire {
            component_id: APQ_COMPONENT_ID,
            op: APP_DATA_OP_UPDATE,
            update: encode(&self)?,
        };
        Ok(CustomProposal::new(APP_DATA_UPDATE, encode(&wire)?))
    }

    /// Strictly decode an `AppDataUpdate` custom proposal: correct proposal type, the
    /// combiner component, `op = update`, and a fully-consumed payload.
    pub fn from_custom_proposal(proposal: &CustomProposal) -> Result<Self> {
        if proposal.proposal_type() != APP_DATA_UPDATE {
            return Err(CombinerError::Mls);
        }
        let wire: AppDataUpdateWire = decode_all(proposal.data())?;
        if wire.component_id != APQ_COMPONENT_ID || wire.op != APP_DATA_OP_UPDATE {
            return Err(CombinerError::Mls);
        }
        decode_all(&wire.update)
    }
}

/// The `ApqInfoUpdate` carried by a commit's applied proposals, if any. Errors on a
/// malformed payload (a well-typed but undecodable AppDataUpdate is an attack or a bug,
/// never ignorable); `Ok(None)` when the commit carries none.
pub fn find_apqinfo_update(applied: &[ProposalInfo<Proposal>]) -> Result<Option<ApqInfoUpdate>> {
    let mut found = None;
    for info in applied {
        if let Proposal::Custom(custom) = &info.proposal {
            if found.is_some() {
                // The rules cap custom proposals at one; two here means the rules were
                // bypassed — refuse rather than pick.
                return Err(CombinerError::ApqInfoMismatch);
            }
            found = Some(ApqInfoUpdate::from_custom_proposal(custom)?);
        }
    }
    Ok(found)
}

/// The attestation carried by a processed or applied commit's description, if any.
/// `Removed` / `ReInit` effects are never legitimate in this protocol (the rules forbid
/// the proposals that produce them) and are refused outright.
pub fn commit_attestation(desc: &CommitMessageDescription) -> Result<Option<ApqInfoUpdate>> {
    match &desc.effect {
        CommitEffect::NewEpoch(new_epoch) => find_apqinfo_update(new_epoch.applied_proposals()),
        _ => Err(CombinerError::ApqInfoMismatch),
    }
}

/// An `ExtensionList` carrying exactly the given `APQInfo` — the GroupContext extension
/// list every combiner group is created with.
pub fn apq_info_extensions(info: &ApqInfo) -> Result<ExtensionList> {
    let mut list = ExtensionList::new();
    list.set_from(info.clone())
        .map_err(|_| CombinerError::Mls)?;
    Ok(list)
}

/// Read the `APQInfo` GroupContext extension out of a group, failing if absent or
/// undecodable — every group this crate creates or joins carries one.
pub fn read_apqinfo<Cfg: MlsConfig>(group: &Group<Cfg>) -> Result<ApqInfo> {
    group
        .context()
        .extensions
        .get_as::<ApqInfo>()
        .map_err(|_| CombinerError::Mls)?
        .ok_or(CombinerError::ApqInfoMismatch)
}

/// Read the `AppBinding` GroupContext extension out of a group: `Ok(None)` when absent
/// (an unbound session is valid — the extension is optional), the opaque bytes when
/// present, and [`CombinerError::AppBindingMismatch`] when present but undecodable (a
/// corrupt binding must never read as "unbound").
pub fn read_app_binding<Cfg: MlsConfig>(group: &Group<Cfg>) -> Result<Option<Vec<u8>>> {
    group
        .context()
        .extensions
        .get_as::<AppBinding>()
        .map(|binding| binding.map(|b| b.data))
        .map_err(|_| CombinerError::AppBindingMismatch)
}

/// Verify a group's `AppBinding` against the binding the caller expects — an exact,
/// symmetric match: `Some(bytes)` must be carried equal, `None` requires the group to
/// carry none. Anything else — expected-but-absent (a wrong-relationship welcome, or a
/// strip: the downgrade shape `APQInfo` verification also refuses), unequal, or
/// present-but-unexpected (never silently accepted; the caller must state the binding it
/// can verify) — is [`CombinerError::AppBindingMismatch`].
pub fn verify_app_binding<Cfg: MlsConfig>(
    group: &Group<Cfg>,
    expected: Option<&[u8]>,
) -> Result<()> {
    if read_app_binding(group)?.as_deref() == expected {
        Ok(())
    } else {
        Err(CombinerError::AppBindingMismatch)
    }
}

/// The classical-half checks shared by the full-pair and deferred joiner verifications:
/// extension present; suites equal the pinned pair and re-validate as a coherent APQ
/// combination; mode matches; `t_session_group_id` is the joined classical group's id;
/// `t_epoch` equals the observed epoch.
fn verify_classical_half<Cfg: MlsConfig>(
    classical: &Group<Cfg>,
    expected: ApqCipherSuite,
) -> Result<ApqInfo> {
    let info = read_apqinfo(classical)?;
    info.check_suites(expected)?;
    if info.t_session_group_id != classical.group_id() {
        return Err(CombinerError::ApqInfoMismatch);
    }
    if info.t_epoch == EPOCH_UNBOUND || info.t_epoch != classical.current_epoch() {
        return Err(CombinerError::ApqInfoMismatch);
    }
    Ok(info)
}

/// Joiner-side `APQInfo` verification for a full pair, run at the join point (both
/// groups at epoch 1): the classical-half checks, plus — the PQ half's extension has
/// identical identity fields, names the joined PQ group, and its `pq_epoch` matches the
/// observed epoch; the classical half's `pq_epoch` must match too (it was written with
/// the pair live).
///
/// Returns the classical half's `ApqInfo` (the authoritative copy for later A.4 checks).
pub fn verify_apqinfo_pair<Cfg1: MlsConfig, Cfg2: MlsConfig>(
    classical: &Group<Cfg1>,
    pq: &Group<Cfg2>,
    expected: ApqCipherSuite,
) -> Result<ApqInfo> {
    let info = verify_classical_half(classical, expected)?;
    let pq_info = read_apqinfo(pq)?;
    if !info.identity_fields_match(&pq_info) {
        return Err(CombinerError::ApqInfoMismatch);
    }
    if info.pq_session_group_id != pq.group_id() {
        return Err(CombinerError::ApqInfoMismatch);
    }
    if pq_info.pq_epoch == EPOCH_UNBOUND
        || pq_info.pq_epoch != pq.current_epoch()
        || info.pq_epoch != pq.current_epoch()
    {
        return Err(CombinerError::ApqInfoMismatch);
    }
    Ok(info)
}

/// Joiner-side `APQInfo` verification for the deferred (A.4-pending) shape: the
/// classical-half checks, plus the extension records the PQ side as pending
/// (`pq_epoch == EPOCH_UNBOUND`) with a non-empty pre-allocated group id — the id the
/// A.4 bootstrap must later use. A welcome without an `APQInfo` at all is a downgrade
/// attempt and fails the same way.
pub fn verify_apqinfo_deferred<Cfg: MlsConfig>(
    classical: &Group<Cfg>,
    expected: ApqCipherSuite,
) -> Result<ApqInfo> {
    let info = verify_classical_half(classical, expected)?;
    if info.pq_epoch != EPOCH_UNBOUND || info.pq_session_group_id.is_empty() {
        return Err(CombinerError::ApqInfoMismatch);
    }
    Ok(info)
}

/// A.4-side verification of the deferred PQ half's own `APQInfo`: identity fields match
/// the classical half's authoritative copy, the group ids name the actual groups (the
/// PQ id being the one pre-allocated at establishment), `t_epoch` is the deferred
/// sentinel (no classical commit rides A.4), and `pq_epoch` matches the observed epoch.
pub fn verify_deferred_pq_info<Cfg: MlsConfig>(
    pq_group: &Group<Cfg>,
    classical_info: &ApqInfo,
    expected: ApqCipherSuite,
) -> Result<()> {
    let pq_info = read_apqinfo(pq_group)?;
    pq_info.check_suites(expected)?;
    // The classical half's copy records its own creation-time view {t: real, pq:
    // EPOCH_UNBOUND}; the A.4-created PQ half records the mirror {t: EPOCH_UNBOUND,
    // pq: real}. Identity fields must agree between them.
    if !pq_info.identity_fields_match(classical_info) {
        return Err(CombinerError::ApqInfoMismatch);
    }
    if pq_info.pq_session_group_id != pq_group.group_id() {
        return Err(CombinerError::ApqInfoMismatch);
    }
    if pq_info.t_epoch != EPOCH_UNBOUND {
        return Err(CombinerError::ApqInfoMismatch);
    }
    if pq_info.pq_epoch == EPOCH_UNBOUND || pq_info.pq_epoch != pq_group.current_epoch() {
        return Err(CombinerError::ApqInfoMismatch);
    }
    Ok(())
}

/// "-02 §4.2.1: all members MUST verify group membership is consistent in both sessions
/// after a join" — both halves' rosters carry exactly the same two Basic-credential
/// identities.
pub fn ensure_membership_consistent<Cfg1: MlsConfig, Cfg2: MlsConfig>(
    classical: &Group<Cfg1>,
    pq: &Group<Cfg2>,
) -> Result<()> {
    fn roster_ids<Cfg: MlsConfig>(group: &Group<Cfg>) -> Result<Vec<Vec<u8>>> {
        let mut ids = group
            .roster()
            .members_iter()
            .map(|member| {
                member
                    .signing_identity
                    .credential
                    .as_basic()
                    .map(|basic| basic.identifier.clone())
                    .ok_or(CombinerError::ApqInfoMismatch)
            })
            .collect::<Result<Vec<_>>>()?;
        ids.sort();
        Ok(ids)
    }
    let classical_ids = roster_ids(classical)?;
    let pq_ids = roster_ids(pq)?;
    if classical_ids.len() != 2 || classical_ids != pq_ids {
        return Err(CombinerError::ApqInfoMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mls_rs::mls_rs_codec::MlsEncode;

    fn suite() -> ApqCipherSuite {
        ApqCipherSuite::default()
    }

    fn info() -> ApqInfo {
        ApqInfo::new(suite(), vec![1; 32], vec![2; 32], 1, 1)
    }

    #[test]
    fn test_apqinfo_extension_round_trips() {
        let list = apq_info_extensions(&info()).unwrap();
        let read: ApqInfo = list.get_as().unwrap().unwrap();
        assert_eq!(read, info());
    }

    #[test]
    fn test_app_binding_extension_round_trips() {
        let mut list = ExtensionList::new();
        list.set_from(AppBinding {
            data: b"relationship-digest".to_vec(),
        })
        .unwrap();
        let read: AppBinding = list.get_as().unwrap().unwrap();
        assert_eq!(read.data, b"relationship-digest");
        // Absent from a fresh list — the optional case reads as None, not an error.
        let empty = ExtensionList::new();
        assert!(empty.get_as::<AppBinding>().unwrap().is_none());
    }

    #[test]
    fn test_apqinfo_update_proposal_round_trips() {
        let update = ApqInfoUpdate {
            t_epoch: 7,
            pq_epoch: 3,
        };
        let proposal = update.to_custom_proposal().unwrap();
        assert_eq!(proposal.proposal_type(), APP_DATA_UPDATE);
        assert_eq!(
            ApqInfoUpdate::from_custom_proposal(&proposal).unwrap(),
            update
        );
    }

    #[test]
    fn test_from_custom_proposal_rejects_wrong_type() {
        let update = ApqInfoUpdate {
            t_epoch: 1,
            pq_epoch: 1,
        };
        let good = update.to_custom_proposal().unwrap();
        let wrong_type = CustomProposal::new(ProposalType::new(0x0009), good.data().to_vec());
        assert!(ApqInfoUpdate::from_custom_proposal(&wrong_type).is_err());
    }

    #[test]
    fn test_from_custom_proposal_rejects_wrong_component_op_and_trailing() {
        let update = ApqInfoUpdate {
            t_epoch: 1,
            pq_epoch: 1,
        };
        // Wrong component id.
        let wire = AppDataUpdateWire {
            component_id: TWOMLS_COMPONENT_ID,
            op: APP_DATA_OP_UPDATE,
            update: update.mls_encode_to_vec().unwrap(),
        };
        let p = CustomProposal::new(APP_DATA_UPDATE, wire.mls_encode_to_vec().unwrap());
        assert!(ApqInfoUpdate::from_custom_proposal(&p).is_err());
        // Wrong op (remove).
        let wire = AppDataUpdateWire {
            component_id: APQ_COMPONENT_ID,
            op: 2,
            update: update.mls_encode_to_vec().unwrap(),
        };
        let p = CustomProposal::new(APP_DATA_UPDATE, wire.mls_encode_to_vec().unwrap());
        assert!(ApqInfoUpdate::from_custom_proposal(&p).is_err());
        // Trailing bytes after the payload.
        let mut inner = update.mls_encode_to_vec().unwrap();
        inner.push(0);
        let wire = AppDataUpdateWire {
            component_id: APQ_COMPONENT_ID,
            op: APP_DATA_OP_UPDATE,
            update: inner,
        };
        let p = CustomProposal::new(APP_DATA_UPDATE, wire.mls_encode_to_vec().unwrap());
        assert!(ApqInfoUpdate::from_custom_proposal(&p).is_err());
        // Trailing bytes after the wire struct.
        let mut outer = AppDataUpdateWire {
            component_id: APQ_COMPONENT_ID,
            op: APP_DATA_OP_UPDATE,
            update: update.mls_encode_to_vec().unwrap(),
        }
        .mls_encode_to_vec()
        .unwrap();
        outer.push(0);
        let p = CustomProposal::new(APP_DATA_UPDATE, outer);
        assert!(ApqInfoUpdate::from_custom_proposal(&p).is_err());
    }

    #[test]
    fn test_check_suites_rejects_mismatch_and_incoherence() {
        let good = info();
        assert!(good.check_suites(suite()).is_ok());

        // Swapped suites: not the expected pair.
        let mut swapped = info();
        std::mem::swap(&mut swapped.t_cipher_suite, &mut swapped.pq_cipher_suite);
        assert!(swapped.check_suites(suite()).is_err());

        // Duplicate suites (both classical): incoherent even if expectation matched.
        let mut dup = info();
        dup.pq_cipher_suite = dup.t_cipher_suite;
        assert!(dup.check_suites(suite()).is_err());

        // Wrong mode for the pair.
        let mut mode = info();
        mode.mode = 1;
        assert!(mode.check_suites(suite()).is_err());
    }
}
