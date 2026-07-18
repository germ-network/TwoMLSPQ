//! The operation whitelist of a TwoMLS group — the `MlsRules` half of the group rules.
//!
//! Every group in this protocol is a 1:1 pair driving a fixed, tiny slice of MLS:
//! one creation commit (the creator adds the single peer), then steady-state commits
//! that fold at most one Update (always the *other* party's leaf) plus external-PSK
//! injections. Nothing else is ever legitimate — no removes, no re-inits, no external
//! commits or senders, no group-context mutations, no resumption PSKs.
//!
//! `filter_proposals` runs on BOTH directions: on receive an error vetoes the peer's
//! entire commit before it is applied; on send it fails a commit build whose proposal
//! cache was poisoned (the session's `queue_proposal` is the only cache entry point,
//! so a violation there is an upstream bug or an injected proposal — fail loudly
//! rather than silently filter, the round recovers because the peer re-staples).
//!
//! This complements, and deliberately does not replace, the session-layer checks:
//! `ensure_two_party` still guards every join (where no commit — and so no rules
//! filter — runs) and re-asserts the roster after every applied commit.

use mls_rs::{
    error::IntoAnyError,
    group::{GroupContext, Roster, Sender},
    mls_rules::{CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle},
    MlsRules,
};

use crate::component::{ApqInfoUpdate, APP_DATA_UPDATE};

/// A commit (built or received) violated the TwoMLS operation whitelist.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// The committer is not an existing member (external commits are never used).
    #[error("external commit forbidden")]
    ExternalCommit,
    /// A proposal type outside the whitelist (Add post-creation, Remove, ReInit,
    /// ExternalInit, GroupContextExtensions, custom).
    #[error("forbidden proposal type in commit")]
    ForbiddenProposal,
    /// The creation commit must be exactly one Add by the lone creator.
    #[error("malformed creation commit")]
    BadCreation,
    /// More than one Update, an Update not attributable to a member, or an Update
    /// covering the committer's own leaf.
    #[error("update proposal count or sender invalid")]
    BadUpdate,
    /// A resumption PSK (only external PSKs bind this protocol's groups).
    #[error("resumption psk forbidden")]
    ResumptionPsk,
    /// The roster is neither mid-creation (1) nor steady-state (2).
    #[error("roster is not two-party")]
    NotTwoParty,
    /// An `AppDataUpdate` custom proposal failed validation: more than one, not the
    /// committer's own, a malformed payload, an attested epoch that is not this group's
    /// next, or co-riding an Update on the PQ half (a FULL commit's PQ half is a
    /// pathless PSK-injection commit and never folds one — that shape difference is
    /// what keeps A.5 re-key commits AppDataUpdate-free).
    #[error("invalid AppDataUpdate proposal")]
    BadAppDataUpdate,
}

impl IntoAnyError for RuleError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// The TwoMLS operation whitelist, applied identically to the classical and PQ halves
/// (`OurConfig`/`PqConfig` share it).
#[derive(Clone, Copy, Debug, Default)]
pub struct TwoMlsRules;

impl MlsRules for TwoMlsRules {
    type Error = RuleError;

    fn filter_proposals(
        &self,
        _direction: CommitDirection,
        source: CommitSource,
        roster: &Roster,
        context: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, RuleError> {
        // Only an existing member ever commits.
        let committer = match source {
            CommitSource::ExistingMember(member) => member,
            CommitSource::NewMember(_) => return Err(RuleError::ExternalCommit),
        };

        // Never legitimate, in any phase.
        if !proposals.remove_proposals().is_empty()
            || !proposals.reinit_proposals().is_empty()
            || !proposals.external_init_proposals().is_empty()
            || !proposals.group_context_ext_proposals().is_empty()
        {
            return Err(RuleError::ForbiddenProposal);
        }

        // The one admissible custom proposal is the -02 `AppDataUpdate` epoch attestation
        // (see `component.rs`), committed by the committer itself on a FULL commit's
        // halves. Its same-half epoch must be exactly this group's next epoch (the
        // pre-commit context is in hand here); the cross-half equality is verified in the
        // session layer, which sees both groups. On the PQ half it never co-rides an
        // Update: a FULL commit's PQ half is a pathless PSK-injection commit, and that
        // shape difference is what keeps A.5 re-key commits (Update + PSK, on the PQ
        // groups) AppDataUpdate-free at the rules level. The CLASSICAL half is the
        // opposite — the bind rides a FOLDING round (the discharge), so the peer's
        // Update co-riding there is the norm, not a violation.
        let customs = proposals.custom_proposals();
        if customs.len() > 1 {
            return Err(RuleError::BadAppDataUpdate);
        }
        if let Some(custom) = customs.first() {
            if custom.proposal.proposal_type() != APP_DATA_UPDATE {
                return Err(RuleError::ForbiddenProposal);
            }
            match custom.sender {
                Sender::Member(index) if index == committer.index => {}
                _ => return Err(RuleError::BadAppDataUpdate),
            }
            let is_pq = match crate::client::suite_is_pq(context.cipher_suite) {
                Some(v) => v,
                None => return Err(RuleError::BadAppDataUpdate),
            };
            if is_pq && !proposals.update_proposals().is_empty() {
                return Err(RuleError::BadAppDataUpdate);
            }
            let update = ApqInfoUpdate::from_custom_proposal(&custom.proposal)
                .map_err(|_| RuleError::BadAppDataUpdate)?;
            let attested = if is_pq {
                update.pq_epoch
            } else {
                update.t_epoch
            };
            if attested != context.epoch + 1 {
                return Err(RuleError::BadAppDataUpdate);
            }
        }

        // Every PSK is external (the A.3 injected secret S) or application (the
        // draft-02 apq_psk / Germ cross-party bindings); this protocol never resumes
        // groups. A proposal for which both accessors are `None` is a resumption PSK.
        if proposals.psk_proposals().iter().any(|p| {
            p.proposal.external_psk_id().is_none() && p.proposal.application_psk().is_none()
        }) {
            return Err(RuleError::ResumptionPsk);
        }

        match roster.members_iter().count() {
            // The creation commit: the lone creator adds the single peer. This is how
            // every half is born (`create_group_with_member` — classical groups at
            // establishment, PQ groups at the A.4 bootstrap); external PSKs may ride
            // it (the bound send group's cross-party / APQ PSKs).
            1 => {
                if proposals.add_proposals().len() != 1 || !proposals.update_proposals().is_empty()
                {
                    return Err(RuleError::BadCreation);
                }
            }
            // Steady state: membership is fixed. At most one Update, and only ever
            // the peer's own leaf — an Update applies to its sender's leaf, so
            // requiring a member sender other than the committer pins it to the one
            // other member.
            2 => {
                if !proposals.add_proposals().is_empty() {
                    return Err(RuleError::ForbiddenProposal);
                }
                let updates = proposals.update_proposals();
                if updates.len() > 1 {
                    return Err(RuleError::BadUpdate);
                }
                for update in updates {
                    match update.sender {
                        Sender::Member(index) if index != committer.index => {}
                        _ => return Err(RuleError::BadUpdate),
                    }
                }
            }
            _ => return Err(RuleError::NotTwoParty),
        }

        Ok(proposals)
    }

    fn commit_options(
        &self,
        _roster: &Roster,
        _context: &GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, RuleError> {
        // Defaults are deliberate: RFC 9420 already forces an updatePath on empty
        // commits and on commits covering Update proposals, which is every commit
        // that needs one; `path_required` would bolt a full ML-KEM updatePath onto
        // the A.3 bind's pathless PSK commit and defeat the side-band's cheapness.
        Ok(CommitOptions::default())
    }

    fn encryption_options(
        &self,
        _roster: &Roster,
        _context: &GroupContext,
    ) -> Result<EncryptionOptions, RuleError> {
        Ok(EncryptionOptions::default())
    }
}
