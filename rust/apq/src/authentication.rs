//! The TwoMLS Authentication Service — the credential half of the group rules.
//!
//! Each party's leaf credential evolves along an app-defined sequence. Candidates ride
//! the classical ratchet's Upd proposals (each frame may propose a different one); the
//! peer's app picks the one it plans to commit (the `queue_proposal` callback); and the
//! peer's commit defines the canonical next credential. The party's own send-group
//! leaf, and both PQ leaves, lag the canonical order and catch up — a lagging leaf may
//! fast-forward to any already-canonical element within the history window.
//!
//! This module supplies the mls-rs [`IdentityProvider`] enforcing that model. The
//! provider is baked into each client's config at build time, but a session drives
//! several clients over its life (the invitation-derived client, a dedicated
//! establishment principal, staged rotation candidates, the archive-restored client) —
//! so each client holds a rebindable [`AuthView`] onto one session-canonical
//! [`AuthCore`], the auth analogue of the session's PSK-store tracking.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use mls_rs::error::IntoAnyError;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::{Credential, CredentialType, SigningIdentity};
use mls_rs::time::MlsTime;
use mls_rs::ExtensionList;
use mls_rs::IdentityProvider;
use mls_rs_core::identity::MemberValidationContext;

/// How many canonical credentials per party are retained for the lag/catch-up rule: a
/// lagging leaf (own send group, PQ halves) must catch up within this many canonical
/// steps. Sessions rotate rarely; 8 is ample.
pub const CREDENTIAL_HISTORY_WINDOW: usize = 8;

/// A credential failed the Authentication Service's rules.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Not a basic credential (the only type this protocol uses).
    #[error("unsupported credential type")]
    UnsupportedCredential,
    /// The identity is not in either party's sequence (nor authorized as a successor).
    #[error("identity is not a known member of this session")]
    UnknownIdentity,
    /// The succession is not app-authorized and not a catch-up within the history.
    #[error("credential succession not permitted")]
    InvalidSuccession,
    /// External senders are never used by this protocol.
    #[error("external senders unsupported")]
    ExternalSender,
}

impl IntoAnyError for AuthError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn basic_id(identity: &SigningIdentity) -> Result<&[u8], AuthError> {
    match &identity.credential {
        Credential::Basic(basic) => Ok(&basic.identifier),
        _ => Err(AuthError::UnsupportedCredential),
    }
}

/// A [`PartySequence`] decomposed for archival: `(history, authorized_next, pinned)` as
/// raw id lists.
pub type SequenceParts = (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>);

/// One party's app-defined credential sequence: the canonical history (oldest →
/// newest, trimmed to [`CREDENTIAL_HISTORY_WINDOW`]) plus the app-authorized
/// in-flight successors (several candidates may be proposed; the one the peer
/// commits becomes canonical and the rest expire).
#[derive(Debug, Clone, Default)]
pub struct PartySequence {
    history: VecDeque<Vec<u8>>,
    authorized_next: Vec<Vec<u8>>,
    /// Credentials held ADMISSIBLE (and valid as a successor `pred`) regardless of the
    /// [`CREDENTIAL_HISTORY_WINDOW`] eviction — for a credential that a live leaf still
    /// carries but the rolling window would otherwise drop. The acute case: a deferred
    /// A.4 bootstrap leaf carries the peer's frozen ESTABLISHMENT credential, which
    /// enough peer rotations would evict before that leaf is created / caught up. Pinned
    /// (older than all `history`) at bootstrap create, retired once A.5 rotates the leaf
    /// onto the current credential. Only widens ADMISSION (`known_ids`) and lets an
    /// evicted-but-pinned id serve as a successor `pred`; it never makes a pinned id a
    /// successor TARGET, so it cannot authorize a downgrade.
    pinned: Vec<Vec<u8>>,
}

impl PartySequence {
    pub fn seeded(id: Vec<u8>) -> Self {
        let mut s = Self::default();
        s.commit(id);
        s
    }

    /// The canonical current credential (newest committed element).
    pub fn current(&self) -> Option<&[u8]> {
        self.history.back().map(Vec::as_slice)
    }

    pub fn contains(&self, id: &[u8]) -> bool {
        self.history.iter().any(|h| h == id)
    }

    fn position(&self, id: &[u8]) -> Option<usize> {
        self.history.iter().position(|h| h == id)
    }

    fn is_authorized(&self, id: &[u8]) -> bool {
        self.authorized_next.iter().any(|a| a == id)
    }

    fn is_pinned(&self, id: &[u8]) -> bool {
        self.pinned.iter().any(|p| p == id)
    }

    /// Hold `id` admissible past window eviction (idempotent). See the `pinned` field.
    pub fn pin(&mut self, id: Vec<u8>) {
        if !self.is_pinned(&id) {
            self.pinned.push(id);
        }
    }

    /// Retire a pin once the leaf carrying it has been rotated off it (idempotent).
    pub fn unpin(&mut self, id: &[u8]) {
        self.pinned.retain(|p| p != id);
    }

    /// The currently-pinned credentials (for retirement: a caller drops any no live leaf
    /// still carries).
    pub fn pinned_ids(&self) -> impl Iterator<Item = &[u8]> {
        self.pinned.iter().map(Vec::as_slice)
    }

    /// App-authorize `id` as a permitted next credential (idempotent).
    pub fn authorize(&mut self, id: Vec<u8>) {
        if !self.is_authorized(&id) {
            self.authorized_next.push(id);
        }
    }

    /// Canonicalize `id`: it becomes the sequence's newest element and every other
    /// in-flight authorization expires (the committed one defines the next credential;
    /// stale candidates must be re-authorized against the new canonical state).
    /// Idempotent when `id` is already current.
    pub fn commit(&mut self, id: Vec<u8>) {
        if self.current() == Some(id.as_slice()) {
            return;
        }
        self.authorized_next.clear();
        self.history.retain(|h| h != &id);
        self.history.push_back(id);
        while self.history.len() > CREDENTIAL_HISTORY_WINDOW {
            self.history.pop_front();
        }
    }

    /// May a leaf currently bearing `pred` move to `succ`?
    /// - same id — the routine Upd;
    /// - `pred` known and `succ` app-authorized — the canonical step;
    /// - both known with `succ` newer — a lagging leaf catching up.
    ///
    /// A `pred` that is only PINNED (evicted from `history` but held admissible) counts as
    /// KNOWN and OLDEST — older than every `history` element — so a leaf still bearing an
    /// evicted establishment credential can catch up to any current one. A pinned id is
    /// never a valid `succ` here (it is not in `history` or `authorized_next`), so this
    /// cannot authorize a downgrade back onto the pinned credential.
    pub fn valid_successor(&self, pred: &[u8], succ: &[u8]) -> bool {
        if pred == succ {
            return true;
        }
        let pred_pos = self.position(pred);
        if pred_pos.is_none() && !self.is_pinned(pred) {
            return false;
        }
        if self.is_authorized(succ) {
            return true;
        }
        // `succ` must be newer than `pred`. A pinned-but-evicted `pred` is oldest, so any
        // `history` `succ` is newer than it.
        match (pred_pos, self.position(succ)) {
            (_, None) => false,
            (Some(pp), Some(sp)) => sp > pp,
            (None, Some(_)) => true, // pred pinned+evicted (oldest) < any history succ
        }
    }

    pub fn known_ids(&self) -> impl Iterator<Item = &[u8]> {
        self.history
            .iter()
            .chain(self.authorized_next.iter())
            .chain(self.pinned.iter())
            .map(Vec::as_slice)
    }

    /// (history, authorized_next, pinned) as raw id lists, for session archival.
    pub fn to_parts(&self) -> SequenceParts {
        (
            self.history.iter().cloned().collect(),
            self.authorized_next.clone(),
            self.pinned.clone(),
        )
    }

    pub fn from_parts(
        history: Vec<Vec<u8>>,
        authorized_next: Vec<Vec<u8>>,
        pinned: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            history: history.into(),
            authorized_next,
            pinned,
        }
    }
}

/// The session-canonical AS state: both parties' sequences, plus the one-shot
/// adoption window a session opens strictly around a welcome join whose creator
/// principal it cannot know in advance (the peer's dedicated establishment principal —
/// authenticity rides the cross-party PSK bound into that welcome).
#[derive(Debug, Default)]
pub struct AuthCore {
    pub mine: PartySequence,
    pub theirs: PartySequence,
    pub adopting: bool,
}

impl AuthCore {
    fn knows(&self, id: &[u8]) -> bool {
        self.mine.known_ids().any(|k| k == id) || self.theirs.known_ids().any(|k| k == id)
    }

    fn valid_successor(&self, pred: &[u8], succ: &[u8]) -> bool {
        pred == succ
            || self.mine.valid_successor(pred, succ)
            || self.theirs.valid_successor(pred, succ)
    }
}

pub type AuthCoreHandle = Arc<Mutex<AuthCore>>;

/// A client's rebindable view of an [`AuthCore`]. Every mls-rs client one session
/// drives must resolve to the session's single canonical core; [`AuthView::rebind`]
/// points an adopted client's view there.
#[derive(Debug, Clone)]
pub struct AuthView(Arc<Mutex<AuthCoreHandle>>);

impl AuthView {
    /// A fresh core knowing only the client's own identity — the state of a principal
    /// not (yet) attached to any session.
    pub fn seeded(own_id: &[u8]) -> Self {
        let core = AuthCore {
            mine: PartySequence::seeded(own_id.to_vec()),
            ..AuthCore::default()
        };
        Self(Arc::new(Mutex::new(Arc::new(Mutex::new(core)))))
    }

    /// The core this view currently resolves to.
    pub fn core(&self) -> AuthCoreHandle {
        Arc::clone(&self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Point this view at another (session-canonical) core.
    pub fn rebind(&self, canonical: &AuthCoreHandle) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Arc::clone(canonical);
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut AuthCore) -> R) -> R {
        let core = self.core();
        let mut guard = core.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }
}

/// The mls-rs [`IdentityProvider`] enforcing the TwoMLS AS. Both halves of a
/// [`CombinerClient`](crate::CombinerClient) share one view: the AS is
/// credential-level and suite-agnostic, and the PQ-lag rule falls out of the
/// sequence model.
#[derive(Debug, Clone)]
pub struct TwoMlsIdentityProvider {
    view: AuthView,
}

impl TwoMlsIdentityProvider {
    pub fn new(view: AuthView) -> Self {
        Self { view }
    }
}

impl IdentityProvider for TwoMlsIdentityProvider {
    type Error = AuthError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), AuthError> {
        let id = basic_id(signing_identity)?;
        self.view.with(|core| {
            if core.adopting || core.knows(id) {
                Ok(())
            } else {
                Err(AuthError::UnknownIdentity)
            }
        })
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), AuthError> {
        Err(AuthError::ExternalSender)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, AuthError> {
        basic_id(signing_identity).map(<[u8]>::to_vec)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, AuthError> {
        let pred = basic_id(predecessor)?;
        let succ = basic_id(successor)?;
        self.view.with(|core| Ok(core.valid_successor(pred, succ)))
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![BasicCredential::credential_type()]
    }
}
