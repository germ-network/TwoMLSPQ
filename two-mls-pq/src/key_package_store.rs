//! Synthetic key-package storage for the combiner, ported from the classical MultiMLS
//! `ManagedKeyPackageStore` (Swift), plus the concrete instantiation of the generic `apq`
//! combiner over it. It plays two roles behind one type:
//!
//!   * **capture** (client side): a `CombinerClient`'s default (empty) store; mls-rs stashes
//!     the private `KeyPackageData` whenever it generates a key package. Wrapping the generate
//!     call in `capture()` (`start_capture` / `stop_capture`, the "divert") hands back
//!     exactly the key package(s) produced, so the private material can be moved into an
//!     Invitation instead of lingering in the client, which then `purge_all`s.
//!   * **serve** (invitation side, via `for_invitation`): built `preloaded` with a fixed
//!     set of key packages so mls-rs can `get` them back when joining a welcome.
//!
//! All clones share the same backing state (interior mutability), so a handle retained by
//! `CombinerClient` observes the entries mls-rs inserts through its own clone.
//!
//! # Design: one unified type, not two
//!
//! The client (capture) and invitation (serve) roles are behaviourally distinct, so a
//! `CaptureKeyPackageStore` + `FixedKeyPackageStore` split is tempting. We deliberately use
//! ONE type: the roles differ only in how the same map is populated and drained, not in the
//! `KeyPackageStorage` contract. Two types would pin `TwoMlsPqIdentity` and
//! `TwoMlsPqInvitation` to two *different* `apq::CombinerClient<S>` instantiations,
//! complicating the shared session/group plumbing for no behavioural gain. The Swift
//! reference (`ManagedKeyPackageStore`) is likewise a single class (one `storage` dict + a
//! `divert` mode), and the "client stores nothing" invariant is enforced by `purge_all`
//! after capture, not by a second type (which would retain just as much).

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use mls_rs::storage_provider::KeyPackageData;
use mls_rs::KeyPackageStorage;

/// A captured (storage id, private key package) pair.
pub(crate) type KeyPackageSecret = (Vec<u8>, KeyPackageData);

use crate::providers::{Classical, Pq};

/// The generic `apq` combiner specialised to the synthetic (capture/serve) store and the
/// build's pinned crypto providers (see `crate::providers`).
pub(crate) type CombinerClient = apq::CombinerClient<SyntheticKeyPackageStore, Classical, Pq>;
pub(crate) type CombinerGroup = apq::CombinerGroup<SyntheticKeyPackageStore, Classical, Pq>;
pub(crate) type MlsClient = apq::MlsClient<SyntheticKeyPackageStore, Classical>;
pub(crate) type MlsGroup = apq::MlsGroup<SyntheticKeyPackageStore, Classical>;
pub(crate) type PqMlsClient = apq::PqMlsClient<SyntheticKeyPackageStore, Pq>;

#[derive(Clone, Default)]
pub struct SyntheticKeyPackageStore {
    entries: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
    // `Some` while a capture is in progress; inserts are recorded here as well as stored,
    // so the caller can pull out exactly what a single generate call produced.
    capture: Arc<Mutex<Option<Vec<KeyPackageSecret>>>>,
    // When true, `delete` is a no-op: this store serves a *last-resort* invitation, so
    // mls-rs's automatic post-join key-package delete must not remove the single key package
    // it holds (the KP has to remain available to service further welcomes). Set once at
    // construction and never mutated, so a plain bool is fine across the Arc-shared clones.
    // Because an invitation serves exactly one key package, this is a single flag rather than
    // a per-id map. Defaults false (capture/identity-restore stores honor mls-rs's delete).
    last_resort: bool,
}

impl SyntheticKeyPackageStore {
    /// A store preloaded with a fixed set of key packages (an Invitation's KP(s)), honoring
    /// mls-rs's delete (single-use). Use [`for_invitation`](Self::for_invitation) to opt a
    /// last-resort invitation's store out of that delete.
    pub fn preloaded(entries: impl IntoIterator<Item = KeyPackageSecret>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(entries.into_iter().collect())),
            capture: Arc::new(Mutex::new(None)),
            last_resort: false,
        }
    }

    /// The **invitation** role: a store fixed to the invitation's own key package, which
    /// mls-rs `get`s when joining a welcome. When `last_resort` is set the store ignores
    /// mls-rs's post-join `delete`, so the key package survives to service further welcomes;
    /// otherwise the delete is honored (the classic single-use key package).
    pub fn for_invitation(
        entries: impl IntoIterator<Item = KeyPackageSecret>,
        last_resort: bool,
    ) -> Self {
        Self {
            last_resort,
            ..Self::preloaded(entries)
        }
    }

    /// Begin recording inserts. Pairs with [`stop_capture`](Self::stop_capture). Note the
    /// port records on `insert` only (the Swift original also captured on `get`); that is
    /// sufficient here because invitation generation is always generate ⇒ insert.
    pub fn start_capture(&self) {
        *self.capture.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
    }

    /// Stop recording and return the key package(s) inserted since `start_capture`.
    pub fn stop_capture(&self) -> Vec<KeyPackageSecret> {
        self.capture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .unwrap_or_default()
    }

    /// Run `f` (a key-package generation) while capturing, returning its result alongside
    /// exactly the key package(s) mls-rs inserted during the call.
    pub fn capture<T>(&self, f: impl FnOnce() -> T) -> (T, Vec<KeyPackageSecret>) {
        self.start_capture();
        let out = f();
        (out, self.stop_capture())
    }

    /// Drop all stored key packages. Used on the client after captured material has been
    /// moved into an Invitation, so the client retains no key-package private data.
    pub fn purge_all(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Snapshot every stored key package as `(storage id, KeyPackageData)`, sorted by id for
    /// a deterministic byte order. Used by session archival to carry the client's retained
    /// key-package private material (e.g. an initiator's return-group key package, minted but
    /// not yet consumed by the peer's return welcome) across a self-contained restore.
    pub fn all_entries(&self) -> Vec<KeyPackageSecret> {
        let mut entries: Vec<KeyPackageSecret> = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(id, pkg)| (id.clone(), pkg.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    fn do_insert(&self, id: Vec<u8>, pkg: KeyPackageData) {
        if let Some(captured) = self
            .capture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            captured.push((id.clone(), pkg.clone()));
        }
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, pkg);
    }

    fn do_get(&self, id: &[u8]) -> Option<KeyPackageData> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    fn do_delete(&self, id: &[u8]) {
        // A last-resort invitation's store retains its single key package across joins:
        // ignore mls-rs's automatic post-join delete so the KP can service further welcomes.
        // Single-use lifetime is enforced one level up (the invitation drops its captured
        // key-package material after the first accept); see `two-mls-pq/src/key_packages.rs`.
        if self.last_resort {
            return;
        }
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
}

// mls-rs is built in sync mode here (`mls_build_async` off), so the `KeyPackageStorage`
// trait methods are synchronous.
impl KeyPackageStorage for SyntheticKeyPackageStore {
    type Error = Infallible;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.do_delete(id);
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        self.do_insert(id, pkg);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        Ok(self.do_get(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dummy key package with distinct secret-key bytes so `get` can confirm identity.
    fn dummy(id: &[u8]) -> KeyPackageSecret {
        let pkg = KeyPackageData::new(id.to_vec(), vec![0xAA; 32].into(), vec![0xBB; 32].into(), 0);
        (id.to_vec(), pkg)
    }

    #[test]
    fn single_use_store_honors_mls_rs_delete() {
        let id = b"kp".to_vec();
        let mut store = SyntheticKeyPackageStore::for_invitation([dummy(&id)], false);
        assert!(store.get(&id).unwrap().is_some());
        // mls-rs deletes a used key package after a successful join.
        store.delete(&id).unwrap();
        assert!(
            store.get(&id).unwrap().is_none(),
            "a single-use invitation store must drop the used key package"
        );
    }

    #[test]
    fn last_resort_store_ignores_mls_rs_delete() {
        let id = b"kp".to_vec();
        let mut store = SyntheticKeyPackageStore::for_invitation([dummy(&id)], true);
        assert!(store.get(&id).unwrap().is_some());
        // The same automatic delete must be a no-op for a last-resort store, so the key
        // package stays available to service further welcomes.
        store.delete(&id).unwrap();
        assert!(
            store.get(&id).unwrap().is_some(),
            "a last-resort invitation store must retain its key package across joins"
        );
    }
}
