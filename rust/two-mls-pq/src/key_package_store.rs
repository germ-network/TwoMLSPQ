//! Synthetic key-package storage for the combiner, ported from the classical MultiMLS
//! `ManagedKeyPackageStore` (Swift), plus the concrete instantiation of the generic `apq`
//! combiner over it. It plays two roles behind one type:
//!
//!   * **capture** (client side): a `CombinerClient`'s default (empty) store; mls-rs stashes
//!     the private `KeyPackageData` whenever it generates a key package. Wrapping the generate
//!     call in `capture()` (`start_capture` / `stop_capture`, the "divert") hands back
//!     exactly the key package(s) produced, so the private material can be moved into an
//!     Invitation instead of lingering in the client, which then `purge_all`s.
//!   * **serve** (invitation side, via `for_invitation`): built `preloaded` with the
//!     invitation's key package purely so mls-rs can `get` it while joining a welcome. It is
//!     only that serving interface — but note the store is NOT what clears the key package
//!     afterwards: mls-rs's post-join `delete` is deferred (it fires on the group's next
//!     `write_to_storage`, after `accept` has already returned), so `accept` explicitly
//!     `purge_all`s the acceptor's stores once the join is done. That purge is what keeps the
//!     invitation's key package from lingering in (or migrating into the archive of) the
//!     session client — do not mistake the store's own `delete` handling for making it
//!     redundant. Key-package lifetime (single-use vs last-resort reuse) lives on the
//!     invitation, which retains its own captured material and rebuilds a fresh serving store
//!     on each `receive`.
//!
//! All clones share the same backing state (interior mutability), so a handle retained by
//! `CombinerClient` observes the entries mls-rs inserts through its own clone.
//!
//! # Design: one unified type, not two
//!
//! The client (capture) and invitation (serve) roles are behaviourally distinct, so a
//! `CaptureKeyPackageStore` + `FixedKeyPackageStore` split is tempting. We deliberately use
//! ONE type: the roles differ only in how the same map is populated and drained, not in the
//! `KeyPackageStorage` contract. Two types would pin `TwoMlsPqPrincipal` and
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
pub(crate) type PqMlsGroup = apq::PqMlsGroup<SyntheticKeyPackageStore, Pq>;
pub(crate) type PqMlsClient = apq::PqMlsClient<SyntheticKeyPackageStore, Pq>;

#[derive(Clone, Default)]
pub struct SyntheticKeyPackageStore {
    entries: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
    // `Some` while a capture is in progress; inserts are recorded here as well as stored,
    // so the caller can pull out exactly what a single generate call produced.
    capture: Arc<Mutex<Option<Vec<KeyPackageSecret>>>>,
}

impl SyntheticKeyPackageStore {
    /// A store preloaded with a fixed set of key packages (an Invitation's KP(s)).
    pub fn preloaded(entries: impl IntoIterator<Item = KeyPackageSecret>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(entries.into_iter().collect())),
            capture: Arc::new(Mutex::new(None)),
        }
    }

    /// The **invitation** role: a store fixed to the invitation's own key package, which
    /// mls-rs `get`s while joining a welcome and `delete`s once it has consumed it. It is a
    /// serving interface, nothing more — the invitation, not this store, owns key-package
    /// lifetime (see `two-mls-pq/src/key_packages.rs`).
    pub fn for_invitation(entries: impl IntoIterator<Item = KeyPackageSecret>) -> Self {
        Self::preloaded(entries)
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

    /// Insert one key package's private material — the SESSION-owned custody path (the
    /// pre-committed A.3 bootstrap KP secret is injected just-in-time before the
    /// Welcome' join, mirroring how `inject_send_psks` fills the PSK stores).
    pub(crate) fn insert_entry(&self, secret: KeyPackageSecret) {
        self.do_insert(secret.0, secret.1);
    }

    /// Remove one key package's private material by storage id — the counterpart of
    /// [`insert_entry`](Self::insert_entry): the just-in-time injection is cleaned up as
    /// soon as the join has consumed it (and a generate whose secret moves into session
    /// custody is removed here so it is not double-homed in the client archive).
    pub(crate) fn remove_entry(&self, id: &[u8]) {
        self.do_delete(id);
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
    fn serving_store_honors_mls_rs_delete() {
        let id = b"kp".to_vec();
        let mut store = SyntheticKeyPackageStore::for_invitation([dummy(&id)]);
        assert!(store.get(&id).unwrap().is_some());
        // The store is a serving interface: mls-rs deletes a key package once it has joined
        // with it, and the store honors that so nothing lingers to migrate into the session.
        store.delete(&id).unwrap();
        assert!(
            store.get(&id).unwrap().is_none(),
            "the serving store must drop a key package mls-rs has consumed"
        );
    }
}
