//! A group-state storage provider whose records can be exported and re-imported one group at a
//! time, so MLS groups survive a process restart. Semantics match mls-rs's in-memory provider
//! (epoch retention of three, insert/update/trim per write); the addition is
//! `export_group` / `import_group`, which session archival pulls per group — the session
//! enumerates the groups it owns rather than snapshotting any client's whole store (see the
//! book's object-model notes). Blobs are encoded with `mls_rs_codec` (the workspace-standard
//! MLS wire codec), not a bespoke framing.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs::GroupStateStorage;
use mls_rs_core::group::{EpochRecord, GroupState};
use zeroize::Zeroizing;

use crate::{CombinerError, Result};

/// Matches mls-rs's `DEFAULT_EPOCH_RETENTION_LIMIT` (which is private, so it cannot be
/// referenced); `test_retention_matches_mls_rs_in_memory_provider` pins the two together, so a
/// fork-side change fails a test here instead of silently diverging. A smaller window would drop
/// epoch secrets the protocol still expects to find when decrypting slightly out-of-order
/// messages.
const EPOCH_RETENTION: usize = 3;

/// Format tag for the `export_group` blob, so the layout can evolve (or grow a migration path)
/// without old archives decoding as garbage. Bump on any change to the wire structs.
const STORAGE_FORMAT_VERSION: u8 = 1;

// Secrets are held zeroized (like mls-rs's own `InMemoryGroupData`) so state overwrites, epoch
// updates, retention trims, and restore's map replacement all wipe the buffers they discard.
#[derive(Clone, Default)]
struct GroupRecord {
    state: Zeroizing<Vec<u8>>,
    epochs: VecDeque<(u64, Zeroizing<Vec<u8>>)>,
}

// In its own module because the derive-generated impls reference the std `Result`, which the
// crate-local `Result` alias imported above would shadow.
mod wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};
    use zeroize::Zeroizing;

    /// Archived form of one retained epoch (`GroupRecord::epochs` entry). Secret bytes stay
    /// `Zeroizing` even in this transient form so dropped snapshots are wiped.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct EpochEntry {
        pub(super) id: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) data: Zeroizing<Vec<u8>>,
    }

    /// Archived form of one `GroupRecord` plus its map key; `Vec<GroupEntry>` is the whole blob.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct GroupEntry {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) state: Zeroizing<Vec<u8>>,
        pub(super) epochs: Vec<EpochEntry>,
    }
}

use wire::{EpochEntry, GroupEntry};

/// In-memory group-state storage backed by a shared map. Clones share the same underlying map (the
/// `Arc`), matching mls-rs's `InMemoryGroupStateStorage`, so a clone handed to a client and a clone
/// kept by `CombinerClient` see the same writes.
#[derive(Clone, Default)]
pub struct PersistableGroupStorage {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, GroupRecord>>>,
}

impl PersistableGroupStorage {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<Vec<u8>, GroupRecord>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Serialise one group's record (state + retained epoch secrets) into a self-describing,
    /// versioned MLS-codec blob. The output is plaintext secret material; callers must seal it.
    /// Callers typically `write_to_storage()` on the live group first so the record is current.
    pub fn export_group(&self, group_id: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let entry = {
            let map = self.lock();
            let rec = map.get(group_id).ok_or(CombinerError::ArchiveInvalid)?;
            GroupEntry {
                id: group_id.to_vec(),
                state: rec.state.clone(),
                epochs: rec
                    .epochs
                    .iter()
                    .map(|(id, data)| EpochEntry {
                        id: *id,
                        data: data.clone(),
                    })
                    .collect(),
            }
        };
        // Exact-size preallocation: a growing Vec would strand unwiped partial copies of the
        // secrets in freed allocations, out of reach of the final `Zeroizing` wrapper.
        let mut out = Zeroizing::new(Vec::with_capacity(1 + entry.mls_encoded_len()));
        out.push(STORAGE_FORMAT_VERSION);
        entry
            .mls_encode(&mut out)
            .map_err(|_| CombinerError::ArchiveInvalid)?;
        Ok(out)
    }

    /// Insert one group record decoded from `bytes` (produced by [`export_group`]), returning
    /// the group id so the caller can `load_group` it. Rejects blobs that violate the
    /// invariants `write` maintains — strictly ascending epoch ids and at most
    /// [`EPOCH_RETENTION`] of them — since `max_epoch_id` relies on them.
    pub fn import_group(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let (&version, mut reader) = bytes.split_first().ok_or(CombinerError::ArchiveInvalid)?;
        if version != STORAGE_FORMAT_VERSION {
            return Err(CombinerError::ArchiveInvalid);
        }
        let entry =
            GroupEntry::mls_decode(&mut reader).map_err(|_| CombinerError::ArchiveInvalid)?;
        if !reader.is_empty() {
            return Err(CombinerError::ArchiveInvalid);
        }
        let ascending = entry.epochs.windows(2).all(|w| w[0].id < w[1].id);
        if !ascending || entry.epochs.len() > EPOCH_RETENTION {
            return Err(CombinerError::ArchiveInvalid);
        }
        let group_id = entry.id.clone();
        let epochs = entry.epochs.into_iter().map(|e| (e.id, e.data)).collect();
        self.lock().insert(
            entry.id,
            GroupRecord {
                state: entry.state,
                epochs,
            },
        );
        Ok(group_id)
    }
}

impl GroupStateStorage for PersistableGroupStorage {
    type Error = Infallible;

    fn state(
        &self,
        group_id: &[u8],
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
        Ok(self.lock().get(group_id).map(|g| g.state.clone()))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
        Ok(self.lock().get(group_id).and_then(|g| {
            g.epochs
                .iter()
                .find(|(id, _)| *id == epoch_id)
                .map(|(_, d)| d.clone())
        }))
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> std::result::Result<(), Infallible> {
        let mut map = self.lock();
        let rec = map.entry(state.id).or_default();
        rec.state = state.data;
        for e in epoch_inserts {
            rec.epochs.push_back((e.id, e.data));
        }
        for e in epoch_updates {
            if let Some(slot) = rec.epochs.iter_mut().find(|(id, _)| *id == e.id) {
                slot.1 = e.data;
            }
        }
        while rec.epochs.len() > EPOCH_RETENTION {
            rec.epochs.pop_front();
        }
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> std::result::Result<Option<u64>, Infallible> {
        Ok(self
            .lock()
            .get(group_id)
            .and_then(|g| g.epochs.back().map(|(id, _)| *id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_round_trips_state_and_epochs() {
        let mut s = PersistableGroupStorage::new();
        s.write(
            GroupState {
                id: b"g1".to_vec(),
                data: Zeroizing::new(b"state-bytes".to_vec()),
            },
            vec![EpochRecord::new(0, Zeroizing::new(b"epoch0".to_vec()))],
            vec![],
        )
        .unwrap();

        let restored = PersistableGroupStorage::new();
        let gid = restored
            .import_group(&s.export_group(b"g1").unwrap())
            .unwrap();
        assert_eq!(gid, b"g1".to_vec());

        assert_eq!(
            restored.state(b"g1").unwrap().map(|z| z.to_vec()),
            Some(b"state-bytes".to_vec())
        );
        assert_eq!(
            restored.epoch(b"g1", 0).unwrap().map(|z| z.to_vec()),
            Some(b"epoch0".to_vec())
        );
        assert_eq!(restored.max_epoch_id(b"g1").unwrap(), Some(0));
    }

    #[test]
    fn test_export_unknown_group_fails() {
        let s = PersistableGroupStorage::new();
        assert!(s.export_group(b"nope").is_err());
    }

    #[test]
    fn test_storage_trims_to_retention_limit() {
        let mut s = PersistableGroupStorage::new();
        for e in 0..(EPOCH_RETENTION as u64 + 2) {
            s.write(
                GroupState {
                    id: b"g".to_vec(),
                    data: Zeroizing::new(vec![e as u8]),
                },
                vec![EpochRecord::new(e, Zeroizing::new(vec![e as u8]))],
                vec![],
            )
            .unwrap();
        }
        // The oldest epochs are dropped; only the last EPOCH_RETENTION survive.
        assert!(s.epoch(b"g", 0).unwrap().is_none());
        assert!(s.epoch(b"g", EPOCH_RETENTION as u64 + 1).unwrap().is_some());
    }

    /// A valid single-group blob for tamper tests.
    fn sample_blob() -> Vec<u8> {
        let mut s = PersistableGroupStorage::new();
        s.write(
            GroupState {
                id: b"g".to_vec(),
                data: Zeroizing::new(vec![1]),
            },
            vec![EpochRecord::new(0, Zeroizing::new(vec![2]))],
            vec![],
        )
        .unwrap();
        s.export_group(b"g").unwrap().to_vec()
    }

    #[test]
    fn test_import_rejects_truncated_blob() {
        let s = PersistableGroupStorage::new();
        assert!(s.import_group(&[STORAGE_FORMAT_VERSION, 0xFF]).is_err());
        let blob = sample_blob();
        assert!(s.import_group(&blob[..blob.len() - 1]).is_err());
    }

    #[test]
    fn test_import_rejects_trailing_bytes() {
        let s = PersistableGroupStorage::new();
        let mut blob = sample_blob();
        blob.push(0x00);
        assert!(s.import_group(&blob).is_err());
    }

    #[test]
    fn test_import_rejects_wrong_version() {
        let s = PersistableGroupStorage::new();
        let mut blob = sample_blob();
        blob[0] = STORAGE_FORMAT_VERSION + 1;
        assert!(s.import_group(&blob).is_err());
        assert!(s.import_group(&[]).is_err());
    }

    /// `max_epoch_id` returns the back of the deque, which is the maximum only while epoch ids
    /// ascend; a blob violating that (or exceeding the retention bound) must not import.
    #[test]
    fn test_import_rejects_invariant_violating_epochs() {
        // `write` can't produce these, so build the malformed payloads at the wire layer.
        let encode = |ids: &[u64]| {
            let entry = GroupEntry {
                id: b"g".to_vec(),
                state: Zeroizing::new(vec![1]),
                epochs: ids
                    .iter()
                    .map(|&id| EpochEntry {
                        id,
                        data: Zeroizing::new(vec![2]),
                    })
                    .collect(),
            };
            let mut out = vec![STORAGE_FORMAT_VERSION];
            entry.mls_encode(&mut out).unwrap();
            out
        };
        let s = PersistableGroupStorage::new();
        // Baseline: an in-order blob imports.
        assert!(s.import_group(&encode(&[0, 1, 2])).is_ok());
        assert!(s.import_group(&encode(&[2, 1])).is_err());
        assert!(s.import_group(&encode(&[1, 1])).is_err());
        assert!(s.import_group(&encode(&[1, 2, 3, 4])).is_err());
    }

    /// Pins `EPOCH_RETENTION` (and the trim behaviour) to mls-rs's in-memory provider at the
    /// pinned fork rev: if the fork changes its private `DEFAULT_EPOCH_RETENTION_LIMIT`, this
    /// fails here instead of restored sessions silently retaining a different epoch window
    /// than live ones.
    #[test]
    fn test_retention_matches_mls_rs_in_memory_provider() {
        use mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage;

        let mut ours = PersistableGroupStorage::new();
        let mut theirs = InMemoryGroupStateStorage::new();
        for e in 0..10u64 {
            let state = || GroupState {
                id: b"g".to_vec(),
                data: Zeroizing::new(vec![e as u8]),
            };
            let inserts = || vec![EpochRecord::new(e, Zeroizing::new(vec![e as u8]))];
            ours.write(state(), inserts(), vec![]).unwrap();
            theirs.write(state(), inserts(), vec![]).unwrap();
        }
        for e in 0..10u64 {
            assert_eq!(
                ours.epoch(b"g", e).unwrap().map(|z| z.to_vec()),
                theirs.epoch(b"g", e).unwrap().map(|z| z.to_vec()),
                "epoch {e} retention diverges from mls-rs's provider"
            );
        }
        assert_eq!(
            ours.max_epoch_id(b"g").unwrap(),
            theirs.max_epoch_id(b"g").unwrap()
        );
    }
}
