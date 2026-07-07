//! A group-state storage provider whose contents can be serialised, so a `CombinerClient`'s MLS
//! groups survive a process restart. Semantics match mls-rs's in-memory provider (epoch retention
//! of three, insert/update/trim per write); the addition is `to_bytes` / `restore_from_bytes`
//! over the whole map, which session archival seals and persists. The blob is encoded with
//! `mls_rs_codec` (the workspace-standard MLS wire codec), not a bespoke framing.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::GroupStateStorage;
use mls_rs_core::group::{EpochRecord, GroupState};
use zeroize::Zeroizing;

use crate::{CombinerError, Result};

/// Matches mls-rs's `DEFAULT_EPOCH_RETENTION_LIMIT`; a smaller window would drop epoch secrets the
/// protocol still expects to find when decrypting slightly out-of-order messages.
const EPOCH_RETENTION: usize = 3;

#[derive(Clone, Default)]
struct GroupRecord {
    state: Vec<u8>,
    epochs: VecDeque<(u64, Vec<u8>)>,
}

// In its own module because the derive-generated impls reference the std `Result`, which the
// crate-local `Result` alias imported above would shadow.
mod wire {
    use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};

    /// Archived form of one retained epoch (`GroupRecord::epochs` entry).
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct EpochEntry {
        pub(super) id: u64,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) data: Vec<u8>,
    }

    /// Archived form of one `GroupRecord` plus its map key; `Vec<GroupEntry>` is the whole blob.
    #[derive(MlsSize, MlsEncode, MlsDecode)]
    pub(super) struct GroupEntry {
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) id: Vec<u8>,
        #[mls_codec(with = "mls_rs_codec::byte_vec")]
        pub(super) state: Vec<u8>,
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

    /// Serialise the whole map (group states + retained epoch secrets) into a self-describing
    /// MLS-codec blob. The output is plaintext secret material; callers must seal it.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let entries: Vec<GroupEntry> = self
            .lock()
            .iter()
            .map(|(gid, rec)| GroupEntry {
                id: gid.clone(),
                state: rec.state.clone(),
                epochs: rec
                    .epochs
                    .iter()
                    .map(|(id, data)| EpochEntry {
                        id: *id,
                        data: data.clone(),
                    })
                    .collect(),
            })
            .collect();
        entries
            .mls_encode_to_vec()
            .map(Zeroizing::new)
            .map_err(|_| CombinerError::Mls)
    }

    /// Replace this storage's contents with a map decoded from `bytes` (produced by `to_bytes`).
    pub fn restore_from_bytes(&self, bytes: &[u8]) -> Result<()> {
        let mut reader = bytes;
        let entries = Vec::<GroupEntry>::mls_decode(&mut reader).map_err(|_| CombinerError::Mls)?;
        if !reader.is_empty() {
            return Err(CombinerError::Mls);
        }
        let mut map = BTreeMap::new();
        for entry in entries {
            let epochs = entry.epochs.into_iter().map(|e| (e.id, e.data)).collect();
            map.insert(
                entry.id,
                GroupRecord {
                    state: entry.state,
                    epochs,
                },
            );
        }
        *self.lock() = map;
        Ok(())
    }
}

impl GroupStateStorage for PersistableGroupStorage {
    type Error = Infallible;

    fn state(
        &self,
        group_id: &[u8],
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
        Ok(self
            .lock()
            .get(group_id)
            .map(|g| Zeroizing::new(g.state.clone())))
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
                .map(|(_, d)| Zeroizing::new(d.clone()))
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
        rec.state = state.data.to_vec();
        for e in epoch_inserts {
            rec.epochs.push_back((e.id, e.data.to_vec()));
        }
        for e in epoch_updates {
            if let Some(slot) = rec.epochs.iter_mut().find(|(id, _)| *id == e.id) {
                slot.1 = e.data.to_vec();
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
        restored.restore_from_bytes(&s.to_bytes().unwrap()).unwrap();

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

    #[test]
    fn test_restore_rejects_truncated_blob() {
        let s = PersistableGroupStorage::new();
        assert!(s.restore_from_bytes(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn test_restore_rejects_trailing_bytes() {
        let s = PersistableGroupStorage::new();
        let mut blob = s.to_bytes().unwrap().to_vec();
        blob.push(0x00);
        assert!(s.restore_from_bytes(&blob).is_err());
    }
}
