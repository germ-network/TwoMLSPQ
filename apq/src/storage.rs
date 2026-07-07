//! A group-state storage provider whose contents can be serialised, so a `CombinerClient`'s MLS
//! groups survive a process restart. Semantics match mls-rs's in-memory provider (epoch retention
//! of three, insert/update/trim per write); the addition is `to_bytes` / `from_bytes` over the
//! whole map, which session archival seals and persists.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};

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
    /// length-prefixed blob. The output is plaintext secret material; callers must seal it.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let map = self.lock();
        let mut out = Vec::new();
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (gid, rec) in map.iter() {
            put(&mut out, gid);
            put(&mut out, &rec.state);
            out.extend_from_slice(&(rec.epochs.len() as u32).to_le_bytes());
            for (id, data) in &rec.epochs {
                out.extend_from_slice(&id.to_le_bytes());
                put(&mut out, data);
            }
        }
        Zeroizing::new(out)
    }

    /// Replace this storage's contents with a map decoded from `bytes` (produced by `to_bytes`).
    pub fn restore_from_bytes(&self, bytes: &[u8]) -> Result<()> {
        let mut cur = Cursor::new(bytes);
        let groups = cur.u32()?;
        let mut map = BTreeMap::new();
        for _ in 0..groups {
            let gid = cur.bytes()?.to_vec();
            let state = cur.bytes()?.to_vec();
            let epoch_count = cur.u32()?;
            let mut epochs = VecDeque::new();
            for _ in 0..epoch_count {
                let id = cur.u64()?;
                let data = cur.bytes()?.to_vec();
                epochs.push_back((id, data));
            }
            map.insert(gid, GroupRecord { state, epochs });
        }
        cur.expect_end()?;
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

fn put(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.rest.len() < n {
            return Err(CombinerError::Mls);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn expect_end(&self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(CombinerError::Mls)
        }
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
        restored.restore_from_bytes(&s.to_bytes()).unwrap();

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
        let mut blob = s.to_bytes().to_vec();
        blob.push(0x00);
        assert!(s.restore_from_bytes(&blob).is_err());
    }
}
