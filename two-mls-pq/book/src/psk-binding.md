# PSK Binding

The two halves of a Combiner group — and the two parties' groups — are tied together
by a PSK chain. This is what makes the construction hybrid: an attacker must break the
classical half *and* the ML-KEM-768 half to break a session.

## The chain

```
Group_A.classical epoch N
  → exportSecret(label="exportSecret", context="derive", len=32)
  → ExternalPsk ID = LE-u64(epoch) || group_id bytes
  → injected into Group_A.pq + Group_B.classical + Group_B.pq
```

Both parties are members of Group_A, so both can independently derive the same PSK.
Derivation only works at the group's *current* epoch, though — a frame that crossed
one of the deriver's own commits references an epoch mls-rs can no longer export. The
session therefore keeps a small **PSK ledger** of its send group's recent epochs
(derived when each epoch is entered, retained across a window of commits) and
live-injects it into the resolving stores immediately before processing a bound
Welcome or commit; entries falling out of the window are deleted from the stores.
See the [Concepts](./concepts.md) object-model notes.

## Refresh

On a full commit, the send group advances to epoch `N+1`, a fresh PSK is exported from
that epoch and injected into the receive group. This re-binds the two groups to the new
epoch and provides break-in recovery.

## Invariants — never change

These values are protocol-specified; changing any of them silently breaks
interoperability:

- `export_secret` label: `b"exportSecret"`
- `export_secret` context: `b"derive"`
- output length: `32`
- PSK ID encoding: `epoch.to_le_bytes() || group_id_bytes`
