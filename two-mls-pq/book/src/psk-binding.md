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

Both parties are members of Group_A, so both can independently re-derive the same PSK
and register it before processing the bound Welcome or commit.

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
