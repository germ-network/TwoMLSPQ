# PSK Binding

Two distinct PSK chains tie the construction together. The **APQ-PSK** binds the two
halves of one APQ group — this is what makes a send group hybrid: an attacker
must break the classical half *and* the ML-KEM-768 half to break a session. The
**cross-party TwoMLS-PSK** ties one party's send group to the group it receives on, so
the two directions of a session share fate.

## The APQ-PSK (hybrid binding, PQ → classical)

Each APQ group is created PQ half first; the classical half then absorbs the PQ
half's secrecy at birth:

```
Group_A.pq epoch N
  → exportSecret(label="exportSecret", context="derive", len=32)
  → ExternalPsk ID = LE-u64(epoch) || group_id bytes
  → injected into Group_A.classical's creation commit
```

Both parties are members of Group_A.pq, so the joiner independently re-derives the
same PSK: it joins the PQ half first, registers the APQ-PSK, then joins the classical
half whose Welcome demands it.

## The cross-party TwoMLS-PSK (receive → send)

The acceptor's send group is bound to the group it receives on:

```
Group_A.classical (the acceptor's receive group) at its current epoch
  → exportSecret(label="exportSecret", context="derive", len=32)
  → injected into Group_B.classical's creation commit
```

Derivation only works at the group's *current* epoch, though — a frame that crossed
one of the deriver's own commits references an epoch mls-rs can no longer export. The
session therefore keeps a small **PSK ledger** of its send group's recent epochs
(derived when each epoch is entered, retained across a window of commits) and
live-injects it into the resolving stores immediately before processing a bound
Welcome or commit; entries falling out of the window are deleted from the stores.
See the [Concepts](./concepts.md) object-model notes.

## Refresh

On a full commit — one that consumes the peer's approved Upd proposal — the committer
re-exports the cross-party PSK from its **receive** group's classical half at the
current epoch and injects it into its own send-group commit, re-binding the two
directions and providing break-in recovery.

The PQ half's secrecy refreshes on the PQ ratchet: fresh ML-KEM
entropy is injected into the send group's PQ half as a per-round PSK, and the
re-exported APQ-PSK is bound into the classical half's commit in the same round.

The PQ re-key adds a third, PQ-to-PQ chain: each of its two
`Commit'`s cross-injects a PSK exported from the PQ half of the **opposite** send
group (same
exporter invariants, same exported-ID encoding), tying the two directions' PQ halves
to each other while their updatePaths rotate the leaves.

## Invariants — never change

These values are protocol-specified; changing any of them silently breaks
interoperability:

- `export_secret` label: `b"exportSecret"`
- `export_secret` context: `b"derive"`
- output length: `32`
- exported PSK ID encoding (APQ-PSK and cross-party PSK):
  `epoch.to_le_bytes() || group_id_bytes`
- injected-secret PSK ID (the PQ ratchet's per-round entropy): the exported encoding
  plus a trailing domain byte `0x52`, keeping the two ID spaces disjoint
