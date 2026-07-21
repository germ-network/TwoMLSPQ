# PSK Binding

Three PSK chains tie the construction together. The **APQ-PSK** binds the two halves
of one APQ group — this is what makes a send group hybrid: an attacker must break the
classical half *and* the ML-KEM-768 half to break a session. The **cross-party
TwoMLS-PSK** ties one party's send group to the group it receives on, so the two
directions of a session share fate. The **injected-secret PSK** carries the per-round
ML-KEM entropy of the A.4 ratchet.

The first two follow `draft-ietf-mls-combiner-02` §6.2 exactly: they are derived with
the **Safe Extensions** recipe of `draft-ietf-mls-extensions-08` §4.4 and imported as
`psk_type = application(3)` PSKs. The injected-secret PSK is Germ's own extension and
stays an `external(1)` PSK — it is externally-sourced KEM entropy, not a draft-02
`apq_psk`.

## The conformant recipe (Safe Extensions)

Both the APQ-PSK and the cross-party PSK are derived, on a given group at a given
epoch, from a leaf of that epoch's **Exporter Tree** — a 2^16-leaf tree rooted at
`application_export_secret = DeriveSecret(epoch_secret, "application_export")`, indexed
by a `ComponentID`:

```
apq_exporter = SafeExportSecret(component_id)        # one leaf of the epoch's Exporter Tree
apq_psk_id   = DeriveSecret(apq_exporter, "psk_id")
apq_psk      = DeriveSecret(apq_exporter, "psk")
# the leaf is deleted after both derivations — forward secrecy
```

`SafeExportSecret` **consumes** the leaf: a given `(group, epoch, component)` can be
exported exactly once, and its source key material is deleted per the RFC 9420 §9.2
deletion schedule. The **component id is what separates the two chains** — the
`DeriveSecret` labels (`"psk_id"`, `"psk"`) are fixed across both:

| Chain | `ComponentID` | Direction |
|-------|---------------|-----------|
| APQ-PSK | `0xFF01` (`APQ_COMPONENT_ID`) | PQ half → classical half of the *same* APQ group |
| cross-party TwoMLS-PSK | `0xFF02` (`TWOMLS_COMPONENT_ID`) | receive group → send group |

Both are imported with a `PreSharedKey` proposal carrying `psk_type = application(3)`
with `(component_id, psk_id)`. The value is installed in the group's PSK store under
the application **storage id** `0x03 ‖ component_id ‖ len(psk_id) ‖ psk_id`. The
committer live-injects the value into the resolving store immediately before building
or processing the commit that references it, and drops it once consumed. Both parties
derive the identical `(psk_id, psk)` independently — nothing PSK-related crosses the
wire except the id inside the proposal.

> Component ids are 16-bit because the Exporter Tree has only 2^16 leaves.
> `0xFF01`/`0xFF02` sit in the draft's private-use range. (draft-08 types `ComponentID`
> as `uint32`; -09 narrows it to `uint16` — the fork rejects any id ≥ 2^16.)

## The APQ-PSK (hybrid binding, PQ → classical)

Each APQ group is created PQ half first; the classical half then absorbs the PQ half's
secrecy at birth:

```
Group_A.pq @ epoch N
  → export_psk(component = 0xFF01)          # SafeExportSecret + DeriveSecret psk_id/psk
  → imported as an application PSK into Group_A.classical's creation commit
```

Both parties are members of Group_A.pq, so the joiner independently re-derives the same
PSK: it joins the PQ half first, registers the APQ-PSK, then joins the classical half
whose Welcome demands it.

## The cross-party TwoMLS-PSK (receive → send)

The acceptor's send group is bound to the group it receives on:

```
Group_A.classical (the acceptor's receive group) @ its current epoch
  → export_psk(component = 0xFF02)
  → imported as an application PSK into Group_B.classical's creation commit
```

`SafeExportSecret` only derives at the group's *current* epoch, and consumes the leaf.
A frame that crossed one of the deriver's own commits references an epoch the group can
no longer export, so the session keeps a small **send-PSK ledger** of its send group's
recent epochs (derived once when each epoch is entered) and live-injects the right
entry into the resolving store immediately before processing a bound Welcome or commit.
The ledger rides the session archive as reconstructed values (`ExportedPsk::from_parts`
recomputes the storage id) so a restore never re-exports a consumed leaf.

## Refresh is event-driven

The cross-party binding refreshes **only when the peer's send group has new entropy** —
not on a fixed schedule. On a folding commit (one that consumes the peer's approved Upd
proposal), the committer re-exports the cross-party PSK from its **receive** group and
binds it into its own send-group commit *only if that receive group has advanced since
the last binding* (tracked by the `last_cross_injected` watermark). A commit with no
new peer entropy carries **no** cross-party PSK: the previous binding's entanglement
still holds, and re-deriving would consume the same exporter leaf for nothing. It still
folds the peer's Upd and rotates its own leaf via the updatePath.

Establishment seeds the watermark to the epoch it bound at creation, so the acceptor's
first routine commit — which would otherwise redundantly re-bind the peer at the epoch
establishment already covered — correctly skips. The establishment cross-party PSK is
load-bearing: it is the sole PQ-protection path for the acceptor's classical-only send
group before the A.3 bootstrap.

The APQ-PSK refreshes on the A.4 ratchet: fresh ML-KEM entropy is injected into the
send group's PQ half, and the re-exported APQ-PSK (component `0xFF01`) is bound into the
classical half's commit in the same round.

The A.5 PQ re-key adds the PQ-to-PQ use of the cross-party chain: each of its two
`Commit'`s cross-injects a component-`0xFF02` PSK exported from the PQ half of the
**opposite** send group (same recipe), tying the two directions' PQ halves to each
other while their updatePaths rotate the leaves. These exports are event-driven too,
guarded by the PQ watermarks (`last_cross_injected_pq`, `last_send_pq_exported`) so a
re-key round never re-exports a consumed PQ leaf.

## The injected-secret PSK (A.4 KEM entropy)

The A.4 ratchet's per-round secret `S` — the shared secret of an out-of-band ML-KEM
encapsulation — is injected as an **`external(1)` PSK**, not an application PSK. It is
externally-sourced entropy rather than an exporter-derived value, so it keeps its own
structural id `LE-u64(epoch) ‖ group_id ‖ 0x52` in both recipe phases. The trailing
`0x52` domain byte, together with the length difference (41 bytes vs. the 38-byte
application storage id), keeps its id space disjoint from the exported chains.

## Invariants — never change

These values are protocol-specified; changing any of them silently breaks
interoperability:

- APQ-PSK component id: `0xFF01`; cross-party TwoMLS-PSK component id: `0xFF02`
- `DeriveSecret` labels: `"psk_id"` and `"psk"` (fixed across both components)
- Exporter-tree root label: `"application_export"`
- application PSK storage id: `0x03 ‖ component_id ‖ len(psk_id) ‖ psk_id`
- import type: `psk_type = application(3)` for the APQ and cross-party PSKs
- injected-secret PSK: `external(1)`, id `epoch.to_le_bytes() ‖ group_id ‖ 0x52`, keeping
  the two id spaces disjoint
