---
"@germ-network/two-mls-pq": patch
---

Scope the FULL-commit forced updatePath to the classical half.

Contract 25's rotated-discharge fix (`TwoMlsRules::commit_options` forcing an
updatePath onto attestation-carrying commits) was meant to be classical-only —
its own comment said so — but both halves share `TwoMlsRules`
(`OurConfig`/`PqConfig`), so since v0.10.0 it also bolted an ML-KEM updatePath
onto the PQ group's pathless PSK-injection binds (292 B → 4011 B, the bench's
"13x smaller" reading 0x) and into the establishment welcome (+~1.3 KB on the
§A.1 envelope). The predicate now also requires a non-PQ cipher suite
(`suite_is_pq`, same total recognition `filter_proposals` uses), restoring the
contract-24 pathless bind the book documents. No PQ bug required the path: PQ
bind freshness is the injected secret S, and PQ credential handoffs ride A.5's
updatePath commit, whose folded Update forces a path regardless of this option.
The classical discharge keeps its forced path (the actual bug fix), pinned by
the existing rotated-discharge test; the new `test_bind_pq_commit_is_pathless`
pins the restored PQ shape on both build and receive. Wire-compatible both
directions — no receive-side rule checks path presence — so no binding-contract
bump.
