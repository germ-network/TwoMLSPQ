---
"@germ-network/two-mls-pq": minor
---

Export the attachment wire CEK (GER-1985)

Two FFI additions, `export_attachment_cek_send(key_id)` and
`export_attachment_cek_recv(key_id, epoch)`, deriving the symmetric key an
attachment's sealed container is opened with:
`ExpandWithLabel(SafeExportSecret_classical(0xFF03), "attachment", key_id, 32)`.
Classical-only by design — the classical key schedule already absorbs a
PQ-derived PSK via the existing APQ-PSK binding, so the export is downstream
of ML-KEM entropy without needing to combine both APQ halves, and 3.0.11's
receive-only staging freezes whatever recipe ships. `ExpandWithLabel` is
reimplemented locally in `apq` (mls-rs keeps its own `pub(crate)`, and its one
public door hard-codes empty context) — the reimplementation is verified
field-for-field against mls-rs's own private `Label` struct, since neither the
determinism test nor the cross-provider interop test can catch a wrong RFC
9420 label on its own: both sides of either test run the same code.

Send is lazy — export and ledger the send-classical epoch's component on
first use, since a session that never sends an attachment should not pay a
0xFF03 export at all. Recv is the harder half: `safe_export_secret` only
works at a group's CURRENT epoch, but mls-rs retains older epoch secrets, so
a frame delayed past a later commit can still decrypt from an epoch the recv
group has since moved past. The session now captures the recv-classical
component EAGERLY, immediately before a commit advances past it, into a
small session-owned ledger — and, for the common case of an attachment
fetched before anything has committed past its epoch yet, `export_attachment_cek_recv`
also exports live rather than requiring the eager path to have already run.
A ledger miss reports the new `AttachmentComponentUnavailable` — not
retriable, since the component is either evicted or was never captured, and
the frame that needs it decrypted fine; only the attachment behind it is
unopenable by this session.

Finding the recv-side ledger correctness case exposed a real, pre-existing
bug: `MlsSenderMessage.epoch` reported the recv group's CURRENT epoch at
decrypt time rather than the frame's own authenticated epoch
(`MlsMessage::epoch()`, the same accessor `commit.epoch()` already used
elsewhere in this crate). The two agree for every in-order frame — which is
every frame any existing caller has ever observed, so this is a behavior fix
rather than an API change — and diverge only for a frame processed after a
later commit has already landed, exactly the case this ticket needed keyed
correctly.

Archive layout bumps 3 → 4 rather than adding the two new ledger fields to
the shipped v3 tail in place: v3's own "unreleased byte" exception closed at
0.15.0, which shipped v3's two-field tail (`responder_wire_ct`, `pq_wedged`)
for real. A v3 blob's tail now decodes against a frozen `ArchiveTailV3`
shape and lifts into the current tail with empty attachment ledgers; v3
joins v2 as an accepted older layout on restore, exactly the mechanism v3
itself used to carry 0.14 sessions across its own introduction.

Binding contract 32 → 33.
