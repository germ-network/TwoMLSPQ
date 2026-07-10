# Planned Features

These methods exist in the API surface but currently return `Err` — they are
scheduled work.

| Area | Methods | Status |
|------|---------|--------|
| Reconnect | epoch-history window; `process_incoming` → `None` on unknown epoch; recovery from `EpochDesync` (a stapled commit ahead of the receive group) | not yet implemented |

Session archive/restore, transport routing (`should_listen_on`, `send_rendezvous`,
`forwarded`), the always-staple wire format, and **header encryption** (the symmetric
steady-state layer) — previously listed here — are implemented; see the
[API Reference](./api-reference.md) for the archive contract (plaintext, single-use,
total — a session is always archivable), [Session Lifecycle](./session-lifecycle.md)
for routing, [Wire Format](./wire-format.md) for the message frame, and
[Header Encryption](./header-encryption.md) for the outer seal (`open_incoming`) and
its two documented refinements (PQ-family side-band keys; the initial-welcome envelope
inside `initiate`).

Beyond the methods above, the roadmap includes:

- **Classical-only session mode** — make the ML-KEM-768 half optional so a session can
  run classical-only and upgrade to post-quantum later (needed for migrating existing
  classical conversations).
- **Legacy archive import** — a constructor that imports old classical group snapshots
  from the previous app and emits a TwoMLSPQ archive.
- **CommProtocol PQ suite** — adding the post-quantum suite at the routing layer so
  TwoMLSPQ is reachable end-to-end.
