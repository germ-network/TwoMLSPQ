# Planned Features

These methods exist in the API surface but currently return `Err` — they are
scheduled work.

| Area | Methods | Status |
|------|---------|--------|
| Reconnect | epoch-history window; `process_incoming` → `None` on unknown epoch | not yet implemented |

Session archive/restore and transport routing (`should_listen_on`,
`send_rendezvous`, `forwarded`) — previously listed here — are implemented; see the
[API Reference](./api-reference.md) for the archive contract (plaintext, single-use,
total — a session is always archivable) and [Session Lifecycle](./session-lifecycle.md)
for routing.

Beyond the methods above, the roadmap includes:

- **Classical-only session mode** — make the ML-KEM-768 half optional so a session can
  run classical-only and upgrade to post-quantum later (needed for migrating existing
  classical conversations).
- **Legacy archive import** — a constructor that imports old classical group snapshots
  from the previous app and emits a TwoMLSPQ archive.
- **CommProtocol PQ suite** — adding the post-quantum suite at the routing layer so
  TwoMLSPQ is reachable end-to-end.
