# Planned Features

These methods exist in the API surface but currently return `Err` — they are
scheduled work.

| Area | Methods | Status |
|------|---------|--------|
| Session archive / restore | `TwoMlsPqSession::archive`, `from_archive` | not yet implemented (`ArchiveInvalid`); the *invitation* archives today, sessions do not. A session archive must serialize the per-epoch listen map (rendezvous exporters are only derivable at their epoch) and the spawn token, or restored sessions silently lose routing and replay acknowledgment |
| Reconnect | epoch-history window; `process_incoming` → `None` on unknown epoch | not yet implemented |

Transport routing (`should_listen_on`, `send_rendezvous`, `forwarded`) — previously
listed here — is implemented; see [Session Lifecycle](./session-lifecycle.md).

Beyond the methods above, the roadmap includes:

- **Classical-only session mode** — make the ML-KEM-768 half optional so a session can
  run classical-only and upgrade to post-quantum later (needed for migrating existing
  classical conversations).
- **Legacy archive import** — a constructor that imports old classical group snapshots
  from the previous app and emits a TwoMLSPQ archive.
- **CommProtocol PQ suite** — adding the post-quantum suite at the routing layer so
  TwoMLSPQ is reachable end-to-end.
