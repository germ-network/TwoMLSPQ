# Planned Features

These methods exist in the API surface but currently return `Err` — they are scheduled
work, tracked in `MASTER-PLAN.md` at the repository root.

| Area | Methods | Status |
|------|---------|--------|
| Archive / restore | `archive`, `from_archive` | not yet implemented (`ArchiveInvalid`) |
| Transport | `should_listen_on`, `send_rendezvous`, `forwarded` | not yet implemented (`SessionNotReady`) |
| Reconnect | epoch-history window; `process_incoming` → `None` on unknown epoch | not yet implemented |

Beyond the methods above, the roadmap includes:

- **Classical-only session mode** — make the ML-KEM-768 half optional so a session can
  run classical-only and upgrade to post-quantum later (needed for migrating existing
  classical conversations).
- **Legacy archive import** — a constructor that imports old classical group snapshots
  from the previous app and emits a TwoMLSPQ archive.
- **CommProtocol PQ suite** — adding the post-quantum suite at the routing layer so
  TwoMLSPQ is reachable end-to-end.

See `MASTER-PLAN.md` for the full phased plan, dependencies, and open decisions.
