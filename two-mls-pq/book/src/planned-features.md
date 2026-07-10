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

Beyond the methods above, the roadmap includes (the first two in order):

- **Wire-format reassessment** — always staple the send-group commit (or the
  send group's welcome until one exists) so any single frame brings the peer up to
  the sender's epoch; collapse the message path to one frame shape and retag. To
  be planned separately; a prerequisite for header encryption.
- **Header encryption** — an outer encryption layer making every outbound frame a
  single opaque blob (no plaintext tags, group ids, epochs, or Welcome metadata);
  the design is written up in [Header Encryption (design)](./header-encryption.md)
  and applies on top of the reworked wire format.
- **Classical-only session mode** — make the ML-KEM-768 half optional so a session can
  run classical-only and upgrade to post-quantum later (needed for migrating existing
  classical conversations).
- **Legacy archive import** — a constructor that imports old classical group snapshots
  from the previous app and emits a TwoMLSPQ archive.
- **CommProtocol PQ suite** — adding the post-quantum suite at the routing layer so
  TwoMLSPQ is reachable end-to-end.
