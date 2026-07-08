# Planned Features

These methods exist in the API surface but currently return `Err` — they are
scheduled work.

| Area | Methods | Status |
|------|---------|--------|
| Session archive / restore | `TwoMlsPqSession::archive`, `from_archive` | not yet implemented (`ArchiveInvalid`); the *invitation* archives today, sessions do not. A session archive must serialize the per-epoch listen map (rendezvous exporters are only derivable at their epoch) and the spawn token, or restored sessions silently lose routing and replay acknowledgment |
| Reconnect | epoch-history window; `process_incoming` → `None` on unknown epoch | not yet implemented |

Transport routing (`should_listen_on`, `send_rendezvous`, `forwarded`) — previously
listed here — is implemented; see [Session Lifecycle](./session-lifecycle.md).
