# Planned Features

**In-library `EpochDesync` recovery is not planned — there is no "reconnect"
at this layer.** When a stapled commit arrives ahead of the receive group,
`process_incoming` surfaces `EpochDesync` and the session is not recovered
in-library: recovery is OUT-OF-SESSION — the host re-establishes a fresh
session (restore cannot heal it; the persisted state is desynced too). The
epoch-history window once sketched here for in-library recovery has been
dropped, and the vocabulary with it: "reconnect" survives in these docs only
when naming the CLASSICAL TwoMLS rejoin mechanism, which has no PQ
counterpart.

Session persistence (push-based — `ArchiveSink` / `install_sink` / `restore`),
transport routing (`should_listen_on`, `send_rendezvous`, `forwarded`), the always-staple
wire format, and **header encryption** (the symmetric steady-state layer) — previously
listed here — are implemented; see the [API Reference](./api-reference.md) for the
persistence contract (plaintext-and-seal, push-after-mutation, total — a session is always
encodable), [Session Lifecycle](./session-lifecycle.md)
for routing, [Wire Format](./wire-format.md) for the message frame, and
[Header Encryption](./header-encryption.md) for the outer seal (`open_incoming`) and
its two documented refinements (PQ-family side-band keys; the initial-welcome envelope
inside `initiate`).

Beyond the methods above, the roadmap includes:

- **Classical-only session mode** — make the ML-KEM-768 half optional so a session can
  run classical-only and upgrade to post-quantum later (needed for migrating existing
  classical conversations).
- **Legacy archive import** — a constructor that imports old classical group snapshots
  from the previous app and stands up a restorable TwoMLSPQ session.
- **CommProtocol PQ suite** — adding the post-quantum suite at the routing layer so
  TwoMLSPQ is reachable end-to-end.
