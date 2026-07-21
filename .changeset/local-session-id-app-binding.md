---
"@germ-network/two-mls-pq": minor
---

Expose two adopter affordances on the Swift surface; both additive, no wire or contract change.

- `PQSession.localSessionId` (FFI `send_group_id() -> MlsGroupId?`) — this side's OWN send-group classical id, the mirror of `receiveGroupId`. A stable, per-endpoint session identifier present from creation. Unlike `activeSessionId()` (the shared hash of the two client ids) it is LOCAL — each endpoint's send group differs — so an adopter can key local session state by it without sharing an at-rest identifier with its peer. It is the identity value on its own, separate from `shouldListenOn()`'s routing/rendezvous tuple.
- `PQClient.reply(appBinding:)` / `PQInvitation.receive(expectedAppBinding:)` — the high-level wrapper now threads the AppBinding (contract 15) through to `initiate(appBinding:)` / `receive(expectedAppBinding:)` instead of hardcoding `nil`. Both default to `nil` (source-compatible). A session may now be created bound to a relationship digest and the peer's welcome verified against it (`AppBindingMismatch` on a mismatch, checked before invitation state is claimed).
