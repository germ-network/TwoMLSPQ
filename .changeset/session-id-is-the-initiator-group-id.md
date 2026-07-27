---
"@germ-network/two-mls-pq": minor
---

The session id is the initiator's group id; remove the client-id-pair hash

`active_session_id()` and its `SessionId` type returned a hash of the two client
ids — `SHA-256(min(a,b) ‖ max(a,b))`, no seed. That is a participant-**pair**
fingerprint, not a session id: anyone holding the two public client ids can
compute it, and it is identical across every session the pair ever opens. Both
are removed (finishing what contract 31 began by dropping the free
`derive_session_id`).

The real session id is the **initiator's randomly-generated group id** — fresh
per session, unpredictable, and already shared, because the initiator's send
group is the acceptor's receive group. Read it with `send_group_id()` on the
initiator and `receive_group_id()` on the acceptor (the classical half, present
from construction); both name the same value, and it survives archive restore
with the group state. The tests now assert this, including that two sessions
between the *same* pair get different ids — the property the old hash could never
satisfy.

Nothing downstream breaks: the vended Swift wrapper never forwarded the accessor,
AbstractTwoMLS never called it, and the app already keys on group ids
(`receiveGroupId` / `sendGroupId`). The stored field is dropped from the live
session; its slot stays vestigial in the archive (written empty, ignored on
decode) so a released 0.14 archive still decodes under the v3 migration.

Binding contract 31 → 32 — two FFI symbols removed, re-pair the vendored binding.
No wire change (archive layout stays v3) and no error-variant change.
