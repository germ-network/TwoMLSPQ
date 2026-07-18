---
"@germ-network/two-mls-pq": minor
---

Route a parallel-delivered A.4 bootstrap KP′ to its session by content (contract 23).

A KP′ shipped as a §A.1 bootstrap envelope (contract 21) carries no session id, and a
reusable invitation spawns many sessions, so it cannot be routed by transport address.
The invitation now keeps a commitment→group table — populated at `receive` from the
`H(bootstrap KP)` commitment it was already given — and the new
`bootstrap_kp_group_id(kp_frame)` resolves a framed `[0x13][KP′]` against it, the
bootstrap-KP counterpart of `forward_group_id`/`processed_welcome_group_id`. The hash
stays in Rust, so a frame that resolves can never fail `pq_bootstrap_respond`'s own
commitment check. `pq_bootstrap_begin` (the rendezvous side-band path) is unchanged.

Invitation archive layout changed (`INVITATION_VERSION` 1 → 2, pre-release hard cut): a
stale invitation blob fails to decode and must be regenerated.
