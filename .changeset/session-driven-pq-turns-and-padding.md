---
"@germ-network/two-mls-pq": minor
---

Session-driven PQ side-band advancement, optional side-band frame padding, lazy credential staging,
and a rotated-party discharge fix (binding contract 23 → 25).

The session now DRIVES its own A.3 ratchet and A.5 re-key rounds — the host no longer calls
`pq_ratchet_begin` / `pq_rekey_begin` (both removed). On each `encrypt`, when it is our turn and the
side-band is idle, the session opens the next round automatically: an A.5 credential catch-up when
the send-PQ leaf still lags the canonical (classically committed) principal, else an A.3 ratchet.
The host just takes the staged frame from `pq_pending_outbound` to send alongside the message, so
its PQ role is now `.finishBootstrap` (A.4) plus ordinary sends. A staged A.5 is checkpointed with
the send so a crash-restore cannot strand its pending update.

Every header-sealed frame gains a 4-byte little-endian length prefix, and a new
`set_pad_target(Option<u64>)` lets a host zero-pad each side-band frame up to the co-stapled
message's size (capped at a push-payload budget), so the two co-stapled payloads are
size-indistinguishable to an on-path observer. Absent the intent, frames go out at their natural
size. The prefix is a hard wire change — a v23 seal mis-parses under a v24 open — so the binding
contract bumps 23 → 24.

Credential staging is now LAZY (contract 24 → 25). `prepare_to_encrypt(Some(id))` admits an unstaged
candidate on the fly — minting its keys and authorizing it — so a rotation can ride the very first
frame with no separate stage call; `stage_rotation` is removed from the FFI (a session advances state
only by sending, so pre-staging bought nothing). Establishing a dedicated per-session principal is now
"born-dedicated": `receive(new_client_id:)` creates the acceptor's send group directly under that
principal (its creator leaf carries the id), retiring the old establish-under-founding → rotate dance.

Also fixes a rotated party's owed-bind discharge: when it discharged via the bare evidence-gating
license (no approved fold), the commit carried the credential handoff but no updatePath, so the new
leaf never reached the peer and its next message failed to verify. A FULL (attestation-carrying)
classical commit now always includes a path.
