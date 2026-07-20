---
"@germ-network/two-mls-pq": minor
---

Session-driven PQ side-band advancement + optional side-band frame padding (binding contract 23 → 24).

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
