---
"@germ-network/two-mls-pq": minor
---

Close the PQ bind's consume-then-fail window

A bind's PQ half is a pathless commit carrying the -02 `AppDataUpdate` attestation,
and the group rules reject *any* Update co-riding that attestation. So a single
by-ref proposal cached in our send-PQ half makes every later bind commit fail — and
it fails **after** the round's one-shot input is already spent: A.4's ephemeral
opened, A.3's key package consumed by the join, A.5's `Commit'` applied.

That was reachable by the counterparty, with no forgery. MLS files a by-ref proposal
into the cache inside `process_incoming_message`, which runs *before* the A.4 leg
door inspects the message kind — so a proposal routed through a door that answers a
benign, retriable error still lands in the cache and stays there. The next bind then
tore itself apart: the ephemeral gone, the parked encapsulation key no longer
re-mintable, the side-band unable to open another round, every retry answering the
apparently-retriable `SessionNotReady` forever, and `is_fully_established()` still
reporting true. Because the bind's persist captures partial mutations by design, the
tear reached the archive too, so restoring reproduced it.

The three bind entry points now check for that residue in their **guard** phase,
where refusing is free — nothing consumed, no checkpoint written, and the peer's next
honest frame completes the round — and the two doors that admit a proposal drop it on
the way out.

Past the point of no return, where no guard can help, each trigger's tail now runs
inside a region that renames any escaping failure to the new fatal
`BindTriggerFailed` and latches it. That latch **rides the archive**, unlike
`BindApplyFailed`: the apply latch is allowed to heal on restore only because inbound
processing persists on success alone, which is exactly what these closures do not do.
A verdict that healed here would hand the honest label back to a session that is still
torn. It completes the trigger/discharge/apply family and is queryable via
`pq_side_band_wedged()` — worth polling, because A.3's wedge otherwise looks healthy.
Classical messaging is unaffected throughout, and an already-reserved bind still
discharges.

Two smaller corrections ride along. The A.3/A.5 responder now derives its bind secret
*before* consuming the round, so a failed re-export is a no-op the peer's next
re-staple retries instead of a silent, unlatched dead end. And the post-commit
header-key capture is now best-effort with a re-derivation backstop in
`should_listen_on`, since it is the repeatable exporter — latching a round that
actually succeeded would be the fix over-firing.

Binding contract 29 → 30. Archive layout stays v3, gaining one tail field.
