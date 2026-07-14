---
"@germ-network/two-mls-pq": patch
---

Doc truth fix: `forwarded` and contract 16's pre-establishment staples.

The `forwarded(spawn_token)` doc (and the session-lifecycle book section) still
justified the `Ok(None)` return with "an initiator cannot staple a private
message pre-establishment" — false since §A.1 replier-first sends (contract 16),
where every pre-establishment frame staples the sender's CURRENT app message.
The return contract is unchanged; the reason is corrected: `forwarded` only
validates the routing, and the staple rides the envelope itself — the host
parses it out (`decode_initial_plaintext`) and delivers it through
`process_incoming`. Also updates the book's spawn-token convention note to the
stable-prefix digest Germ's adapter actually uses. Doc-only — no code change.
