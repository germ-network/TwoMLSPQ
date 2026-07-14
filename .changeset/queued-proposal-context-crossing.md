---
"@germ-network/two-mls-pq": patch
---

Fix the agent-handoff binding context so cross-endpoint handoffs validate.

An agent handoff is signed by the sender against its `proposal_context`
(SHA-256 of its recv group's classical id) and validated by the receiver against
the `context` that `process_incoming` stamps on the `QueuedRemoteProposal`. That
stamp used the receiver's *recv* group id — but the two endpoints' recv groups
are distinct MLS groups (A's recv is B's send), so the values never matched and
every cross-endpoint handoff signature failed to validate. It stayed latent
because the only prior consumer never read `proposal_context`; the first consumer
that does could not complete its first agent rotation (a Signature-validation
failure that cascaded to a dropped decrypt).

Stamp the queued proposal's context from our send group's classical id — the
reverse channel, which is the sender's recv group — so sign and validate agree.
Also correct `test_proposal_hash_is_digest_of_the_staple_both_sides_agree_on`,
which asserted the receiver's context equalled the receiver's *own*
`proposal_context` (trivially true under the bug); it now asserts equality with
the *sender's*, the contract that actually gates handoff validation.
