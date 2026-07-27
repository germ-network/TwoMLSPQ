---
"@germ-network/two-mls-pq": minor
---

Gate the A.5 `Upd'` door on content type, and refuse a rekey while a bind is owed

The A.5 `Upd'` door carries a proposal, but the routing tag is the sender's, and
it feeds `process_incoming_message` on our own send-PQ — which validates and
*applies* a commit atomically. The peer is a member of that group, so it could
author a commit there that would apply, moving our send-PQ epoch, before the
door's kind check refused it — and the refusal wore the fatal `Mls` disposition
that asks a host to tear the session down. This closes the same gap the A.4 leg
doors already closed: the door now reads the content type off the plaintext
framing first and refuses anything but a proposal with the retriable
`DecryptionFailed`, nothing applied.

The door also now refuses a rekey while a classical bind is owed. Its closure
commits our send-PQ, which moves the epoch an owed bind reserved in its
attestation — and discharging against a moved epoch fails with the PQ leaf
already spent. An honest peer never reaches this (owing a bind means the turn is
still ours), so a deviating one is refused in the guard phase as a retriable
no-op, exactly as the bind entry points guard the same reservation.

No wire, FFI, or error-variant change; a session that saw the old fatal `Mls`
here now sees a retriable `DecryptionFailed`.
