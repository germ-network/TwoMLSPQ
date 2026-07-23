---
"TwoMLSPQ": minor
---

Report a replayed application message as `StaleFrame`, not `DecryptionFailed`

A host running two delivery channels over one queue — a push relay alongside a
socket — is handed the second copy of every frame it receives. That copy
decrypts into a message key the first already spent, and the crate collapsed it
into `DecryptionFailed`, whose Swift disposition is `.retryLater`. So the host
spooled and re-attempted ciphertext that can never open, and every genuine
transient failure was buried in the noise.

Every application-message decrypt now separates the two through one mapping:
mls-rs `KeyMissing` / `InvalidLeafConsumption` — the errors that prove the
message key is spent, and a ratchet only moves forward — become the new
`StaleFrame`, which bridges to `SessionError.staleFrame` and its
`.discardFrame` disposition. Everything else stays `DecryptionFailed` and keeps
its transient meaning, epoch misses included: an application message carries no
epoch bound check, so a miss cannot be told apart from a frame that arrived
ahead of the commit it needs, and only the transient reading is safe there.

That covers the A.4 side-band legs too, which contract 27 reframed as
application messages. Those previously reported `Mls` for any failed decrypt —
and `Mls` carries the `fatal` disposition, which tells a host its own state may
be inconsistent. A host that acts on that literally tears the session down, so
a peer frame it merely could not open must never produce it.

That door is reachable, not theoretical: the `pq_inflight` guards answer
duplicates WITHIN a round, but a leg re-delivered from a round that has since
closed clears them and reaches the decrypt. Two existing tests already drove
exactly that and pinned `Mls`; they now pin `StaleFrame`. For a host running a
push relay alongside a socket, such a re-delivery is designed-in traffic, so
the old mapping put a session teardown one dropped ack away.

Binding contract 27 → 28: `StaleFrame` is appended to `TwoMlsPqError`, so
prior variants keep their ordinals. No wire change and no FFI signature change.
