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

The app-message arms of `process_incoming` now separate the two: mls-rs
`KeyMissing` / `InvalidLeafConsumption` — the errors that prove the generation
is spent — become the new `StaleFrame`, which bridges to
`SessionError.staleFrame` and its `.discardFrame` disposition. Everything else
stays `DecryptionFailed` and keeps its transient meaning.

Binding contract 27 → 28: `StaleFrame` is appended to `TwoMlsPqError`, so
prior variants keep their ordinals. No wire change and no FFI signature change.
