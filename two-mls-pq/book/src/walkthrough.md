# Walkthrough: Alice & Bob

The runnable version of this walkthrough lives in `src/demo.rs` as the
`demo_e2e_full_session` test. Run it with output:

```sh
cargo test -p two-mls-pq demo_ -- --nocapture
# real ML-KEM-768:
cargo test -p two-mls-pq --features cryptokit demo_ -- --nocapture
```

The narrative, step by step:

1. **Identities** — Alice and Bob each build a `TwoMlsPqIdentity` for their `ClientId`
   (opaque identity bytes); the MLS signing key is generated internally.
2. **Key packages** — each generates a `CombinerKeyPackage` (classical + ML-KEM-768
   halves, same `ClientId`).
3. **Parsing** — the peer's halves parse to `MlsKeyPackage`s; the classical suite is
   `0x0003`, the PQ suite `0xFDEA`; the two `ClientId`s must match.
4. **Establishment** — `initiate` → `APQWelcome_A` → `accept` → `APQWelcome_B` →
   `process_incoming`. Both sides are now established with the PSK chain bound.
5. **Partial commit** — Alice `prepare_to_encrypt(None)` + `encrypt`; Bob decrypts.
6. **Full commit** — Bob proposes; Alice `queue_proposal` then commits on her next send,
   advancing the epoch and refreshing the PSK.
7. **Continued messaging** — bidirectional traffic continues post-refresh.
8. **Rotation** — Alice `stage_rotation` + `prepare_to_encrypt(Some(new_id))`; Bob
   observes `CommitResult.new_sender`.

For the full sequence diagrams see `docs/flows.md`, `docs/alice-bob.md`, and
`docs/diagrams.md` in the repository.
