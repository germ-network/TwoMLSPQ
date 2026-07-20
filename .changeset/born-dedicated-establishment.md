---
"@germ-network/two-mls-pq": minor
---

Born-dedicated establishment now carries a signed identity delegation (binding contract 26). A `receive(new_client_id:)` acceptor whose dedicated credential differs from the invitation identity is non-emittable until `install_establishment_envelope` supplies the host's signed handoff, which wraps the unmodified `APQWelcome_A` in a new `0x0B` establishment-handoff staple. The initiator's `process_incoming` pauses on that frame (`DecryptResult.pending_establishment`) for out-of-band verification and completes via the stateless re-feed `process_incoming_approved(ciphertext, approved_envelope_digest:, approved_welcome_digest:, expected_creator:)`; a bare welcome whose creator differs from the invitation identity is refused at the join. `receive(new_client_id:)` equal to the invitation identity degenerates to the nil topology. New errors: `EstablishmentEnvelopeRequired`, `EstablishmentCreatorMismatch`, `EstablishmentEnvelopeConflict`.
