---
"@germ-network/two-mls-pq": minor
---

§A.1 pre-establishment initiator sends (binding contract 16; archive versions reset to the
pre-release floor).

The initiator can now send app messages immediately after `initiate`, before the
acceptor's return welcome exists (architecture-diagrams 08-twoMLSPQ-APQ §A.1) —
previously `prepare_to_encrypt` returned `SessionNotReady` until both groups were
established, on live and restored sessions alike. Pre-establishment,
`prepare_to_encrypt` is a no-op round (`proposal_message` empty; `proposal_hash` is
the WELCOME digest — the documented carve-out on the v14 guarantee) and `encrypt`
emits a fresh §A.1 envelope per frame (contract 16 atop v0.3.0 AppBinding — `initiate` keeps `app_binding` and loses `app_payload`), HPKE-sealed to the retained peer KP′,
re-stapling the establishment sections plus the app message — any single frame lets
the invitation holder join and read it.

Envelope wire v2: tagged `[0x15][u32 kem_len][kem][ct]`; plaintext is four optional
u32-LE length-prefixed sections `[app_payload][welcome][return_kp][stapled_message]`
under the either/or rule — a host `app_payload` is establishment-SELF-SUFFICIENT
(carries the welcome + return key package inside) and replaces the bare sections.
`initiate` lost its `app_payload` parameter (a payload that signs over the welcome
cannot exist before `initiate` returns); attach with the new
`set_initial_app_payload` / `set_initial_return_key_package` (initiator-only,
pre-establishment-only; capture AFTER attaching — the retained state rides the
archive, so a birth-captured replier restores send-ready). New read-only
`initial_welcome()`; `InitialFrame` reshaped (all four sections, `welcome` now
optional); new exported `decode_initial_plaintext`. Replay-stable token/dedup keying:
the stable prefix (`app_payload` when present, else `welcome`); all consequential
state keys off the signed, JOINED welcome — the other sections are unauthenticated
routing hints. The stapled app message is `[0x13][classical PrivateMessage]`, handed
to `process_incoming` after the join. Establishment clears the retained state.

Archive layout versions reset to the pre-release floor (SESSION_ARCHIVE and INVITATION
both → 1 — the accumulated ladders carried no compatibility value pre-release; history
stays in git): ALL persisted sessions and invitations regenerate, fail-closed
(`ArchiveInvalid`). The v0.3.0 key-package WIRE cut (KP v3, a published artifact) is
untouched. Composes
with v0.3.0 AppBinding: the binding rides the welcome every pre-establishment frame
re-staples, so `receive(expected_app_binding:)` verifies it on a join from any frame.
