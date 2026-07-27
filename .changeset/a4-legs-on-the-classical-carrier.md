---
"@germ-network/two-mls-pq": minor
---

Carry the A.4 ratchet legs in the classical groups

The EK (`0x17`) and CT (`0x19`) travelled as MLS application messages in the
initiator's send-PQ group. Both of MLS's authentication factors are *fresher* in
the classical half: its leaf signature and epoch secrets heal on every round and
adopt a principal rotation the moment it is canonicalized, while a send-PQ leaf
lags until an A.5 catch-up. Each leg now rides its own sender's **send-classical**
group instead, sealed under the classical header family.

Nothing is traded away in strength. MLS cipher suites are monolithic and both
halves sign Ed25519 — the PQ suite is confidentiality-only — so the signature
factor was already classical, and the classical epoch secrets are ML-KEM-seeded
through the APQ PSK. Under a break of ML-KEM the classical carrier keeps both
factors where the PQ carrier kept only the signature. The round's binding to the
PQ group is untouched: `ct_seal_psk` is still a PQ-group exporter keyed into the
seal over `S`, so a ciphertext answering a different group or epoch still fails
its open.

The responder mints its CT in its **own** send group, not the mirror the EK
arrived in. That mirror routinely holds its uncommitted routine `Upd`, and mls-rs
refuses to encrypt while a by-ref proposal is cached — a failure that would land
after the EK decrypt had already consumed its generation, stranding the round
with no way to retry.

What the classical carrier costs is that a leg's ciphertext is pinned to the
epoch it was minted at, and ordinary traffic advances that epoch past the peer's
retention window within a few commits. So an unanswered leg is now **re-minted**
at the current epoch on every send. Without it a leg that went undelivered across
that window would become permanently undecryptable, and since nothing clears the
in-flight round but its own completion, the side-band would wedge for the
session's lifetime. What survives a stall is therefore the round, not a leg's
bytes: a blob captured before a burst of commits stops opening, exactly as a
message frame from that moment does.

Re-minting means one logical leg exists as several valid wraps, and MLS retains
the keys of generations it skipped so they can arrive out of order — so a
superseded wrap redelivered late still decrypts, where a replay of the wrap
actually consumed does not. Answering one after its round had closed would park a
responder against an ephemeral the initiator already discarded, deadlocking the
side-band permanently. Both receive paths therefore reject, before decrypting,
any leg below the receiver's current classical epoch: reaching epoch E proves the
sender committed E, and that commit's own send re-minted the live leg to E, so
anything below it is superseded or replayed by construction. Legs that arrive
*ahead* of the receiver stay retriable, as they always were.

Sessions established on 0.14 survive the upgrade. The archive layout goes to v3
and, for the first time, still **accepts** v2 — the new state rides a tail
appended after the byte-unchanged body, so an older blob decodes as the same
prefix. A round restored from v2 comes back intact and completes. An initiator's
parked encapsulation key is in the old form, which an upgraded peer will not
answer, so the first send after the restore converts it — re-minting the new form
from the ephemeral the round still holds. That closes the window against an
upgraded peer at the cost of one against a peer still on 0.14, which is the right
way round: the first is permanent once both ends upgrade, the second heals the
moment the peer does. A responder instead keeps re-sending the PQ-carried
ciphertext it parked, which `pq_ratchet_bind` still accepts — its payload is
encrypted to the peer and cannot be rebuilt, so refusing it would strand an
otherwise completable round.

Wire-breaking for the A.4 side-band in one direction only: `pq_ratchet_respond`
answers the classical form alone and **drops** a PQ-carried EK non-fatally,
without consuming anything, so the two forms never interleave inside a round. A
peer that has not yet upgraded therefore cannot answer a new-form EK, and the PQ
side-band — with it, A.5 credential catch-up — pauses for that pair until it
does. The unanswerable old-form leg reports `StaleFrame` (discard — no retry of
those bytes can ever succeed on this build), never anything a host should tear a
session down over. Classical messaging is unaffected throughout.

Persistence gets cheaper on the way past. Opening a round and answering one are
now classical-only mutations — the PQ half is read exactly once, through a
repeatable exporter that consumes no leaf — so neither pushes a `Checkpoint` any
more, and the two ML-KEM ratchet trees stop being serialized on every A.4 leg.
Only the bind, which really does commit the PQ half, still checkpoints.

Binding contract 28 → 29. No FFI signature or error-variant change. Hosts may
newly see `StaleFrame` (discard) on a side-band leg, since legs are re-sent as
fresh wraps rather than fixed bytes and an older copy is no longer retriable.
