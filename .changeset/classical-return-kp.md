---
"@germ-network/two-mls-pq": minor
---

The establishment return key package is classical-only, and the A.4 bootstrap key
package is pre-committed (contract 20).

`receive`/`accept` now take the initiator's bare classical MLS KeyPackage message in
place of the dual combiner blob — its PQ half fed nothing but a halves-agree check, and
A.4 minted a fresh key package anyway (~2.6 KB of dead weight per establishment reply) —
plus a required 32-byte `bootstrap_kp_commitment`: SHA-256 of the initiator's PQ
keyPackage, which the host carries inside its SIGNED establishment payload. `initiate`
mints that PQ key package up front with SESSION-OWNED custody — both halves ride the
session archive, the private half injected just-in-time at the bind join — so neither a
restore nor a Phase 8 rotation's client swap can strand the committed round
(`bootstrap_kp_commitment()` exposes the hash for the host's envelope).
`pq_bootstrap_begin` sends the retained pre-committed KP, and
`pq_bootstrap_respond` rejects a KP′ hashing to anything else (`BootstrapKpMismatch`,
new error variant, appended). This anchors the ML-KEM key material to the host's signed
establishment rather than resting it on classical channel auth alone. When a commitment
is pinned, the hash check replaces the names-the-established-peer equality (strictly
stronger — it pins the exact committed bytes), so a KP′ under a since-rotated principal
still lands (PQ leaves lag credentials by design; A.5 catches them up).

Host worklist: `reply`-side flows mint a classical KP (`generate_key_package`, x25519)
instead of `generate_combiner_key_package` for the return KP; the signed app welcome
carries the classical KP + the 32-byte commitment; the receive flow threads the
commitment into `receive`. `set_initial_return_key_package` takes the bare classical
bytes. Archive layout changed (pre-release hard cut: old blobs fail to decode and are
regenerated).
