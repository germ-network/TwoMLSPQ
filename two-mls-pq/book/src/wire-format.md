# Wire Format

Every outbound blob is a tagged frame — there are no bare MLS messages on the wire.

| Tag | Value | Meaning |
|-----|-------|---------|
| `APQ_TAG` | `0x01` | APQ Welcome (invitation channel; also the message frame's staple-slot welcome form) |
| `MESSAGE_FRAME_TAG` | `0x03` | The message frame: `[staple][proposal][app]` — the only message-path frame |
| `PQ_EK_TAG` | `0x05` | PQ ratchet: ML-KEM encapsulation key |
| `PQ_CT_TAG` | `0x07` | PQ ratchet: ML-KEM ciphertext |
| `PQ_BIND_TAG` | `0x09` | PQ ratchet bind: PQ partial commit + classical commit + app |
| `PQ_BOOTSTRAP_KP_TAG` | `0x0B` | Bootstrap: PQ key package for the deferred send-group half |
| `PQ_BOOTSTRAP_BIND_TAG` | `0x0D` | Bootstrap: the new PQ group's Welcome (PQ-groups-only; no classical commit) |
| `PQ_REKEY_UPD_TAG` | `0x0F` | PQ re-key: initiator's `Upd'` proposal |
| `PQ_REKEY_COMMIT_TAG` | `0x11` | PQ re-key: `[Commit'][counter-Upd'-or-empty]` |

Each multi-section frame uses a `u32`-LE length prefix per embedded field. Hosts
classify PQ side-band frames via the exported `pq_frame_kind` (never by matching raw
tag bytes); everything that is not a side-band frame or a standalone welcome routes to
`process_incoming`.

## The message frame: always staple the commit

The message path has exactly one shape, `[0x03][staple][proposal][app]`, with **no
optional sections**:

- **`staple`** — the sender's latest send-group classical commit, re-stapled on
  **every** frame until superseded, or the send group's APQWelcome until the first
  commit exists. Any single received frame therefore brings the peer up to the
  sender's current epoch: losing the frame that first carried a commit no longer
  strands the direction — the next frame heals it. (Multi-commit gaps still exceed
  one staple; that is reconnect territory.)
- **`proposal`** — the routine `Upd(sender)` addressed to the peer's send group,
  staged on every round, including principal-rotation rounds.
- **`app`** — the application message; its authenticated data is
  `sha256(proposal)` on every round.

The staple slot self-discriminates by its first byte: an APQWelcome starts `0x01`,
an `MLSMessage` starts `0x00` (its two-byte `ProtocolVersion`). The receiver
processes staples **idempotently** — a welcome for an already-joined group and a
commit older than the receive group's epoch are cheap skips; a commit *ahead* of the
receive group surfaces `EpochDesync` before the app ciphertext is touched.

**Rotation is not a frame kind.** A principal rotation is a commit whose
authenticated data carries the new `ClientId` (ratchet commits have empty AD — that
is the whole discriminator). It rides the same message frame, stages the same
routine proposal, and folds any queued peer proposal it finds cached.

## Why re-stapling stays cheap

Commits *can* be large, but the protocol keeps the classical staple small by design:
classical stapled commits carry **no PQ keys** — PQ work rides partial PQ commits on
the side-band (no updatePath), and big ML-KEM updatePaths are isolated to A.5 on the
PQ groups alone. So the steady-state staple is a classical two-member commit, a few
hundred bytes.

The unavoidably large staples are the APQ welcomes, and only until the first commit:

- the **acceptor** staples only a classical-half welcome (~1 KB) — its PQ group is
  deferred to the A.4 bootstrap for exactly this reason;
- the **initiator** re-staples its full two-half APQ welcome (ML-KEM-sized, several
  KB) on every frame until its first commit — a window that is app-gated (it closes
  when the first peer proposal is approved and committed) and whose repeats the peer
  skips idempotently.

## Why the tags are odd

All tags are **odd** — the rule that lets a tagged frame and an MLS message be told
apart from their first byte alone. An `MLSMessage` begins with its two-byte
`ProtocolVersion` (MLS 1.0 = `0x0001`, big-endian), so its **first byte is always
`0x00`**, and `0x00` is even by construction. The invariant now does double duty: it
is also what makes the message frame's staple slot self-discriminating (welcome
`0x01` vs. commit `0x00`) without a separate discriminator byte. The entire even
space stays unused and in reserve; extending the protocol is "take the next unused
odd value."

## Draft-02 conformance inside the frames

The Germ tags above are the *transport* envelope; inside them the MLS payloads carry
the `draft-ietf-mls-combiner-02` structures directly. The apq crate conforms to the
draft, and the Germ frames **enclose** the draft-02 wire shapes rather than replacing
them.

- **APQInfo** — a GroupContext extension (type `0xF0A1`) present in both halves of each
  APQ group and carried automatically in every Welcome's GroupInfo. It names both group
  ids, the mode, both cipher suites, and the creation-time epochs; it is written once at
  creation and never rewritten, and joiners verify it against the groups they actually
  joined (see [group rules](./group-rules.md), rule 7).
- **AppDataUpdate** — a custom proposal (type `0x0008`) that rides both commits of every
  FULL commit, attesting the new epochs of both halves. Receivers verify the two copies
  agree and match the actual post-commit epochs before any app data is decrypted.
- **Combiner key package (v2)** — the `CombinerKeyPackage` payload adopts the draft's §7
  `APQKeyPackage { t_key_package, pq_key_package }` TLS encoding inside Germ's version
  framing. A v1 (pre-conformance) key package is rejected outright.

The conformance cutover is a hard version bump — `COMBINER_KEY_PACKAGE_VERSION = 2`,
`SESSION_ARCHIVE_VERSION = 8`, `BINDING_CONTRACT_VERSION = 12` — because every occupied
leaf must now advertise the new extension (`0xF0A1`) and proposal (`0x0008`) types, and
a leaf that cannot support them is rejected rather than silently degraded.

## Invariants

The tag values are part of the on-wire protocol; pre-release, a renumber is allowed
(this format renumbered the PQ side-band from `0x0B–0x17` and deleted the retired
`0x07` reservation along with the old `BUNDLED`/`PARTIAL`/`STAPLED_WELCOME` frames —
stale frames from older builds fail loudly in the decoders). When adding a message
type, pick an unused **odd** value, add matching `encode_*`/`decode_*` helpers
following the `u32`-LE length-prefix pattern, and extend `pq_frame_kind` if it is a
side-band frame — hosts dispatch on the classifier, so a frame kind that never
reaches it is invisible to them.
