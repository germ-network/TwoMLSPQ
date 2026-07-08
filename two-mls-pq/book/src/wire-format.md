# Wire Format

Every outbound ciphertext is prefixed with a one-byte tag. Plain application messages
have no tag (they are raw MLS ciphertext starting with the MLS version bytes).

| Tag | Value | Meaning |
|-----|-------|---------|
| `APQ_TAG` | `0x01` | APQ Welcome (session establishment) |
| `BUNDLED_TAG` | `0x03` | Rotation commit + app (agent rotation) |
| `PARTIAL_TAG` | `0x05` | A.2 ratchet frame: optional send-group commit + stapled `Upd(sender)` proposal + app |
| — | `0x07` | Retired (the pre-A.2 full-bundle frame); reserved so old frames are rejected |
| `STAPLED_WELCOME_TAG` | `0x09` | Return APQWelcome stapled onto the acceptor's first app frame |
| `PQ_EK_TAG` | `0x0B` | PQ ratchet: ML-KEM encapsulation key |
| `PQ_CT_TAG` | `0x0D` | PQ ratchet: ML-KEM ciphertext |
| `PQ_BIND_TAG` | `0x0F` | PQ ratchet bind: PQ partial commit + classical commit + app |
| `PQ_BOOTSTRAP_KP_TAG` | `0x11` | Bootstrap: PQ key package for the deferred send-group half |
| `PQ_BOOTSTRAP_BIND_TAG` | `0x13` | Bootstrap: the new PQ group's Welcome |
| `PQ_REKEY_UPD_TAG` | `0x15` | PQ re-key: initiator's `Upd'` proposal |
| `PQ_REKEY_COMMIT_TAG` | `0x17` | PQ re-key: `[Commit'][counter-Upd'-or-empty]` |

Each tagged frame uses a `u32`-LE length prefix per embedded field. For example, the
APQ Welcome is:

```
[0x01][u32-LE classical-len][classical bytes][u32-LE pq-len][pq bytes]
```

## Why the tags are odd

All tags are **odd** — not decoration, but the rule that lets a tagged frame and an
untagged application message be told apart from their first byte alone.

A plain application message carries no tag: it is a raw `MLSMessage`, and an `MLSMessage`
begins with its two-byte `ProtocolVersion` (MLS 1.0 = `0x0001`, big-endian), so its
**first byte is always `0x00`**. On receipt the leading byte is the discriminator — a
recognised tag routes to that frame's decoder, and anything else falls through to the MLS
parser. A tag of `0x00` would make a bare MLS frame and a tagged frame indistinguishable.

Restricting tags to odd values enforces the "never `0x00`" property by construction
(`0x00` is even), so no odd tag can collide with the MLS version prefix — and it does so
without anyone having to reason about which byte values the MLS encoding might take. It
also keeps the entire **even** space unused and in reserve. Extending the protocol is
then simply "take the next unused odd value," which is why the invariant below is stated
that way.

## Invariants

The tag values are part of the on-wire protocol. Changing a tag without a version
negotiation mechanism silently corrupts existing sessions — and a retired tag
(`0x07`) must stay reserved so stale frames fail loudly instead of misparsing. When
adding a message type, pick an unused **odd** value and add matching `encode_*` /
`decode_*` helpers following the existing `u32`-LE length-prefix pattern.
