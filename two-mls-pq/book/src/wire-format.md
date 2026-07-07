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
| `PQ_EK_TAG` | `0x0B` | PQ ratchet: ML-KEM encapsulation key (`cryptokit` builds) |
| `PQ_CT_TAG` | `0x0D` | PQ ratchet: ML-KEM ciphertext (`cryptokit` builds) |
| `PQ_BIND_TAG` | `0x0F` | PQ ratchet bind: PQ partial commit + classical commit + app (`cryptokit` builds) |
| `PQ_BOOTSTRAP_KP_TAG` | `0x11` | Bootstrap: PQ key package for the deferred send-group half |
| `PQ_BOOTSTRAP_BIND_TAG` | `0x13` | Bootstrap: the new PQ group's Welcome |

All tags are **odd**. Each tagged frame uses a `u32`-LE length prefix per embedded
field. For example, the APQ Welcome is:

```
[0x01][u32-LE classical-len][classical bytes][u32-LE pq-len][pq bytes]
```

## Invariants

The tag values are part of the on-wire protocol. Changing a tag without a version
negotiation mechanism silently corrupts existing sessions — and a retired tag
(`0x07`) must stay reserved so stale frames fail loudly instead of misparsing. When
adding a message type, pick an unused **odd** value and add matching `encode_*` /
`decode_*` helpers following the existing `u32`-LE length-prefix pattern.
