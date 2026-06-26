# Wire Format

Every outbound ciphertext is prefixed with a one-byte tag. Plain application messages
have no tag (they are raw MLS ciphertext starting with the MLS version bytes).

| Tag | Value | Meaning |
|-----|-------|---------|
| `APQ_TAG` | `0x01` | APQ Welcome (session establishment) |
| `BUNDLED_TAG` | `0x03` | Rotation commit + app (agent rotation) |
| `PARTIAL_TAG` | `0x05` | Receive-group self-Update commit + app |
| `FULL_BUNDLE_TAG` | `0x07` | Epoch-advance + PSK-refresh commit + app |

All tags are **odd**. Each tagged frame uses a `u32`-LE length prefix per embedded
field. For example, the APQ Welcome is:

```
[0x01][u32-LE classical-len][classical bytes][u32-LE pq-len][pq bytes]
```

## Invariants

The tag values are part of the on-wire protocol. Changing a tag without a version
negotiation mechanism silently corrupts existing sessions. When adding a message type,
pick an unused **odd** value and add matching `encode_*` / `decode_*` helpers following
the existing `u32`-LE length-prefix pattern.
