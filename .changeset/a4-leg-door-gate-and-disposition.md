---
"@germ-network/two-mls-pq": minor
---

Gate the A.4 leg doors on content type, and stop them answering with `Mls`

The EK and CT doors carry application messages only, but the routing tag is
chosen by the sender, and MLS validates and applies atomically — so a Commit
smuggled behind a leg tag could be *applied*, moving an epoch, before the door's
kind check refused it. The doors now read the content type off the plaintext
framing and refuse anything but an application message before any keys or state
are touched.

Every rejection at those doors also stops reporting `Mls`, whose disposition is
fatal — "our own state may be inconsistent, discard the session". A host reading
that literally tears the session down, so a frame the peer chose must never be
able to ask for one. Misrouted or malformed legs now report the retriable
`DecryptionFailed`; nothing is consumed and nothing is staged either way.

No wire, FFI, or error-variant change.
