---
"@germ-network/abstract-two-mls": minor
---

Bump TwoMLSPQ to v0.6.0 (contract 20): classical-only establishment return key
package, hash-bound A.4 bootstrap key package.

`Client.reply` now returns a fourth element, `bootstrapKpCommitment` (SHA-256 of
the initiator's pre-committed PQ bootstrap key package), and `myKeyPackage` is now
the initiator's CLASSICAL return key package (bare MLS KeyPackage message) rather
than a combiner blob — the PQ key package travels in A.4, bound by that
commitment. `Invitation.receive` gains a required `bootstrapKpCommitment: Data`
parameter (the classical backend ignores it) and takes the classical return key
package as `remoteKeyPackage`. The host binds `myKeyPackage` + `bootstrapKpCommitment`
into its signed identity envelope and threads the commitment back through `receive`.
New `SessionError.Code.bootstrapKpMismatch` (disposition `.discardFrame`) surfaces the
crate's `BootstrapKpMismatch`. `expectedBindingContract` 19 → 20; the vendored
`two_mls_pq.swift` binding + the `TwoMLSPQ.xcframework` binaryTarget are re-synced to
v0.6.0.

App worklist: the anchor/card reply flows switch `myKeyPackage` to the classical
return KP and carry the 32-byte commitment inside the signed AnchorWelcome/CardWelcome;
the receive flows extract it and pass it to `receive(bootstrapKpCommitment:)`. Archive
layout followed the crate's pre-release hard cut, so existing PQ session/invitation
blobs regenerate.
