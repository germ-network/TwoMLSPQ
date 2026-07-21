---
"@germ-network/two-mls-pq": patch
---

Fix `PQClient`/`PQInvitation` conformance to `AbstractTwoMLS.Client`/`Invitation`, broken by 0.12.0. The `appBinding:`/`expectedAppBinding:` parameters were added to `PQClient.reply` / `PQInvitation.receive` with a default value, but Swift matches protocol witnesses by exact parameter list — a defaulted extra parameter does not witness the fewer-parameter requirement, so the extension conformances stopped compiling in the downstream AbstractTwoMLS package (the crate's own targets don't exercise them, so it slipped past). Restore the exact-signature `reply(keyPackageMessage:)` / `receive(...)` witnesses and expose the binding via non-defaulted `reply(keyPackageMessage:appBinding:)` / `receive(...:expectedAppBinding:)` overloads that they forward to. No wire, contract, or FFI change.
