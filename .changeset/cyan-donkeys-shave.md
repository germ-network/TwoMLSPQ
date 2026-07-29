---
"@germ-network/two-mls-pq": patch
---

Bump mls-rs to the `germ-integration` pin, and keep `APP_DATA_UPDATE` pathless

The fork's `main` was resynced with upstream `awslabs/mls-rs`, and the Germ changes were
recomposed on top of it as `germ-integration`. The pin moves from `ec69dc25` to
`c6ede1ce`, picking up the crypto providers, a recovered cryptokit build fix, the Safe
Extensions exporter tree, and attachment CEK derivation.

The resync requires one behavioural fix. Upstream added
`MlsRules::custom_proposal_requires_update_path` with a default of `true`, so
`APP_DATA_UPDATE` — an attestation that changes no group membership — began forcing an
updatePath. On the PQ half that put an ML-KEM updatePath on a commit that must stay
pathless: the bind commit grew past a whole ML-KEM-768 ciphertext. `TwoMlsRules` now
overrides the hook to `false`, restoring the behaviour `apq` was written against. Where a
path _is_ wanted — the FULL commit discharging an owed bind on the classical half —
`commit_options` still pins it explicitly, which is where that decision belongs.

Also drops `serde` — both the `mls-rs` feature and the unused `[workspace.dependencies]`
entry. Nothing in the workspace consumes either: no `.rs` file references serde and no
member crate declares it. mls-rs's serde derives are `cfg_attr`-attached, so they never
participate in `MlsEncode`/`MlsDecode`; removing the feature cannot move a byte of the
stored format. Archiving goes through the crate's own `MlsEncode`/`MlsDecode` wire
structs, which are untouched.

No wire, FFI, or error-variant change. Group state written by the previous pin still
loads.
