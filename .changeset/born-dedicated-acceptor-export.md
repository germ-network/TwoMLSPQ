---
"@germ-network/two-mls-pq": minor
---

`TwoMlsPqSession.migrationExport()` now exports every reachable session state instead of
refusing unsettled ones: pre-establishment initiators, born-dedicated acceptors at any point,
staged rotation candidates, lagging leaves, and parked or wedged PQ rounds. It fails only on
corrupt data (`ArchiveInvalid`). The export carries per-group signing keys (`leafKeys`), the
rotation candidate, an own-offer window with its leaf secrets, and deployed-engine flags
(`deployedState`). A pre-A.3 acceptor's `leafKeys.sendPq` is empty, since A.3 founding mints
its own key, and `leafKeys.sendClassical` carries `current` only. Minting requires
twomlspq-swift 0.3.0 or later. `BINDING_CONTRACT_VERSION` bumps 35 → 36.

`SessionMigrator.mintArchive(kind:from:classicalProvider:pqProvider:)` is removed.
`SessionMigrator.mint(kind:from:classicalProvider:pqProvider:)` returns a `MintResult`: the
session archive plus, when present, the minted own-offer window, which the caller must persist
before the archive.

`SessionError.Code.misroutedFrame` now has disposition `.discardFrame` (was `.callerBug`): an
ill-timed side-band re-send is normal traffic. This shifts app-side handling and any analytics
bucketed by disposition.

Also corrects the 0.17.0 changelog's claim that pre-v35 group state no longer loads: it does,
and sessions written by v0.15.0 and v0.16.0 restore and migrate, pinned by fixtures.
