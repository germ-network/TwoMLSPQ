---
"@germ-network/two-mls-pq": minor
---

`TwoMlsPqSession.migrationExport()` now admits a born-dedicated acceptor, once its
establishment envelope has installed and its recv-classical leaf has caught up, and an
acceptor still holding its parked return welcome (previously refused on both). The
recv-PQ leaf a born-dedicated acceptor's session never catches up now exports as a new
`pqLeafCustody` field, so the app's migrator can seat it correctly on the migrated
side. `BINDING_CONTRACT_VERSION` bumps 35 → 36 for the new record and field.

That catch-up happens only once the peer folds the acceptor's catch-up offer. A caller
that folds only offers introducing a new client never folds it, so such born-dedicated
acceptors remain refused until a later release carries unconverged custody.

Also corrects the 0.17.0 changelog's claim that group state written before that
release ("pre-v35") no longer loads: it does. Sessions written by v0.16.0 restore and
keep messaging under this engine, pinned by fixtures.

`SessionError.Code.misroutedFrame` now has disposition `.discardFrame` (was `.callerBug`): an ill-timed
side-band re-send is normal traffic, and the peer re-sends until answered, so dropping it is lossless.
This shifts app-side handling and any analytics bucketed by disposition.
