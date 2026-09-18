---
"@germ-network/two-ml-pq": minor
---

Add `SessionError.Code.checkpointPending`, dispositioned `.retryLater`, so a benign
no-checkpoint session archive is distinguishable from `.archiveInvalid`'s discard-and-
re-establish. A missing checkpoint is a structural gap, not corruption, so the restore
retries and keeps the artifact rather than regenerating it. This closes the free-text
`"acceptorGap:"` detail-prefix workaround downstream.

Caveat: adding a public enum case is technically source-breaking for any downstream
exhaustive `switch` over `Code` without a default — in-repo consumers are verified clean.
