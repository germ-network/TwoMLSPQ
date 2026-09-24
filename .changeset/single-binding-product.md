---
"@germ-network/two-mls-pq": minor
---

**Breaking:** the `TwoMLSPQMigrate` product is removed. Its module now ships in the `TwoMLSPQ`
product, so `import TwoMLSPQMigrate` (and `import TwoMLSPQBinding`) keep working for any target
that depends on `TwoMLSPQ`. On every target that declared it, swap
`.product(name: "TwoMLSPQMigrate", package: "TwoMLSPQ")` for
`.product(name: "TwoMLSPQ", package: "TwoMLSPQ")`. Imports are unchanged.

With the binding in two products, an Xcode build could link a second copy into one process, for
example the `TwoMLSPQ` product as a shared framework plus `TwoMLSPQMigrate` linked statically into a
test bundle. The first callback through the other copy then aborted with "Callback interface
failure" (`unexpectedStaleHandle`). The binding now lives in exactly one product.
