---
"@germ-network/two-mls-pq": patch
---

Release tooling (trial): stop republishing the xcframework when it has not changed.

Most releases here change only the Swift wrapper, yet every one rebuilt and
republished the whole ~2.4 MB xcframework. Because the zip embedded mtimes it was
not byte-reproducible, so that republished binary also got a NEW checksum despite
being functionally identical — meaning nothing in the published artifacts could
distinguish "the Rust binary changed" from "we rebuilt the same source on a
different day", and consumers re-downloaded it either way.

`buildIosDynamic.sh` now builds a deterministic archive (fixed mtimes, sorted
entry order, no extra attributes), and the release job skips the pin and upload
when the freshly computed checksum equals the one `Package.swift` already pins.
The checksum becomes the binary's identity, moving only when the binary moves.

**What adopters may notice:** a tag's `Package.swift` can pin an EARLIER tag's
asset url. That is intended — it is the signal that the binary did not change
between those releases, and the checksum still verifies the exact bytes SwiftPM
downloads. Nothing about resolution or verification changes.

Safe by construction: equal checksums mean the archives are byte-identical, so
reuse is definitionally correct, and any mismatch — including build
nondeterminism we have not chased down (the dylibs embed absolute source paths
for panic locations, stable within a CI runner but not across machines) — falls
through to the normal publish path. There is no outcome where a stale binary
ships; the worst case is that the trial never fires and releases publish exactly
as before. Reuse additionally re-verifies that the pinned asset is still
reachable, and publishes fresh if it is not.

**Operational consequence:** published release assets are now load-bearing for
later tags. Do not delete them.
