#!/usr/bin/env bash
#
# The deployed-pin differential run. The harness tests against the DEPLOYED production
# pin (two-mls-pq@c501f9d, mls-rs b43703f), not origin/main Rust — the user chose deployed
# behavior as the differential reference (see Tests/TwoMLSPQMigrateTests/Differential/
# README.md). Two bindings can't coexist in one module, so this SWAPS the pin's binding +
# xcframework into the working tree, runs only the differential suite, and RESTORES main's
# on exit (a trap, so an interrupted run still restores).
#
# The Swift engine leg runs against twomlspq-swift MAIN by default (its scratch checkout is
# fetched/reset every run), so engine changes merged ahead of the released tag are visible to
# the differential. TWOMLSPQ_SWIFT_LOCAL=release (or empty) opts into the released tag instead.
#
# Fail-fast: the suite's `bindingContractMatchesLedger` asserts the linked binding's
# contract version equals the ledger's (33 at the pin). Resolving the released v0.10.0
# binary instead of the local build surfaces as that mismatch, not a late FFI failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_SHA="${DIFFERENTIAL_PIN_SHA:-c501f9d}"
PIN_WORKTREE="${DIFFERENTIAL_PIN_WORKTREE:-/tmp/ger-2566-pin}"
BINDING="Sources/TwoMLSPQBinding/two_mls_pq.swift"
BUILD="buildIos"

# The Swift engine leg runs against twomlspq-swift MAIN by default (Package.swift redirects
# the ranged dep to TWOMLSPQ_SWIFT_LOCAL). Escape hatch: TWOMLSPQ_SWIFT_LOCAL=release — or an
# empty value — skips the redirect and resolves the released tag, for pre/post comparison.
# The checkout's leaf directory MUST be `twomlspq-swift`: SwiftPM derives the package
# identity from it, so any other name fails resolution with "unknown package".
SWIFT_MAIN="${TWOMLSPQ_SWIFT_MAIN:-/tmp/ger-2583-swift-main/twomlspq-swift}"
SWIFT_REPO="${TWOMLSPQ_SWIFT_REPO:-https://github.com/germ-network/twomlspq-swift.git}"
SWIFT_BRANCH="${TWOMLSPQ_SWIFT_BRANCH:-main}"

cd "$ROOT"

# Decide the redirect up front. An explicit non-"release" path overrides the default scratch.
if [ -z "${TWOMLSPQ_SWIFT_LOCAL+x}" ]; then
	SWIFT_REDIRECT=1
elif [ -z "$TWOMLSPQ_SWIFT_LOCAL" ] || [ "$TWOMLSPQ_SWIFT_LOCAL" = release ]; then
	SWIFT_REDIRECT=0
	echo "TWOMLSPQ_SWIFT_LOCAL=${TWOMLSPQ_SWIFT_LOCAL:-(empty)}: resolving the released twomlspq-swift tag."
else
	SWIFT_REDIRECT=1
	SWIFT_MAIN="$TWOMLSPQ_SWIFT_LOCAL"
fi

if [ "$SWIFT_REDIRECT" = 1 ]; then
	if [ "$(basename "$SWIFT_MAIN")" != twomlspq-swift ]; then
		echo "ERROR: local twomlspq-swift checkout must have leaf directory 'twomlspq-swift' (got '$(basename "$SWIFT_MAIN")'). SwiftPM derives the package identity from the leaf." >&2
		exit 1
	fi
	if [ ! -e "$SWIFT_MAIN" ]; then
		echo "Cloning twomlspq-swift $SWIFT_BRANCH → $SWIFT_MAIN"
		git clone --depth 1 --branch "$SWIFT_BRANCH" "$SWIFT_REPO" "$SWIFT_MAIN"
	elif [ ! -d "$SWIFT_MAIN/.git" ]; then
		echo "ERROR: $SWIFT_MAIN exists but is not a git checkout. Remove it and re-run." >&2
		exit 1
	fi
	echo "Updating $SWIFT_MAIN to origin/$SWIFT_BRANCH..."
	git -C "$SWIFT_MAIN" fetch --depth 1 origin "$SWIFT_BRANCH"
	git -C "$SWIFT_MAIN" reset --hard FETCH_HEAD
	export TWOMLSPQ_SWIFT_LOCAL="$SWIFT_MAIN"
fi

# 1. A worktree of TwoMLSPQ at the pin, outside ~/tmp/worktrees/agent (it is a build
#    scratch, not agent work).
if [ ! -d "$PIN_WORKTREE/rust" ]; then
	echo "Creating pin worktree at $PIN_WORKTREE ($PIN_SHA)"
	git -C "$ROOT" worktree add "$PIN_WORKTREE" "$PIN_SHA"
fi

# Reusing an existing worktree is only safe if it is actually AT the pin: a stale checkout
# of a different commit with the same contract version would slip past the binding canary.
ACTUAL_SHA="$(git -C "$PIN_WORKTREE" rev-parse --short=7 HEAD)"
if [ "$ACTUAL_SHA" != "$PIN_SHA" ]; then
	echo "ERROR: $PIN_WORKTREE is at $ACTUAL_SHA, expected $PIN_SHA. Remove it and re-run." >&2
	exit 1
fi

# 2. Build the pin's xcframework + binding (writes buildIos/ + bindings/ in the worktree).
echo "Building the pin xcframework (this takes a while)..."
bash "$PIN_WORKTREE/scripts/buildIosDynamic.sh"

# 3. Stash main's binding + framework, then install the pin's. A single EXIT trap restores
#    both (and Package.resolved, which the twomlspq-swift redirect rewrites) and removes the
#    stash, so an interrupted run leaves neither the tree swapped nor a temp dir behind. The
#    buildIos restore is guarded: the original tree may have had none.
STASH="$(mktemp -d)"
trap 'cp "$STASH/binding" "$BINDING"; rm -rf "$BUILD"; if [ -d "$STASH/buildIos" ]; then cp -R "$STASH/buildIos" "$BUILD"; fi; if [ -f "$STASH/Package.resolved" ]; then cp "$STASH/Package.resolved" Package.resolved; fi; rm -rf "$STASH"; echo "Restored main binding + xcframework + Package.resolved."' EXIT

cp "$BINDING" "$STASH/binding"
cp Package.resolved "$STASH/Package.resolved"
rm -rf "$STASH/buildIos"
if [ -d "$BUILD" ]; then cp -R "$BUILD" "$STASH/buildIos"; fi

cp "$PIN_WORKTREE/bindings/two_mls_pq.swift" "$BINDING"
rm -rf "$BUILD"
cp -R "$PIN_WORKTREE/$BUILD" "$BUILD"

# 4. Run only the differential suite against the pin.
export TWOMLSPQ_LOCAL_XCFRAMEWORK=1
export DIFFERENTIAL_DEPLOYED_PIN=1
# The pin's binding predates the migration-export FFI, so the migrators and the suites
# that import them cannot compile against it; Package.swift drops them under this flag.
export TWOMLSPQ_PIN_BINDING=1
swift test --filter DifferentialHarnessTests "$@"
