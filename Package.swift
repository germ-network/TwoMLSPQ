// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import Foundation
import PackageDescription

// The TwoMLSPQ dynamic xcframework is built from the in-repo Rust workspace
// (`rust/`) by `scripts/buildIosDynamic.sh`. Two consumption modes:
//   • In-repo dev/CI set TWOMLSPQ_LOCAL_XCFRAMEWORK to consume the LOCAL build
//     (`buildIos/TwoMLSPQ.xcframework`) — no release needed to test a wire change.
//   • External consumers (the app resolving a git tag) get the pinned url+checksum,
//     which the release workflow rewrites to each new release.
// EITHER WAY, keep `Sources/TwoMLSPQ/two_mls_pq.swift` re-synced from the SAME build
// as the binary (uniffi embeds a checksum contract verified at init; the
// `binding_contract_version()` ↔ `expectedBindingContract` canary guards a mismatch).
// The packaging stays DYNAMIC so the adopting app can still link the legacy static
// MLSrs alongside it (avoids the `_rust_eh_personality` dup-symbol + modulemap
// collision) — a static xcframework is a later step, once the app drops legacy.
let twoMLSPQrs: Target =
	ProcessInfo.processInfo.environment["TWOMLSPQ_LOCAL_XCFRAMEWORK"] != nil
	? .binaryTarget(name: "TwoMLSPQrs", path: "buildIos/TwoMLSPQ.xcframework")
	: .binaryTarget(
		name: "TwoMLSPQrs",
		url:
			"https://github.com/germ-network/TwoMLSPQ/releases/download/v0.10.0/TwoMLSPQ.xcframework.zip",
		checksum: "3ca1b86d265d2ded4ac78da4b0f26373a68ae65e0d814f542422de509a51c0fd"
	)

let package = Package(
	name: "TwoMLSPQ",
	// Import/link floors. The PQ backend's ML-KEM paths additionally require
	// OS 26 (CryptoKit ML-KEM-768) at RUNTIME — that floor applies only to
	// calling the PQ API, not to importing or linking this package.
	platforms: [.iOS(.v17), .macOS(.v15)],
	products: [
		// The forward-looking PUBLIC product: the concrete PQ types (`PQSession`,
		// `PQInvitation`, `PQClient`, …), their value/currency types, and the UniFFI
		// binding. The backward-compat shim PROTOCOLS live in the separate
		// `AbstractTwoMLS` package (which depends on and re-exports this), keeping this
		// product's surface clear of the legacy-shim abstraction.
		.library(
			name: "TwoMLSPQ",
			targets: ["TwoMLSPQ"]
		)
	],
	dependencies: [
		// Not the shim protocol — a type dependency. `TypedDigest`/`DataIdentifier` are
		// load-bearing shared crypto vocabulary (the proposal digest's `.wireFormat` is
		// signed into the cross-party agent handoff), so the concrete types name them.
		.package(
			url: "https://github.com/germ-network/autonomous-comm-protocol.git",
			from: "1.2.0"
		)
	],
	targets: [
		// The public product: the hand-written concrete PQ types + value/currency types,
		// top-level in this module. Depends on the internal binding target below (so the raw
		// UniFFI interface types stay out of this surface) + CommProtocol for `TypedDigest`.
		.target(
			name: "TwoMLSPQ",
			dependencies: [
				"TwoMLSPQBinding",
				.product(name: "CommProtocol", package: "autonomous-comm-protocol"),
			]
		),
		// The generated UniFFI binding (`two_mls_pq.swift`, owning its own `RustBuffer` from
		// `two_mls_pqFFI`). An INTERNAL target — not vended — so its `@unchecked Sendable`
		// interface classes never reach a public consumer; the `TwoMLSPQ` wrapper types are
		// the only supported handles. Kept a distinct module so its generated `PrincipalState`/
		// `SideBandSealing`/… don't collide with the wrapper's currency types of the same name.
		.target(
			name: "TwoMLSPQBinding",
			dependencies: ["TwoMLSPQrs"]
		),
		twoMLSPQrs,
		// The concrete/FFI-level suites: raw-FFI invitation flows and the total
		// TwoMlsPqError → SessionError mapping (`@testable` for the internal error bridge +
		// `import TwoMLSPQBinding` for the raw crate cases). The abstract-surface suites live
		// in the AbstractTwoMLS package, which owns the protocols + conformances.
		.testTarget(
			name: "TwoMLSPQTests",
			dependencies: [
				"TwoMLSPQ",
				"TwoMLSPQBinding",
				.product(name: "CommProtocol", package: "autonomous-comm-protocol"),
			]
		),
	],
	swiftLanguageModes: [.v6]
)
