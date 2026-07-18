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
			"https://github.com/germ-network/TwoMLSPQ/releases/download/v0.7.0/TwoMLSPQ.xcframework.zip",
		checksum: "800f13693b86b2c9784092baf9ec2e0f94ccfc6f94b90d4cd01dc7c9ac70cee6"
	)

let package = Package(
	name: "AbstractTwoMLS",
	// Import/link floors. The PQ backend's ML-KEM paths additionally require
	// OS 26 (CryptoKit ML-KEM-768) at RUNTIME — that floor applies only to
	// calling the PQ API, not to importing or linking this package.
	platforms: [.iOS(.v17), .macOS(.v15)],
	products: [
		// Vend ONLY the abstraction. The concrete UniFFI wrapper (`TwoMLSPQ`) stays an
		// internal target (it still links transitively): uniffi stamps its interface
		// classes `@unchecked Sendable` (Rust Send+Sync, lock-serialized — memory-safe
		// but with no ordering guarantees), so exposing it would hand consumers a
		// freely-shareable session handle and defeat the deliberately non-Sendable
		// wrapper types, which are the only supported session handles.
		.library(
			name: "AbstractTwoMLS",
			targets: ["AbstractTwoMLS"]
		)
	],
	dependencies: [
		.package(
			url: "https://github.com/germ-network/autonomous-comm-protocol.git",
			from: "1.2.0"
		)
	],
	targets: [
		// Abstraction layer. Hosts the protocol surface (and, later, the conformances
		// mapping each concrete implementation onto it).
		.target(
			name: "AbstractTwoMLS",
			dependencies: [
				"TwoMLSPQ",
				.product(name: "CommProtocol", package: "autonomous-comm-protocol"),
			]
		),
		// PQ implementation — UniFFI wrapper for the TwoMLSPQ framework. Owns its own
		// `RustBuffer` (from `two_mls_pqFFI`).
		.target(
			name: "TwoMLSPQ",
			dependencies: ["TwoMLSPQrs"]
		),
		twoMLSPQrs,
		.testTarget(
			name: "AbstractTwoMLSTests",
			// TwoMLSPQ is named explicitly: the tests exercise the concrete
			// backend directly (in-package target imports are unaffected by the
			// product narrowing above — external consumers can import only
			// AbstractTwoMLS).
			dependencies: ["AbstractTwoMLS", "TwoMLSPQ"]
		),
	],
	swiftLanguageModes: [.v6]
)
