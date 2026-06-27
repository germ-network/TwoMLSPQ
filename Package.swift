// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "AbstractTwoMLS",
	platforms: [.iOS(.v17), .macOS(.v15)],
	products: [
		// Vend all three modules: the abstraction plus each concrete UniFFI wrapper.
		// The wrappers must be separate modules — each generated wrapper imports its own
		// `*FFI` C module, and both FFI modules declare a C `RustBuffer` / `ForeignBytes`
		// / `RustCallStatus`. Importing both into one Swift module makes those types
		// ambiguous; isolating each wrapper in its own module resolves it.
		.library(
			name: "AbstractTwoMLS",
			targets: ["AbstractTwoMLS", "TwoMLSPQ"]
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
			dependencies: ["MLSrs"]
		),
		// Classical implementation — UniFFI wrapper for the legacy mls-rs-uniffi-ios
		// framework. Owns its own `RustBuffer` (from `mls_rs_uniffi_iosFFI`).
		.target(
			name: "MLSrsClassic",
			dependencies: ["MLSrsLegacy"]
		),
		.binaryTarget(
			name: "MLSrsLegacy",
			url:
				"https://github.com/germ-network/mls-rs-uniffi/releases/download/1.1.8/MLSrs.xcframework.zip",
			checksum: "5ece2e77d463d573eaa4e35363c88e2d50a09a16cd57635ed572a26467482d2f"
		),
		.binaryTarget(
			name: "MLSrs",
			url:
				"https://github.com/germ-network/TwoMLSPQ/releases/download/0.0.2/MLSrs.xcframework.zip",
			checksum: "c6e19bcb94c1f86e4f96f434844b0f3ddd459b4b5fca5da45f74b6b9143b24c3"
		),
		.testTarget(
			name: "AbstractTwoMLSTests",
			dependencies: ["AbstractTwoMLS", "MLSrsClassic"]
		),
	],
	swiftLanguageModes: [.v6]
)
