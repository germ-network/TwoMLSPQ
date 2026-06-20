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
			targets: ["AbstractTwoMLS", "TwoMLSPQ", "MLSrsClassic"]
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
				"MLSrsClassic",
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
				"https://github.com/germ-network/mls-rs-uniffi/releases/download/1.1.6/MLSrs.xcframework.zip",
			checksum: "3af8bb4d322d5622c5fcf369ef467436bd38658b7cd2ee780a81bc056ee49867"
		),
		.binaryTarget(
			name: "MLSrs",
			url:
				"https://github.com/germ-network/TwoMLSPQ/releases/download/0.0.1/MLSrs.xcframework.zip",
			checksum: "e6a307ac2cdc01a8207408cfae1b33ab1c064e0ae71d7d7a4e9813aed79ba0c7"
		),
		.testTarget(
			name: "AbstractTwoMLSTests",
			dependencies: ["AbstractTwoMLS"]
		),
	],
	swiftLanguageModes: [.v6]
)
