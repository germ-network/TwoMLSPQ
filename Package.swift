// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "AbstractTwoMLS",
	platforms: [.iOS(.v17), .macOS(.v15)],
	products: [
		// Vend the abstraction plus each concrete UniFFI wrapper. The wrappers must be
		// separate modules: each imports its own `*FFI` C module, and both FFI modules
		// declare a C `RustBuffer` / `ForeignBytes` / `RustCallStatus` — ambiguous if
		// imported into one Swift module.
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
			dependencies: ["TwoMLSPQrs"]
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
			name: "TwoMLSPQrs",
			// Dynamic (cdylib) framework xcframework from TwoMLSPQ
			// scripts/buildIosDynamic.sh — dynamic lib + framework packaging lets
			// TwoMLSPQ coexist with the legacy classical static MLSrs lib (avoids both
			// the `_rust_eh_personality` duplicate-symbol link error and the
			// include/module.modulemap collision).
			// IMPORTANT: when this URL changes, re-sync Sources/TwoMLSPQ/two_mls_pq.swift
			// from the SAME release (uniffi embeds a checksum contract verified at init).
			//
			// LOCAL DEV: swap in the sibling checkout's local build while iterating on
			// TwoMLSPQ. After every Rust change, rebuild with `scripts/buildIosDynamic.sh`
			// and re-sync Sources/TwoMLSPQ/two_mls_pq.swift from TwoMLSPQ/bindings/ —
			// binary + binding MUST come from the same build (see above). Keep that
			// swap uncommitted.
			// path: "../TwoMLSPQ/buildIos/TwoMLSPQ.xcframework"
			url:
				"https://github.com/germ-network/TwoMLSPQ/releases/download/0.0.10/TwoMLSPQ.xcframework.zip",
			checksum: "f83f43d1d35afadcfc9adbadae290b6c83209c9c53e6680fcaa4d243108a3acf"
		),
		.testTarget(
			name: "AbstractTwoMLSTests",
			dependencies: ["AbstractTwoMLS", "MLSrsClassic"]
		),
	],
	swiftLanguageModes: [.v6]
)
