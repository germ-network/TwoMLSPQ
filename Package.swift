// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "AbstractTwoMLS",
	platforms: [.iOS(.v17), .macOS(.v15)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
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
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "AbstractTwoMLS",
			dependencies: [
				"MLSrs",
				.product(name: "CommProtocol", package: "autonomous-comm-protocol")
			]
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
