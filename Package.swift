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
				.product(name: "CommProtocol", package: "autonomous-comm-protocol")
			]
		),
		.testTarget(
			name: "AbstractTwoMLSTests",
			dependencies: ["AbstractTwoMLS"]
		),
	],
	swiftLanguageModes: [.v6]
)
