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
// RELEASE CONVENTION — the `url` + `checksum` below must always name an ALREADY-RELEASED tag
// with that release's real, CI-computed checksum. NEVER pre-bump them to the next, unreleased
// version: `release-artifacts.yml`'s finalize job pins the NEW tag itself on publish (it builds
// the zip on the pinned runner, so the checksum only exists then), and its idempotency guard
// SKIPS build+pin+upload when the url already names the tag being finalized. A hand-pre-pinned
// url therefore ships a release with NO asset — the url 404s. Leave these lagging; the workflow
// pins each tag forward. (v0.10.0 was shipped asset-less exactly this way; see the guard fix.)
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
		checksum: "897071cf3ba8fd278c205aa13dcea3303dc01195167dc39e7eabc7510db51dee"
	)

// ANDROID (DEPS-1 prototype). xcframeworks are Apple-only: SwiftPM's
// `BinaryTarget+Extensions.swift` maps the android environment to `nil`, so an xcframework
// binaryTarget resolves to ZERO libraries on an Android triple — silently, with no diagnostic.
// Android therefore needs its OWN binary target, and it is an SE-0482 artifactbundle
// (Swift 6.2+) carrying the STATIC `libtwo_mls_pq.a` plus its headers and modulemap, because
// `ArtifactsArchiveMetadata` has no `dynamicLibrary` artifact type. iOS stays dynamic for the
// reasons above; the two platforms ship separate products from the same crate.
// `binaryTarget` itself cannot be conditioned, so both are declared and the DEPENDENCY EDGE
// carries the platform condition. Gated on an env var while this is a spike; a release would
// pin both by url+checksum — note `release-artifacts.yml`'s checksum rewrite is `count=1` and
// would silently mis-pin the first of two binaryTargets, so it must be anchored to the target
// name before a second one ships.
let localAndroid = ProcessInfo.processInfo.environment["TWOMLSPQ_LOCAL_ANDROID"] != nil

let androidBinaryTargets: [Target] =
	localAndroid
	? [
		.binaryTarget(
			name: "TwoMLSPQrsAndroid",
			path: "buildAndroid/TwoMLSPQ-android.artifactbundle"
		)
	]
	: []

let bindingDependencies: [Target.Dependency] =
	localAndroid
	? [
		.target(name: "TwoMLSPQrs", condition: .when(platforms: [.iOS, .macOS])),
		.target(name: "TwoMLSPQrsAndroid", condition: .when(platforms: [.android])),
	]
	: ["TwoMLSPQrs"]

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
		// TEST-ONLY. The public product has no external Swift dependencies: digests and
		// routing ids cross its surface as self-describing `Data` this package owns (see
		// PQDigest.swift), so a suite change ships from here without a CommProtocol
		// release. The test target still mints client ids with `AgentPrivateKey` the way
		// the app does — `ClientID` IS `AgentPublicKey.wireFormat`, carried opaquely but
		// persisted in MLS group state, so testing against the real encoding is the point.
		.package(
			url: "https://github.com/germ-network/autonomous-comm-protocol.git",
			from: "1.2.0"
		),
		// NON-APPLE ONLY, and linked as such: `PQDigest` needs SHA-256, which comes from
		// CryptoKit on Apple and from swift-crypto everywhere else. The target edge below is
		// conditioned, so nothing extra is linked into an Apple build — but the package
		// dependency itself is unconditional, because SwiftPM resolves dependencies before it
		// knows the target platform. Already in the resolved graph transitively (4.5.0).
		.package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
	],
	targets: [
		// The public product: the hand-written concrete PQ types + value/currency types,
		// top-level in this module. Depends ONLY on the internal binding target below (so the
		// raw UniFFI interface types stay out of this surface) — no external Swift packages.
		.target(
			name: "TwoMLSPQ",
			dependencies: [
				"TwoMLSPQBinding",
				// SHA-256 for PQDigest where there is no CryptoKit. Conditioned, so an Apple
				// build links nothing extra — see the import in PQDigest.swift.
				.product(
					name: "Crypto",
					package: "swift-crypto",
					condition: .when(platforms: [.android, .linux])
				),
			]
		),
		// The generated UniFFI binding (`two_mls_pq.swift`, owning its own `RustBuffer` from
		// `two_mls_pqFFI`). An INTERNAL target — not vended — so its `@unchecked Sendable`
		// interface classes never reach a public consumer; the `TwoMLSPQ` wrapper types are
		// the only supported handles. Kept a distinct module so its generated `PrincipalState`/
		// `SideBandSealing`/… don't collide with the wrapper's currency types of the same name.
		.target(
			name: "TwoMLSPQBinding",
			dependencies: bindingDependencies,
			linkerSettings: [
				// SE-0482 artifactbundles do not propagate transitive link dependencies, and a
				// Rust staticlib needs its libc satellites named explicitly. This is what
				// `rustc --print=native-static-libs` reports for aarch64-linux-android
				// (`-ldl -llog -lunwind -ldl -lm -lc`, less the two the linker always adds).
				.linkedLibrary("dl", .when(platforms: [.android])),
				.linkedLibrary("log", .when(platforms: [.android])),
				.linkedLibrary("unwind", .when(platforms: [.android])),
				.linkedLibrary("m", .when(platforms: [.android])),
			]
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
	] + androidBinaryTargets,
	swiftLanguageModes: [.v6]
)
