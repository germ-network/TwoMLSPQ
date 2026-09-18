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
// EITHER WAY, keep `Sources/TwoMLSPQBinding/two_mls_pq.swift` re-synced from the SAME build
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
			"https://github.com/germ-network/TwoMLSPQ/releases/download/v0.19.0/TwoMLSPQ.xcframework.zip",
		checksum: "0a75041d41b243e92a87ae189c999a03cd8950140fcff58dbd20e677c06f4d69"
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
		),
		// The Rust-free slice: the pure-Swift currency types, no binding/xcframework.
		// For all-Swift consumers (e.g. Android builds, where the xcframework has no
		// slice). `TwoMLSPQ` re-exports it, so `import TwoMLSPQ` is unchanged.
		.library(
			name: "TwoMLSPQTypes",
			targets: ["TwoMLSPQTypes"]
		),
		// The invitation migrator library (GER-2372 R3) — consumes the Rust migration
		// export and mints a native twomlspq-swift invitation archive.
		.library(
			name: "TwoMLSPQMigrate",
			targets: ["TwoMLSPQMigrate"]
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
		// The native-side migrator dependency (GER-2372): twomlspq-swift carries R1's
		// `InvitationMigration.mintArchive` + `MigratedIdentity` and R2's
		// `SessionMigration.mintArchive` + `MigratedSession`, which `TwoMLSPQMigrate`
		// maps the Rust migration exports onto. 0.1.1 is the first tag carrying R2
		// (SessionMigration + the ML-KEM `hpkeSecretKeySize`); its transitive deps
		// (swift-mls, swift-secret-bytes, swift-crypto, GermConvenience) resolve
		// automatically.
		.package(
			url: "https://github.com/germ-network/twomlspq-swift.git",
			.upToNextMinor(from: "0.1.1")
		),
		// Declared directly (not just transitively through twomlspq-swift) because
		// the migrate targets import their products. Library deps stay ranged
		// (`upToNextMinor`) — an exact pin here is what forces a coordinated
		// release of THIS repo every time a dep's patch lands, and is what
		// conflicts against a consumer's own tighter pin; twomlspq-swift's own
		// swift-mls requirement is ranged the same way (the 0.1.1 floor carries
		// the C0 `Nsk` length check). Exactness belongs to the app-level repo.
		.package(
			url: "https://github.com/germ-network/swift-mls.git",
			.upToNextMinor(from: "0.1.1")
		),
		.package(
			url: "https://github.com/germ-network/swift-secret-bytes.git",
			.upToNextMinor(from: "0.4.0")
		)
	],
	targets: [
		// The public product: the hand-written concrete PQ types, top-level in this module
		// (the currency types live in the `TwoMLSPQTypes` target, re-exported). Depends only on
		// the internal binding target below (so the raw UniFFI interface types stay out of this
		// surface) — no external Swift packages.
		.target(
			name: "TwoMLSPQ",
			dependencies: ["TwoMLSPQBinding", "TwoMLSPQTypes"]
		),
		// The binding-free currency types (CoreTypes, PQRatchetTypes, SessionError).
		// NO dependencies — Foundation only; must never depend on TwoMLSPQBinding.
		.target(name: "TwoMLSPQTypes"),
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
		// The migrators (GER-2372 R3, GER-2433 C1): map the Rust engine's migration
		// exports (`TwoMlsPqInvitation.migrationExport`, GER-2484 R2;
		// `TwoMlsPqSession.migrationExport`, GER-2433 C1) onto twomlspq-swift's
		// `InvitationMigration.mintArchive` / `SessionMigration.mintArchive`, MINTING
		// native `SecretArchive`s from legacy Rust state (dual-read / single-write:
		// the Rust engine stays a read-only legacy decoder). Separate target so its
		// twomlspq-swift dependency — and that package's `Invitation`/`ClientID` type
		// names, which collide with this package's — stay out of the public
		// `TwoMLSPQ` product.
		.target(
			name: "TwoMLSPQMigrate",
			dependencies: [
				"TwoMLSPQBinding",
				.product(name: "TwoMLSPQSession", package: "twomlspq-swift"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
				// The session mint takes per-half `CipherSuiteProvider`s (the
				// invitation mint was provider-free) — `MLS.CipherSuiteProvider`
				// lives in swift-mls's MLSCrypto, its `MLS` namespace in MLSCodec.
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "MLSCodec", package: "swift-mls"),
			]
		),
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
		// The migrator's differential proof: a real Rust invitation migrated → restored
		// twomlspq-swift → the SAME §A.1 envelope opened by both engines. Drives the raw
		// FFI directly (the `TwoMLSPQ` wrappers stay out of it), hence the binding plus
		// the native-side modules the restore and providers need.
		.testTarget(
			name: "TwoMLSPQMigrateTests",
			dependencies: [
				"TwoMLSPQMigrate",
				"TwoMLSPQBinding",
				.product(name: "TwoMLSPQSession", package: "twomlspq-swift"),
				.product(name: "TwoMLSPQCrypto", package: "twomlspq-swift"),
				.product(name: "MLSCrypto", package: "swift-mls"),
			]
		),
	],
	swiftLanguageModes: [.v6]
)
