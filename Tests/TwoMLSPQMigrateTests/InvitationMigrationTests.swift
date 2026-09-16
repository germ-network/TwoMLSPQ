import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// The differential migration proof (GER-2372 R3): a REAL Rust invitation,
// migrated to a native archive and restored, opens the SAME §A.1 envelope
// the Rust invitation opens — equivalently, not just successfully. Runs on
// macOS 26 with the CryptoKit provider build (the PQ 96-byte
// integrityCheckedRepresentation is seed-bearing and genuinely reconstructs
// under CryptoKit only).
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper
// names, so FFI record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class InvitationMigrationTests: XCTestCase {
	/// The native providers, mirroring twomlspq-swift's own test scaffolding.
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	private func rustInvitation(clientId: Data, lastResort: Bool) throws -> (
		base: TwoMLSPQBinding.TwoMlsPqInvitation,
		export: TwoMLSPQBinding.MigrationExport
	) {
		let principal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: clientId)
		let archive = try principal.generateInvitation(lastResort: lastResort)
		let base = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(archive: archive)
		return (base, try base.migrationExport())
	}

	// MARK: AC1 — differential open

	func testMigratedInvitationOpensSameEnvelope() throws {
		let clientId = Data("mig-diff".utf8)
		let (rustInvitation, export) = try rustInvitation(
			clientId: clientId, lastResort: true)

		// Seal a §A.1 establishment envelope to the invitation's published PQ key
		// package via the Rust engine's own primitives (fresh ML-KEM encapsulation
		// per call — cross-impl comparison must be seal-then-open, never ciphertext
		// equality), then open it with BOTH engines and require the same frame.
		let published = rustInvitation.combinerKeyPackage()
		var plaintext = Data([0x07])  // ESTABLISHMENT_VECTOR_TAG
		for section in [Data("differential payload".utf8)] as [Data?] {
			var length = UInt32(section?.count ?? 0).littleEndian
			withUnsafeBytes(of: &length) { plaintext.append(contentsOf: $0) }
			if let section { plaintext.append(section) }
		}
		for _ in 0..<3 { plaintext.append(contentsOf: [0, 0, 0, 0]) }  // absent sections
		let sealed = try TwoMLSPQBinding.hpkeSealToKeyPackage(
			keyPackage: published, plaintext: plaintext, info: nil,
			aad: TwoMLSPQBinding.envelopeFramingAad())
		// The §A.1 outer frame: `[u32-LE kem_len][kem_output][ciphertext]`, no tag.
		var blob = Data()
		var kemLen = UInt32(sealed.kemOutput.count).littleEndian
		withUnsafeBytes(of: &kemLen) { blob.append(contentsOf: $0) }
		blob.append(sealed.kemOutput)
		blob.append(sealed.ciphertext)

		let rustOpened = try rustInvitation.openInitial(blob: blob)

		let nativeArchive = try InvitationMigrator.mintArchive(from: export)
		let native = try TwoMLSPQSession.Invitation.restore(
			archive: nativeArchive,
			classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let nativeOpened = try native.openInitial(blob)

		guard case .establishment(let nativeFrame) = nativeOpened,
			case .establishment(let rustFrame) = rustOpened
		else {
			XCTFail("open was not an establishment frame on both engines")
			return
		}
		XCTAssertEqual(nativeFrame.appPayload, rustFrame.appPayload)
		XCTAssertEqual(nativeFrame.appPayload, Data("differential payload".utf8))

		// Publication continuity: the migrated invitation must hand out the SAME
		// combiner key package bytes the Rust one published — a peer holding the
		// pre-migration KP must keep resolving this identity.
		// Publication continuity: the migrated invitation re-publishes the SAME
		// key packages (the native halves decode from — and re-encode to — the
		// export's bare bytes; the Rust side's published form is the MLSMessage
		// frame around those exact bytes, 4 header bytes larger).
		let nativeKP = try XCTUnwrap(native.combinerKeyPackage)
		let identity = try XCTUnwrap(export.identity)
		XCTAssertEqual(try nativeKP.classical.mlsEncoded(), identity.classicalKeyPackage)
		XCTAssertEqual(try nativeKP.pq.mlsEncoded(), identity.pqKeyPackage)
	}

	// MARK: AC2 — spent single-use

	func testSpentSingleUseMigratesToIdentityNilArchive() throws {
		// Consume a single-use invitation through a real establishment (the only path
		// that spends it), then migrate: `identity == nil`, and the restored native
		// invitation fails `openInitial` cleanly (`.invitationSpent`-equivalent).
		let round = try establishedInvitation(lastResort: false)
		let export = try round.base.migrationExport()
		XCTAssertNil(export.identity)

		let nativeArchive = try InvitationMigrator.mintArchive(from: export)
		let native = try TwoMLSPQSession.Invitation.restore(
			archive: nativeArchive,
			classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		XCTAssertNil(native.combinerKeyPackage)
		XCTAssertThrowsError(try native.openInitial(Data([0x07]))) { error in
			XCTAssertEqual(error as? TwoMLSError, .invitationSpent)
		}
	}

	// MARK: AC3 — routing tables survive

	func testRoutingTablesSurviveMigration() throws {
		// A last-resort invitation with a real accepted welcome: spawned/processed/
		// bootstrap/consumed all populate. The restored native invitation must resolve
		// the same receive-group classical ids.
		let round = try establishedInvitation(lastResort: true)
		let export = try round.base.migrationExport()

		XCTAssertEqual(export.consumedRemotes.count, 1)
		XCTAssertEqual(export.forwardTable.count, 1)
		XCTAssertEqual(export.processedWelcomes.count, 1)
		XCTAssertEqual(export.bootstrapRouting.count, 1)
		XCTAssertEqual(export.stateSeq, 1)

		let expectedGroupID = round.receiveGroupID
		let nativeArchive = try InvitationMigrator.mintArchive(from: export)
		let native = try TwoMLSPQSession.Invitation.restore(
			archive: nativeArchive,
			classicalProvider: classicalProvider,
			pqProvider: pqProvider)

		XCTAssertEqual(
			native.forwardGroupID(spawnToken: round.spawnToken), expectedGroupID)
		XCTAssertEqual(
			native.processedWelcomeGroupID(welcome: round.welcome), expectedGroupID)
		XCTAssertEqual(
			native.bootstrapKPGroupID(kpFrame: round.bootstrapKPFrame), expectedGroupID)
	}

	// MARK: AC4 — mutation-verify

	func testPerturbedSecretIsRejectedAtMint() throws {
		// Flip one byte of an exported secret: the mint must fail LOUDLY
		// (`.archiveInvalid`) — proving the differential test detects a bad
		// export/map rather than merely that something decoded.
		let (_, export) = try rustInvitation(
			clientId: Data("mig-mutate".utf8), lastResort: true)
		var identity = try XCTUnwrap(export.identity)
		// A middle byte: X25519 clamps byte 0's low bits away, so a flip there
		// could survive clamping-adjacent to the original scalar.
		identity.classicalInitSecretKey[16] ^= 0xFF
		var perturbed = export
		perturbed.identity = identity

		XCTAssertThrowsError(try InvitationMigrator.mintArchive(from: perturbed)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
		// The unperturbed export still mints — the rejection is the mutation, not
		// a broken fixture.
		XCTAssertNoThrow(try InvitationMigrator.mintArchive(from: export))
	}

	// MARK: - Rust establishment scaffolding

	/// Facts of one Rust two-party establishment round: the receiver's invitation,
	/// the spawn token, the exact welcome bytes, the bootstrap-KP commitment, and the
	/// spawned session's receive-group classical id.
	private struct Establishment {
		let base: TwoMLSPQBinding.TwoMlsPqInvitation
		let spawnToken: Data
		let welcome: Data
		let bootstrapKPFrame: Data
		let receiveGroupID: Data
	}

	/// A full Rust two-party establishment through the FFI: Alice initiates to Bob's
	/// invitation, Bob receives (populating consumed/spawned/processed/bootstrap and,
	/// for a single-use invitation, consuming the key package).
	private func establishedInvitation(lastResort: Bool) throws -> Establishment {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("mig-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mig-bob".utf8))
		let bobArchive = try bobPrincipal.generateInvitation(lastResort: lastResort)
		let bob = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(archive: bobArchive)

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bob.combinerKeyPackage(), appBinding: nil)
		let welcome = try XCTUnwrap(aliceSession.initialWelcome())
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		// The parallel KP-prime envelope (read AFTER the commitment, before anything
		// else consumes the round), opened with Bob's own invitation for the
		// bootstrap frame a self-route resolves on.
		let kpEnvelope = try aliceSession.pqBootstrapEnvelope()
		let opened = try bob.openInitial(blob: kpEnvelope)
		guard case .bootstrapKp(let kpFrame) = opened else {
			throw NSError(
				domain: "mig", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected a bootstrap-KP envelope"
				])
		}
		let spawnToken = Data("mig-spawn-token".utf8)
		let bobSession = try bob.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: spawnToken,
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		let groups = try XCTUnwrap(bobSession.receiveGroupId())
		return Establishment(
			base: bob, spawnToken: spawnToken, welcome: welcome,
			bootstrapKPFrame: kpFrame, receiveGroupID: groups.classical.bytes)
	}
}
