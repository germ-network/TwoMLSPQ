import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// The differential SESSION migration proof (GER-2433 C1): a REAL Rust
// two-mls-pq session pair, driven through full establishment (§A.1 + the
// parallel §A.3 bootstrap, so all four group halves and the PQ round state
// exist) — then one side's `migrationExport()` is minted into a native
// archive, restored, and shown to KEEP MESSAGING with the Rust peer in both
// directions. Runs on macOS 26 with the CryptoKit provider build (the PQ
// 96-byte integrityCheckedRepresentation genuinely reconstructs under
// CryptoKit only).
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper
// names, so FFI record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class SessionMigrationTests: XCTestCase {
	/// The native providers, mirroring the invitation differential suite.
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	// MARK: AC1 — differential session migration (checkpoint kind)

	func testMigratedSessionKeepsMessagingWithRustPeer() throws {
		let pair = try establishedSessionPair()
		let export = try pair.alice.migrationExport()

		// Migrate alice to the native engine and restore her there.
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Rust bob → migrated alice: a fresh frame from the Rust peer decrypts.
		try rustSay(pair.bob, "bob-to-migrated-alice")
		let inbound = try XCTUnwrap(lastRustFrame)
		let opened = try nativeAlice.processIncoming(inbound)
		guard case .decrypted(let decrypted) = opened else {
			XCTFail("expected a decrypted application frame, got \(opened)")
			return
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-to-migrated-alice".utf8))

		// Migrated alice → Rust bob: her reply decrypts on the Rust peer.
		_ = try nativeAlice.prepareToEncrypt()
		let reply = try nativeAlice.encrypt(Data("migrated-alice-to-bob".utf8))
		let bobGot = try XCTUnwrap(pair.bob.processIncoming(ciphertext: reply.frame))
		XCTAssertEqual(
			bobGot.applicationMessage?.appMessageData,
			Data("migrated-alice-to-bob".utf8))
	}

	// MARK: AC2 — core + checkpoint reconcile

	func testMintedCoreAndCheckpointReconcile() throws {
		let pair = try establishedSessionPair()
		let export = try pair.alice.migrationExport()

		// Mint both kinds from the ONE export (a core omits the PQ trees; the
		// reconcile splices them from the checkpoint), then restore from the
		// pair exactly as the app's two-slot persistence would.
		let checkpoint = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		let core = try SessionMigrator.mint(
			kind: .core, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: core, checkpoint: checkpoint,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// The reconciled session messages in both directions with the Rust peer.
		try rustSay(pair.bob, "bob-to-reconciled")
		let inbound = try XCTUnwrap(lastRustFrame)
		guard case .decrypted(let decrypted) = try nativeAlice.processIncoming(inbound)
		else {
			XCTFail("expected a decrypted application frame")
			return
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-to-reconciled".utf8))

		_ = try nativeAlice.prepareToEncrypt()
		let reply = try nativeAlice.encrypt(Data("reconciled-to-bob".utf8))
		let bobGot = try XCTUnwrap(pair.bob.processIncoming(ciphertext: reply.frame))
		XCTAssertEqual(
			bobGot.applicationMessage?.appMessageData, Data("reconciled-to-bob".utf8))
	}

	// MARK: AC3 — mutation-verify

	func testPerturbedExportFailsLoudly() throws {
		let pair = try establishedSessionPair()
		var export = try pair.alice.migrationExport()

		// Flip one byte of the signing secret: the mint's derive-check must
		// reject it (`.archiveInvalid`) — proving the differential test detects
		// a bad export/map rather than merely that something decoded.
		export.identity.signingKey[16] ^= 0xFF
		XCTAssertThrowsError(
			try SessionMigrator.mint(
				kind: .checkpoint, from: export,
				classicalProvider: classicalProvider, pqProvider: pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .archiveInvalid)
		}

		// A corrupted group snapshot must not silently restore-and-decode:
		// whichever layer rejects it, the migrated session must not come up
		// able to decrypt with a wrong key.
		var torn = try pair.alice.migrationExport()
		torn.sendGroup.classical[16] ^= 0xFF
		XCTAssertThrowsError(
			try SessionMigrator.mint(
				kind: .checkpoint, from: torn,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	// MARK: - Rust establishment scaffolding

	/// One full Rust establishment through the FFI: alice initiates to bob's
	/// invitation, ships the parallel §A.3 bootstrap envelope, bob receives and
	/// responds, alice binds — then a commit round discharges the owed bind and
	/// a message round trip confirms both directions. All four group halves
	/// exist at return (`isFullyEstablished` on both ends).
	private func establishedSessionPair() throws -> (
		alice: TwoMLSPQBinding.TwoMlsPqSession, bob: TwoMLSPQBinding.TwoMlsPqSession
	) {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("sm-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("sm-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		// Read the commitment BEFORE emitting: the emit consumes the
		// pre-committed KP and quiets the accessor.
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let kpEnvelope = try aliceSession.pqBootstrapEnvelope()
		let replyEnvelope = try XCTUnwrap(aliceSession.pendingOutbound())

		// Bob holds the parallel KP′ (dispatched by its inner 0x13 tag), then
		// opens the reply and establishes.
		let heldKp: Data
		switch try bobInvitation.openInitial(blob: kpEnvelope) {
		case .bootstrapKp(let frame): heldKp = frame
		case let other:
			throw NSError(
				domain: "sm", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected a bootstrap-KP envelope, got \(other)"
				])
		}
		let welcome: Data
		switch try bobInvitation.openInitial(blob: replyEnvelope) {
		case .establishment(let frame): welcome = try XCTUnwrap(frame.welcome)
		case let other:
			throw NSError(
				domain: "sm", code: 2,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope, got \(other)"
				])
		}
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("sm-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		// Bob stands up his deferred send-PQ half from the held KP′ and sends
		// Welcome′ alongside the return welcome.
		try bobSession.pqBootstrapRespond(kpMsg: heldKp)
		let welcomePrime = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		let returnWelcome = try XCTUnwrap(bobSession.pendingOutbound())

		// Alice establishes off the return welcome, then binds the Welcome′ —
		// her emit registered the A.3 round, so no `pqBootstrapBegin` is needed.
		_ = try aliceSession.processIncoming(ciphertext: returnWelcome)
		try aliceSession.pqBootstrapBind(welcomeMsg: welcomePrime)

		// Discharge the owed bind: bob offers an Upd, alice approves and her
		// next round commits (the bind rides that commit's staple).
		try dischargeBind(binder: aliceSession, peer: bobSession)
		XCTAssertTrue(aliceSession.isFullyEstablished())
		XCTAssertTrue(bobSession.isFullyEstablished())

		// One message round trip in each direction, so both sides have
		// processed a peer frame (and the export's send ratchets are live).
		try rustSay(aliceSession, "confirm-a", deliverTo: bobSession)
		try rustSay(bobSession, "confirm-b", deliverTo: aliceSession)
		return (aliceSession, bobSession)
	}

	/// The last frame `rustSay(_:_:)` produced but did not deliver — the
	/// Rust peer's message for the MIGRATED session to open.
	private var lastRustFrame: Data?

	/// The bind discharge is just a committing round (the peer offers an Upd, the binder
	/// approves + commits it — the bind rides that commit's staple); delegate to the shared
	/// helper rather than duplicating it.
	private func dischargeBind(
		binder: TwoMLSPQBinding.TwoMlsPqSession, peer: TwoMLSPQBinding.TwoMlsPqSession
	) throws {
		try RustSessionTestHelpers.committingRound(binder: binder, peer: peer)
	}

	/// Prepare + encrypt on a Rust session; deliver to `deliverTo` when given,
	/// else park the frame in `lastRustFrame` for the migrated session.
	private func rustSay(
		_ session: TwoMLSPQBinding.TwoMlsPqSession, _ text: String,
		deliverTo: TwoMLSPQBinding.TwoMlsPqSession? = nil
	) throws {
		_ = try session.prepareToEncrypt(proposing: nil)
		let frame = try session.encrypt(appMessage: Data(text.utf8))
		if let deliverTo {
			let got = try XCTUnwrap(
				deliverTo.processIncoming(ciphertext: frame.cipherText))
			XCTAssertEqual(got.applicationMessage?.appMessageData, Data(text.utf8))
		} else {
			lastRustFrame = frame.cipherText
		}
	}
}
