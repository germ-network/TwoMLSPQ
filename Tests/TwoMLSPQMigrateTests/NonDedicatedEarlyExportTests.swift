import CryptoKit
import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// A NON-dedicated acceptor that never drains `pendingOutbound()` exports fine even BEFORE
// the initiator has processed anything from it — the acceptor's parked return
// welcome rides `current_staple` until its own first send-group commit, so the initiator
// still joins off the very first ordinary frame. See the module note in
// `rust/two-mls-pq/src/session/migration.rs`.

@available(macOS 26, iOS 26, *)
final class NonDedicatedEarlyExportTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	func testMigratedAcceptorsFirstFrameEstablishesRustInitiator() throws {
		let (aliceSession, bobSession) = try establishNonDedicatedPair()

		// Export bob BEFORE alice has processed anything from him: he never drained
		// `pendingOutbound()`, and alice has not yet joined Group_B.
		let export = try bobSession.migrationExport()
		XCTAssertNil(export.pqLeafCustody, "a non-dedicated acceptor carries no PQ custody")
		XCTAssertNotNil(
			export.joinedWelcomeDigest,
			"bob's own join of Group_A is recorded even though it came via the `welcome:` "
				+ "parameter, not a staple — he needs it to dedup alice's later re-staples"
		)

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Native bob's FIRST frame: its staple is still his birth return-welcome (he has not
		// committed his own send group yet) — delivering it must JOIN Rust alice AND decrypt
		// the app message in the same call.
		_ = try nativeBob.prepareToEncrypt()
		let firstFrame = try nativeBob.encrypt(Data("bob-first".utf8))
		let aliceResult = try XCTUnwrap(
			aliceSession.processIncoming(ciphertext: firstFrame.frame))
		XCTAssertEqual(
			aliceResult.applicationMessage?.appMessageData, Data("bob-first".utf8))

		// Messages both ways. Alice has not committed either, so HER frames still re-staple
		// HER OWN birth welcome (Welcome_A) — native bob's `recvGroup` is already established
		// (joined via the `welcome:` parameter at `receive`, not a staple), so he must
		// recognize the repeat and skip re-joining (`joinedWelcomeDigest`), just decrypting.
		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let aliceFrame1 = try aliceSession.encrypt(appMessage: Data("alice-1".utf8))
		let bobOpened1 = try nativeBob.processIncoming(aliceFrame1.cipherText)
		guard case .decrypted(let bobDecrypted1) = bobOpened1 else {
			XCTFail("expected a decrypted application frame, got \(bobOpened1)")
			return
		}
		XCTAssertEqual(bobDecrypted1.applicationMessage, Data("alice-1".utf8))

		_ = try nativeBob.prepareToEncrypt()
		let bobFrame2 = try nativeBob.encrypt(Data("bob-2".utf8))
		let aliceGot2 = try XCTUnwrap(
			aliceSession.processIncoming(ciphertext: bobFrame2.frame))
		XCTAssertEqual(aliceGot2.applicationMessage?.appMessageData, Data("bob-2".utf8))

		// A second alice frame, STILL re-stapling Welcome_A (she still has not committed):
		// the dedup must keep holding, not just work once.
		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let aliceFrame2 = try aliceSession.encrypt(appMessage: Data("alice-2".utf8))
		let bobOpened2 = try nativeBob.processIncoming(aliceFrame2.cipherText)
		guard case .decrypted(let bobDecrypted2) = bobOpened2 else {
			XCTFail("expected a decrypted application frame, got \(bobOpened2)")
			return
		}
		XCTAssertEqual(bobDecrypted2.applicationMessage, Data("alice-2".utf8))
	}

	/// Mutation: blank `joinedWelcomeDigest` in the export — the mint still succeeds (the
	/// field is optional data, not cross-checked at mint time), but the flow it exists to
	/// support breaks downstream: native bob can no longer recognize alice's re-stapled
	/// birth welcome as an already-joined repeat, and `processIncoming` throws
	/// `.unexpectedWelcome` instead of decrypting.
	func testNilJoinedWelcomeDigestBreaksTheReStapleDedup() throws {
		let (aliceSession, bobSession) = try establishNonDedicatedPair()
		var export = try bobSession.migrationExport()
		export.joinedWelcomeDigest = nil

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Bob's own first frame still establishes alice fine — this direction never
		// consults bob's `joinedWelcomeDigest` (that guards HIS reads of HER re-staples).
		_ = try nativeBob.prepareToEncrypt()
		let firstFrame = try nativeBob.encrypt(Data("bob-first".utf8))
		_ = try XCTUnwrap(aliceSession.processIncoming(ciphertext: firstFrame.frame))

		// Alice's first ordinary frame re-staples her own birth welcome (Welcome_A) — with
		// no `joinedWelcomeDigest` to recognize it, native bob's dedup guard fails closed.
		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let aliceFrame = try aliceSession.encrypt(appMessage: Data("alice-1".utf8))
		XCTAssertThrowsError(try nativeBob.processIncoming(aliceFrame.cipherText)) {
			error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .unexpectedWelcome)
		}
	}

	// MARK: - Scaffolding

	/// alice initiates, bob `receive`s under NO dedicated id (`newClientId: nil`) and never
	/// drains `pendingOutbound()` — the app's real acceptor shape (it never drains one).
	private func establishNonDedicatedPair() throws -> (
		alice: TwoMLSPQBinding.TwoMlsPqSession, bob: TwoMLSPQBinding.TwoMlsPqSession
	) {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("nd-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("nd-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let envelope = try XCTUnwrap(aliceSession.pendingOutbound())
		guard case .establishment(let frame) = try bobInvitation.openInitial(blob: envelope)
		else {
			throw NSError(
				domain: "establishNonDedicatedPair", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope"
				])
		}
		let welcome = try XCTUnwrap(frame.welcome)
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("nd-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		return (aliceSession, bobSession)
	}
}
