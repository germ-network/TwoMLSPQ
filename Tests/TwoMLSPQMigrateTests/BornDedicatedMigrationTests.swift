import CryptoKit
import Foundation
import MLSCrypto
import SecretBytes
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// Contract 26 (born-dedicated) migration: a REAL Rust born-dedicated pair, driven through
// classical convergence (folding the acceptor's catch-up Upd) and the A.3 bootstrap, then
// the ACCEPTOR's `migrationExport()`
// is minted into a native archive and shown to keep messaging (and committing) with the Rust
// peer, in both directions, and to survive a native re-archive/restore. Companion to
// `SessionMigrationTests` (the non-dedicated differential); see `RustSessionTestHelpers` for
// the shared FFI establishment scaffolding.
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper names, so FFI
// record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class BornDedicatedMigrationTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	// MARK: - Migrate the born-dedicated ACCEPTOR to native; Rust initiator stays live

	func testMigratedBornDedicatedAcceptorKeepsMessagingAndCommittingWithRustPeer() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPair()
		let export = try pair.bob.migrationExport()
		XCTAssertNotNil(export.pqLeafCustody, "the recv-PQ leaf never catches up in Rust")
		XCTAssertEqual(export.pqLeafCustody?.clientId, pair.invitationId)
		XCTAssertFalse(export.owesEstablishmentEnvelope)
		XCTAssertFalse(export.initiated)

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// A message alice -> bob and bob -> alice.
		try aliceSays(pair.alice, "alice-to-native-bob", to: &nativeBob)
		try bobSays(&nativeBob, "native-bob-to-alice", to: pair.alice)

		// One committing round EACH way.
		// (i) alice folds native bob's Upd.
		_ = try nativeBob.prepareToEncrypt()
		let bobUpdFrame = try nativeBob.encrypt(Data("bob-upd".utf8))
		let aliceOffered = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: bobUpdFrame.frame)?.proposal)
		try pair.alice.queueProposal(digest: aliceOffered.digest)
		let alicePrepared = try pair.alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			alicePrepared.didCommit, "alice's fold of native bob's Upd should commit")
		let aliceCommitFrame = try pair.alice.encrypt(appMessage: Data("alice-commit".utf8))
		let bobCommitOpened = try nativeBob.processIncoming(aliceCommitFrame.cipherText)
		guard case .decrypted(let bobCommitDecrypted) = bobCommitOpened else {
			XCTFail("expected a decrypted application frame, got \(bobCommitOpened)")
			return
		}
		XCTAssertTrue(
			bobCommitDecrypted.didApplyRemoteCommit,
			"native bob should see alice's remote commit applied")

		// (ii) native bob folds alice's Upd.
		_ = try pair.alice.prepareToEncrypt(proposing: nil)
		let aliceUpdFrame = try pair.alice.encrypt(appMessage: Data("alice-upd".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceUpdFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(
			bobPrepared.didCommit, "native bob's fold of alice's Upd should commit")
		let bobCommitFrame = try nativeBob.encrypt(Data("bob-commit".utf8))
		let aliceGotCommit = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: bobCommitFrame.frame))
		XCTAssertEqual(
			aliceGotCommit.applicationMessage?.appMessageData, Data("bob-commit".utf8))

		// A message each way, again — `makeSessionArchive` is `internal` (unreachable
		// here), so re-archive via the return-cadence `StateUpdate` `encrypt()` already
		// carries (`EncryptResult.update` — the pending-advance state a caller needs to
		// persist rides every ordinary send, never a separate opt-in step), paired with
		// the ORIGINAL `.checkpoint` mint. `encrypt` never touches a PQ tree, so this
		// stays `.core` —
		// exactly the app's own two-slot persistence shape, and nothing moved the PQ
		// trees since the mint, so the checkpoint pairs with it cleanly.
		try aliceSays(pair.alice, "alice-to-native-bob-2", to: &nativeBob)
		let latestCore = try bobSaysCapturingCore(
			&nativeBob, "native-bob-to-alice-2", to: pair.alice)

		var restoredBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: latestCore, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		try aliceSays(pair.alice, "alice-to-restored-bob", to: &restoredBob)
		try bobSays(&restoredBob, "restored-bob-to-alice", to: pair.alice)
	}

	// MARK: - Exercise the exported PQ custody key via a mechanical A.5

	/// A.2/A.4 never sign in recv.pq, so a mechanical A.5 (native bob as initiator) is the
	/// only round that ever uses the custodied PQ signing key: `pqRekeyBegin` proposes a
	/// plain (non-rotating) self-Update signed with it into `recvGroup.pq`.
	func testMigratedAcceptorSignsWithCustodiedPQKeyDuringA5Rekey() throws {
		// The AT-DISCHARGE point, not `bornDedicatedSessionPair`: nothing has sent since
		// the A.3 bind discharge, so nothing has auto-staged, and `pqRekeyBegin`'s clean
		// slate precondition holds without needing to drain anything (a drain would
		// discharge a full round and pass the PQ turn away, defeating the point).
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPairAtDischarge()
		let export = try pair.bob.migrationExport()
		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Preconditions `pqRekeyBegin` requires: bob holds the PQ turn (the bootstrap
		// discharge just passed it to him) and nothing else is mid-flight.
		XCTAssertTrue(nativeBob.myPQTurn)

		// Native bob (turn holder) begins the round: an Upd' signed with the custodied key.
		let begin = try nativeBob.pqRekeyBegin()

		// Rust alice (committer) folds it into an includePath commit on her send-PQ group.
		let announced = try pair.alice.pqRekeyRespond(updMsg: begin.frame)
		XCTAssertNil(announced, "the mechanical rekey carries no credential handoff")
		let commitFrame = try XCTUnwrap(pair.alice.pqTakePendingOutbound())

		// Native bob applies alice's Commit' and owes the classical bind.
		_ = try nativeBob.pqRekeyApply(commitFrame)

		// Bind discharge: alice offers an Upd, native bob (the binder) folds + commits it.
		_ = try pair.alice.prepareToEncrypt(proposing: nil)
		let aliceUpdFrame = try pair.alice.encrypt(appMessage: Data("a5-bind-upd".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceUpdFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(bobPrepared.didCommit, "the bind discharge needs a committing round")
		let bobCommitFrame = try nativeBob.encrypt(Data("a5-bind-commit".utf8))
		let aliceGotCommit = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: bobCommitFrame.frame))
		XCTAssertEqual(
			aliceGotCommit.applicationMessage?.appMessageData,
			Data("a5-bind-commit".utf8))

		// A message each way — the round closed cleanly.
		try aliceSays(pair.alice, "post-a5-alice", to: &nativeBob)
		try bobSays(&nativeBob, "post-a5-bob", to: pair.alice)
	}

	// MARK: Mutations

	func testNilPQLeafCustodyThrowsArchiveInvalid() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPair()
		var export = try pair.bob.migrationExport()
		export.pqLeafCustody = nil
		XCTAssertThrowsError(
			try SessionMigrator.mintArchive(
				kind: .checkpoint, from: export,
				classicalProvider: classicalProvider, pqProvider: pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .archiveInvalid)
		}
	}

	func testFlippedPQLeafCustodySigningKeyThrowsArchiveInvalid() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPair()
		var export = try pair.bob.migrationExport()
		export.pqLeafCustody?.pqSigningKey[0] ^= 0xFF
		XCTAssertThrowsError(
			try SessionMigrator.mintArchive(
				kind: .checkpoint, from: export,
				classicalProvider: classicalProvider, pqProvider: pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: Negatives — refused before convergence

	func testPreInstallBobExportThrowsSessionNotReady() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedPending()
		XCTAssertThrowsError(try pair.bob.migrationExport()) { error in
			XCTAssertEqual(error as? TwoMLSPQBinding.TwoMlsPqError, .SessionNotReady)
		}
	}

	func testInstalledButUnfoldedBobExportThrowsSessionNotReady() throws {
		let (pair, _) = try RustSessionTestHelpers.bornDedicatedInstalledUnfolded()
		XCTAssertThrowsError(try pair.bob.migrationExport()) { error in
			XCTAssertEqual(error as? TwoMLSPQBinding.TwoMlsPqError, .SessionNotReady)
		}
	}

	// MARK: - Native <-> Rust one-frame helpers (mirrors `RustSessionTestHelpers`)

	private func aliceSays(
		_ alice: TwoMLSPQBinding.TwoMlsPqSession, _ text: String,
		to nativeBob: inout TwoMLSPQSession.TwoMLSSession
	) throws {
		_ = try alice.prepareToEncrypt(proposing: nil)
		let frame = try alice.encrypt(appMessage: Data(text.utf8))
		let opened = try nativeBob.processIncoming(frame.cipherText)
		guard case .decrypted(let decrypted) = opened else {
			XCTFail("expected a decrypted application frame, got \(opened)")
			return
		}
		XCTAssertEqual(decrypted.applicationMessage, Data(text.utf8))
	}

	private func bobSays(
		_ nativeBob: inout TwoMLSPQSession.TwoMLSSession, _ text: String,
		to alice: TwoMLSPQBinding.TwoMlsPqSession
	) throws {
		_ = try bobSaysCapturingCore(&nativeBob, text, to: alice)
	}

	/// Like `bobSays`, but returns the `EncryptResult`'s own `.core`-kind `StateUpdate`
	/// archive — the only public way to pull a fresh archive out of a live
	/// `TwoMLSSession` (`makeSessionArchive` is `internal`).
	@discardableResult
	private func bobSaysCapturingCore(
		_ nativeBob: inout TwoMLSPQSession.TwoMLSSession, _ text: String,
		to alice: TwoMLSPQBinding.TwoMlsPqSession
	) throws -> SecretArchive {
		_ = try nativeBob.prepareToEncrypt()
		let result = try nativeBob.encrypt(Data(text.utf8))
		let got = try XCTUnwrap(alice.processIncoming(ciphertext: result.frame))
		XCTAssertEqual(got.applicationMessage?.appMessageData, Data(text.utf8))
		XCTAssertEqual(result.update.kind, .core, "encrypt never touches a PQ tree")
		return result.update.archive
	}
}
