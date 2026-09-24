import CryptoKit
import Foundation
import MLSCrypto
import SecretBytes
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// Contract 26 (born-dedicated) migration: drives a REAL Rust born-dedicated pair through
// classical convergence and the A.3 bootstrap, mints the ACCEPTOR's `migrationExport()` into
// a native archive, and confirms it keeps messaging and committing with the Rust peer, in
// both directions, and survives a native re-archive/restore. Companion to
// `SessionMigrationTests` (the non-dedicated differential); see `RustSessionTestHelpers` for
// the shared FFI establishment scaffolding.
//
// `two_mls_pq` type names collide with this package's wrapper names, so FFI record types are
// module-qualified throughout.

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

		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		try aliceSays(pair.alice, "alice-to-native-bob", to: &nativeBob)
		try bobSays(&nativeBob, "native-bob-to-alice", to: pair.alice)

		// One committing round each way. (i) alice folds native bob's Upd.
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

		// Re-archive by pairing the original `.checkpoint` mint with the `.core` `StateUpdate`
		// that `encrypt()` returns on every send (`makeSessionArchive` itself is `internal`,
		// unreachable from here). `encrypt` never touches the PQ tree, so that checkpoint
		// still applies unchanged.
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

	/// A.2/A.4 never sign in recv.pq, so this mechanical A.5 round (native bob as initiator)
	/// is the only path that exercises the custodied PQ signing key, via `pqRekeyBegin`'s
	/// plain self-Update into `recvGroup.pq`.
	func testMigratedAcceptorSignsWithCustodiedPQKeyDuringA5Rekey() throws {
		// Must start at the AT-DISCHARGE point, not `bornDedicatedSessionPair`: nothing has
		// sent since the A.3 bind discharge, so `pqRekeyBegin`'s clean-slate precondition
		// holds without draining anything (a drain would pass the PQ turn away).
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPairAtDischarge()
		let export = try pair.bob.migrationExport()
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
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

		try aliceSays(pair.alice, "post-a5-alice", to: &nativeBob)
		try bobSays(&nativeBob, "post-a5-bob", to: pair.alice)
	}

	// MARK: Mutations

	/// Nulling `pqLeafCustody` doesn't break the mint: `leafKeys` is authoritative for key
	/// resolution and independently carries the acceptor's recv-PQ custody. Contrast
	/// `testFlippedPQLeafCustodySigningKeyThrowsArchiveInvalid`, where a present but wrong
	/// `pqLeafCustody` still fails its own derive-check.
	func testNilPQLeafCustodyNoLongerBreaksTheMint() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPair()
		var export = try pair.bob.migrationExport()
		export.pqLeafCustody = nil
		XCTAssertNoThrow(
			try SessionMigrator.mint(
				kind: .checkpoint, from: export,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	func testFlippedPQLeafCustodySigningKeyThrowsArchiveInvalid() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPair()
		var export = try pair.bob.migrationExport()
		export.pqLeafCustody?.pqSigningKey[0] ^= 0xFF
		XCTAssertThrowsError(
			try SessionMigrator.mint(
				kind: .checkpoint, from: export,
				classicalProvider: classicalProvider, pqProvider: pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: Pre-convergence: now mints and drives a native session too
	//
	// A born-dedicated acceptor that hasn't installed its establishment envelope, or has
	// installed but not yet converged, still exports cleanly (`owesEstablishmentEnvelope`
	// reports the pre-install case; the custody search resolves whatever each leaf currently
	// presents). These tests mint, restore natively, and keep driving the same protocol
	// steps the live Rust pair would take next.

	func testPreInstallBobExportNowSucceeds() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedPending()
		let export = try pair.bob.migrationExport()
		XCTAssertTrue(export.owesEstablishmentEnvelope)

		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Bob owed his contract-26 handoff pre-migration; native enforces the same
		// non-emittable gate, so install it before anything can send.
		let signedEnvelope = Data("bd-signed-establishment-delegation".utf8)
		_ = try nativeBob.installEstablishmentEnvelope(signedEnvelope)

		// Native bob's first frame carries the `0x0B` handoff staple, so Rust alice pauses
		// on it; approve it out of band (mirroring `installMockEstablishmentEnvelope`) and
		// she joins in the same call.
		_ = try nativeBob.prepareToEncrypt()
		let firstFrame = try nativeBob.encrypt(Data("bob-first".utf8))
		let alicePaused = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: firstFrame.frame))
		let pending = try XCTUnwrap(alicePaused.pendingEstablishment)
		XCTAssertEqual(pending.envelope, signedEnvelope)
		let aliceResumed = try pair.alice.processIncomingApproved(
			ciphertext: firstFrame.frame,
			approvedEnvelopeDigest: Data(SHA256.hash(data: pending.envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: pending.welcome)),
			expectedCreator: pair.dedicatedId)
		XCTAssertEqual(
			aliceResumed?.applicationMessage?.appMessageData, Data("bob-first".utf8))

		_ = try pair.alice.prepareToEncrypt(proposing: nil)
		let aliceFrame = try pair.alice.encrypt(appMessage: Data("alice-1".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("alice-1".utf8))
	}

	func testInstalledButUnfoldedBobExportNowSucceeds() throws {
		let (pair, bobUpd) = try RustSessionTestHelpers.bornDedicatedInstalledUnfolded()
		let export = try pair.bob.migrationExport()

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Alice folds bob's still-outstanding catch-up Upd (the recv-classical lag
		// `leafKeys.recvClassical.pending[dedicatedId]` carried across the mint),
		// converging her copy to his dedicated identity. Bob's install-then-confirm frame is
		// his first-ever send but lands as a window entry rather than framed, so retry with
		// the minted window blob on `.ownOfferWindowRequired`.
		try pair.alice.queueProposal(digest: bobUpd.digest)
		let alicePrepared = try pair.alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			alicePrepared.didCommit, "alice's fold of bob's catch-up Upd should commit")
		let aliceCommitFrame = try pair.alice.encrypt(appMessage: Data("alice-commit".utf8))
		let bobOpened: TwoMLSPQSession.IncomingResult
		do {
			bobOpened = try nativeBob.processIncoming(aliceCommitFrame.cipherText)
		} catch TwoMLSPQSession.TwoMLSError.ownOfferWindowRequired {
			let window = try XCTUnwrap(
				minted.ownOfferWindow,
				"the mint must have returned a window if native demands one")
			bobOpened = try nativeBob.processIncoming(
				aliceCommitFrame.cipherText, ownOfferWindow: window.archive)
		}
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("alice-commit".utf8))
		XCTAssertTrue(
			bobDecrypted.didApplyRemoteCommit,
			"native bob should see alice's fold of his catch-up applied")

		try aliceSays(pair.alice, "post-convergence-alice", to: &nativeBob)
		try bobSays(&nativeBob, "post-convergence-bob", to: pair.alice)
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

	/// Like `bobSays`, but also returns the `EncryptResult`'s `.core` `StateUpdate` archive —
	/// the only public way to pull a fresh archive out of a live session (`makeSessionArchive`
	/// is `internal`).
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
