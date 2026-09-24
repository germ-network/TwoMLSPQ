import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import XCTest

// Testable only to read native own-leaf ids, which have no public accessor.
@testable import TwoMLSPQSession

// A stuck §A.5 rekey, cross-engine: a deployed Rust party (A) rotates its classical
// identity, its lagging send-PQ leaf opens §A.5 to catch up in the peer-committed PQ
// group, and the peer (B) has since migrated to native. Companion to
// `BornDedicatedMigrationTests`'s mechanical A.5 case (native initiates, Rust responds):
// this drives the other direction. Alice's own send-PQ leaf is never moved by any of
// this — only a responder's own Commit' carries its current credential
// (`pq_rekey_respond`'s `set_new_signing_identity`), and nothing here makes alice a
// responder catching herself up — but `leafKeys`'s general catch-up carries that lag
// directly, so she migrates too, at the end.
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper names, so FFI
// record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class RotatedRekeyHealTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	// MARK: - HEAL: B folds A's rotation, then heals A's stuck A.5 across engines

	func testNativeBHealsRotatedRustAsStuckA5Rekey() throws {
		let (alice, bob) = try establishedNonDedicatedPair()

		// Snapshot bob before he learns of alice's rotation, for the stale-history check
		// below.
		let earlyBobExport = try bob.migrationExport()
		// Alice's original PQ key, before rotation swaps her whole identity (classical and
		// PQ together) to the new principal's — her send-PQ leaf keeps presenting this key
		// for the rest of the test, since nothing ever moves it.
		let originalAlicePQSignatureKey = try alice.migrationExport().identity
			.pqSignatureKey

		// Alice rotates; bob folds the handoff — lazy staging admits the candidate with no
		// separate stage call.
		let newAliceId = TwoMLSPQBinding.ClientId(bytes: Data("rrh-alice-rotated".utf8))
		_ = try alice.prepareToEncrypt(proposing: newAliceId)
		let rotateFrame = try alice.encrypt(appMessage: Data("rotate".utf8))
		let bobRotateOpened = try XCTUnwrap(
			bob.processIncoming(ciphertext: rotateFrame.cipherText))
		let rotateOffered = try XCTUnwrap(bobRotateOpened.proposal)
		XCTAssertEqual(rotateOffered.proposing, newAliceId)
		try bob.queueProposal(digest: rotateOffered.digest)
		let bobFold = try bob.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobFold.didCommit, "bob's fold of alice's handoff must commit")
		XCTAssertEqual(bobFold.committedRemoteClientId, newAliceId)
		let canonicalizeFrame = try bob.encrypt(appMessage: Data("canonicalize".utf8))
		let aliceCanonOpened = try XCTUnwrap(
			alice.processIncoming(ciphertext: canonicalizeFrame.cipherText))
		let remoteCommit = try XCTUnwrap(aliceCanonOpened.remoteCommit)
		XCTAssertEqual(remoteCommit.newRecipient, newAliceId)

		// Bob still held the turn for that canonicalize send, so it incidentally auto-staged
		// a plain A.4 — a one-round catch-up that must drain before alice's leaf-lag can
		// open A.5. Draining it is what passes the turn to alice.
		let incidentalEk = try XCTUnwrap(bob.pqPendingOutbound(sealing: .fresh))
		try alice.pqRatchetRespond(ekMsg: incidentalEk)
		let incidentalCt = try XCTUnwrap(alice.pqTakePendingOutbound())
		try bob.pqRatchetBind(ctMsg: incidentalCt)
		try RustSessionTestHelpers.committingRound(binder: bob, peer: alice)
		XCTAssertTrue(alice.myPqTurn(), "draining the incidental A.4 must pass the turn")

		// Migrate bob to native after he folded the rotation, so his AS history
		// (`authTheirs`) already carries alice's handoff.
		let lateBobExport = try bob.migrationExport()
		let lateArchive = try SessionMigrator.mint(
			kind: .checkpoint, from: lateBobExport,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: lateArchive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Drive alice (turn holder, leaf lagging) until her send auto-stages the A.5 Upd' —
		// the session self-drives; there is no host-callable "begin".
		_ = try alice.prepareToEncrypt(proposing: nil)
		let opener = try alice.encrypt(appMessage: Data("open-a5".utf8))
		let bobOpenerResult = try nativeBob.processIncoming(opener.cipherText)
		guard case .decrypted(let openerDecrypted) = bobOpenerResult else {
			XCTFail("expected a decrypted application frame, got \(bobOpenerResult)")
			return
		}
		XCTAssertEqual(openerDecrypted.applicationMessage, Data("open-a5".utf8))

		// `migrationExport` refuses mid-round, so read the side-band state instead: native
		// bob (the only party who can open a frame sealed to him) classifies it as the
		// Upd' leg.
		XCTAssertTrue(alice.myPqTurn(), "alice must still hold the turn pre-discharge")
		let firstFetch = try XCTUnwrap(alice.pqPendingOutbound(sealing: .stable))
		let classified = try nativeBob.openIncoming(firstFetch)
		XCTAssertEqual(classified?.kind, .pqSideBand(.rekeyUpd))

		// Model the app's resend policy: re-fetch (not reuse) before delivering — `.stable`
		// sealing must hand out byte-identical bytes.
		let secondFetch = try XCTUnwrap(alice.pqPendingOutbound(sealing: .stable))
		XCTAssertEqual(
			firstFetch, secondFetch,
			"a resend after a simulated loss must be byte-identical")

		// A native peer whose AS history never saw the handoff refuses the move regardless
		// of the frame — splice the pre-rotation `authTheirs` onto the turn-correct export,
		// since the literal early snapshot still shows bob holding the turn and would
		// refuse before ever reaching the id check.
		var unawareExport = lateBobExport
		unawareExport.authTheirs = earlyBobExport.authTheirs
		let unawareArchive = try SessionMigrator.mint(
			kind: .checkpoint, from: unawareExport,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBobUnaware = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: unawareArchive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertThrowsError(try nativeBobUnaware.pqRekeyRespond(secondFetch)) { error in
			XCTAssertEqual(
				error as? TwoMLSPQSession.TwoMLSError, .rekeyProposalRejected)
		}

		// A tampered announced id fails signature verification before the id comparison is
		// even reached, since authenticated data is covered by the framing signature.
		// Corrupt the OPENED plaintext, not the wire bytes — a tampered seal would just
		// fail AEAD open outright, and `pqRekeyRespond`'s `openOrRaw` accepts raw input
		// when re-opening as sealed fails. The announced id is encoded before the leaf's
		// own credential, so its first occurrence in the plaintext is the field under test.
		let openedPlaintext = try XCTUnwrap(classified?.frame)
		var corruptedPlaintext = openedPlaintext
		let announcedIdRange = try XCTUnwrap(
			corruptedPlaintext.firstRange(of: newAliceId.bytes))
		corruptedPlaintext[announcedIdRange.lowerBound] ^= 0xFF
		let corruptedArchive = try SessionMigrator.mint(
			kind: .checkpoint, from: lateBobExport,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBobForCorrupted = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: corruptedArchive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertThrowsError(try nativeBobForCorrupted.pqRekeyRespond(corruptedPlaintext)) {
			error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .decryptionFailed)
		}

		// The real, caught-up native bob accepts it and announces the handoff.
		let sideBandResult = try nativeBob.pqRekeyRespond(secondFetch)
		XCTAssertEqual(sideBandResult.rotatedCredential, newAliceId.bytes)

		// Alice applies the Commit', leaves rekey-initiated, and owes the classical bind.
		try alice.pqRekeyApply(msg: sideBandResult.frame)

		// Bind discharge: native bob offers an Upd, alice (the binder) folds + commits.
		_ = try nativeBob.prepareToEncrypt()
		let bobBindUpd = try nativeBob.encrypt(Data("a5-bind-upd".utf8))
		let aliceBindOpened = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobBindUpd.frame))
		let bindOffered = try XCTUnwrap(aliceBindOpened.proposal)
		try alice.queueProposal(digest: bindOffered.digest)
		let alicePrepared = try alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			alicePrepared.didCommit, "the bind discharge needs a committing round")
		let aliceCommitFrame = try alice.encrypt(appMessage: Data("a5-bind-commit".utf8))
		let bobGotCommit = try nativeBob.processIncoming(aliceCommitFrame.cipherText)
		guard case .decrypted(let bobCommitDecrypted) = bobGotCommit else {
			XCTFail("expected a decrypted application frame, got \(bobGotCommit)")
			return
		}
		XCTAssertEqual(bobCommitDecrypted.applicationMessage, Data("a5-bind-commit".utf8))

		// Postcondition: alice's PQ leaf presents her new id in native bob's view
		// (`rotatedCredential` above). Passing the turn back needs a full round: bob
		// (nothing of his lags) opens a plain A.4, and its own discharge hands the turn to
		// alice.
		_ = try nativeBob.prepareToEncrypt()
		let followUpOpener = try nativeBob.encrypt(Data("post-a5-opener".utf8))
		let aliceFollowUpOpened = try alice.processIncoming(
			ciphertext: followUpOpener.frame)
		XCTAssertEqual(
			aliceFollowUpOpened?.applicationMessage?.appMessageData,
			Data("post-a5-opener".utf8))
		let followUpEk = try XCTUnwrap(nativeBob.pqPendingOutbound())
		try alice.pqRatchetRespond(ekMsg: followUpEk)
		let followUpCt = try XCTUnwrap(alice.pqTakePendingOutbound())
		_ = try nativeBob.pqRatchetBind(followUpCt)

		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceBindUpd2 = try alice.encrypt(appMessage: Data("post-a5-bind-upd".utf8))
		let bobBindOpened2 = try nativeBob.processIncoming(aliceBindUpd2.cipherText)
		guard case .decrypted(let bobDecrypted2) = bobBindOpened2 else {
			XCTFail("expected a decrypted application frame, got \(bobBindOpened2)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted2.queuedProposal.digest)
		let bobPrepared2 = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(bobPrepared2.didCommit, "the second bind discharge needs a commit")
		let bobCommit2 = try nativeBob.encrypt(Data("post-a5-bind-commit".utf8))
		let aliceGotCommit2 = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobCommit2.frame))
		XCTAssertEqual(
			aliceGotCommit2.applicationMessage?.appMessageData,
			Data("post-a5-bind-commit".utf8))

		// `send_pq_leaf_lags` checks alice's own send-PQ leaf. A responder's Commit' carries
		// its current credential when its own send-PQ leaf lags, but alice is always this
		// round's initiator, never a responder catching herself up — so with the turn back,
		// her next send auto-stages another A.5, this time a same-id key change: the steady
		// state for every rotated Rust peer talking to native.
		XCTAssertTrue(alice.myPqTurn())
		_ = try alice.prepareToEncrypt(proposing: nil)
		let secondOpener = try alice.encrypt(appMessage: Data("open-a5-again".utf8))
		let bobSecondOpenerResult = try nativeBob.processIncoming(secondOpener.cipherText)
		guard case .decrypted(let secondOpenerDecrypted) = bobSecondOpenerResult else {
			XCTFail(
				"expected a decrypted application frame, got \(bobSecondOpenerResult)"
			)
			return
		}
		XCTAssertEqual(
			secondOpenerDecrypted.applicationMessage, Data("open-a5-again".utf8))
		let secondUpd = try XCTUnwrap(alice.pqPendingOutbound(sealing: .stable))
		let secondClassified = try nativeBob.openIncoming(secondUpd)
		XCTAssertEqual(secondClassified?.kind, .pqSideBand(.rekeyUpd))
		let secondSideBandResult = try nativeBob.pqRekeyRespond(secondUpd)
		XCTAssertNil(
			secondSideBandResult.rotatedCredential,
			"a same-id catch-up hands off nothing"
		)
		try alice.pqRekeyApply(msg: secondSideBandResult.frame)

		_ = try nativeBob.prepareToEncrypt()
		let thirdBindUpd = try nativeBob.encrypt(Data("a5-again-bind-upd".utf8))
		let aliceThirdBindOpened = try XCTUnwrap(
			alice.processIncoming(ciphertext: thirdBindUpd.frame))
		let thirdBindOffered = try XCTUnwrap(aliceThirdBindOpened.proposal)
		try alice.queueProposal(digest: thirdBindOffered.digest)
		let aliceThirdPrepared = try alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			aliceThirdPrepared.didCommit,
			"the repeated A.5's bind discharge needs a commit"
		)
		let aliceThirdCommitFrame = try alice.encrypt(
			appMessage: Data("a5-again-bind-commit".utf8))
		let bobGotThirdCommit = try nativeBob.processIncoming(
			aliceThirdCommitFrame.cipherText)
		guard case .decrypted(let bobThirdCommitDecrypted) = bobGotThirdCommit else {
			XCTFail("expected a decrypted application frame, got \(bobGotThirdCommit)")
			return
		}
		XCTAssertEqual(
			bobThirdCommitDecrypted.applicationMessage,
			Data("a5-again-bind-commit".utf8))

		_ = try alice.prepareToEncrypt(proposing: nil)
		let finalAliceFrame = try alice.encrypt(appMessage: Data("post-heal-alice".utf8))
		let finalBobResult = try nativeBob.processIncoming(finalAliceFrame.cipherText)
		guard case .decrypted(let finalBobDecrypted) = finalBobResult else {
			XCTFail("expected a decrypted application frame, got \(finalBobResult)")
			return
		}
		XCTAssertEqual(finalBobDecrypted.applicationMessage, Data("post-heal-alice".utf8))

		_ = try nativeBob.prepareToEncrypt()
		let finalBobFrame = try nativeBob.encrypt(Data("post-heal-bob".utf8))
		let finalAliceResult = try XCTUnwrap(
			alice.processIncoming(ciphertext: finalBobFrame.frame))
		XCTAssertEqual(
			finalAliceResult.applicationMessage?.appMessageData,
			Data("post-heal-bob".utf8))

		// Alice's send-PQ leaf never gets bumped by any of this (same reasoning as above) —
		// mint her and restore natively too.
		let aliceExport = try alice.migrationExport()
		XCTAssertEqual(
			aliceExport.leafKeys.sendPq.current?.signatureKey,
			originalAlicePQSignatureKey,
			"alice's send-PQ leaf still presents her ORIGINAL (pre-rotation) PQ key — "
				+ "nothing in this flow ever moves it")
		let aliceArchive = try SessionMigrator.mint(
			kind: .checkpoint, from: aliceExport,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		_ = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: aliceArchive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
	}

	// MARK: - CHARACTERIZATION: a rotation-before-bind mismatch never heals from the peer

	/// The deployed Rust engine binds A.3 with the current (post-rotation) principal's
	/// signing key, but the peer's send-PQ tree — built from the bootstrap KP frozen at
	/// `initiate()` — still records the original key for that leaf. The later A.5 Upd'
	/// never matches what the peer's tree has on record, and unlike the heal case above, no
	/// later classical fold reconciles it — this party heals only by migrating itself.
	func testNativeBNeverHealsRotationBeforeA3Bind() throws {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("rrh2-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("rrh2-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let kpEnvelope = try aliceSession.pqBootstrapEnvelope()
		let replyEnvelope = try XCTUnwrap(aliceSession.pendingOutbound())

		let heldKp: Data
		switch try bobInvitation.openInitial(blob: kpEnvelope) {
		case .bootstrapKp(let frame): heldKp = frame
		case let other:
			throw NSError(
				domain: "rrh2", code: 1,
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
				domain: "rrh2", code: 2,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope, got \(other)"
				])
		}
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("rrh2-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		// Bob's send-PQ tree is built here, from alice's KP frozen at `initiate()` — the
		// leaf presentation that never gets revised.
		try bobSession.pqBootstrapRespond(kpMsg: heldKp)
		let welcomePrime = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		let returnWelcome = try XCTUnwrap(bobSession.pendingOutbound())

		// Alice establishes her classical groups off the return welcome, so she can propose
		// a rotation before ever closing A.3 with `pqBootstrapBind`.
		_ = try aliceSession.processIncoming(ciphertext: returnWelcome)

		let newAliceId = TwoMLSPQBinding.ClientId(
			bytes: Data("rrh2-alice-rotated".utf8))
		_ = try aliceSession.prepareToEncrypt(proposing: newAliceId)
		let rotateFrame = try aliceSession.encrypt(appMessage: Data("rotate".utf8))
		let bobRotateOpened = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: rotateFrame.cipherText))
		let rotateOffered = try XCTUnwrap(bobRotateOpened.proposal)
		try bobSession.queueProposal(digest: rotateOffered.digest)
		let bobFold = try bobSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobFold.didCommit)
		let canonicalizeFrame = try bobSession.encrypt(
			appMessage: Data("canonicalize".utf8))
		let aliceCanonOpened = try XCTUnwrap(
			aliceSession.processIncoming(ciphertext: canonicalizeFrame.cipherText))
		let remoteCommit = try XCTUnwrap(aliceCanonOpened.remoteCommit)
		XCTAssertEqual(remoteCommit.newRecipient, newAliceId)

		// Alice now closes A.3 — binding with her current (rotated) principal, while bob's
		// send-PQ tree still carries her original KP's presentation for that leaf.
		try aliceSession.pqBootstrapBind(welcomeMsg: welcomePrime)

		// A.3's own bind discharge: alice (binder) offers the bind riding her commit; bob
		// applies the staple and gains the turn. Unlike the heal test, neither side's send
		// auto-stages anything here — alice loses her turn inside this same discharge,
		// before any auto-stage check runs on her own send.
		try RustSessionTestHelpers.committingRound(binder: aliceSession, peer: bobSession)

		// Bob (now turn holder, nothing of his lags) opens a plain A.4; draining it hands
		// the turn to alice, whose leaf already lags the pre-bind rotation.
		_ = try bobSession.prepareToEncrypt(proposing: nil)
		let bobOpener = try bobSession.encrypt(appMessage: Data("post-a3-opener".utf8))
		_ = try aliceSession.processIncoming(ciphertext: bobOpener.cipherText)
		let incidentalEk = try XCTUnwrap(bobSession.pqPendingOutbound(sealing: .fresh))
		try aliceSession.pqRatchetRespond(ekMsg: incidentalEk)
		let incidentalCt = try XCTUnwrap(aliceSession.pqTakePendingOutbound())
		try bobSession.pqRatchetBind(ctMsg: incidentalCt)
		try RustSessionTestHelpers.committingRound(binder: bobSession, peer: aliceSession)
		XCTAssertTrue(aliceSession.myPqTurn())

		let bobExport = try bobSession.migrationExport()
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: bobExport,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let opener = try aliceSession.encrypt(appMessage: Data("open-a5".utf8))
		let bobOpenerResult = try nativeBob.processIncoming(opener.cipherText)
		guard case .decrypted = bobOpenerResult else {
			XCTFail("expected a decrypted application frame, got \(bobOpenerResult)")
			return
		}
		let parkedUpd = try XCTUnwrap(aliceSession.pqPendingOutbound(sealing: .stable))

		// Respond throws `.decryptionFailed`: the framing signature doesn't verify against
		// the leaf key bob's tree has on record (alice signed with her post-rotation key;
		// the tree still holds pre-rotation).
		XCTAssertThrowsError(try nativeBob.pqRekeyRespond(parkedUpd)) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .decryptionFailed)
		}
		// Nothing is consumed: a retry throws the identical error. `makeSessionArchive` is
		// internal, so "unchanged" is checked behaviorally below — bob keeps messaging
		// correctly, which a corrupted state could not survive.
		XCTAssertThrowsError(try nativeBob.pqRekeyRespond(parkedUpd)) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .decryptionFailed)
		}

		_ = try nativeBob.prepareToEncrypt()
		let bobFrame = try nativeBob.encrypt(Data("bob-still-healthy".utf8))
		let aliceGot = try XCTUnwrap(
			aliceSession.processIncoming(ciphertext: bobFrame.frame))
		XCTAssertEqual(
			aliceGot.applicationMessage?.appMessageData, Data("bob-still-healthy".utf8))
		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let aliceFrame = try aliceSession.encrypt(
			appMessage: Data("alice-still-sends".utf8))
		let bobGot = try nativeBob.processIncoming(aliceFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobGot else {
			XCTFail("expected a decrypted application frame, got \(bobGot)")
			return
		}
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("alice-still-sends".utf8))

		// Alice stays rekey-initiated — her side never saw a Commit', so nothing let her
		// leave the round — and the same parked Upd' bytes come back byte-identical.
		let stillParked = try XCTUnwrap(aliceSession.pqPendingOutbound(sealing: .stable))
		XCTAssertEqual(parkedUpd, stillParked)
	}

	// MARK: - Native responder carries its own rotation onto its send-PQ leaf

	/// Bob migrates, then rotates natively, and Rust alice's fold of that rotation opens her
	/// A.5 (her own send-PQ leaf lags her earlier rotation). Native bob's responder Commit'
	/// carries his current credential, moving his lagging send-PQ leaf to his new id, and
	/// Rust alice's `pq_rekey_apply` accepts a Commit' whose committer path leaf changes id.
	func testMigratedNativeResponderCarriesItsRotatedIdToRust() throws {
		let (alice, bob) = try establishedNonDedicatedPair()
		let aliceRotated = TwoMLSPQBinding.ClientId(bytes: Data("rrh-alice-rotated".utf8))
		_ = try alice.prepareToEncrypt(proposing: aliceRotated)
		let rotateFrame = try alice.encrypt(appMessage: Data("rotate".utf8))
		let opened = try XCTUnwrap(bob.processIncoming(ciphertext: rotateFrame.cipherText))
		try bob.queueProposal(digest: try XCTUnwrap(opened.proposal).digest)
		XCTAssertTrue(try bob.prepareToEncrypt(proposing: nil).didCommit)
		let canonicalize = try bob.encrypt(appMessage: Data("canonicalize".utf8))
		_ = try XCTUnwrap(alice.processIncoming(ciphertext: canonicalize.cipherText))

		// Drain the A.4 bob's commit auto-staged, so alice holds the PQ turn at export.
		let incidentalEk = try XCTUnwrap(bob.pqPendingOutbound(sealing: .fresh))
		try alice.pqRatchetRespond(ekMsg: incidentalEk)
		let incidentalCt = try XCTUnwrap(alice.pqTakePendingOutbound())
		try bob.pqRatchetBind(ctMsg: incidentalCt)
		try RustSessionTestHelpers.committingRound(binder: bob, peer: alice)
		XCTAssertTrue(alice.myPqTurn())

		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: try bob.migrationExport(),
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let bobOriginal = nativeBob.myPrincipalState.clientID

		let bobRotated = Data("rrh-bob-rotated".utf8)
		_ = try nativeBob.prepareToEncrypt(rotating: bobRotated)
		let bobOffer = try nativeBob.encrypt(Data("bob-rotate".utf8))
		let aliceGot = try XCTUnwrap(alice.processIncoming(ciphertext: bobOffer.frame))
		try alice.queueProposal(digest: try XCTUnwrap(aliceGot.proposal).digest)
		XCTAssertTrue(try alice.prepareToEncrypt(proposing: nil).didCommit)
		let aliceFold = try alice.encrypt(appMessage: Data("alice-fold".utf8))
		guard case .decrypted = try nativeBob.processIncoming(aliceFold.cipherText) else {
			return XCTFail("expected native bob to decrypt alice's fold")
		}
		XCTAssertEqual(nativeBob.myPrincipalState, .sync(bobRotated))

		// Alice's fold opens her A.5.
		let upd = try XCTUnwrap(alice.pqPendingOutbound(sealing: .stable))
		XCTAssertEqual(
			try nativeBob.openIncoming(upd)?.kind, .pqSideBand(.rekeyUpd))
		XCTAssertEqual(try sendPQLeafID(of: nativeBob), bobOriginal)

		let response = try nativeBob.pqRekeyRespond(upd)
		XCTAssertEqual(response.rotatedCredential, aliceRotated.bytes)
		XCTAssertEqual(try sendPQLeafID(of: nativeBob), bobRotated)
		try alice.pqRekeyApply(msg: response.frame)
	}

	private func sendPQLeafID(of session: TwoMLSPQSession.TwoMLSSession) throws -> Data {
		let group = try XCTUnwrap(session.sendGroup?.pq)
		return try TwoMLSPQSession.basicIdentifier(
			TwoMLSPQSession.TwoMLSSession.ownLeaf(of: group).credential)
	}

	// MARK: - Shared establishment scaffolding

	/// A non-dedicated Rust pair through full establishment and the A.3 bind discharge, with
	/// no trailing sends — so nothing has auto-staged and bob (the discharge's non-binder)
	/// holds the turn at return. Mirrors `RustSessionTestHelpers.
	/// bornDedicatedSessionPairAtDischarge`'s clean-slate shape, which
	/// `SessionMigrationTests.establishedSessionPair` doesn't preserve since its trailing
	/// sends legitimately auto-stage.
	private func establishedNonDedicatedPair() throws -> (
		alice: TwoMLSPQBinding.TwoMlsPqSession, bob: TwoMLSPQBinding.TwoMlsPqSession
	) {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("rrh-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("rrh-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let kpEnvelope = try aliceSession.pqBootstrapEnvelope()
		let replyEnvelope = try XCTUnwrap(aliceSession.pendingOutbound())

		let heldKp: Data
		switch try bobInvitation.openInitial(blob: kpEnvelope) {
		case .bootstrapKp(let frame): heldKp = frame
		case let other:
			throw NSError(
				domain: "rrh", code: 1,
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
				domain: "rrh", code: 2,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope, got \(other)"
				])
		}
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("rrh-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		try bobSession.pqBootstrapRespond(kpMsg: heldKp)
		let welcomePrime = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		let returnWelcome = try XCTUnwrap(bobSession.pendingOutbound())

		_ = try aliceSession.processIncoming(ciphertext: returnWelcome)
		try aliceSession.pqBootstrapBind(welcomeMsg: welcomePrime)

		try RustSessionTestHelpers.committingRound(binder: aliceSession, peer: bobSession)
		XCTAssertTrue(aliceSession.isFullyEstablished())
		XCTAssertTrue(bobSession.isFullyEstablished())

		return (aliceSession, bobSession)
	}
}
