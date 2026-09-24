import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// `leafKeys`/`deployedState` cross-engine cases the mapper's core round-trip suites don't
// otherwise cover: a rotate-before-bind mis-signed A.5 wedge, a two-rotation session, and the
// own-offer window end to end. Companion to `SessionMigrationTests` and
// `RotatedRekeyHealTests`; see `RustSessionTestHelpers` for the shared FFI scaffolding.
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper names, so FFI
// record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class DeployedStateMigrationTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	// MARK: - Rotate-before-bind: a mis-signed A.5 parks, then drops at import

	/// Alice rotates D -> N before her A.3 bind, so her self-driven A.5 Upd' is mis-signed
	/// — framed with N against a leaf the peer's tree still has on record as D. Export must
	/// carry the parked round; native import drops it and resumes with a plain ratchet.
	func testRotateBeforeBindWedgeDropsAtImportAndSelfDrivesAPlainRatchet() throws {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("rbb-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("rbb-bob".utf8))
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
				domain: "rbb", code: 1,
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
				domain: "rbb", code: 2,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope, got \(other)"
				])
		}
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("rbb-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		// Bob's leg 2: his send-PQ tree (Group_B.pq) is founded HERE, from alice's KP
		// frozen at `initiate()` — the presentation that never gets revised.
		try bobSession.pqBootstrapRespond(kpMsg: heldKp)
		let welcomePrime = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		let returnWelcome = try XCTUnwrap(bobSession.pendingOutbound())

		_ = try aliceSession.processIncoming(ciphertext: returnWelcome)
		let dPQSignatureKey = try aliceSession.migrationExport().identity.pqSignatureKey

		let newAliceId = TwoMLSPQBinding.ClientId(bytes: Data("rbb-alice-rotated".utf8))
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

		// A.3 leg 3 binds against alice's CURRENT (rotated) principal, while bob's
		// send-PQ tree still carries her original KP's presentation.
		try aliceSession.pqBootstrapBind(welcomeMsg: welcomePrime)
		try RustSessionTestHelpers.committingRound(binder: aliceSession, peer: bobSession)

		// Bob (turn holder, nothing of HIS lags) opens a plain A.4; draining it hands
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

		// Self-stages the A.5 Upd' — mis-signed with N against a leaf still presenting D.
		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let opener = try aliceSession.encrypt(appMessage: Data("open-a5".utf8))
		_ = try bobSession.processIncoming(ciphertext: opener.cipherText)

		// Export alice: CARRIED, not refused.
		let export = try aliceSession.migrationExport()
		guard case .rekeyInitiated = export.pqInflight else {
			XCTFail(
				"expected a parked rekey-initiated round, got "
					+ "\(String(describing: export.pqInflight))")
			return
		}
		let recvPQCurrent = try XCTUnwrap(export.leafKeys.recvPq.current)
		XCTAssertEqual(
			recvPQCurrent.signatureKey, dPQSignatureKey,
			"recv-PQ's own leaf still presents the pre-rotation identity D, not N")

		// Recv-classical still has un-folded self-proposals from the rotate/canonicalize/
		// opener sends, so an own-offer window may ride the export too — irrelevant here,
		// so mint via the window-tolerant entry point and take only the archive.
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// The parked Upd' is DROPPED at import: nothing outstanding to resend.
		XCTAssertNil(
			nativeAlice.pqPendingOutbound(),
			"no pending side-band should survive import")

		// Once the PQ turn is alice's, her next send opens a plain A.4 (not an A.5),
		// classified by the Rust peer as the ratchet EK leg, under the carried key.
		XCTAssertTrue(nativeAlice.myPQTurn)
		_ = try nativeAlice.prepareToEncrypt()
		let followUp = try nativeAlice.encrypt(Data("post-restore-a4".utf8))
		let bobOpened = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: followUp.frame))
		XCTAssertEqual(
			bobOpened.applicationMessage?.appMessageData, Data("post-restore-a4".utf8))
		let ekLeg = try XCTUnwrap(nativeAlice.pqPendingOutbound())
		let classified = try bobSession.openIncoming(blob: ekLeg)
		XCTAssertEqual(classified?.kind, .pqSideBand(kind: .ratchetEphemeralKey))
		XCTAssertNoThrow(try bobSession.pqRatchetRespond(ekMsg: ekLeg))
	}

	// MARK: - Two rotations: each PQ group's `current` is its own presented key

	/// Alice rotates id0 -> id1 through a completed A.5 (recv-PQ converges to id1; send-PQ,
	/// never a round's RESPONDER here, still lags id0), then id1 -> id2 purely classically
	/// with no A.5 at all — each PQ group's `current` must equal the key it's actually
	/// presenting.
	func testTwoRotationsEachPQGroupCurrentIsItsPresentedKey() throws {
		let (aliceSession, bobSession) = try establishFullPair()

		// id0: alice's PQ key before any rotation — the key her send-PQ leaf will keep
		// presenting throughout (it never responds to a peer-opened round).
		let id0PQSignatureKey = try aliceSession.migrationExport().identity.pqSignatureKey

		// Post-`establishFullPair`, bob holds the PQ turn — alice is already the
		// non-turn-holder `rekey_round` requires, so no extra flip is needed.
		XCTAssertFalse(aliceSession.myPqTurn())

		// --- Rotation 1: id0 -> id1, driven all the way through a completed A.5. ---
		let id1 = TwoMLSPQBinding.ClientId(bytes: Data("two-rot-id1".utf8))
		_ = try aliceSession.prepareToEncrypt(proposing: id1)
		let rotate1Frame = try aliceSession.encrypt(appMessage: Data("rotate1".utf8))
		let bobRotate1Opened = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: rotate1Frame.cipherText))
		let rotate1Offered = try XCTUnwrap(bobRotate1Opened.proposal)
		try bobSession.queueProposal(digest: rotate1Offered.digest)
		let bobFold1 = try bobSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobFold1.didCommit)
		XCTAssertEqual(bobFold1.committedRemoteClientId, id1)
		let canonicalize1Frame = try bobSession.encrypt(
			appMessage: Data("canonicalize1".utf8))
		let aliceCanon1Opened = try XCTUnwrap(
			aliceSession.processIncoming(ciphertext: canonicalize1Frame.cipherText))
		XCTAssertEqual(aliceCanon1Opened.remoteCommit?.newRecipient, id1)

		// Bob (turn holder) incidentally auto-stages a plain A.4 on that canonicalize
		// send — the one-round catch-up deferral; drain it to pass the turn to alice.
		let incidentalEk = try XCTUnwrap(bobSession.pqPendingOutbound(sealing: .fresh))
		try aliceSession.pqRatchetRespond(ekMsg: incidentalEk)
		let incidentalCt = try XCTUnwrap(aliceSession.pqTakePendingOutbound())
		try bobSession.pqRatchetBind(ctMsg: incidentalCt)
		try RustSessionTestHelpers.committingRound(binder: bobSession, peer: aliceSession)
		XCTAssertTrue(aliceSession.myPqTurn())

		// Alice (turn holder, leaf lagging) self-stages the A.5 Upd' announcing id1.
		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let rekeyOpener = try aliceSession.encrypt(appMessage: Data("open-a5".utf8))
		_ = try bobSession.processIncoming(ciphertext: rekeyOpener.cipherText)
		let upd = try XCTUnwrap(aliceSession.pqPendingOutbound(sealing: .stable))
		let classified = try bobSession.openIncoming(blob: upd)
		XCTAssertEqual(classified?.kind, .pqSideBand(kind: .rekeyUpdate))
		let rotatedTo = try bobSession.pqRekeyRespond(updMsg: upd)
		XCTAssertEqual(rotatedTo, id1)
		let commitPrime = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		try aliceSession.pqRekeyApply(msg: commitPrime)
		try RustSessionTestHelpers.committingRound(binder: aliceSession, peer: bobSession)

		// --- Rotation 2: id1 -> id2, purely classical — no A.5 for it at all. ---
		let id2 = TwoMLSPQBinding.ClientId(bytes: Data("two-rot-id2".utf8))
		_ = try aliceSession.prepareToEncrypt(proposing: id2)
		let rotate2Frame = try aliceSession.encrypt(appMessage: Data("rotate2".utf8))
		let bobRotate2Opened = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: rotate2Frame.cipherText))
		let rotate2Offered = try XCTUnwrap(bobRotate2Opened.proposal)
		try bobSession.queueProposal(digest: rotate2Offered.digest)
		let bobFold2 = try bobSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobFold2.didCommit)
		XCTAssertEqual(bobFold2.committedRemoteClientId, id2)
		let canonicalize2Frame = try bobSession.encrypt(
			appMessage: Data("canonicalize2".utf8))
		let aliceCanon2Opened = try XCTUnwrap(
			aliceSession.processIncoming(ciphertext: canonicalize2Frame.cipherText))
		XCTAssertEqual(aliceCanon2Opened.remoteCommit?.newRecipient, id2)

		let export = try aliceSession.migrationExport()

		// send-PQ still lags id0 — it was never the RESPONDER of any round.
		let sendPQ = export.leafKeys.sendPq
		let sendCurrent = try XCTUnwrap(sendPQ.current)
		XCTAssertEqual(sendCurrent.signatureKey, id0PQSignatureKey)
		let sendCatchUp = try XCTUnwrap(sendPQ.pending.first { $0.target == id2.bytes })
		XCTAssertEqual(sendCatchUp.key.signatureKey, export.identity.pqSignatureKey)

		// recv-PQ converged to id1 via the completed A.5, but now also lags id2.
		let recvPQ = export.leafKeys.recvPq
		let recvCurrent = try XCTUnwrap(recvPQ.current)
		XCTAssertNotEqual(
			recvCurrent.signatureKey, id0PQSignatureKey,
			"recv-PQ must have converged off id0 via the completed A.5")
		let recvCatchUp = try XCTUnwrap(recvPQ.pending.first { $0.target == id2.bytes })
		XCTAssertEqual(recvCatchUp.key.signatureKey, export.identity.pqSignatureKey)

		// The mint's own `validateLeafKeys` independently re-checks that every EXISTING
		// group's `current` equals what its leaf actually presents, so a successful
		// restore is itself the cross-engine proof.
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Messaging works both ways.
		_ = try bobSession.prepareToEncrypt(proposing: nil)
		let bobFrame = try bobSession.encrypt(
			appMessage: Data("bob-to-migrated-alice".utf8))
		let opened = try nativeAlice.processIncoming(bobFrame.cipherText)
		guard case .decrypted(let decrypted) = opened else {
			XCTFail("expected a decrypted application frame, got \(opened)")
			return
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-to-migrated-alice".utf8))

		_ = try nativeAlice.prepareToEncrypt()
		let reply = try nativeAlice.encrypt(Data("migrated-alice-to-bob".utf8))
		let bobGot = try XCTUnwrap(bobSession.processIncoming(ciphertext: reply.frame))
		XCTAssertEqual(
			bobGot.applicationMessage?.appMessageData,
			Data("migrated-alice-to-bob".utf8))
	}

	// MARK: - The own-offer window end to end

	/// Alice re-proposes the same rotation candidate three times, never letting bob fold
	/// any of them, then migrates at rest (nothing framed, so recency is unrecoverable —
	/// all three offers are window candidates, plus one baseline same-identity refresh
	/// `establishFullPair` already leaves cached). Bob folds the OLDEST offer, out of
	/// order relative to alice's current: native import must resolve it via the window
	/// blob, not the framed entry.
	func testOwnOfferWindowLetsBobFoldAnOlderOfferAfterAliceMigrates() throws {
		let (aliceSession, bobSession) = try establishFullPair()
		let candidate = TwoMLSPQBinding.ClientId(bytes: Data("window-candidate".utf8))

		// Offer #1: delivered to bob now (he holds it "offered", unqueued) — this is the
		// one he folds later, out of order.
		_ = try aliceSession.prepareToEncrypt(proposing: candidate)
		let frame1 = try aliceSession.encrypt(appMessage: Data("re-propose-1".utf8))
		let bobOffer1 = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: frame1.cipherText))
		let offer1 = try XCTUnwrap(bobOffer1.proposal)

		// Offer #2 and #3 (the eventual framed/latest one): alice moves on locally: bob
		// never sees either.
		_ = try aliceSession.prepareToEncrypt(proposing: candidate)
		_ = try aliceSession.encrypt(appMessage: Data("re-propose-2".utf8))
		_ = try aliceSession.prepareToEncrypt(proposing: candidate)
		_ = try aliceSession.encrypt(appMessage: Data("re-propose-3".utf8))

		// At rest nothing is framed, so the window carries all three offers plus the
		// baseline same-identity refresh `establishFullPair` already left cached (4 total).
		let export = try aliceSession.migrationExport()
		let window = try XCTUnwrap(
			export.deployedState?.ownOffers, "expected an outstanding own-offer window")
		XCTAssertEqual(window.offers.count, 4)

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let mintedWindow = try XCTUnwrap(
			minted.ownOfferWindow, "the mint must return the window blob alongside it")
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Rust bob folds offer #1 — an OLDER offer, delivered out of order relative to
		// alice's own current (#3).
		try bobSession.queueProposal(digest: offer1.digest)
		let bobPrepared = try bobSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "bob's fold of the older offer should commit")
		let foldFrame = try bobSession.encrypt(appMessage: Data("fold-older".utf8))

		// Native alice's `processIncoming` without the blob throws `.ownOfferWindowRequired`
		// — her framed `stagedUpdates` only carries offer #3, not the ref bob's commit
		// names. Retryable: a separate copy proves nothing changed.
		var nativeAliceRetry = nativeAlice
		XCTAssertThrowsError(try nativeAliceRetry.processIncoming(foldFrame.cipherText)) {
			error in
			XCTAssertEqual(
				error as? TwoMLSPQSession.TwoMLSError, .ownOfferWindowRequired)
		}

		// The retry with the blob succeeds.
		let result = try nativeAlice.processIncoming(
			foldFrame.cipherText, ownOfferWindow: mintedWindow.archive)
		guard case .decrypted(let decrypted) = result else {
			XCTFail("expected a decrypted application frame, got \(result)")
			return
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("fold-older".utf8))
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
	}

	/// A real same-id candidate (K′) offer must survive the export window alongside a
	/// plain same-key refresh `establishFullPair` already leaves cached — proving it's
	/// genuinely in the window, not just in `pending[mine.current]` where the refresh
	/// could otherwise have evicted it.
	func testOwnOfferWindowKeepsSameIdCandidateOfferPastAPlainRefresh() throws {
		let (aliceSession, bobSession) = try establishFullPair()
		let ownId = TwoMLSPQBinding.ClientId(bytes: Data("dsm-alice".utf8))

		_ = try aliceSession.prepareToEncrypt(proposing: ownId)
		let kPrimeFrame = try aliceSession.encrypt(appMessage: Data("same-id-k-prime".utf8))
		let bobOpened = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: kPrimeFrame.cipherText))
		let kPrimeOffer = try XCTUnwrap(bobOpened.proposal)

		let export = try aliceSession.migrationExport()
		let recvEntry = try XCTUnwrap(
			export.leafKeys.recvClassical.pending.first { $0.target == ownId.bytes })
		let window = try XCTUnwrap(
			export.deployedState?.ownOffers, "expected an outstanding own-offer window")
		// `proposalRef` (mls-rs's reference) and `QueuedRemoteProposal.digest` (bob's
		// independently computed SHA-256 binding) are different identifiers for the same
		// proposal and can't be compared directly — the window count plus the downstream
		// fold are the real proof; per-offer decode is covered on the Rust side.
		XCTAssertEqual(
			window.offers.count, 2,
			"the K′ offer and establishFullPair's baseline refresh, matching "
				+ "pending[mine.current] (\(recvEntry.key.signatureKey))")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let mintedWindow = try XCTUnwrap(
			minted.ownOfferWindow, "the mint must return the window blob alongside it")
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Rust bob folds the K′ offer.
		try bobSession.queueProposal(digest: kPrimeOffer.digest)
		let bobPrepared = try bobSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "bob's fold of the K′ offer should commit")
		XCTAssertEqual(bobPrepared.committedRemoteClientId, ownId)
		let foldFrame = try bobSession.encrypt(appMessage: Data("fold-k-prime".utf8))

		// Native alice's first attempt, no window blob, must throw.
		var nativeAliceRetry = nativeAlice
		XCTAssertThrowsError(try nativeAliceRetry.processIncoming(foldFrame.cipherText)) {
			error in
			XCTAssertEqual(
				error as? TwoMLSPQSession.TwoMLSError, .ownOfferWindowRequired)
		}

		// The retry with the blob succeeds — the K′ offer really is in the window.
		let result = try nativeAlice.processIncoming(
			foldFrame.cipherText, ownOfferWindow: mintedWindow.archive)
		guard case .decrypted(let decrypted) = result else {
			XCTFail("expected a decrypted application frame, got \(result)")
			return
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("fold-k-prime".utf8))
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
	}

	// MARK: - Same-id candidate coverage

	/// Bob repeatedly re-proposes his own dedicated id with a fresh same-id candidate key,
	/// never folded by alice — `recv_classical`'s pending set must collapse every
	/// re-proposal of the same target to one entry, not grow with the call count.
	func testBornDedicatedRepeatedSameIdCandidateFramesCollapseToOnePendingEntry() throws {
		let (pair, _) = try RustSessionTestHelpers.bornDedicatedInstalledUnfolded()

		for i in 0..<5 {
			_ = try pair.bob.prepareToEncrypt(
				proposing: TwoMLSPQBinding.ClientId(bytes: pair.dedicatedId))
			let frame = try pair.bob.encrypt(appMessage: Data("catchup-\(i)".utf8))
			// Left unfolded: alice receives but never queues/commits it.
			_ = try pair.alice.processIncoming(ciphertext: frame.cipherText)
		}

		let export = try pair.bob.migrationExport()
		let forDedicated = export.leafKeys.recvClassical.pending.filter {
			$0.target == pair.dedicatedId
		}
		XCTAssertEqual(
			forDedicated.count, 1,
			"N re-proposals of the same target must collapse to one pending entry")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	/// Bob has both a real identity-signed catch-up offer and a same-id K′-signed
	/// candidate outstanding for his own dedicated id — the identity's own key must win
	/// `recv_classical`'s pending entry.
	func testBornDedicatedMixedIdentityAndCandidateOffersPreferTheIdentityKey() throws {
		let (pair, _) = try RustSessionTestHelpers.bornDedicatedInstalledUnfolded()

		// A plain self-refresh: bob's recv-classical leaf still presents the invitation
		// identity, so re-proposing his OWN (dedicated) identity is a genuine credential
		// change — a real, signer-carrying entry under the identity's own key. Left
		// unfolded.
		_ = try pair.bob.prepareToEncrypt(proposing: nil)
		let identityFrame = try pair.bob.encrypt(appMessage: Data("identity-catchup".utf8))
		_ = try pair.alice.processIncoming(ciphertext: identityFrame.cipherText)

		// A same-id candidate's own re-proposal of the SAME dedicated id, signed with a
		// fresh key K′ — coexists with the identity-signed offer above.
		_ = try pair.bob.prepareToEncrypt(
			proposing: TwoMLSPQBinding.ClientId(bytes: pair.dedicatedId))
		let candidateFrame = try pair.bob.encrypt(
			appMessage: Data("same-id-candidate".utf8))
		_ = try pair.alice.processIncoming(ciphertext: candidateFrame.cipherText)

		let export = try pair.bob.migrationExport()
		let recvEntry = try XCTUnwrap(
			export.leafKeys.recvClassical.pending.first {
				$0.target == pair.dedicatedId
			})
		XCTAssertEqual(
			recvEntry.key.signatureKey, export.identity.signatureKey,
			"the identity's key must win when both a real identity offer and a same-id "
				+ "candidate are outstanding")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	/// A same-id candidate's real K′ offer at rest (the mandatory handoff), then an
	/// identity-signed catch-up left FRAMED (`prepareToEncrypt`, not `encrypt`ed) — the
	/// framed entry must win `recv_classical`'s pending entry, and the mint must still
	/// accept the archive even though the K′ offer stays in the window despite losing here
	/// (mint independently re-checks every window offer against current/pending).
	func testBornDedicatedFramedIdentityCatchupDropsTheRealSameIdCandidateOffer() throws {
		let (pair, _) = try RustSessionTestHelpers.bornDedicatedSameIdHandoffUnfolded()

		// A plain self-refresh: bob's recv-classical leaf still presents the invitation
		// identity, so this is a genuine credential change — an identity-signed catch-up,
		// left FRAMED. The mandatory handoff already left a real, unfolded same-id
		// candidate (K′) offer outstanding for bob's dedicated id.
		_ = try pair.bob.prepareToEncrypt(proposing: nil)

		let export = try pair.bob.migrationExport()
		let recvEntry = try XCTUnwrap(
			export.leafKeys.recvClassical.pending.first {
				$0.target == pair.dedicatedId
			})
		XCTAssertEqual(
			recvEntry.key.signatureKey, export.identity.signatureKey,
			"the framed identity-signed catch-up wins mine.current's pending entry")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	/// A real identity-signed catch-up at rest, then the same-id candidate's own
	/// re-proposal left FRAMED — the framed entry (it rides the snapshot, not the window)
	/// must win `recv_classical`'s pending entry even with a real identity offer also
	/// outstanding, and the mint must still accept the archive.
	func testBornDedicatedFramedSameIdCandidateWinsOverARealIdentityCatchup() throws {
		let (pair, _) = try RustSessionTestHelpers.bornDedicatedSameIdHandoffUnfolded()

		// A plain self-refresh: bob's recv-classical leaf still presents the invitation
		// identity, so this is a genuine credential change — a real, identity-signed
		// catch-up, left AT REST (encrypted) alongside the mandatory handoff's still-real,
		// still-unfolded same-id candidate (K′) offer.
		_ = try pair.bob.prepareToEncrypt(proposing: nil)
		let identityFrame = try pair.bob.encrypt(appMessage: Data("identity-catchup".utf8))
		_ = try pair.alice.processIncoming(ciphertext: identityFrame.cipherText)

		// The same same-id candidate, re-proposed — reuses the existing staged candidate
		// (same key), but this new proposal is left FRAMED (no paired `encrypt`).
		_ = try pair.bob.prepareToEncrypt(
			proposing: TwoMLSPQBinding.ClientId(bytes: pair.dedicatedId))

		let export = try pair.bob.migrationExport()
		let recvEntry = try XCTUnwrap(
			export.leafKeys.recvClassical.pending.first {
				$0.target == pair.dedicatedId
			})
		XCTAssertNotEqual(
			recvEntry.key.signatureKey, export.identity.signatureKey,
			"the framed same-id candidate offer must win over a real identity-signed "
				+ "catch-up, not the identity's key")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	/// A framed entry can go stale without ever being cleared: bob folds and commits
	/// offer-1 while alice's offer-2 stays framed, unencrypted, so her recv-classical
	/// epoch advances with the stale offer-2 still in pending-proposal bookkeeping.
	/// Folding offer-1 also canonicalizes id1 as alice's principal, abandoning id2's
	/// candidacy — `recvClassical.pending` ends up empty, yet export, restore, and a
	/// subsequent send must all still succeed.
	func testStaleFramedEntrySurvivesExportHarmlessly() throws {
		let (alice, bob) = try establishFullPair()

		let id1 = TwoMLSPQBinding.ClientId(bytes: Data("stale-id1".utf8))
		_ = try alice.prepareToEncrypt(proposing: id1)
		let enc1 = try alice.encrypt(appMessage: Data("offer-1".utf8))
		let offer1 = try XCTUnwrap(
			bob.processIncoming(ciphertext: enc1.cipherText)?.proposal)

		let id2 = TwoMLSPQBinding.ClientId(bytes: Data("stale-id2".utf8))
		_ = try alice.prepareToEncrypt(proposing: id2)

		try bob.queueProposal(digest: offer1.digest)
		let bobPrepared = try bob.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "bob's fold of offer-1 must commit")
		let commitFrame = try bob.encrypt(appMessage: Data("canonicalize".utf8))

		_ = try alice.processIncoming(ciphertext: commitFrame.cipherText)

		let export = try alice.migrationExport()
		XCTAssertTrue(
			export.leafKeys.recvClassical.pending.isEmpty,
			"id1's canonicalization abandons id2's own candidacy along with it")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// A subsequent native send must still work.
		_ = try nativeAlice.prepareToEncrypt()
		let followUp = try nativeAlice.encrypt(Data("post-restore".utf8))
		let bobGot = try XCTUnwrap(bob.processIncoming(ciphertext: followUp.frame))
		XCTAssertEqual(bobGot.applicationMessage?.appMessageData, Data("post-restore".utf8))
	}

	// MARK: - Shared establishment scaffolding

	/// A non-dedicated pair through full establishment (both PQ halves live) and the
	/// A.3 bind discharge, with no trailing sends — bob (the discharge's non-binder)
	/// holds the PQ turn at return.
	private func establishFullPair() throws -> (
		alice: TwoMLSPQBinding.TwoMlsPqSession, bob: TwoMLSPQBinding.TwoMlsPqSession
	) {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("dsm-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("dsm-bob".utf8))
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
				domain: "dsm", code: 1,
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
				domain: "dsm", code: 2,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope, got \(other)"
				])
		}
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("dsm-spawn".utf8),
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
