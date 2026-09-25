import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// A totality sweep, not a regression pin: eight export shapes the round-trip suites
// don't otherwise exercise, pushed through export -> map -> mint -> restore with minimal
// assertions. The point is coverage of native's acceptance, not any field's exact value
// — a native refusal here is a bug to report, not to paper over.
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper names, so FFI
// record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class MintCoverageTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	// MARK: - 1. Pre-establishment initiator

	/// A bare pre-establishment initiator with an app payload attached. `recvGroup` is nil
	/// and both reservations stand in for groups that don't exist yet. Mirrors the Rust
	/// `test_migration_export_pre_establishment_initiator_with_payload`.
	func testPreEstablishmentInitiatorWithPayloadMintsAndRestores() throws {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-pre-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-pre-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		// Mint-and-retain the return KP before attaching the payload, matching the app's own
		// ordering in `PQSession.swift`'s `createTwoMLSGroup`.
		_ = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		try aliceSession.setInitialAppPayload(payload: Data("mc-host-signed".utf8))

		let export = try aliceSession.migrationExport()
		XCTAssertNil(
			export.recvGroup, "a pre-establishment initiator has no recv group yet")
		XCTAssertEqual(export.initialAppPayload, Data("mc-host-signed".utf8))
		XCTAssertEqual(export.identity.classicalInitSecretKey?.count, 32)
		XCTAssertNotNil(export.leafKeys.recvClassical.current, "recv-classical reservation")
		XCTAssertNotNil(export.leafKeys.recvPq.current, "recv-PQ reservation")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	// MARK: - 2. Card initiator rotated while stalled at A.3

	/// A pipelined-A.3 (card) initiator who has sent her bootstrap KP and establishment
	/// envelope, and processed bob's return welcome, but has not yet called
	/// `pqBootstrapBind` — the A.3 round is open and stalled. A classical rotation
	/// self-driven in that window (never delivered) must still export and mint cleanly.
	func testCardInitiatorRotatedWhileStalledAtA3() throws {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-card-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-card-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let kpEnvelope = try aliceSession.pqBootstrapEnvelope()
		let replyEnvelope = try XCTUnwrap(aliceSession.pendingOutbound())

		guard
			case .bootstrapKp(let heldKp) = try bobInvitation.openInitial(
				blob: kpEnvelope)
		else {
			return XCTFail("expected a bootstrap-KP envelope")
		}
		guard
			case .establishment(let frame) = try bobInvitation.openInitial(
				blob: replyEnvelope)
		else {
			return XCTFail("expected an establishment envelope")
		}
		let welcome = try XCTUnwrap(frame.welcome)
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("mc-card-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		try bobSession.pqBootstrapRespond(kpMsg: heldKp)
		_ = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		let returnWelcome = try XCTUnwrap(bobSession.pendingOutbound())
		_ = try aliceSession.processIncoming(ciphertext: returnWelcome)

		// Stalled: alice never calls `pqBootstrapBind`; the rotation below is never
		// delivered to bob.
		let newAliceId = TwoMLSPQBinding.ClientId(bytes: Data("mc-card-alice-rotated".utf8))
		_ = try aliceSession.prepareToEncrypt(proposing: newAliceId)
		_ = try aliceSession.encrypt(appMessage: Data("mc-rotate".utf8))

		let export = try aliceSession.migrationExport()
		XCTAssertNotNil(export.bootstrapKpSecret, "A.3 is still outstanding")
		XCTAssertNotNil(export.rotationCandidate, "the self-driven rotation is staged")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	// MARK: - 3. Four-candidate export

	/// Four distinct classical candidates staged in a row, none ever folded — each rides
	/// `recv_classical`'s pending set, and `send_classical`'s stays empty.
	func testFourCandidateExportMintsAndRestores() throws {
		let (alice, _) = try establishCardPair()

		for n in 0..<4 {
			let candidate = TwoMLSPQBinding.ClientId(
				bytes: Data("mc-4cand-\(n)".utf8))
			_ = try alice.prepareToEncrypt(proposing: candidate)
			_ = try alice.encrypt(appMessage: Data("mc-4cand-msg-\(n)".utf8))
		}

		let export = try alice.migrationExport()
		XCTAssertGreaterThanOrEqual(
			export.leafKeys.recvClassical.pending.count, 4,
			"all four staged candidates should ride recv-classical's pending set")
		XCTAssertTrue(export.leafKeys.sendClassical.pending.isEmpty)

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	// MARK: - 4. A window of more than 64 offers

	/// 70 same-identity refreshes, never folded, exceed the 64-entry sampled trial native
	/// applies to the offer window, exercised against real (not synthetic) cache data.
	func testOwnOfferWindowOver64EntriesMintsAndRestores() throws {
		let (alice, _) = try establishCardPair()

		for n in 0..<70 {
			_ = try alice.prepareToEncrypt(proposing: nil)
			_ = try alice.encrypt(appMessage: Data("mc-window-\(n)".utf8))
		}

		let export = try alice.migrationExport()
		let window = try XCTUnwrap(
			export.deployedState?.ownOffers,
			"70 unfolded refreshes must produce a window")
		XCTAssertGreaterThan(window.offers.count, 64)

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNotNil(minted.ownOfferWindow)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	// MARK: - 5. Mid-prepare export

	/// Exported with a `prepareToEncrypt` outstanding (no paired `encrypt` yet): the
	/// latest offer is framed and `Placement::Snapshot`-routed, excluded from the window.
	func testMidPrepareExportMintsAndRestores() throws {
		let (alice, _) = try establishCardPair()
		_ = try alice.prepareToEncrypt(proposing: nil)

		let export = try alice.migrationExport()
		XCTAssertFalse(
			export.stagedUpdates.isEmpty, "the outstanding prepare stages an Upd")

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertNoThrow(
			try TwoMLSPQSession.TwoMLSSession.restore(
				core: nil, checkpoint: minted.archive,
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	// MARK: - 6. A `pq_wedged` export

	/// No FFI-reachable way exists to latch `pq_wedged` deliberately — it only sets past a
	/// bind's point of no return on a genuine internal failure the public API can't
	/// trigger on demand (see the Rust `test_migration_export_carries_pq_wedged`, which
	/// pokes the field directly). So a synthetic mutation stands in: native's mint must
	/// carry the wedged flag through (`deployedState.pqWedged` is a straight passthrough)
	/// rather than reject it.
	func testPqWedgedExportMintsAndRestores() throws {
		let (alice, _) = try establishCardPair()
		var export = try alice.migrationExport()
		var deployed =
			export.deployedState
			?? TwoMLSPQBinding.SessionMigrationDeployedState(
				ownOffers: nil, pqWedged: nil,
				noCustody: TwoMLSPQBinding.SessionMigrationNoCustody(
					sendClassical: false, sendPq: false, recvClassical: false,
					recvPq: false))
		deployed.pqWedged = .bootstrap
		export.deployedState = deployed

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let restored = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertTrue(restored.pqSideBandWedged)
	}

	// MARK: - 7. The no-custody state

	/// Mirrors the Rust `test_migration_export_carries_no_custody_from_an_unchecked_join_
	/// signer`. Alice's send-PQ signer (installed at `initiate`) is never itself refreshed;
	/// three classical rotations run while her recv-PQ leaf (populated only at bob's A.3
	/// join) sits untouched, so bob's post-bind A.5 catch-up moves alice's send-PQ signer
	/// while nothing refreshes recv-PQ — it ends up presenting a key the derive pool can no
	/// longer produce. A genuine, FFI-reachable no-custody state, unlike the synthetic
	/// `pq_wedged` case above.
	func testRecvPqNoCustodyExportMintsAndRestores() throws {
		let (alice, bob) = try establishConfirmedNonDedicatedPair()

		let kp = try alice.pqBootstrapBegin(rotating: nil)
		try bob.pqBootstrapRespond(kpMsg: kp)

		try rotateRound(
			party: bob, peer: alice,
			newId: TwoMLSPQBinding.ClientId(bytes: Data("mc-nc-bob1".utf8)))
		try rotateRound(
			party: alice, peer: bob,
			newId: TwoMLSPQBinding.ClientId(bytes: Data("mc-nc-alice1".utf8)))
		try rotateRound(
			party: bob, peer: alice,
			newId: TwoMLSPQBinding.ClientId(bytes: Data("mc-nc-bob-extra".utf8)))

		let welcome = try XCTUnwrap(bob.pqPendingOutbound(sealing: .fresh))
		try alice.pqBootstrapBind(welcomeMsg: welcome)
		try RustSessionTestHelpers.committingRound(binder: alice, peer: bob)

		// bob's send-PQ leaf lags his twice-rotated identity, staging an A.5 catch-up.
		_ = try bob.prepareToEncrypt(proposing: nil)
		let postBind = try bob.encrypt(appMessage: Data("post-bind".utf8))
		_ = try alice.processIncoming(ciphertext: postBind.cipherText)

		// Drain remaining side-band legs, dispatched by the opened frame's kind — mirrors
		// the Rust test's pump loop, tolerating a per-leg error (a stale/already-applied
		// leg later).
		for _ in 0..<8 {
			var delivered = false
			for (from, to) in [(alice, bob), (bob, alice)] {
				guard let leg = from.pqPendingOutbound(sealing: .fresh) else {
					continue
				}
				guard let opened = try? to.openIncoming(blob: leg) else { continue }
				guard case .pqSideBand(let kind) = opened.kind else { continue }
				switch kind {
				case .bootstrapKeyPackage:
					_ = try? to.pqBootstrapRespond(kpMsg: leg)
				case .bootstrapWelcome: _ = try? to.pqBootstrapBind(welcomeMsg: leg)
				case .ratchetEphemeralKey: _ = try? to.pqRatchetRespond(ekMsg: leg)
				case .ratchetCiphertext: _ = try? to.pqRatchetBind(ctMsg: leg)
				case .rekeyUpdate: _ = try? to.pqRekeyRespond(updMsg: leg)
				case .rekeyCommit: _ = try? to.pqRekeyApply(msg: leg)
				}
				delivered = true
			}
			if !delivered { break }
		}

		let export = try alice.migrationExport()
		let deployed = try XCTUnwrap(export.deployedState)
		XCTAssertTrue(
			deployed.noCustody.recvPq,
			"expected recv_pq no_custody once the handoff drops the last copy of D")
		XCTAssertFalse(deployed.noCustody.sendClassical)
		XCTAssertFalse(deployed.noCustody.sendPq)
		XCTAssertFalse(deployed.noCustody.recvClassical)
		XCTAssertNil(export.leafKeys.recvPq.current)

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let restored = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertTrue(restored.noCustody.contains(.recvPQ))
	}

	// MARK: - 8. Pre-A.3 acceptor

	/// A confirmed pair before A.3: bob's send-PQ isn't founded yet, so his export carries the
	/// canonical empty set, neither a reservation nor no-custody. Native bob then answers A.3
	/// himself on a freshly minted key, and Rust alice binds and discharges.
	func testPreA3AcceptorExportsEmptySendPqAndAnswersA3Natively() throws {
		let (alice, bob) = try establishConfirmedNonDedicatedPair()

		let export = try bob.migrationExport()
		XCTAssertNil(export.leafKeys.sendPq.current)
		XCTAssertTrue(export.leafKeys.sendPq.pending.isEmpty)
		XCTAssertFalse(export.deployedState?.noCustody.sendPq ?? false)

		let minted = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: minted.archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertFalse(nativeBob.isFullyEstablished)

		let kp = try alice.pqBootstrapBegin(rotating: nil)
		let welcomePrime = try nativeBob.pqBootstrapRespond(kp).frame
		XCTAssertTrue(nativeBob.isFullyEstablished)
		let opened = try XCTUnwrap(try alice.openIncoming(blob: welcomePrime))
		try alice.pqBootstrapBind(welcomeMsg: opened.frame)

		// Discharge the bind: native bob offers, Rust alice commits.
		_ = try nativeBob.prepareToEncrypt()
		let bobUpd = try nativeBob.encrypt(Data("mc-a3-bob-upd".utf8))
		let offered = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobUpd.frame)?.proposal)
		try alice.queueProposal(digest: offered.digest)
		XCTAssertTrue(try alice.prepareToEncrypt(proposing: nil).didCommit)
		let aliceCommit = try alice.encrypt(appMessage: Data("mc-a3-alice-commit".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceCommit.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("mc-a3-alice-commit".utf8))
		XCTAssertTrue(alice.isFullyEstablished())

		_ = try nativeBob.prepareToEncrypt()
		let bobMsg = try nativeBob.encrypt(Data("mc-a3-bob-msg".utf8))
		let aliceGot = try XCTUnwrap(alice.processIncoming(ciphertext: bobMsg.frame))
		XCTAssertEqual(
			aliceGot.applicationMessage?.appMessageData, Data("mc-a3-bob-msg".utf8))
	}

	// MARK: - Shared establishment scaffolding

	/// A plain pair (no bootstrap-KP piggyback, PQ deferred), joined with one confirm frame
	/// each way so both sides satisfy the `peer_confirmed` precondition a later unilateral
	/// rotation commit needs. Mirrors the Rust `establish_confirmed_sessions` helper.
	private func establishConfirmedNonDedicatedPair() throws -> (
		alice: TwoMLSPQBinding.TwoMlsPqSession, bob: TwoMLSPQBinding.TwoMlsPqSession
	) {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-nc-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-nc-bob".utf8))
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
				domain: "mc-nc", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope"
				])
		}
		let welcome = try XCTUnwrap(frame.welcome)
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("mc-nc-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		let welcomeB = try XCTUnwrap(bobSession.pendingOutbound())
		_ = try aliceSession.processIncoming(ciphertext: welcomeB)

		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let confirmA = try aliceSession.encrypt(appMessage: Data("confirm-a".utf8))
		_ = try bobSession.processIncoming(ciphertext: confirmA.cipherText)
		_ = try bobSession.prepareToEncrypt(proposing: nil)
		let confirmB = try bobSession.encrypt(appMessage: Data("confirm-b".utf8))
		_ = try aliceSession.processIncoming(ciphertext: confirmB.cipherText)

		return (aliceSession, bobSession)
	}

	/// Mirrors the Rust `rotate_round` helper: `party` proposes `newId`, `peer` commits it
	/// (the committed credential defines `party`'s next identity), and `party` applies the
	/// returning canonicalize frame.
	private func rotateRound(
		party: TwoMLSPQBinding.TwoMlsPqSession, peer: TwoMLSPQBinding.TwoMlsPqSession,
		newId: TwoMLSPQBinding.ClientId
	) throws {
		_ = try party.prepareToEncrypt(proposing: newId)
		let enc = try party.encrypt(appMessage: Data("rotate".utf8))
		let offered = try XCTUnwrap(
			peer.processIncoming(ciphertext: enc.cipherText)?.proposal)
		XCTAssertEqual(offered.proposing, newId)
		try peer.queueProposal(digest: offered.digest)
		let prepared = try peer.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(prepared.didCommit)
		XCTAssertEqual(prepared.committedRemoteClientId, newId)
		let frame = try peer.encrypt(appMessage: Data("canonicalize".utf8))
		let got = try XCTUnwrap(party.processIncoming(ciphertext: frame.cipherText))
		XCTAssertEqual(got.remoteCommit?.newRecipient, newId)
	}

	/// A non-dedicated ("card") pair through full establishment, with a trailing message
	/// each way so neither side has anything mid-flight at return. Duplicated (not shared)
	/// across this package's test files by convention — see
	/// `DeployedStateMigrationTests.establishFullPair`.
	private func establishCardPair() throws -> (
		alice: TwoMLSPQBinding.TwoMlsPqSession, bob: TwoMLSPQBinding.TwoMlsPqSession
	) {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("mc-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("mc-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let kpEnvelope = try aliceSession.pqBootstrapEnvelope()
		let replyEnvelope = try XCTUnwrap(aliceSession.pendingOutbound())

		guard
			case .bootstrapKp(let heldKp) = try bobInvitation.openInitial(
				blob: kpEnvelope)
		else {
			throw NSError(
				domain: "mc", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected a bootstrap-KP envelope"
				])
		}
		guard
			case .establishment(let frame) = try bobInvitation.openInitial(
				blob: replyEnvelope)
		else {
			throw NSError(
				domain: "mc", code: 2,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope"
				])
		}
		let welcome = try XCTUnwrap(frame.welcome)
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("mc-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)

		try bobSession.pqBootstrapRespond(kpMsg: heldKp)
		let welcomePrime = try XCTUnwrap(bobSession.pqTakePendingOutbound())
		let returnWelcome = try XCTUnwrap(bobSession.pendingOutbound())

		_ = try aliceSession.processIncoming(ciphertext: returnWelcome)
		try aliceSession.pqBootstrapBind(welcomeMsg: welcomePrime)
		try RustSessionTestHelpers.committingRound(binder: aliceSession, peer: bobSession)
		XCTAssertTrue(aliceSession.isFullyEstablished())
		XCTAssertTrue(bobSession.isFullyEstablished())

		try RustSessionTestHelpers.rustSay(bobSession, "mc-pq-app", deliverTo: aliceSession)
		try RustSessionTestHelpers.rustSay(
			aliceSession, "mc-pq-app-2", deliverTo: bobSession)
		return (aliceSession, bobSession)
	}
}
