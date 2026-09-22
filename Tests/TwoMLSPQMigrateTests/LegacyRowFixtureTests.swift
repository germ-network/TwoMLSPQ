import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// Proves that `PQSession.Persisted` rows written by TwoMLSPQ v0.16.0 (binding contract 33,
// pre-`swift_export`) still restore and keep messaging under this engine, and that the
// initiator row migrates to the native engine. See Fixtures/v0.16.0/README.md for what the
// six capture points (p1-p6) represent and how they were generated — p4/p5/p6 additionally pin
// that a PQ round left PARKED (never delivered — a session whose side-band transport stalled,
// permanently for p4, after A.3 for p5, or in the field shape p6 exercises) still HEALS after
// restore once the parked leg is finally delivered.
//
// This target does NOT depend on `TwoMLSPQ` (Package.swift name collisions) — rows are decoded
// with a local `Codable` matching `PQSession.Persisted`'s JSON shape, and restored through the
// raw binding, the app's own migration path.
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper names, so FFI record
// types are module-qualified throughout (matching `SessionMigrationTests`).

private struct PersistedRow: Codable {
	var core: Data?
	var checkpoint: Data
}

private struct FixtureMeta: Codable {
	struct SideSeqs: Codable {
		var coreSeq: UInt64?
		var checkpointSeq: UInt64
		/// This side's own `isFullyEstablished()` at capture.
		var isFullyEstablished: Bool
		/// This side's own `PQSession.turn` at capture — `"weInitiate"` / `"theyInitiate"`.
		var turn: String
		/// Whether this side still owed an outbound side-band leg at capture
		/// (`pendingSideBand(sealing:)` non-nil).
		var legParked: Bool
	}
	struct PointInfo: Codable {
		/// Per-point, not shared — p6 is an independent identity pair from p1-p5.
		var dedicatedId: String
		var initiator: SideSeqs
		var acceptor: SideSeqs
	}
	var points: [String: PointInfo]
}

private enum FixtureTestError: Error {
	case missingMetaPoint(String)
}

@available(macOS 26, iOS 26, *)
final class LegacyRowFixtureTests: XCTestCase {
	/// The native providers, mirroring `SessionMigrationTests`.
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	private func fixturesDir() -> URL {
		Bundle.module.resourceURL!.appendingPathComponent("Fixtures/v0.16.0")
	}

	private func loadRow(point: String, side: String) throws -> PersistedRow {
		let url =
			fixturesDir()
			.appendingPathComponent(point)
			.appendingPathComponent("\(side).json")
		return try JSONDecoder().decode(PersistedRow.self, from: try Data(contentsOf: url))
	}

	private func loadMeta() throws -> FixtureMeta {
		let url = fixturesDir().appendingPathComponent("meta.json")
		return try JSONDecoder().decode(FixtureMeta.self, from: try Data(contentsOf: url))
	}

	/// The app's raw-binding migration path: `TwoMlsPqSession.restore(core:checkpoint:)`.
	private func restore(_ row: PersistedRow) throws -> TwoMLSPQBinding.TwoMlsPqSession {
		try TwoMLSPQBinding.TwoMlsPqSession.restore(
			core: row.core.map { TwoMLSPQBinding.Archive(bytes: $0) },
			checkpoint: TwoMLSPQBinding.Archive(bytes: row.checkpoint))
	}

	/// Restore a row AND make the seq/establishment/turn/parked-leg claims real: the restored
	/// session's own `stateSeq()`, `isFullyEstablished()`, `myPqTurn()`, and parked-leg state
	/// (`pqPendingOutbound(sealing:)` non-nil) must all match what meta recorded for that row at
	/// capture, and — acceptor only — its `myPrincipalState()` must be `.sync` of meta's
	/// dedicated id. `file`/`line` thread through so a failure attributes to the caller.
	private func restoreAndVerify(
		point: String, side: String,
		file: StaticString = #filePath, line: UInt = #line
	) throws -> TwoMLSPQBinding.TwoMlsPqSession {
		let row = try loadRow(point: point, side: side)
		let meta = try loadMeta()
		guard let pointMeta = meta.points[point] else {
			throw FixtureTestError.missingMetaPoint(point)
		}
		let sideMeta = side == "initiator" ? pointMeta.initiator : pointMeta.acceptor

		let session = try restore(row)

		XCTAssertEqual(
			session.stateSeq(), max(sideMeta.coreSeq ?? 0, sideMeta.checkpointSeq),
			"\(point)/\(side): restored stateSeq should match meta's recorded seq",
			file: file, line: line)
		XCTAssertEqual(
			session.isFullyEstablished(), sideMeta.isFullyEstablished,
			"\(point)/\(side): isFullyEstablished should match meta's recorded value",
			file: file, line: line)
		XCTAssertEqual(
			session.myPqTurn(), sideMeta.turn == "weInitiate",
			"\(point)/\(side): myPqTurn() should match meta's recorded turn",
			file: file, line: line)
		XCTAssertEqual(
			session.pqPendingOutbound(sealing: .fresh) != nil, sideMeta.legParked,
			"\(point)/\(side): parked-leg state should match meta's recorded legParked",
			file: file, line: line)
		if side == "acceptor" {
			guard let dedicatedIdBytes = Data(base64Encoded: pointMeta.dedicatedId)
			else {
				XCTFail(
					"meta.dedicatedId is not valid base64", file: file,
					line: line)
				return session
			}
			if case .sync(let clientId) = session.myPrincipalState() {
				XCTAssertEqual(
					clientId.bytes, dedicatedIdBytes,
					"\(point)/acceptor: myPrincipalState should be the dedicated id",
					file: file, line: line)
			} else {
				XCTFail(
					"\(point)/acceptor: expected .sync principal state",
					file: file, line: line)
			}
		}
		return session
	}

	// MARK: - meta sanity

	/// At least one captured row must have coreSeq > checkpointSeq, so the core-splice restore
	/// path (core's identity/classical/meta layered over the checkpoint's PQ trees) is
	/// actually exercised by the points below, not just a checkpoint-only restore.
	/// `restoreAndVerify`'s own stateSeq assertion above is what makes this claim real rather
	/// than a check on the JSON alone (verified: pointing it at the wrong point's rows fails).
	func testAtLeastOneRowExercisesCoreSplice() throws {
		let meta = try loadMeta()
		let exercised = meta.points.values.contains {
			($0.initiator.coreSeq ?? 0) > $0.initiator.checkpointSeq
				|| ($0.acceptor.coreSeq ?? 0) > $0.acceptor.checkpointSeq
		}
		XCTAssertTrue(
			exercised,
			"expected at least one row with coreSeq > checkpointSeq across the captured points"
		)
	}

	// MARK: - Restore + liveness, per point

	func testP1RestoresAndStaysLive() throws {
		try assertRestoreAndLiveness(point: "p1-bob-sent-unfolded")
	}

	func testP2RestoresAndStaysLive() throws {
		try assertRestoreAndLiveness(point: "p2-converged")
	}

	func testP3RestoresAndStaysLive() throws {
		try assertRestoreAndLiveness(point: "p3-steady")
	}

	func testP4RestoresAndStaysLive() throws {
		try assertRestoreAndLiveness(point: "p4-a3-stalled")
	}

	func testP5RestoresAndStaysLive() throws {
		try assertRestoreAndLiveness(point: "p5-a4-stalled")
	}

	func testP6RestoresAndStaysLive() throws {
		try assertRestoreAndLiveness(point: "p6-a3-responded-stalled")
	}

	/// Restore both v0.16.0 rows, then prove they are live (not just decodable): a message each
	/// way, a committing round each way, a message each way. (p4/p5/p6 additionally still carry
	/// their parked leg here — that healing is a separate, dedicated test below.)
	private func assertRestoreAndLiveness(point: String) throws {
		let alice = try restoreAndVerify(point: point, side: "initiator")
		let bob = try restoreAndVerify(point: point, side: "acceptor")

		try RustSessionTestHelpers.rustSay(alice, "\(point)-alice-1", deliverTo: bob)
		try RustSessionTestHelpers.rustSay(bob, "\(point)-bob-1", deliverTo: alice)

		try RustSessionTestHelpers.committingRound(binder: alice, peer: bob)
		try RustSessionTestHelpers.committingRound(binder: bob, peer: alice)

		try RustSessionTestHelpers.rustSay(alice, "\(point)-alice-2", deliverTo: bob)
		try RustSessionTestHelpers.rustSay(bob, "\(point)-bob-2", deliverTo: alice)
	}

	// MARK: - A stalled PQ round heals after restore (p4/p5/p6)

	/// p4: alice's A.3 KP' leg was left parked (never delivered) before capture. After restore
	/// it is STILL there (the side-band take is non-nil) — deliver it now and drive the round
	/// to completion: bob responds, alice binds the Welcome', the owed bind discharges (a
	/// committing round — the same raw-level pattern `SessionMigrationTests.dischargeBind`
	/// uses), then a message each way.
	func testP4StalledA3RoundHealsAfterRestore() throws {
		let alice = try restoreAndVerify(point: "p4-a3-stalled", side: "initiator")
		let bob = try restoreAndVerify(point: "p4-a3-stalled", side: "acceptor")

		let sealedKp = try XCTUnwrap(
			alice.pqPendingOutbound(sealing: .fresh),
			"expected alice's parked A.3 KP' leg to survive restore")
		let openedKp = try XCTUnwrap(try bob.openIncoming(blob: sealedKp))
		try bob.pqBootstrapRespond(kpMsg: openedKp.frame)

		let sealedWelcomePrime = try XCTUnwrap(bob.pqTakePendingOutbound())
		let openedWelcomePrime = try XCTUnwrap(
			try alice.openIncoming(blob: sealedWelcomePrime))
		try alice.pqBootstrapBind(welcomeMsg: openedWelcomePrime.frame)

		// Discharge the owed bind — peer (bob) offers, alice (the binder) approves + commits.
		try RustSessionTestHelpers.committingRound(binder: alice, peer: bob)

		XCTAssertTrue(
			alice.isFullyEstablished(), "the healed round should fully establish alice")
		XCTAssertTrue(
			bob.isFullyEstablished(), "the healed round should fully establish bob")
		// The discharge is also what passes the PQ turn from the initiator to the acceptor
		// (mirrors LifecycleTests' A.3 step) — assert it actually moved, and that neither side
		// is left with anything still parked, BEFORE any further send can auto-stage a new leg.
		XCTAssertFalse(
			alice.myPqTurn(), "the discharge should pass the PQ turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge should pass the PQ turn to bob")
		XCTAssertNil(
			alice.pqPendingOutbound(sealing: .fresh), "alice should have nothing parked"
		)
		XCTAssertNil(
			bob.pqPendingOutbound(sealing: .fresh), "bob should have nothing parked")

		try RustSessionTestHelpers.rustSay(alice, "p4-healed-alice", deliverTo: bob)
		try RustSessionTestHelpers.rustSay(bob, "p4-healed-bob", deliverTo: alice)
	}

	/// p5: a NEW A.4 EK was auto-staged and left parked (never delivered) before capture, on
	/// whichever side held the turn. After restore it is STILL there on that same side — find
	/// it, deliver it now, and drive the round to completion: the peer responds with the CT,
	/// the turn holder binds it (discharging its own owed bind via a committing round), then a
	/// message each way.
	func testP5StalledA4RoundHealsAfterRestore() throws {
		let alice = try restoreAndVerify(point: "p5-a4-stalled", side: "initiator")
		let bob = try restoreAndVerify(point: "p5-a4-stalled", side: "acceptor")

		// Pick the turn holder from meta (restoreAndVerify already confirmed both sides' own
		// `myPqTurn()`/parked state agree with it) rather than re-probing pendingOutbound here.
		let meta = try loadMeta()
		let pointMeta = try XCTUnwrap(meta.points["p5-a4-stalled"])
		let aliceHolds = pointMeta.initiator.legParked
		XCTAssertNotEqual(
			aliceHolds, pointMeta.acceptor.legParked,
			"exactly one side should hold the parked A.4 leg")
		let turnHolder = aliceHolds ? alice : bob
		let other = aliceHolds ? bob : alice

		XCTAssertTrue(
			turnHolder.myPqTurn(), "the turn holder should still hold the PQ turn")
		let pqBefore = turnHolder.epochs().pqEpoch

		let sealedEk = try XCTUnwrap(
			turnHolder.pqPendingOutbound(sealing: .fresh),
			"expected the turn holder's parked A.4 EK to survive restore")
		let openedEk = try XCTUnwrap(try other.openIncoming(blob: sealedEk))
		try other.pqRatchetRespond(ekMsg: openedEk.frame)

		let sealedCt = try XCTUnwrap(other.pqTakePendingOutbound())
		let openedCt = try XCTUnwrap(try turnHolder.openIncoming(blob: sealedCt))
		try turnHolder.pqRatchetBind(ctMsg: openedCt.frame)

		// The round actually COMPLETED: the PQ epoch advanced by exactly one, and neither side
		// still owes an outbound side-band leg.
		XCTAssertEqual(
			turnHolder.epochs().pqEpoch, pqBefore + 1,
			"binding the CT should advance the turn holder's PQ epoch by one")
		XCTAssertNil(
			turnHolder.pqPendingOutbound(sealing: .fresh),
			"the turn holder should have nothing parked after binding")
		XCTAssertNil(
			other.pqPendingOutbound(sealing: .fresh),
			"the peer should have nothing parked either")

		// Discharge the turn holder's own owed bind — the peer offers, the turn holder commits.
		try RustSessionTestHelpers.committingRound(binder: turnHolder, peer: other)

		// The discharge passes the PQ turn to the peer — assert it actually moved, BEFORE any
		// further send (the final rustSay below) can auto-stage a new leg on the new holder.
		XCTAssertFalse(
			turnHolder.myPqTurn(),
			"the discharge should pass the PQ turn away from the holder")
		XCTAssertTrue(other.myPqTurn(), "the discharge should pass the PQ turn to the peer")

		try RustSessionTestHelpers.rustSay(alice, "p5-healed-alice", deliverTo: bob)
		try RustSessionTestHelpers.rustSay(bob, "p5-healed-bob", deliverTo: alice)
	}

	/// p6: bob already answered A.3 (his Welcome' response) before capture, but it was never
	/// shipped — it is the field shape, not p4's contrived one. After restore it is STILL there
	/// on bob's side — deliver it directly to alice (`pqBootstrapBind`; no `pqBootstrapRespond`
	/// step here, since bob already ran that part), discharge the owed bind, then a message
	/// each way.
	func testP6ResponderStalledA3HealsAfterRestore() throws {
		let alice = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "initiator")
		let bob = try restoreAndVerify(point: "p6-a3-responded-stalled", side: "acceptor")

		let sealedWelcomePrime = try XCTUnwrap(
			bob.pqPendingOutbound(sealing: .fresh),
			"expected bob's parked A.3 Welcome' response to survive restore")
		let openedWelcomePrime = try XCTUnwrap(
			try alice.openIncoming(blob: sealedWelcomePrime))
		try alice.pqBootstrapBind(welcomeMsg: openedWelcomePrime.frame)

		// Discharge the owed bind — peer (bob) offers, alice (the binder) approves + commits.
		try RustSessionTestHelpers.committingRound(binder: alice, peer: bob)

		XCTAssertTrue(
			alice.isFullyEstablished(), "the healed round should fully establish alice")
		XCTAssertTrue(
			bob.isFullyEstablished(),
			"bob was already fully established by his own response")
		// Same turn-passing / nothing-left-parked shape as p4's discharge.
		XCTAssertFalse(
			alice.myPqTurn(), "the discharge should pass the PQ turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge should pass the PQ turn to bob")
		XCTAssertNil(
			alice.pqPendingOutbound(sealing: .fresh), "alice should have nothing parked"
		)
		XCTAssertNil(
			bob.pqPendingOutbound(sealing: .fresh), "bob should have nothing parked")

		try RustSessionTestHelpers.rustSay(alice, "p6-healed-alice", deliverTo: bob)
		try RustSessionTestHelpers.rustSay(bob, "p6-healed-bob", deliverTo: alice)
	}

	// MARK: - Initiator migration, every point, with a cross-engine committing round each way

	func testP1InitiatorMigratesAndMessagesRustAcceptor() throws {
		try assertInitiatorMigrates(point: "p1-bob-sent-unfolded")
	}

	func testP2InitiatorMigratesAndMessagesRustAcceptor() throws {
		try assertInitiatorMigrates(point: "p2-converged")
	}

	func testP3InitiatorMigratesAndMessagesRustAcceptor() throws {
		try assertInitiatorMigrates(point: "p3-steady")
	}

	func testP4InitiatorMigratesAndMessagesRustAcceptor() throws {
		try assertInitiatorMigrates(point: "p4-a3-stalled")
	}

	func testP5InitiatorMigratesAndMessagesRustAcceptor() throws {
		try assertInitiatorMigrates(point: "p5-a4-stalled")
	}

	func testP6InitiatorMigratesAndMessagesRustAcceptor() throws {
		try assertInitiatorMigrates(point: "p6-a3-responded-stalled")
	}

	/// Pattern of `SessionMigrationTests.testMigratedSessionKeepsMessagingWithRustPeer`: mint a
	/// native archive from the export, restore it there, message a FRESH Rust restore of the
	/// acceptor row both ways, then a cross-engine COMMITTING round each way —
	/// native alice folds bob's Upd and Rust bob folds native alice's — before a final message
	/// each way.
	private func assertInitiatorMigrates(point: String) throws {
		let freshAlice = try restoreAndVerify(point: point, side: "initiator")
		let export = try freshAlice.migrationExport()

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let bob = try restoreAndVerify(point: point, side: "acceptor")

		// Message each way.
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFrame = try bob.encrypt(
			appMessage: Data("\(point)-bob-to-migrated-alice".utf8))
		let opened = try nativeAlice.processIncoming(bobFrame.cipherText)
		guard case .decrypted(let decrypted) = opened else {
			XCTFail("expected a decrypted application frame, got \(opened)")
			return
		}
		XCTAssertEqual(
			decrypted.applicationMessage, Data("\(point)-bob-to-migrated-alice".utf8))

		_ = try nativeAlice.prepareToEncrypt()
		let reply = try nativeAlice.encrypt(Data("\(point)-migrated-alice-to-bob".utf8))
		let bobGot = try XCTUnwrap(bob.processIncoming(ciphertext: reply.frame))
		XCTAssertEqual(
			bobGot.applicationMessage?.appMessageData,
			Data("\(point)-migrated-alice-to-bob".utf8))

		// Cross-engine committing round, native alice as binder: Rust bob offers an Upd, native
		// alice queues it (from the decrypted frame's ALWAYS-present `queuedProposal`) and her
		// next `prepareToEncrypt` must commit it; Rust bob applies the resulting commit.
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame = try bob.encrypt(appMessage: Data("\(point)-bob-upd".utf8))
		let aliceOpened = try nativeAlice.processIncoming(bobUpdFrame.cipherText)
		guard case .decrypted(let aliceDecrypted) = aliceOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		let alicePrepared = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared.didCommit, "native alice's fold of bob's Upd should commit")
		let aliceCommitFrame = try nativeAlice.encrypt(Data("\(point)-alice-commit".utf8))
		let bobGotCommit = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame.frame))
		XCTAssertEqual(
			bobGotCommit.applicationMessage?.appMessageData,
			Data("\(point)-alice-commit".utf8))

		// Cross-engine committing round, Rust bob as binder: native alice offers an Upd, Rust
		// bob queues + commits it; native alice sees the remote commit applied.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceUpdFrame = try nativeAlice.encrypt(Data("\(point)-alice-upd".utf8))
		let bobDecrypted = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceUpdFrame.frame))
		let bobOffered = try XCTUnwrap(bobDecrypted.proposal)
		try bob.queueProposal(digest: bobOffered.digest)
		let bobPrepared = try bob.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "Rust bob's fold of alice's Upd should commit")
		let bobCommitFrame = try bob.encrypt(appMessage: Data("\(point)-bob-commit".utf8))
		let aliceCommitOpened = try nativeAlice.processIncoming(bobCommitFrame.cipherText)
		guard case .decrypted(let aliceCommitDecrypted) = aliceCommitOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceCommitOpened)")
			return
		}
		XCTAssertEqual(
			aliceCommitDecrypted.applicationMessage, Data("\(point)-bob-commit".utf8))
		XCTAssertTrue(
			aliceCommitDecrypted.didApplyRemoteCommit,
			"native alice should see the remote commit applied")

		// Final message each way.
		_ = try nativeAlice.prepareToEncrypt()
		let finalFromAlice = try nativeAlice.encrypt(Data("\(point)-final-alice".utf8))
		let bobGotFinal = try XCTUnwrap(
			bob.processIncoming(ciphertext: finalFromAlice.frame))
		XCTAssertEqual(
			bobGotFinal.applicationMessage?.appMessageData,
			Data("\(point)-final-alice".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let finalFromBob = try bob.encrypt(appMessage: Data("\(point)-final-bob".utf8))
		let aliceFinalOpened = try nativeAlice.processIncoming(finalFromBob.cipherText)
		guard case .decrypted(let aliceFinalDecrypted) = aliceFinalOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceFinalOpened)")
			return
		}
		XCTAssertEqual(
			aliceFinalDecrypted.applicationMessage, Data("\(point)-final-bob".utf8))
	}

	// MARK: - Acceptor export still refused (every point)

	func testP1AcceptorExportRefusedSessionNotReady() throws {
		try assertAcceptorExportRefused(point: "p1-bob-sent-unfolded")
	}

	func testP2AcceptorExportRefusedSessionNotReady() throws {
		try assertAcceptorExportRefused(point: "p2-converged")
	}

	func testP3AcceptorExportRefusedSessionNotReady() throws {
		try assertAcceptorExportRefused(point: "p3-steady")
	}

	func testP4AcceptorExportRefusedSessionNotReady() throws {
		try assertAcceptorExportRefused(point: "p4-a3-stalled")
	}

	func testP5AcceptorExportRefusedSessionNotReady() throws {
		try assertAcceptorExportRefused(point: "p5-a4-stalled")
	}

	func testP6AcceptorExportRefusedSessionNotReady() throws {
		try assertAcceptorExportRefused(point: "p6-a3-responded-stalled")
	}

	/// The born-dedicated acceptor's `migrationExport()` is refused at every captured point —
	/// admitting an installed, classical-converged acceptor is a separate, later change.
	private func assertAcceptorExportRefused(point: String) throws {
		let bob = try restoreAndVerify(point: point, side: "acceptor")
		XCTAssertThrowsError(try bob.migrationExport()) { error in
			XCTAssertEqual(error as? TwoMLSPQBinding.TwoMlsPqError, .SessionNotReady)
		}
	}
}
