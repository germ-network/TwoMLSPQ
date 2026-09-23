import Foundation
import MLSCrypto
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// Proves that `PQSession.Persisted` rows written by older TwoMLSPQ releases (pre-`swift_export`)
// still restore and keep messaging under this engine, and that the initiator row migrates to the
// native engine. Covers two historical binding contracts, one fixture directory each — see
// Fixtures/v0.15.0/README.md (binding contract 32) and Fixtures/v0.16.0/README.md (binding
// contract 33) for what the six capture points (p1-p6) represent and how they were generated —
// p4/p5/p6 additionally pin that a PQ round left PARKED (never delivered — a session whose
// side-band transport stalled, permanently for p4, after A.3 for p5, or in the field shape p6
// exercises) still HEALS after restore once the parked leg is finally delivered.
//
// `LegacyRowFixtureTests` reads `Fixtures/<Self.fixtureVersion>`; `LegacyRowFixtureTestsV015`
// overrides that alone to point at v0.15.0's fixtures — XCTest runs every inherited test method
// on each subclass, so the whole suite below runs twice (once per pinned contract) with no
// duplicated test bodies.
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
class LegacyRowFixtureTests: XCTestCase {
	/// The `Fixtures/<version>` subdirectory this run restores from. Override in a subclass to
	/// point at a different pinned binding contract — see `LegacyRowFixtureTestsV015` below.
	class var fixtureVersion: String { "v0.16.0" }

	/// The native providers, mirroring `SessionMigrationTests`.
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	private func fixturesDir() -> URL {
		Bundle.module.resourceURL!.appendingPathComponent("Fixtures/\(Self.fixtureVersion)")
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

	// MARK: - Acceptor export: p1 still refused, p2-p6 now migrate

	/// p1: bob has sent but alice has not yet folded his catch-up Upd — his recv-classical
	/// leaf still presents the invitation identity's key, and the custody gate refuses it
	/// (`SessionNotReady`, not `Mls`).
	func testP1AcceptorExportRefusedSessionNotReady() throws {
		let bob = try restoreAndVerify(point: "p1-bob-sent-unfolded", side: "acceptor")
		XCTAssertThrowsError(try bob.migrationExport()) { error in
			XCTAssertEqual(error as? TwoMLSPQBinding.TwoMlsPqError, .SessionNotReady)
		}
	}

	func testP2AcceptorMigratesAndMessagesRustInitiator() throws {
		try assertAcceptorMigrates(point: "p2-converged")
	}

	func testP3AcceptorMigratesAndMessagesRustInitiator() throws {
		try assertAcceptorMigrates(point: "p3-steady")
	}

	func testP4AcceptorMigratesAndMessagesRustInitiator() throws {
		try assertAcceptorMigrates(point: "p4-a3-stalled")
	}

	func testP5AcceptorMigratesAndMessagesRustInitiator() throws {
		try assertAcceptorMigrates(point: "p5-a4-stalled")
	}

	func testP6AcceptorMigratesAndMessagesRustInitiator() throws {
		try assertAcceptorMigrates(point: "p6-a3-responded-stalled")
	}

	/// The 0.16.0 ACCEPTOR row at `point` (converged onward) now exports, mints, and
	/// restores natively: a message each way with a FRESH Rust restore of the initiator
	/// row, then a cross-engine committing round each way — mirrors
	/// `assertInitiatorMigrates` with the roles swapped. This is the app's real
	/// population: born-dedicated, 0.16-written, never-drained parked welcome.
	private func assertAcceptorMigrates(point: String) throws {
		let freshBob = try restoreAndVerify(point: point, side: "acceptor")
		let export = try freshBob.migrationExport()
		XCTAssertNotNil(
			export.pqLeafCustody, "\(point): the acceptor's PQ custody should export")

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let alice = try restoreAndVerify(point: point, side: "initiator")

		// Message each way.
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceFrame = try alice.encrypt(
			appMessage: Data("\(point)-alice-to-migrated-bob".utf8))
		let opened = try nativeBob.processIncoming(aliceFrame.cipherText)
		guard case .decrypted(let decrypted) = opened else {
			XCTFail("expected a decrypted application frame, got \(opened)")
			return
		}
		XCTAssertEqual(
			decrypted.applicationMessage, Data("\(point)-alice-to-migrated-bob".utf8))

		_ = try nativeBob.prepareToEncrypt()
		let reply = try nativeBob.encrypt(Data("\(point)-migrated-bob-to-alice".utf8))
		let aliceGot = try XCTUnwrap(alice.processIncoming(ciphertext: reply.frame))
		XCTAssertEqual(
			aliceGot.applicationMessage?.appMessageData,
			Data("\(point)-migrated-bob-to-alice".utf8))

		// Cross-engine committing round, native bob as binder: Rust alice offers an Upd,
		// native bob queues it and his next `prepareToEncrypt` must commit it; Rust alice
		// applies the resulting commit.
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceUpdFrame = try alice.encrypt(appMessage: Data("\(point)-alice-upd".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceUpdFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(
			bobPrepared.didCommit, "native bob's fold of alice's Upd should commit")
		let bobCommitFrame = try nativeBob.encrypt(Data("\(point)-bob-commit".utf8))
		let aliceGotCommit = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobCommitFrame.frame))
		XCTAssertEqual(
			aliceGotCommit.applicationMessage?.appMessageData,
			Data("\(point)-bob-commit".utf8))

		// Cross-engine committing round, Rust alice as binder: native bob offers an Upd,
		// Rust alice queues + commits it; native bob sees the remote commit applied.
		_ = try nativeBob.prepareToEncrypt()
		let bobUpdFrame = try nativeBob.encrypt(Data("\(point)-bob-upd".utf8))
		let aliceDecrypted = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobUpdFrame.frame))
		let aliceOffered = try XCTUnwrap(aliceDecrypted.proposal)
		try alice.queueProposal(digest: aliceOffered.digest)
		let alicePrepared = try alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			alicePrepared.didCommit, "Rust alice's fold of bob's Upd should commit")
		let aliceCommitFrame = try alice.encrypt(
			appMessage: Data("\(point)-alice-commit".utf8))
		let bobCommitOpened = try nativeBob.processIncoming(aliceCommitFrame.cipherText)
		guard case .decrypted(let bobCommitDecrypted) = bobCommitOpened else {
			XCTFail("expected a decrypted application frame, got \(bobCommitOpened)")
			return
		}
		XCTAssertEqual(
			bobCommitDecrypted.applicationMessage, Data("\(point)-alice-commit".utf8))
		XCTAssertTrue(
			bobCommitDecrypted.didApplyRemoteCommit,
			"native bob should see the remote commit applied")

		// Final message each way.
		_ = try nativeBob.prepareToEncrypt()
		let finalFromBob = try nativeBob.encrypt(Data("\(point)-final-bob".utf8))
		let aliceGotFinal = try XCTUnwrap(
			alice.processIncoming(ciphertext: finalFromBob.frame))
		XCTAssertEqual(
			aliceGotFinal.applicationMessage?.appMessageData,
			Data("\(point)-final-bob".utf8))

		_ = try alice.prepareToEncrypt(proposing: nil)
		let finalFromAlice = try alice.encrypt(
			appMessage: Data("\(point)-final-alice".utf8))
		let bobFinalOpened = try nativeBob.processIncoming(finalFromAlice.cipherText)
		guard case .decrypted(let bobFinalDecrypted) = bobFinalOpened else {
			XCTFail("expected a decrypted application frame, got \(bobFinalOpened)")
			return
		}
		XCTAssertEqual(
			bobFinalDecrypted.applicationMessage, Data("\(point)-final-alice".utf8))
	}

	// MARK: - Field-state healing across engines (the real card shape)

	/// p6(i): the acceptor (bob) migrates to native; the initiator (alice) stays Rust. Bob's
	/// parked Welcome' response (never shipped before capture) must survive BOTH the export
	/// and the native restore — shown by taking it off native bob's OWN side-band peek,
	/// exactly as a live native host would to re-send a dropped leg. Delivered to Rust
	/// alice, the owed bind then discharges with a cross-engine committing round (native bob
	/// as the peer, Rust alice as the binder — `assertAcceptorMigrates`'s own pattern).
	func testP6AcceptorMigratedHealsA3WithRustInitiator() throws {
		let alice = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "initiator")
		let freshBob = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "acceptor")
		let export = try freshBob.migrationExport()
		XCTAssertNotNil(
			export.pendingSideBand, "bob's parked Welcome' should be in the export")
		XCTAssertNotNil(export.pqInflight, "bob's bootstrap-responded state should export")

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Bob's own send.pq was already founded before capture (he answered A.3 himself),
		// and his recv.pq (mirroring alice's Group_A.pq) has been his from the initial
		// establishment — so native bob is ALREADY fully established right off the
		// restore, before the heal below ever runs. Migration must preserve that.
		XCTAssertTrue(
			nativeBob.isFullyEstablished,
			"native bob's own A.3 response should already be complete after restore")

		// The native side-band take: bob still holds the parked Welcome' after migration.
		let welcomePrimeSealed = try XCTUnwrap(
			nativeBob.pqPendingOutbound(),
			"native bob should still hold the parked Welcome' after migration")

		// Deliver to Rust alice and discharge the owed bind across engines: native bob (the
		// peer) offers an Upd, Rust alice (the binder) queues + commits it.
		let opened = try XCTUnwrap(try alice.openIncoming(blob: welcomePrimeSealed))
		try alice.pqBootstrapBind(welcomeMsg: opened.frame)

		_ = try nativeBob.prepareToEncrypt()
		let bobUpd = try nativeBob.encrypt(Data("p6h-bob-upd".utf8))
		let offered = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobUpd.frame)?.proposal)
		try alice.queueProposal(digest: offered.digest)
		let alicePrepared = try alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			alicePrepared.didCommit,
			"alice's discharge commit should fold bob's offered Upd")
		let aliceCommit = try alice.encrypt(appMessage: Data("p6h-alice-commit".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceCommit.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("p6h-alice-commit".utf8))

		XCTAssertTrue(alice.isFullyEstablished(), "the healed round should establish alice")
		XCTAssertNil(
			alice.pqPendingOutbound(sealing: .fresh), "alice should have nothing parked"
		)
		XCTAssertNil(
			nativeBob.pqPendingOutbound(), "native bob should have nothing parked")
		// The discharge passes the PQ turn from the binder (alice, who owed the bind) to
		// the peer (bob) — same shape as the Rust-only p6 heal test above.
		XCTAssertFalse(
			alice.myPqTurn(), "the discharge should pass the PQ turn away from alice")
		XCTAssertTrue(
			nativeBob.myPQTurn, "the discharge should pass the PQ turn to native bob")

		// A message each way.
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceMsg = try alice.encrypt(appMessage: Data("p6h-alice-msg".utf8))
		let bobGotMsg = try nativeBob.processIncoming(aliceMsg.cipherText)
		guard case .decrypted(let bobMsgDecrypted) = bobGotMsg else {
			XCTFail("expected a decrypted application frame, got \(bobGotMsg)")
			return
		}
		XCTAssertEqual(bobMsgDecrypted.applicationMessage, Data("p6h-alice-msg".utf8))

		_ = try nativeBob.prepareToEncrypt()
		let bobMsg = try nativeBob.encrypt(Data("p6h-bob-msg".utf8))
		let aliceGotMsg = try XCTUnwrap(alice.processIncoming(ciphertext: bobMsg.frame))
		XCTAssertEqual(
			aliceGotMsg.applicationMessage?.appMessageData, Data("p6h-bob-msg".utf8))

		// A committing round each way.
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceUpdFrame = try alice.encrypt(appMessage: Data("p6h-alice-upd".utf8))
		let bobOpened2 = try nativeBob.processIncoming(aliceUpdFrame.cipherText)
		guard case .decrypted(let bobDecrypted2) = bobOpened2 else {
			XCTFail("expected a decrypted application frame, got \(bobOpened2)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted2.queuedProposal.digest)
		let bobPrepared = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(
			bobPrepared.didCommit, "native bob's fold of alice's Upd should commit")
		let bobCommitFrame = try nativeBob.encrypt(Data("p6h-bob-commit".utf8))
		let aliceGotCommit = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobCommitFrame.frame))
		XCTAssertEqual(
			aliceGotCommit.applicationMessage?.appMessageData,
			Data("p6h-bob-commit".utf8))

		_ = try nativeBob.prepareToEncrypt()
		let bobUpdFrame2 = try nativeBob.encrypt(Data("p6h-bob-upd2".utf8))
		let aliceDecrypted2 = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobUpdFrame2.frame))
		let aliceOffered2 = try XCTUnwrap(aliceDecrypted2.proposal)
		try alice.queueProposal(digest: aliceOffered2.digest)
		let alicePrepared2 = try alice.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			alicePrepared2.didCommit, "Rust alice's fold of bob's Upd should commit")
		let aliceCommitFrame2 = try alice.encrypt(
			appMessage: Data("p6h-alice-commit2".utf8))
		let bobCommitOpened2 = try nativeBob.processIncoming(aliceCommitFrame2.cipherText)
		guard case .decrypted(let bobCommitDecrypted2) = bobCommitOpened2 else {
			XCTFail("expected a decrypted application frame, got \(bobCommitOpened2)")
			return
		}
		XCTAssertEqual(
			bobCommitDecrypted2.applicationMessage, Data("p6h-alice-commit2".utf8))
		XCTAssertTrue(
			bobCommitDecrypted2.didApplyRemoteCommit,
			"native bob should see the remote commit applied")
	}

	/// p6(ii): the initiator (alice) migrates to native; the acceptor (bob) stays Rust.
	/// Bob's parked Welcome' (his own §A.3 response, still on the Rust side) is delivered
	/// straight into native alice's `pqBootstrapJoin` — which unseals it itself, same as
	/// `processIncoming` — joining Group_B.pq and owing the classical bind in one call. The
	/// bind then discharges with native alice as the binder (mirrors `assertInitiatorMigrates`).
	func testP6InitiatorMigratedHealsA3WithRustAcceptor() throws {
		let freshAlice = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "initiator")
		let export = try freshAlice.migrationExport()

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let bob = try restoreAndVerify(point: "p6-a3-responded-stalled", side: "acceptor")
		let sealedWelcomePrime = try XCTUnwrap(
			bob.pqPendingOutbound(sealing: .fresh),
			"expected bob's parked A.3 Welcome' response to survive restore")

		// Native alice's `pqBootstrapJoin` unseals `inbound` itself (like `processIncoming`)
		// — no separate open step, unlike the Rust-side `openIncoming` + `pqBootstrapBind`.
		_ = try nativeAlice.pqBootstrapJoin(sealedWelcomePrime)

		// Discharge across engines: Rust bob (the peer) offers an Upd, native alice (the
		// binder) queues + commits it.
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame = try bob.encrypt(appMessage: Data("p6h2-bob-upd".utf8))
		let aliceOpened = try nativeAlice.processIncoming(bobUpdFrame.cipherText)
		guard case .decrypted(let aliceDecrypted) = aliceOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		let alicePrepared = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared.didCommit,
			"native alice's discharge commit should fold bob's offered Upd")
		let aliceCommitFrame = try nativeAlice.encrypt(Data("p6h2-alice-commit".utf8))
		let bobGotCommit = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame.frame))
		XCTAssertEqual(
			bobGotCommit.applicationMessage?.appMessageData,
			Data("p6h2-alice-commit".utf8))

		XCTAssertTrue(
			nativeAlice.isFullyEstablished,
			"the healed round should establish native alice")
		XCTAssertNil(
			nativeAlice.pqPendingOutbound(), "native alice should have nothing parked")
		XCTAssertNil(
			bob.pqPendingOutbound(sealing: .fresh), "bob should have nothing parked")
		// The discharge passes the PQ turn from the binder (native alice) to the peer
		// (Rust bob).
		XCTAssertFalse(
			nativeAlice.myPQTurn,
			"the discharge should pass the PQ turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge should pass the PQ turn to bob")

		// A message each way.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceMsg = try nativeAlice.encrypt(Data("p6h2-alice-msg".utf8))
		let bobGotMsg = try XCTUnwrap(bob.processIncoming(ciphertext: aliceMsg.frame))
		XCTAssertEqual(
			bobGotMsg.applicationMessage?.appMessageData, Data("p6h2-alice-msg".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobMsg = try bob.encrypt(appMessage: Data("p6h2-bob-msg".utf8))
		let aliceGotMsg = try nativeAlice.processIncoming(bobMsg.cipherText)
		guard case .decrypted(let aliceMsgDecrypted) = aliceGotMsg else {
			XCTFail("expected a decrypted application frame, got \(aliceGotMsg)")
			return
		}
		XCTAssertEqual(aliceMsgDecrypted.applicationMessage, Data("p6h2-bob-msg".utf8))

		// A committing round each way.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceUpdFrame = try nativeAlice.encrypt(Data("p6h2-alice-upd".utf8))
		let bobDecrypted = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceUpdFrame.frame))
		let bobOffered = try XCTUnwrap(bobDecrypted.proposal)
		try bob.queueProposal(digest: bobOffered.digest)
		let bobPrepared = try bob.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "Rust bob's fold of alice's Upd should commit")
		let bobCommitFrame = try bob.encrypt(appMessage: Data("p6h2-bob-commit".utf8))
		let aliceCommitOpened = try nativeAlice.processIncoming(bobCommitFrame.cipherText)
		guard case .decrypted(let aliceCommitDecrypted) = aliceCommitOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceCommitOpened)")
			return
		}
		XCTAssertEqual(
			aliceCommitDecrypted.applicationMessage, Data("p6h2-bob-commit".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame2 = try bob.encrypt(appMessage: Data("p6h2-bob-upd2".utf8))
		let aliceOpened2 = try nativeAlice.processIncoming(bobUpdFrame2.cipherText)
		guard case .decrypted(let aliceDecrypted2) = aliceOpened2 else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened2)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted2.queuedProposal.digest)
		let alicePrepared2 = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared2.didCommit, "native alice's fold of bob's Upd should commit")
		let aliceCommitFrame2 = try nativeAlice.encrypt(Data("p6h2-alice-commit2".utf8))
		let bobGotCommit2 = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame2.frame))
		XCTAssertEqual(
			bobGotCommit2.applicationMessage?.appMessageData,
			Data("p6h2-alice-commit2".utf8))
	}

	/// p4(iii): the initiator (alice) migrates to native; the acceptor (bob) stays Rust.
	/// p4's shape is earlier than p6's — alice's KP' was parked but bob never responded — so
	/// native alice's OWN side-band take is what must survive the migration this time, and
	/// the round runs its FULL A.3 shape: deliver KP' to Rust bob (`pqBootstrapRespond`), his
	/// Welcome' response back to native alice (`pqBootstrapJoin`), then discharge.
	func testP4InitiatorMigratedHealsA3WithRustAcceptor() throws {
		let freshAlice = try restoreAndVerify(point: "p4-a3-stalled", side: "initiator")
		let export = try freshAlice.migrationExport()
		XCTAssertNotNil(
			export.pendingSideBand, "alice's parked KP' leg should be in the export")

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// The native side-band take: alice still holds her parked KP' after migration.
		let sealedKp = try XCTUnwrap(
			nativeAlice.pqPendingOutbound(),
			"native alice should still hold her parked KP' after migration")

		let bob = try restoreAndVerify(point: "p4-a3-stalled", side: "acceptor")
		let openedKp = try XCTUnwrap(try bob.openIncoming(blob: sealedKp))
		try bob.pqBootstrapRespond(kpMsg: openedKp.frame)

		let sealedWelcomePrime = try XCTUnwrap(bob.pqTakePendingOutbound())
		// Native's `pqBootstrapJoin` unseals `inbound` itself.
		_ = try nativeAlice.pqBootstrapJoin(sealedWelcomePrime)

		// Discharge across engines: Rust bob (the peer) offers, native alice (the binder)
		// commits.
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame = try bob.encrypt(appMessage: Data("p4h-bob-upd".utf8))
		let aliceOpened = try nativeAlice.processIncoming(bobUpdFrame.cipherText)
		guard case .decrypted(let aliceDecrypted) = aliceOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		let alicePrepared = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared.didCommit,
			"native alice's discharge commit should fold bob's offered Upd")
		let aliceCommitFrame = try nativeAlice.encrypt(Data("p4h-alice-commit".utf8))
		let bobGotCommit = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame.frame))
		XCTAssertEqual(
			bobGotCommit.applicationMessage?.appMessageData,
			Data("p4h-alice-commit".utf8))

		XCTAssertTrue(
			nativeAlice.isFullyEstablished,
			"the healed round should establish native alice")
		XCTAssertNil(
			nativeAlice.pqPendingOutbound(), "native alice should have nothing parked")
		XCTAssertNil(
			bob.pqPendingOutbound(sealing: .fresh), "bob should have nothing parked")
		// The discharge passes the PQ turn from the binder (native alice) to the peer
		// (Rust bob).
		XCTAssertFalse(
			nativeAlice.myPQTurn,
			"the discharge should pass the PQ turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge should pass the PQ turn to bob")

		// A message each way.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceMsg = try nativeAlice.encrypt(Data("p4h-alice-msg".utf8))
		let bobGotMsg = try XCTUnwrap(bob.processIncoming(ciphertext: aliceMsg.frame))
		XCTAssertEqual(
			bobGotMsg.applicationMessage?.appMessageData, Data("p4h-alice-msg".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobMsg = try bob.encrypt(appMessage: Data("p4h-bob-msg".utf8))
		let aliceGotMsg = try nativeAlice.processIncoming(bobMsg.cipherText)
		guard case .decrypted(let aliceMsgDecrypted) = aliceGotMsg else {
			XCTFail("expected a decrypted application frame, got \(aliceGotMsg)")
			return
		}
		XCTAssertEqual(aliceMsgDecrypted.applicationMessage, Data("p4h-bob-msg".utf8))

		// A committing round each way.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceUpdFrame = try nativeAlice.encrypt(Data("p4h-alice-upd".utf8))
		let bobDecrypted = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceUpdFrame.frame))
		let bobOffered = try XCTUnwrap(bobDecrypted.proposal)
		try bob.queueProposal(digest: bobOffered.digest)
		let bobPrepared = try bob.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "Rust bob's fold of alice's Upd should commit")
		let bobCommitFrame = try bob.encrypt(appMessage: Data("p4h-bob-commit".utf8))
		let aliceCommitOpened = try nativeAlice.processIncoming(bobCommitFrame.cipherText)
		guard case .decrypted(let aliceCommitDecrypted) = aliceCommitOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceCommitOpened)")
			return
		}
		XCTAssertEqual(aliceCommitDecrypted.applicationMessage, Data("p4h-bob-commit".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame2 = try bob.encrypt(appMessage: Data("p4h-bob-upd2".utf8))
		let aliceOpened2 = try nativeAlice.processIncoming(bobUpdFrame2.cipherText)
		guard case .decrypted(let aliceDecrypted2) = aliceOpened2 else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened2)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted2.queuedProposal.digest)
		let alicePrepared2 = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared2.didCommit, "native alice's fold of bob's Upd should commit")
		let aliceCommitFrame2 = try nativeAlice.encrypt(Data("p4h-alice-commit2".utf8))
		let bobGotCommit2 = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame2.frame))
		XCTAssertEqual(
			bobGotCommit2.applicationMessage?.appMessageData,
			Data("p4h-alice-commit2".utf8))
	}

	/// p5's A.4 heal, cross-engine: unlike p4/p6's A.3, p5's rows are already fully
	/// established (both PQ halves live) and mid a ROUTINE A.4 ratchet instead. meta pins
	/// the initiator as the turn holder with the parked leg (`legParked: true`), so THAT
	/// side migrates to native; the acceptor stays Rust. Native's side-band take returns
	/// the parked EK, Rust bob responds with the CT, and native binds it directly
	/// (`pqRatchetBind` unseals its own input, like `pqBootstrapJoin`).
	func testP5A4HealMigratesInitiatorToNative() throws {
		let freshAlice = try restoreAndVerify(point: "p5-a4-stalled", side: "initiator")
		let export = try freshAlice.migrationExport()
		XCTAssertNotNil(
			export.pendingSideBand, "alice's parked A.4 EK should be in the export")
		XCTAssertNotNil(export.pqInflight, "the in-flight A.4 round should export")

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let bob = try restoreAndVerify(point: "p5-a4-stalled", side: "acceptor")
		XCTAssertTrue(nativeAlice.myPQTurn, "the turn holder should still hold the PQ turn")

		let sealedEk = try XCTUnwrap(
			nativeAlice.pqPendingOutbound(),
			"native alice should still hold the parked A.4 EK after migration")
		let openedEk = try XCTUnwrap(try bob.openIncoming(blob: sealedEk))
		try bob.pqRatchetRespond(ekMsg: openedEk.frame)

		let sealedCt = try XCTUnwrap(bob.pqTakePendingOutbound())
		// Native's `pqRatchetBind` unseals `inbound` itself. The pinned twomlspq-swift
		// release (0.2.1) exposes no public PQ-epoch accessor to assert the numeric
		// advance directly (unlike Rust's `epochs()`) — `pqRatchetBind` succeeding
		// without error already proves the CT decrypted and verified against the
		// correct epoch's derived secret, and the round's full discharge plus the
		// continued messaging below is the completion proof this test relies on.
		_ = try nativeAlice.pqRatchetBind(sealedCt)

		XCTAssertNil(
			nativeAlice.pqPendingOutbound(), "native alice should have nothing parked")
		XCTAssertNil(
			bob.pqPendingOutbound(sealing: .fresh), "bob should have nothing parked")

		// Discharge the turn holder's own owed bind: the peer (bob) offers, native alice
		// (the binder) queues + commits it.
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame = try bob.encrypt(appMessage: Data("p5h-bob-upd".utf8))
		let aliceOpened = try nativeAlice.processIncoming(bobUpdFrame.cipherText)
		guard case .decrypted(let aliceDecrypted) = aliceOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		let alicePrepared = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared.didCommit,
			"native alice's discharge commit should fold bob's offered Upd")
		let aliceCommitFrame = try nativeAlice.encrypt(Data("p5h-alice-commit".utf8))
		let bobGotCommit = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame.frame))
		XCTAssertEqual(
			bobGotCommit.applicationMessage?.appMessageData,
			Data("p5h-alice-commit".utf8))

		// The discharge passes the PQ turn away from the holder (alice) to the peer (bob).
		XCTAssertFalse(
			nativeAlice.myPQTurn,
			"the discharge should pass the PQ turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge should pass the PQ turn to bob")

		// A message each way.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceMsg = try nativeAlice.encrypt(Data("p5h-alice-msg".utf8))
		let bobGotMsg = try XCTUnwrap(bob.processIncoming(ciphertext: aliceMsg.frame))
		XCTAssertEqual(
			bobGotMsg.applicationMessage?.appMessageData, Data("p5h-alice-msg".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobMsg = try bob.encrypt(appMessage: Data("p5h-bob-msg".utf8))
		let aliceGotMsg = try nativeAlice.processIncoming(bobMsg.cipherText)
		guard case .decrypted(let aliceMsgDecrypted) = aliceGotMsg else {
			XCTFail("expected a decrypted application frame, got \(aliceGotMsg)")
			return
		}
		XCTAssertEqual(aliceMsgDecrypted.applicationMessage, Data("p5h-bob-msg".utf8))

		// A committing round each way.
		_ = try nativeAlice.prepareToEncrypt()
		let aliceUpdFrame = try nativeAlice.encrypt(Data("p5h-alice-upd".utf8))
		let bobDecrypted = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceUpdFrame.frame))
		let bobOffered = try XCTUnwrap(bobDecrypted.proposal)
		try bob.queueProposal(digest: bobOffered.digest)
		let bobPrepared = try bob.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(bobPrepared.didCommit, "Rust bob's fold of alice's Upd should commit")
		let bobCommitFrame = try bob.encrypt(appMessage: Data("p5h-bob-commit".utf8))
		let aliceCommitOpened = try nativeAlice.processIncoming(bobCommitFrame.cipherText)
		guard case .decrypted(let aliceCommitDecrypted) = aliceCommitOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceCommitOpened)")
			return
		}
		XCTAssertEqual(aliceCommitDecrypted.applicationMessage, Data("p5h-bob-commit".utf8))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame2 = try bob.encrypt(appMessage: Data("p5h-bob-upd2".utf8))
		let aliceOpened2 = try nativeAlice.processIncoming(bobUpdFrame2.cipherText)
		guard case .decrypted(let aliceDecrypted2) = aliceOpened2 else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened2)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted2.queuedProposal.digest)
		let alicePrepared2 = try nativeAlice.prepareToEncrypt()
		XCTAssertTrue(
			alicePrepared2.didCommit, "native alice's fold of bob's Upd should commit")
		let aliceCommitFrame2 = try nativeAlice.encrypt(Data("p5h-alice-commit2".utf8))
		let bobGotCommit2 = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame2.frame))
		XCTAssertEqual(
			bobGotCommit2.applicationMessage?.appMessageData,
			Data("p5h-alice-commit2".utf8))
	}

	/// An OWED bind — bound (A.3 or A.4) but NOT YET discharged — is itself part of the
	/// pending-advance state the export carries, independent of any parked side-band leg
	/// (the p6 shape above already exercises `pendingSideBand`/`pqInflight` together;
	/// this isolates `owedBind` on a session where NEITHER of those is set). Reaches an
	/// owed-bind-but-undischarged state via an ordinary A.4 ratchet round stopped right
	/// after the bind (bob, the turn holder, opens with a plain send; alice responds; bob
	/// binds the CT — owing the classical bind — with nothing parked on either side once
	/// bound). Migrate BOB; native must still discharge the owed bind via an ordinary
	/// committing round, and the peer applies it.
	func testOwedBindCarriesAcrossTheExport() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPairAtDischarge()
		_ = try pair.bob.prepareToEncrypt(proposing: nil)
		let opener = try pair.bob.encrypt(appMessage: Data("ratchet-open".utf8))
		_ = try pair.alice.processIncoming(ciphertext: opener.cipherText)
		let sealedEk = try XCTUnwrap(pair.bob.pqPendingOutbound(sealing: .fresh))
		let openedEk = try XCTUnwrap(try pair.alice.openIncoming(blob: sealedEk))
		try pair.alice.pqRatchetRespond(ekMsg: openedEk.frame)
		let sealedCt = try XCTUnwrap(pair.alice.pqTakePendingOutbound())
		let openedCt = try XCTUnwrap(try pair.bob.openIncoming(blob: sealedCt))
		try pair.bob.pqRatchetBind(ctMsg: openedCt.frame)

		let export = try pair.bob.migrationExport()
		XCTAssertNotNil(
			export.owedBind, "bob's owed classical bind should be in the export")
		XCTAssertNil(export.pendingSideBand, "nothing is parked at this point")
		XCTAssertNil(export.pqInflight, "no A.3/A.4/A.5 round is in flight at this point")

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Discharge across engines: alice (Rust, the peer) offers, native bob (the
		// binder, who owes the bind) queues + commits it.
		_ = try pair.alice.prepareToEncrypt(proposing: nil)
		let aliceUpdFrame = try pair.alice.encrypt(
			appMessage: Data("owed-bind-alice-upd".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceUpdFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(bobPrepared.didCommit, "the owed bind needs a committing round")
		let bobCommitFrame = try nativeBob.encrypt(Data("owed-bind-bob-commit".utf8))
		let aliceGotCommit = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: bobCommitFrame.frame))
		XCTAssertEqual(
			aliceGotCommit.applicationMessage?.appMessageData,
			Data("owed-bind-bob-commit".utf8))

		XCTAssertTrue(
			pair.alice.isFullyEstablished(), "the discharge should not disturb this")
		XCTAssertTrue(nativeBob.isFullyEstablished, "the discharge should not disturb this")
	}

	/// Mutation: blank `owedBind` in the export before minting — the discharge round then
	/// runs with nothing to fold in: native bob commits alice's offered Upd as an ORDINARY
	/// classical round (a real, successful commit), but with no PQ half riding it, so
	/// alice's PQ epoch never advances and the ratchet she already completed on her side
	/// is never acknowledged back to her — the round SUCCEEDS at the classical layer
	/// while the dropped PQ bind is silently lost rather than surfacing as an error.
	func testBlankedOwedBindLosesTheBindSilently() throws {
		let pair = try RustSessionTestHelpers.bornDedicatedSessionPairAtDischarge()
		_ = try pair.bob.prepareToEncrypt(proposing: nil)
		let opener = try pair.bob.encrypt(appMessage: Data("ratchet-open".utf8))
		_ = try pair.alice.processIncoming(ciphertext: opener.cipherText)
		let sealedEk = try XCTUnwrap(pair.bob.pqPendingOutbound(sealing: .fresh))
		let openedEk = try XCTUnwrap(try pair.alice.openIncoming(blob: sealedEk))
		try pair.alice.pqRatchetRespond(ekMsg: openedEk.frame)
		let sealedCt = try XCTUnwrap(pair.alice.pqTakePendingOutbound())
		let openedCt = try XCTUnwrap(try pair.bob.openIncoming(blob: sealedCt))
		try pair.bob.pqRatchetBind(ctMsg: openedCt.frame)
		let pqEpochBefore = pair.alice.epochs().pqEpoch

		var export = try pair.bob.migrationExport()
		XCTAssertNotNil(export.owedBind)
		export.owedBind = nil

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		_ = try pair.alice.prepareToEncrypt(proposing: nil)
		let aliceUpdFrame = try pair.alice.encrypt(appMessage: Data("blank-owed-upd".utf8))
		let bobOpened = try nativeBob.processIncoming(aliceUpdFrame.cipherText)
		guard case .decrypted(let bobDecrypted) = bobOpened else {
			XCTFail("expected a decrypted application frame, got \(bobOpened)")
			return
		}
		_ = try nativeBob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try nativeBob.prepareToEncrypt()
		XCTAssertTrue(
			bobPrepared.didCommit,
			"the classical fold succeeds on its own — nothing detects the missing PQ half"
		)
		let bobCommitFrame = try nativeBob.encrypt(Data("blank-owed-commit".utf8))
		let aliceGotCommit = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: bobCommitFrame.frame))
		XCTAssertEqual(
			aliceGotCommit.applicationMessage?.appMessageData,
			Data("blank-owed-commit".utf8))

		XCTAssertEqual(
			pair.alice.epochs().pqEpoch, pqEpochBefore,
			"alice's PQ epoch never advances — the ratchet she already applied is never acked"
		)
	}
	// MARK: - Mutation: blanking the pending-advance state breaks the heal

	/// p6, blanking ONLY `pendingSideBand` (bob's parked Welcome'; `pqInflight` intact).
	/// A REAL heal attempt, not just a peek: Rust alice still independently holds HER OWN
	/// parked KP' (the p6 shape keeps a copy on both sides), so re-send it to native bob —
	/// exactly the retry a host would attempt after a dropped delivery. It cannot recover:
	/// bob's send.pq is ALREADY founded, so `pqBootstrapRespond`'s idempotent branch needs
	/// a retained frame to re-serve, and there is none. Alice can therefore never receive
	/// a fresh Welcome' to bind, and never establishes — proving `pendingSideBand` is
	/// load-bearing, not `pqPendingOutbound`'s tautological pass-through of it.
	func testBlankedPendingSideBandBreaksP6AcceptorHeal() throws {
		let alice = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "initiator")
		let freshBob = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "acceptor")
		var export = try freshBob.migrationExport()
		export.pendingSideBand = nil

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		XCTAssertNil(
			nativeBob.pqPendingOutbound(),
			"the blanked export leaves nothing for native bob's own side-band take")

		let sealedKp = try XCTUnwrap(
			alice.pqPendingOutbound(sealing: .fresh),
			"alice's own parked KP' should survive her own restore, independent of bob's"
		)
		XCTAssertThrowsError(try nativeBob.pqBootstrapRespond(sealedKp)) { error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .duplicateSideBand)
		}

		XCTAssertFalse(
			alice.isFullyEstablished(),
			"with no Welcome' ever returned, alice can never bind and never establishes"
		)
	}

	/// The same p6 shape, blanking ONLY `pqInflight` this time (`pendingSideBand` intact).
	/// This field is NOT what `pqPendingOutbound()`/`pqBootstrapRespond`'s idempotent
	/// branch read (both key off `pendingSideBand` and `sendGroup.pq`, the real group
	/// state) — so native bob's own side-band take and re-respond BOTH still work, and
	/// alice DOES receive and bind a fresh Welcome'. The heal breaks one step later
	/// instead: bob's `applyBind` (`TwoMLSSession+ClassicalCommit.swift`) explicitly
	/// switches on `pqInflight`, requiring `.bootstrapResponded`/`.responding`/
	/// `.rekeyResponded` before it will apply an incoming bind commit at all — with
	/// `pqInflight` blanked, that switch's `default` arm throws `sessionNotReady` when
	/// bob tries to fold alice's discharge commit. So the heal still fails, just later
	/// and differently than blanking `pendingSideBand` does.
	func testBlankedPqInflightBreaksP6AcceptorHealAtTheBindApply() throws {
		let alice = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "initiator")
		let freshBob = try restoreAndVerify(
			point: "p6-a3-responded-stalled", side: "acceptor")
		var export = try freshBob.migrationExport()
		export.pqInflight = nil

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeBob = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		// Native bob's own side-band take is UNAFFECTED — it reads `pendingSideBand`,
		// left intact here — and alice binds it successfully.
		let welcomePrimeSealed = try XCTUnwrap(
			nativeBob.pqPendingOutbound(),
			"pendingSideBand alone (left untouched here) is what pqPendingOutbound reads"
		)
		let opened = try XCTUnwrap(try alice.openIncoming(blob: welcomePrimeSealed))
		try alice.pqBootstrapBind(welcomeMsg: opened.frame)

		// The discharge round: bob offers, alice commits — bob's own APPLY of that
		// commit is where the blanked `pqInflight` actually bites.
		_ = try nativeBob.prepareToEncrypt()
		let bobUpd = try nativeBob.encrypt(Data("p6mut-bob-upd".utf8))
		let offered = try XCTUnwrap(
			alice.processIncoming(ciphertext: bobUpd.frame)?.proposal)
		try alice.queueProposal(digest: offered.digest)
		XCTAssertTrue(try alice.prepareToEncrypt(proposing: nil).didCommit)
		let aliceCommit = try alice.encrypt(appMessage: Data("p6mut-alice-commit".utf8))
		XCTAssertThrowsError(try nativeBob.processIncoming(aliceCommit.cipherText)) {
			error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .sessionNotReady)
		}
		// Retrying changes nothing — the guard is on bob's own (blanked) state, not
		// anything about the frame — so bob is durably stuck on this commit, not just
		// racing a transient condition.
		XCTAssertThrowsError(try nativeBob.processIncoming(aliceCommit.cipherText)) {
			error in
			XCTAssertEqual(error as? TwoMLSPQSession.TwoMLSError, .sessionNotReady)
		}
	}

	/// The same PAIR of mutations, on the p4 initiator shape — with a genuinely different
	/// (and instructive) result. p4 migrates alice BEFORE bob ever responds, so alice is
	/// still pre-join: blanking ONLY `pendingSideBand` does NOT break this heal, because
	/// native alice's own `pqBootstrapBegin()` re-derives the SAME KP' bytes from her
	/// still-intact identity material (never a fresh mint) and simply restarts the round
	/// — bob's pinned commitment still matches it. Unlike p6's acceptor, whose send.pq is
	/// ALREADY founded and so has no "start over" available to it, the pre-join initiator
	/// always does. Documented precisely, per the brief, rather than asserting a failure
	/// that does not happen.
	func testBlankedPendingSideBandDoesNotBreakP4InitiatorHeal() throws {
		let freshAlice = try restoreAndVerify(point: "p4-a3-stalled", side: "initiator")
		var export = try freshAlice.migrationExport()
		export.pendingSideBand = nil

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		XCTAssertNil(
			nativeAlice.pqPendingOutbound(),
			"the blanked export leaves nothing for native alice's own side-band take")

		// The self-heal: alice is still pre-join and holds the turn, so she can just
		// restart the bootstrap — `pqBootstrapBegin` re-derives, it does not re-mint.
		let restarted = try nativeAlice.pqBootstrapBegin()

		let bob = try restoreAndVerify(point: "p4-a3-stalled", side: "acceptor")
		let openedKp = try XCTUnwrap(try bob.openIncoming(blob: restarted.frame))
		try bob.pqBootstrapRespond(kpMsg: openedKp.frame)
		let sealedWelcomePrime = try XCTUnwrap(bob.pqTakePendingOutbound())
		_ = try nativeAlice.pqBootstrapJoin(sealedWelcomePrime)
		XCTAssertTrue(
			nativeAlice.isFullyEstablished, "the restarted round completes normally")

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame = try bob.encrypt(appMessage: Data("p4mut-bob-upd".utf8))
		let aliceOpened = try nativeAlice.processIncoming(bobUpdFrame.cipherText)
		guard case .decrypted(let aliceDecrypted) = aliceOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		XCTAssertTrue(try nativeAlice.prepareToEncrypt().didCommit)
		let aliceCommitFrame = try nativeAlice.encrypt(Data("p4mut-alice-commit".utf8))
		let bobGotCommit = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame.frame))
		XCTAssertEqual(
			bobGotCommit.applicationMessage?.appMessageData,
			Data("p4mut-alice-commit".utf8)
		)
		XCTAssertFalse(
			nativeAlice.myPQTurn, "the discharge passes the turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge passes the turn to bob")
	}

	/// The p4 initiator shape, blanking ONLY `pqInflight`. Also does not break the heal:
	/// `pqBootstrapJoin` never reads `pqInflight` (only `bootstrapKPSecret` and
	/// `pendingProposal`), and it clears `pqInflight` itself as part of ordinary
	/// completion regardless of what the export carried — so the blanked value is
	/// overwritten before it could matter. Contrast p6's acceptor, where the PEER
	/// (native bob) applying an INCOMING bind is what reads `pqInflight`; here alice is
	/// the one who JOINS and then COMMITS the discharge herself, never on the receiving
	/// end of that specific gate.
	func testBlankedPqInflightDoesNotBreakP4InitiatorHeal() throws {
		let freshAlice = try restoreAndVerify(point: "p4-a3-stalled", side: "initiator")
		var export = try freshAlice.migrationExport()
		export.pqInflight = nil

		let archive = try SessionMigrator.mintArchive(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		var nativeAlice = try TwoMLSPQSession.TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let sealedKp = try XCTUnwrap(
			nativeAlice.pqPendingOutbound(),
			"pendingSideBand alone (left untouched here) is what pqPendingOutbound reads"
		)

		let bob = try restoreAndVerify(point: "p4-a3-stalled", side: "acceptor")
		let openedKp = try XCTUnwrap(try bob.openIncoming(blob: sealedKp))
		try bob.pqBootstrapRespond(kpMsg: openedKp.frame)
		let sealedWelcomePrime = try XCTUnwrap(bob.pqTakePendingOutbound())
		_ = try nativeAlice.pqBootstrapJoin(sealedWelcomePrime)
		XCTAssertTrue(
			nativeAlice.isFullyEstablished,
			"blanking pqInflight alone did not break the heal"
		)

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobUpdFrame = try bob.encrypt(appMessage: Data("p4mut2-bob-upd".utf8))
		let aliceOpened = try nativeAlice.processIncoming(bobUpdFrame.cipherText)
		guard case .decrypted(let aliceDecrypted) = aliceOpened else {
			XCTFail("expected a decrypted application frame, got \(aliceOpened)")
			return
		}
		_ = try nativeAlice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		XCTAssertTrue(try nativeAlice.prepareToEncrypt().didCommit)
		let aliceCommitFrame = try nativeAlice.encrypt(Data("p4mut2-alice-commit".utf8))
		let bobGotCommit = try XCTUnwrap(
			bob.processIncoming(ciphertext: aliceCommitFrame.frame))
		XCTAssertEqual(
			bobGotCommit.applicationMessage?.appMessageData,
			Data("p4mut2-alice-commit".utf8))
		XCTAssertFalse(
			nativeAlice.myPQTurn, "the discharge passes the turn away from alice")
		XCTAssertTrue(bob.myPqTurn(), "the discharge passes the turn to bob")
	}
}

/// Same suite, against the older v0.15.0 fixtures (binding contract 32, session archive
/// layout 3) — every inherited `test...` method above runs again here, unmodified.
@available(macOS 26, iOS 26, *)
final class LegacyRowFixtureTestsV015: LegacyRowFixtureTests {
	override class var fixtureVersion: String { "v0.15.0" }
}
