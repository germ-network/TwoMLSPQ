import CryptoKit
import Foundation
import TwoMLSPQBinding
import XCTest

/// A born-dedicated pair from `RustSessionTestHelpers.bornDedicatedSessionPair()`: both raw
/// FFI sessions, the dedicated id `bob` runs under, and the ORIGINAL invitation identity
/// `alice` still knows him as (what a converged recv-PQ leaf that never catches up keeps
/// presenting — see `pqLeafCustody`).
@available(macOS 26, iOS 26, *)
struct BornDedicatedPair {
	let alice: TwoMLSPQBinding.TwoMlsPqSession
	let bob: TwoMLSPQBinding.TwoMlsPqSession
	let dedicatedId: Data
	let invitationId: Data
}

// Shared raw-FFI session helpers, adapted from `SessionMigrationTests`'s private `rustSay` /
// `dischargeBind` (kept small and generic so `LegacyRowFixtureTests` can reuse the shape
// without depending on that file's establishment scaffolding).
@available(macOS 26, iOS 26, *)
enum RustSessionTestHelpers {
	/// Prepare + encrypt on `session`, deliver to `deliverTo`, and assert the round trip.
	/// `file`/`line` thread through so a failure attributes to the CALLER, not this helper.
	static func rustSay(
		_ session: TwoMLSPQBinding.TwoMlsPqSession, _ text: String,
		deliverTo: TwoMLSPQBinding.TwoMlsPqSession,
		file: StaticString = #filePath, line: UInt = #line
	) throws {
		_ = try session.prepareToEncrypt(proposing: nil)
		let frame = try session.encrypt(appMessage: Data(text.utf8))
		let got = try XCTUnwrap(
			deliverTo.processIncoming(ciphertext: frame.cipherText), file: file,
			line: line)
		XCTAssertEqual(
			got.applicationMessage?.appMessageData, Data(text.utf8), file: file,
			line: line)
	}

	/// One committing round: `peer` offers an Upd, `binder` approves it and its next
	/// `prepareToEncrypt` reports `didCommit`. `file`/`line` thread through so a failure
	/// attributes to the CALLER, not this helper.
	static func committingRound(
		binder: TwoMLSPQBinding.TwoMlsPqSession, peer: TwoMLSPQBinding.TwoMlsPqSession,
		file: StaticString = #filePath, line: UInt = #line
	) throws {
		_ = try peer.prepareToEncrypt(proposing: nil)
		let upd = try peer.encrypt(appMessage: Data("upd".utf8))
		let offered = try XCTUnwrap(
			binder.processIncoming(ciphertext: upd.cipherText)?.proposal, file: file,
			line: line)
		try binder.queueProposal(digest: offered.digest)

		let prepared = try binder.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			prepared.didCommit, "a committing round needs didCommit", file: file,
			line: line)
		let frame = try binder.encrypt(appMessage: Data("commit".utf8))
		let got = try XCTUnwrap(
			peer.processIncoming(ciphertext: frame.cipherText), file: file, line: line)
		XCTAssertEqual(
			got.applicationMessage?.appMessageData, Data("commit".utf8), file: file,
			line: line)
	}

	/// A born-dedicated pair PRE-INSTALL, raw FFI: alice initiates to bob's invitation, and
	/// bob `receive`s under a DEDICATED client id (≠ the invitation id) — unlike
	/// `SessionMigrationTests`' pipelined-A.3 `establishedSessionPair`, no parallel
	/// bootstrap-KP envelope is read here, matching how `TwoMlsPqInvitation.receive` is
	/// actually driven with a dedicated id. Bob owes his establishment envelope; alice
	/// still knows him as the invitation identity.
	static func bornDedicatedPending(
		file: StaticString = #filePath, line: UInt = #line
	) throws -> BornDedicatedPair {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("bd-alice".utf8))
		let invitationId = Data("bd-bob-invitation".utf8)
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: invitationId)
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let commitment = try XCTUnwrap(
			aliceSession.bootstrapKpCommitment(), file: file, line: line)
		let envelope = try XCTUnwrap(aliceSession.pendingOutbound(), file: file, line: line)
		guard case .establishment(let frame) = try bobInvitation.openInitial(blob: envelope)
		else {
			throw NSError(
				domain: "bornDedicatedPending", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"expected an establishment envelope"
				])
		}
		let welcome = try XCTUnwrap(frame.welcome, file: file, line: line)
		let aliceKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		let dedicatedId = Data("bd-bob-dedicated".utf8)
		let bobSession = try bobInvitation.receive(
			welcome: welcome, theirClassicalKeyPackage: aliceKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("bd-spawn".utf8),
			newClientId: dedicatedId, expectedRemote: nil, expectedAppBinding: nil)

		return BornDedicatedPair(
			alice: aliceSession, bob: bobSession, dedicatedId: dedicatedId,
			invitationId: invitationId)
	}

	/// Install the mock delegation on `pair.bob`, returning its bytes.
	@discardableResult
	static func installMockEstablishmentEnvelope(_ pair: BornDedicatedPair) throws -> Data {
		let signedEnvelope = Data("bd-signed-establishment-delegation".utf8)
		try pair.bob.installEstablishmentEnvelope(envelope: signedEnvelope)
		return signedEnvelope
	}

	/// Installed but NOT yet classically converged: bob sends his first (handoff) frame,
	/// alice PAUSES on it and APPROVES — but neither queues nor commits bob's catch-up Upd.
	/// Returns bob's offered Upd (digest + proposing) for the caller to fold, or ignore.
	static func bornDedicatedInstalledUnfolded(
		file: StaticString = #filePath, line: UInt = #line
	) throws -> (pair: BornDedicatedPair, bobUpd: QueuedRemoteProposal) {
		let pair = try bornDedicatedPending(file: file, line: line)
		let signedEnvelope = try installMockEstablishmentEnvelope(pair)
		_ = try pair.bob.prepareToEncrypt(proposing: nil)
		let confirmB = try pair.bob.encrypt(appMessage: Data("confirm-b".utf8))
		let paused = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: confirmB.cipherText), file: file,
			line: line)
		let pending = try XCTUnwrap(paused.pendingEstablishment, file: file, line: line)
		XCTAssertEqual(pending.envelope, signedEnvelope, file: file, line: line)
		XCTAssertEqual(pending.welcome.first, 0x01, file: file, line: line)
		let resumed = try pair.alice.processIncomingApproved(
			ciphertext: confirmB.cipherText,
			approvedEnvelopeDigest: Data(SHA256.hash(data: pending.envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: pending.welcome)),
			expectedCreator: pair.dedicatedId)
		let bobUpd = try XCTUnwrap(resumed?.proposal, file: file, line: line)
		return (pair, bobUpd)
	}

	/// `bornDedicatedInstalledUnfolded`'s same-id-candidate variant: the mandatory handoff
	/// frame proposes `Some(pair.dedicatedId)` (`admit_candidate` mints a fresh K′) instead
	/// of `nil` (a plain identity-signed self-refresh) — a real K′ offer outstanding at
	/// rest. Neither queues nor commits bob's catch-up Upd.
	static func bornDedicatedSameIdHandoffUnfolded(
		file: StaticString = #filePath, line: UInt = #line
	) throws -> (pair: BornDedicatedPair, bobUpd: QueuedRemoteProposal) {
		let pair = try bornDedicatedPending(file: file, line: line)
		let signedEnvelope = try installMockEstablishmentEnvelope(pair)
		_ = try pair.bob.prepareToEncrypt(
			proposing: TwoMLSPQBinding.ClientId(bytes: pair.dedicatedId))
		let confirmB = try pair.bob.encrypt(appMessage: Data("confirm-b".utf8))
		let paused = try XCTUnwrap(
			pair.alice.processIncoming(ciphertext: confirmB.cipherText), file: file,
			line: line)
		let pending = try XCTUnwrap(paused.pendingEstablishment, file: file, line: line)
		XCTAssertEqual(pending.envelope, signedEnvelope, file: file, line: line)
		XCTAssertEqual(pending.welcome.first, 0x01, file: file, line: line)
		let resumed = try pair.alice.processIncomingApproved(
			ciphertext: confirmB.cipherText,
			approvedEnvelopeDigest: Data(SHA256.hash(data: pending.envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: pending.welcome)),
			expectedCreator: pair.dedicatedId)
		let bobUpd = try XCTUnwrap(resumed?.proposal, file: file, line: line)
		return (pair, bobUpd)
	}

	/// A born-dedicated pair, raw FFI, through classical convergence and the A.3 bootstrap +
	/// bind discharge, up to (not including) a trailing message exchange. Bob holds the PQ
	/// turn and nothing is mid-flight at return — contrast `bornDedicatedSessionPair`, whose
	/// trailing sends legitimately auto-stage. Never calls `bob`'s `pendingOutbound()`: the
	/// app never drains an acceptor's parked return welcome, so this pins that shape rather
	/// than the drained one.
	static func bornDedicatedSessionPairAtDischarge(
		file: StaticString = #filePath, line: UInt = #line
	) throws -> BornDedicatedPair {
		let (pair, bobUpd) = try bornDedicatedInstalledUnfolded(file: file, line: line)
		let aliceSession = pair.alice
		let bobSession = pair.bob

		_ = try aliceSession.prepareToEncrypt(proposing: nil)
		let confirmA = try aliceSession.encrypt(appMessage: Data("confirm-a".utf8))
		_ = try bobSession.processIncoming(ciphertext: confirmA.cipherText)

		// Alice folds Bob's catch-up Upd: his recv-classical leaf converges.
		try aliceSession.queueProposal(digest: bobUpd.digest)
		let prep = try aliceSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(prep.didCommit, file: file, line: line)
		let fullA = try aliceSession.encrypt(appMessage: Data("full-a".utf8))
		let res = try XCTUnwrap(
			bobSession.processIncoming(ciphertext: fullA.cipherText), file: file,
			line: line)
		let aliceUpd = try XCTUnwrap(res.proposal, file: file, line: line)

		// And in Bob's direction: his send group commits Alice's Upd.
		try bobSession.queueProposal(digest: aliceUpd.digest)
		let prepB = try bobSession.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(prepB.didCommit, file: file, line: line)
		let fullB = try bobSession.encrypt(appMessage: Data("full-b".utf8))
		_ = try aliceSession.processIncoming(ciphertext: fullB.cipherText)

		// A.3 bootstrap + bind.
		let kp = try aliceSession.pqBootstrapBegin(rotating: nil)
		try bobSession.pqBootstrapRespond(kpMsg: kp)
		let welcomePrime = try XCTUnwrap(
			bobSession.pqTakePendingOutbound(), file: file, line: line)
		try aliceSession.pqBootstrapBind(welcomeMsg: welcomePrime)
		try committingRound(binder: aliceSession, peer: bobSession, file: file, line: line)
		XCTAssertTrue(aliceSession.isFullyEstablished(), file: file, line: line)
		XCTAssertTrue(bobSession.isFullyEstablished(), file: file, line: line)

		return pair
	}

	/// `bornDedicatedSessionPairAtDischarge` plus a message each way. Bob's own send here
	/// legitimately auto-stages a speculative A.4 EK (fires on every turn-holder send) — a
	/// caller needing `pqRekeyBegin`'s clean-slate precondition should use the
	/// discharge-point helper above instead: draining a completed round passes the PQ turn
	/// away, same as any other bind discharge.
	static func bornDedicatedSessionPair(
		file: StaticString = #filePath, line: UInt = #line
	) throws -> BornDedicatedPair {
		let pair = try bornDedicatedSessionPairAtDischarge(file: file, line: line)
		try rustSay(pair.bob, "pq-app", deliverTo: pair.alice, file: file, line: line)
		try rustSay(pair.alice, "pq-app-2", deliverTo: pair.bob, file: file, line: line)
		return pair
	}
}
