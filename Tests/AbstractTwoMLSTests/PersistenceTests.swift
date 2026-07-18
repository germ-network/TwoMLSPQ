//
//  PersistenceTests.swift
//  AbstractTwoMLS
//
//  Push-persistence contract (contract 13): sink installation, the two-slot
//  Core/Checkpoint model, restore via `init(persisted:)`, and the seq-based
//  durability gates. Mirrors the crate's RecordingSink/round_trip fixtures.
//

import AbstractTwoMLS
import CommProtocol
import Foundation
import Testing

// MARK: - Fixtures

/// Test sink mirroring the crate's `RecordingSink`: appends every push, serves
/// the newest blob per slot — exactly the newest-seq-wins retention a real
/// sink keeps. NSLock-guarded: `persist` arrives synchronously on whichever
/// thread drove the mutation.
final class RecordingSink: AbstractTwoMLS.PersistenceSink, @unchecked Sendable {
	private let lock = NSLock()
	private var pushes: [(seq: UInt64, slot: AbstractTwoMLS.PersistedSlot, bytes: Data)] = []

	func persist(seq: UInt64, slot: AbstractTwoMLS.PersistedSlot, bytes: Data) {
		lock.lock()
		defer { lock.unlock() }
		pushes.append((seq, slot, bytes))
	}

	/// Push-order slot kinds, for asserting which mutations pushed what.
	var slots: [AbstractTwoMLS.PersistedSlot] {
		lock.lock()
		defer { lock.unlock() }
		return pushes.map(\.slot)
	}

	var pushCount: Int {
		lock.lock()
		defer { lock.unlock() }
		return pushes.count
	}

	/// Newest-seq blob for the slot (ties break toward the later push, matching
	/// the crate's install-baseline tie rule).
	func latest(_ slot: AbstractTwoMLS.PersistedSlot) -> Data? {
		lock.lock()
		defer { lock.unlock() }
		return pushes.filter { $0.slot == slot }
			.enumerated()
			.max { ($0.element.seq, $0.offset) < ($1.element.seq, $1.offset) }?
			.element.bytes
	}

	func sessionPersisted() throws -> AbstractTwoMLS.PQSession.Persisted {
		guard let checkpoint = latest(.checkpoint) else {
			throw TestErrors.unexpected
		}
		return .init(core: latest(.core), checkpoint: checkpoint)
	}

	func invitationPersisted() throws -> AbstractTwoMLS.PQInvitationArchive {
		guard let checkpoint = latest(.checkpoint) else {
			throw TestErrors.unexpected
		}
		return .init(bytes: checkpoint)
	}
}

/// Install a fresh sink on the live session (its baseline checkpoint makes the
/// capture complete) and rebuild a session from the newest slots — the crate's
/// `round_trip` fixture, through the abstract surface.
func roundTripPush(
	_ session: AbstractTwoMLS.PQSession
) throws -> AbstractTwoMLS.PQSession {
	let sink = RecordingSink()
	try session.installSink(sink)
	return try AbstractTwoMLS.PQSession(persisted: sink.sessionPersisted())
}

// MARK: - Push-persistence contract

struct PersistenceContractTests {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	/// Establish a pair through the abstract surface (local initiates via
	/// reply; remote receives; first frame staples the return welcome).
	private func establishPair() throws -> (
		AbstractTwoMLS.PQSession, AbstractTwoMLS.PQSession
	) {
		let (localSession, sealed) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: sealed,
			expecting: try local.clientId
		)
		try remoteSession.send(to: localSession)
		return (localSession, remoteSession)
	}

	@Test func baselineAndSlotKinds() throws {
		let (localSession, remoteSession) = try establishPair()

		// Install pushes exactly one baseline checkpoint, without advancing seq.
		let sink = RecordingSink()
		let seqAtInstall = remoteSession.stateSeq
		try remoteSession.installSink(sink)
		#expect(sink.slots == [.checkpoint])
		#expect(remoteSession.stateSeq == seqAtInstall)

		// Classical rounds rewrite only the core slot.
		try remoteSession.exchange(with: localSession)
		let afterClassical = sink.slots
		#expect(afterClassical.count > 1)
		#expect(afterClassical.dropFirst().allSatisfy { $0 == .core })

		// The mutation counter advanced and stamped the pushes.
		#expect(remoteSession.stateSeq > seqAtInstall)
	}

	@Test func sessionRestoresFromLatestSlots() throws {
		let (localSession, remoteSession) = try establishPair()
		try localSession.exchange(with: remoteSession)

		// Capture, restore, re-install (a restored session has no sink),
		// and keep talking both ways on the restored object.
		let restored = try roundTripPush(remoteSession)
		try restored.installSink(RecordingSink())
		try localSession.exchange(with: restored)
	}

	@Test func encryptReportsDurabilityDependency() throws {
		let (localSession, remoteSession) = try establishPair()
		try localSession.installSink(RecordingSink())

		// A frame's dependency is the seq its staple persisted at — never
		// ahead of the object's own counter; a routine follow-up imposes no
		// new dependency.
		_ = try localSession.prepareToEncrypt(proposing: nil)
		let first = try localSession.encrypt(appMessage: Data("a".utf8))
		#expect(first.dependsOnSeq <= localSession.stateSeq)
		_ = try remoteSession.processIncoming(ciphertext: first.cipherText)

		_ = try localSession.prepareToEncrypt(proposing: nil)
		let second = try localSession.encrypt(appMessage: Data("b".utf8))
		#expect(second.dependsOnSeq == first.dependsOnSeq)
	}

	@Test func invitationSeqBumpsPerReceive() throws {
		let sink = RecordingSink()
		try remote.currentInvitation.installSink(sink)
		#expect(remote.currentInvitation.stateSeq == 0)
		#expect(sink.slots == [.checkpoint])

		let (_, sealed) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		_ = try remote.currentInvitation.receiveReply(
			ciphertext: sealed,
			expecting: try local.clientId
		)
		#expect(remote.currentInvitation.stateSeq == 1)
		#expect(sink.slots == [.checkpoint, .checkpoint])
	}

	/// Retention canary: the wrapper keeps no Swift reference to the sink
	/// adapter — uniffi's handle map must retain it for as long as the Rust
	/// object holds the Arc, or pushes would stop after a collection.
	@Test func sinkSurvivesWithoutSwiftReferences() throws {
		let (localSession, remoteSession) = try establishPair()
		let sink = RecordingSink()
		try remoteSession.installSink(sink)
		let baseline = sink.pushCount

		for _ in 0..<3 {
			try remoteSession.exchange(with: localSession)
		}
		#expect(sink.pushCount >= baseline + 3)
	}

	// MARK: In-flight state survives the two-slot push

	/// The staged dedicated principal (from `receiveReply(newClientId:)`) rides
	/// the install-time baseline, so the rotation dance completes on a session
	/// restored BEFORE it drives the rotation.
	@Test func stagedRotationSurvivesRestore() throws {
		let (localSession, sealed) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let dedicated = AbstractTwoMLS.ClientID.mock()
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: sealed, expecting: try local.clientId, newClientId: dedicated
		)
		try remoteSession.send(to: localSession)

		let restored = try roundTripPush(remoteSession)
		try restored.installSink(RecordingSink())
		try restored.rotate(to: dedicated, peer: localSession)
	}

	/// The epoch-locked approval tally rides the `core` slot: approving a
	/// candidate, restoring, then committing still folds the approved proposal.
	@Test func queuedApprovalSurvivesRestore() throws {
		let (localSession, sealed) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let dedicated = AbstractTwoMLS.ClientID.mock()
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: sealed, expecting: try local.clientId, newClientId: dedicated
		)
		try remoteSession.send(to: localSession)

		// Remote proposes its candidate; local approves it, then restores BEFORE
		// committing.
		_ = try remoteSession.prepareToEncrypt(proposing: dedicated)
		let frame = try remoteSession.encrypt(appMessage: Data("rotate".utf8))
		let got = try #require(try localSession.processIncoming(ciphertext: frame.cipherText))
		let offered = try #require(got.proposal)
		try localSession.queueProposal(digest: offered.digest)
		#expect(localSession.queuedRemoteSuccessor == dedicated)

		let restored = try roundTripPush(localSession)
		try restored.installSink(RecordingSink())
		#expect(restored.queuedRemoteSuccessor == dedicated)  // tally rode the core

		let prepared = try #require(try restored.prepareToEncrypt(proposing: nil))
		#expect(prepared.didCommit)
		#expect(prepared.commitedRemoteClientId == dedicated)
	}

	/// THE germDM REPRO MIRROR (`restoredReplierSendsFirst`): the replier session is
	/// captured at reply — the install-time baseline checkpoint IS the whole capture
	/// (`core: nil`; nothing has driven the session) — and restored before its first
	/// send. Contract 15 (§A.1): the restored replier sends FIRST, each frame a fresh
	/// welcome-re-stapling envelope, so the acceptor joins from ANY single frame and
	/// establishment completes across the restore boundary. CAPTURE ORDERING: the
	/// capture happens after `createTwoMLSGroup` (inside the reply harness) — the
	/// attached app payload rides the baseline; a capture taken between `reply` and
	/// the attach would restore a replier whose frames carry no identity envelope.
	@Test func birthCapturedReplierRestoresSendReady() throws {
		let (liveSession, _) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)

		// Capture at reply: a fresh sink's baseline checkpoint, core nil — exactly
		// the app's capturePersisted() shape.
		let sink = RecordingSink()
		try liveSession.installSink(sink)
		#expect(sink.slots == [.checkpoint])
		let persisted = try sink.sessionPersisted()
		#expect(persisted.core == nil)

		// Restore (the live object is discarded — single writer) and send first,
		// twice: pre-establishment prepare is a no-op round (nothing staged).
		let restored = try AbstractTwoMLS.PQSession(persisted: persisted)
		try restored.installSink(RecordingSink())
		let prep = try #require(try restored.prepareToEncrypt(proposing: nil))
		#expect(prep.proposalMessage.isEmpty)
		#expect(!prep.didCommit)
		_ = try restored.encrypt(appMessage: Data("first".utf8))
		_ = try #require(try restored.prepareToEncrypt(proposing: nil))
		let second = try restored.encrypt(appMessage: Data("second".utf8))

		// The initial envelope AND frame 1 are dropped: the acceptor joins from the
		// second frame alone, and its staple delivers that message with the join.
		let (remoteSession, stapled) = try remote.currentInvitation.receiveReply(
			ciphertext: second.cipherText,
			expecting: try local.clientId
		)
		#expect(stapled?.appMessageData == Data("second".utf8))

		// Establishment completes across the restore boundary, both directions.
		try remoteSession.send(to: restored)
		try restored.exchange(with: remoteSession)
	}

	/// A parked A.4 bootstrap reply (a checkpoint-touching PQ op) rides the
	/// baseline checkpoint: the round completes on the restored responder.
	@Test func parkedBootstrapReplySurvivesRestore() throws {
		let (localSession, remoteSession) = try establishPair()
		let localPQ = localSession as any AbstractTwoMLS.PQRatchetingSession
		let remotePQ = remoteSession as any AbstractTwoMLS.PQRatchetingSession

		let kp = try localPQ.begin(.finishBootstrap, rotating: nil)
		let inbound = try remotePQ.ingest(kp.payload)  // parks the reply

		// Restore the responder AFTER parking — the parked reply must survive.
		let restored = try roundTripPush(remoteSession)
		try restored.installSink(RecordingSink())
		let restoredPQ = restored as any AbstractTwoMLS.PQRatchetingSession

		let reply = try #require(restoredPQ.advance(after: inbound))
		_ = try localPQ.ingest(reply.payload)
		#expect(localPQ.isFullyEstablished)
		#expect(restoredPQ.isFullyEstablished)
	}
}
