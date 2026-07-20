//
//  LifecycleTests.swift
//  TwoMLSPQ
//

//
//  Deep lifecycle test: the same flow as APIDemo.apiDemo, but checking each step's
//  expected state through the TwoMLSPQ session's internal accessors (epochs, turn,
//  established flags, group ids) via the PQSession adapter's `base`.
//

import CommProtocol
import Foundation
import Testing

import TwoMLSPQBinding

@testable import TwoMLSPQ

struct LifecycleTests {
	let local: ClientWrapper
	let remote: ClientWrapper

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func testExchange() async throws {
		// -- Step 1: initiator forms its APQ send group and mints the plaintext welcome.
		// The concrete `reply` returns the PLAINTEXT APQWelcome (contract 15) plus the
		// return-group key package and the A.4 bootstrap commitment — the app seals the
		// welcome into its signed identity envelope and hands it back via
		// createTwoMLSGroup; this bare harness delivers it plaintext (as PQInvitationTests
		// does), so there is no sealed §A.1 envelope to inspect here.
		let (localSession, welcome, myKeyPackage, bootstrapKpCommitment) =
			try local.client.reply(
				keyPackageMessage: remote.currentInvitation.encodedKeyPackage
			)
		let localBase = localSession.base

		// Send group live at epoch 1 with a full PQ half; no recv group yet.
		#expect(!localBase.isEstablished())
		#expect(!localBase.hasReceiveGroup())
		#expect(!localBase.isFullyEstablished())
		#expect(localBase.myPqTurn())
		#expect(localBase.epochs() == ApqEpochs(pqEpoch: 1, classicalEpoch: 1))
		// The §A.1 bootstrap envelope is parked at initiate and NOT consumed by this
		// plaintext harness (no createTwoMLSGroup) — it stays available as the take-once
		// outbound, and A.4's `begin(.finishBootstrap)` (step 5) carries the same KP′.
		#expect(localBase.pendingOutbound() != nil)

		// Routing: listening works from birth — addresses derive from our send
		// group's classical half, one per epoch. Nowhere to post yet: the post
		// address is the recv group's exporter, and there is no recv group.
		let localListenAtBirth = try localBase.shouldListenOn()
		#expect(!localListenAtBirth.sendGroup.classical.bytes.isEmpty)
		#expect(!localListenAtBirth.sendGroup.pq.bytes.isEmpty)
		#expect(localListenAtBirth.rendezvousByEpoch.count == 1)
		#expect(localListenAtBirth.rendezvousByEpoch.first?.epoch == 1)
		#expect(localListenAtBirth.rendezvousByEpoch.first?.rendezvousId.bytes.count == 32)
		#expect(try localBase.sendRendezvous() == nil)

		// -- Step 2: the invitation receives — recv group up, send group classical-only.
		let (remoteSession, stapled) = try remote.currentInvitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: myKeyPackage,
			bootstrapKpCommitment: bootstrapKpCommitment,
			remoteClientId: try local.clientId,
			welcomeToken: WelcomeToken(TypedDigest(prefix: .sha256, over: welcome)),
			stapledMessage: nil,
			newClientId: .mock()
		)
		#expect(stapled == nil)
		let remoteBase = remoteSession.base

		#expect(remoteBase.isEstablished())
		#expect(remoteBase.hasReceiveGroup())
		// The send-group PQ half is deferred (A.4): established, but not fully.
		#expect(!remoteBase.isFullyEstablished())
		#expect(!remoteBase.myPqTurn())
		#expect(remoteBase.epochs() == ApqEpochs(pqEpoch: 0, classicalEpoch: 1))
		// The recv group (the initiator's ASG) is a full APQ pair.
		let remoteRecv = try #require(remoteBase.receiveGroupId())
		#expect(!remoteRecv.classical.bytes.isEmpty)
		#expect(!remoteRecv.pq.bytes.isEmpty)
		// Each side's view of the peer matches the peer's self-view — modulo the
		// acceptor's staged candidate: `receive(newClientId:)` leaves the acceptor
		// .pending, and a candidate stays PRIVATE to its proposer until a frame
		// carries it (contract v9 candidate lifecycle), so the initiator still
		// sees the canonical invitation identity. Asserted through the abstract
		// truth surface (M6), not the raw binding.
		#expect(localSession.myPrincipalState == remoteSession.theirPrincipalState)
		guard case .pending(let old, _) = remoteSession.myPrincipalState else {
			throw TestErrors.unexpected
		}
		#expect(localSession.theirPrincipalState == .sync(old))

		// Routing: remote can post immediately — its post address is the recv
		// group's current exporter, which is the same MLS group as the initiator's
		// send group, so it appears verbatim in the initiator's listen set.
		let remotePost = try #require(try remoteBase.sendRendezvous())
		#expect(remotePost.bytes.count == 32)
		#expect(
			localListenAtBirth.rendezvousByEpoch
				.contains { $0.rendezvousId.bytes == remotePost.bytes })
		// Remote listens on its own send group: classical id only — the PQ half
		// is the deferred A.4 slot.
		let remoteListenAtBirth = try remoteBase.shouldListenOn()
		#expect(!remoteListenAtBirth.sendGroup.classical.bytes.isEmpty)
		#expect(remoteListenAtBirth.sendGroup.pq.bytes.isEmpty)
		#expect(remoteListenAtBirth.rendezvousByEpoch.first?.epoch == 1)

		// -- Step 3: remote's first frame staples the return welcome; local joins in-band.
		try remoteSession.send(to: localSession)
		#expect(localBase.isEstablished())
		#expect(!localBase.isFullyEstablished())
		// Local's recv group mirrors the deferred half: classical id only, empty PQ slot.
		let localRecv = try #require(localBase.receiveGroupId())
		#expect(!localRecv.classical.bytes.isEmpty)
		#expect(localRecv.pq.bytes.isEmpty)

		// Routing: the stapled join gave local its recv group — somewhere to post.
		let localPost = try #require(try localBase.sendRendezvous())
		#expect(
			try remoteBase.shouldListenOn().rendezvousByEpoch
				.contains { $0.rendezvousId.bytes == localPost.bytes })

		// -- Step 4: classical exchanges proceed while the PQ bootstrap is pending.
		try localSession.exchange(with: remoteSession)

		// Routing: routine rounds don't commit (A.2 commits only when consuming an
		// approved Upd), so no epochs moved and no new addresses were minted.
		#expect(try localBase.shouldListenOn().rendezvousByEpoch.count == 1)
		#expect(try remoteBase.shouldListenOn().rendezvousByEpoch.count == 1)

		// -- Step 4b: a full A.2 round. Remote's stapled Upd(self) is approved and
		// local's next send commits it: local's send group advances to classical
		// epoch 2, minting a new listen address while retaining epoch 1's.
		let remotePostBeforeCommit = try #require(try remoteBase.sendRendezvous())
		_ = try remoteSession.prepareToEncrypt(proposing: nil)
		let updFrame = try remoteSession.encrypt(appMessage: Data("upd".utf8))

		// The encrypt result reports the true APQ pair, not a duplicated single
		// epoch: remote's send group is classical-only pre-A.4, so pqEpoch is 0.
		#expect(updFrame.epochs == APQEpochs(pqEpoch: 0, classicalEpoch: 1))
		let updDecrypted = try #require(
			try localSession.processIncoming(ciphertext: updFrame.cipherText))
		let offered = try #require(updDecrypted.proposal)
		try localSession.queueProposal(digest: offered.digest)

		let prepared = try #require(try localSession.prepareToEncrypt(proposing: nil))
		#expect(prepared.didCommit)
		let commitFrame = try localSession.encrypt(appMessage: Data("commit".utf8))
		#expect(localBase.epochs().classicalEpoch == 2)

		// The initiator's send group is a full APQ pair from birth: pq stays 1
		// while the commit advanced classical to 2 — and the encrypt result
		// matches the session's own epoch view at send time.
		#expect(
			commitFrame.epochs
				== APQEpochs(pqEpoch: 1, classicalEpoch: 2))
		#expect(commitFrame.epochs.pqEpoch == localBase.epochs().pqEpoch)
		#expect(commitFrame.epochs.classicalEpoch == localBase.epochs().classicalEpoch)

		let localListenAfterCommit = try localBase.shouldListenOn()
		#expect(localListenAfterCommit.rendezvousByEpoch.map(\.epoch).sorted() == [1, 2])

		// Remote applies the commit: its post address migrates to the new epoch's
		// channel — present in local's listen set — and the old address stays listed
		// so in-flight traffic posted before the migration still lands.
		_ = try remoteSession.processIncoming(ciphertext: commitFrame.cipherText)
		let remotePostAfterCommit = try #require(try remoteBase.sendRendezvous())
		#expect(remotePostAfterCommit.bytes != remotePostBeforeCommit.bytes)
		#expect(
			localListenAfterCommit.rendezvousByEpoch
				.first { $0.epoch == 2 }?.rendezvousId.bytes
				== remotePostAfterCommit.bytes)
		#expect(
			localListenAfterCommit.rendezvousByEpoch
				.first { $0.epoch == 1 }?.rendezvousId.bytes
				== remotePostBeforeCommit.bytes)
		#expect(try postAddressMatches(poster: localBase, listener: remoteBase))
		#expect(try postAddressMatches(poster: remoteBase, listener: localBase))

		// -- Step 5: A.4 bootstrap. Local owes it (holds the turn).
		#expect(localSession.turn == .weInitiate)
		#expect(remoteSession.turn == .theyInitiate)
		let kp = try localSession.finishBootstrap(rotating: nil)
		#expect(kp.kind == .finishBootstrap)
		// Bootstrap key-package frame — classify by opening the seal (wire tag sealed, v7).
		#expect(try remoteBase.openIncoming(blob: kp.payload)?.kind == .pqSideBand(kind: .bootstrapKeyPackage))

		let remoteClassicalBefore = remoteBase.epochs().classicalEpoch
		let remoteListenBeforeBootstrap = try remoteBase.shouldListenOn()
		let inbound = try remoteSession.ingest(kp.payload)
		#expect(inbound.kind == .finishBootstrap)
		// Responding stands the PQ half up immediately: new PQ group at epoch 1. The
		// classical epoch is untouched — the responder's half of A.4 is PQ-groups-only;
		// the initiator's closing bind is what reaches a classical group, and it rides
		// the initiator's next classical commit as the message-frame staple (v18).
		#expect(remoteBase.isFullyEstablished())
		#expect(remoteBase.epochs().pqEpoch == 1)
		#expect(remoteBase.epochs().classicalEpoch == remoteClassicalBefore)

		// Routing: A.4 is PQ-groups-only — no classical commit, so no new listen
		// addresses — but the send group now advertises its PQ half's id.
		let remoteListenAfterBootstrap = try remoteBase.shouldListenOn()
		#expect(
			remoteListenAfterBootstrap.rendezvousByEpoch.count
				== remoteListenBeforeBootstrap.rendezvousByEpoch.count)
		#expect(!remoteListenAfterBootstrap.sendGroup.pq.bytes.isEmpty)

		// The retention peek (v18) serves the parked reply WITHOUT consuming it:
		// two fresh hand-outs are DIFFERENT ciphertexts of the same retained frame.
		let peek1 = try #require(remoteSession.pendingSideBand(sealing: .fresh))
		let peek2 = try #require(remoteSession.pendingSideBand(sealing: .fresh))
		#expect(peek1 != peek2)
		#expect(try localBase.openIncoming(blob: peek1)?.kind == .pqSideBand(kind: .bootstrapWelcome))

		let reply = try #require(remoteSession.advance(after: inbound))
		#expect(reply.kind == .finishBootstrap)
		// The responder's reply is the new PQ group's Welcome' (v18: the bind is no
		// longer a side-band frame kind — it rides the message-frame staple).
		#expect(try localBase.openIncoming(blob: reply.payload)?.kind == .pqSideBand(kind: .bootstrapWelcome))
		// The consuming take hands the frame out exactly once — retention included.
		#expect(remoteSession.advance(after: inbound) == nil)
		#expect(remoteSession.pendingSideBand(sealing: .fresh) == nil)

		let localClassicalBeforeBind = localBase.epochs().classicalEpoch
		let localInbound = try localSession.ingest(reply.payload)
		#expect(localInbound.kind == .finishBootstrap)
		#expect(localBase.isFullyEstablished())
		// Local's recv mirror gained the PQ group id. Local still HOLDS the turn:
		// the initiator relinquishes at its terminal send — the committing round
		// that staples the bind — not at the trigger.
		#expect(try #require(localBase.receiveGroupId()).pq.bytes.isEmpty == false)
		#expect(localBase.myPqTurn())
		// A.4's closing leg is real work on the initiator (v18): joining the welcomed
		// group exports the cross-party secret, which commits local's OWN send-PQ
		// pathlessly. The classical half is OWED — it rides the next classical commit.
		#expect(localBase.epochs().pqEpoch == 2)
		#expect(localBase.epochs().classicalEpoch == localClassicalBeforeBind)

		// -- Step 6: the next exchange discharges the owed bind — peer first. A
		// classical commit is LICENSED (v19) by a peer offer built against our
		// current epoch, and local committed last in step 4, so local needs one
		// inbound frame before its committing round. Then local's round staples
		// the APQPrivateMessage (both halves); remote applies it and only THEN
		// takes the turn — the bind is the receipt.
		try remoteSession.exchange(with: localSession)
		#expect(localBase.epochs().classicalEpoch == localClassicalBeforeBind + 1)
		#expect(!localBase.myPqTurn())
		#expect(remoteBase.myPqTurn())

		// Routing: still matched after the post-bootstrap exchange rounds.
		#expect(try postAddressMatches(poster: localBase, listener: remoteBase))
		#expect(try postAddressMatches(poster: remoteBase, listener: localBase))

		// -- Step 7: A.3 ratchet — SESSION-DRIVEN (contract 24). There is no host
		// `begin(.ratchet)`: Remote holds the turn (local's A.4 completion passed it),
		// so Remote's next ordinary SEND auto-stages the EK, taken via `pendingSideBand`.
		// (A.5 as a rotation credential catch-up is exercised in the Rust crate suite.)
		#expect(remoteSession.turn == .weInitiate)
		let remotePqBeforeRatchet = remoteBase.epochs().pqEpoch
		try remoteSession.send(to: localSession) // opener — auto-stages Remote's A.3 EK
		let ratchetEk = try #require(remoteSession.pendingSideBand(sealing: .fresh))
		// EK frame — classify by opening the seal (wire tag sealed, v7).
		#expect(try localBase.openIncoming(blob: ratchetEk)?.kind == .pqSideBand(kind: .ratchetEphemeralKey))

		// Local responds: seals the injected secret to the EK, parking the CT reply.
		let ratchetInbound1 = try localSession.ingest(ratchetEk)
		#expect(ratchetInbound1.kind == .ratchet)
		let ratchetReply = try #require(localSession.advance(after: ratchetInbound1))
		#expect(ratchetReply.kind == .ratchet)
		// CT frame — classify by opening the seal.
		#expect(try remoteBase.openIncoming(blob: ratchetReply.payload)?.kind == .pqSideBand(kind: .ratchetCiphertext))
		// The consuming take hands the frame out exactly once.
		#expect(localSession.advance(after: ratchetInbound1) == nil)

		// Remote binds the CT: its send-PQ commits EAGERLY (a pathless partial) and the
		// classical half is OWED — it rides Remote's next classical commit as the staple.
		// No further side-band frame is produced.
		let ratchetInbound2 = try remoteSession.ingest(ratchetReply.payload)
		#expect(ratchetInbound2.kind == .ratchet)
		#expect(remoteSession.advance(after: ratchetInbound2) == nil)
		#expect(remoteBase.epochs().pqEpoch > remotePqBeforeRatchet)

		// Remote's next committing round staples the bind; local applies it and the
		// turn passes back to local.
		try remoteSession.exchange(with: localSession)
		#expect(localSession.turn == .weInitiate)
		#expect(remoteSession.turn == .theyInitiate)

		// -- Step 8: exchanges still flow on the ratcheted groups.
		try localSession.exchange(with: remoteSession)
		_ = try remoteSession.prepareToEncrypt(proposing: nil)
		let postRatchetFrame = try remoteSession.encrypt(appMessage: Data("post-ratchet".utf8))
		let postRatchet = try #require(
			try localSession.processIncoming(ciphertext: postRatchetFrame.cipherText))
		#expect(try postRatchet.applicationMessage.tryUnwrap.appMessageData == Data("post-ratchet".utf8))
	}

	/// The poster's post address is its recv group's current exporter; the recv
	/// group *is* the listener's send group, so that address must appear in the
	/// listener's per-epoch listen set.
	private func postAddressMatches(
		poster: TwoMlsPqSession, listener: TwoMlsPqSession
	) throws -> Bool {
		guard let post = try poster.sendRendezvous() else { return false }
		return try listener.shouldListenOn().rendezvousByEpoch
			.contains { $0.rendezvousId.bytes == post.bytes }
	}
}
