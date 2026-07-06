//
//  AbstractTwoMLSTests.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/30/26.
//
//  Deep lifecycle test: the same flow as APIDemo.apiDemo, but checking each step's
//  expected state through the TwoMLSPQ session's internal accessors (epochs, turn,
//  established flags, group ids) via the PQSession adapter's `base`.
//

import CommProtocol
import Foundation
import Testing

@testable import AbstractTwoMLS
@testable import TwoMLSPQ

struct LifecycleTests {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func testExchange() async throws {
		// -- Step 1: initiator forms its APQ send group and seals the AppWelcome.
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let localBase = localSession.base

		// Send group live at epoch 1 with a full PQ half; no recv group yet.
		#expect(!localBase.isEstablished())
		#expect(!localBase.hasReceiveGroup())
		#expect(!localBase.isFullyEstablished())
		#expect(localBase.myPqTurn())
		#expect(localBase.epochs() == ApqEpochs(pqEpoch: 1, classicalEpoch: 1))
		// reply consumed the APQ welcome into the sealed AppWelcome…
		#expect(localBase.pendingOutbound() == nil)
		// …which travels as a v1 header frame.
		#expect(encryptedCombinedWelcome.first == 1)

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
		let (remoteSession, stapled) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId
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
		// Each side's view of the peer matches the peer's self-view (both in sync).
		#expect(localBase.myAgentState() == remoteBase.theirAgentState())
		#expect(remoteBase.myAgentState() == localBase.theirAgentState())

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
		let updDecrypted = try #require(
			try localSession.processIncoming(ciphertext: updFrame.cipherText))
		let offered = try #require(updDecrypted.proposal)
		try localSession.queueProposal(digest: offered.digest)

		let prepared = try #require(try localSession.prepareToEncrypt(proposing: nil))
		#expect(prepared.didCommit)
		let commitFrame = try localSession.encrypt(appMessage: Data("commit".utf8))
		#expect(localBase.epochs().classicalEpoch == 2)
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
				.first { $0.epoch == 2 }?.rendezvousId.bytes == remotePostAfterCommit.bytes)
		#expect(
			localListenAfterCommit.rendezvousByEpoch
				.first { $0.epoch == 1 }?.rendezvousId.bytes == remotePostBeforeCommit.bytes)
		#expect(try postAddressMatches(poster: localBase, listener: remoteBase))
		#expect(try postAddressMatches(poster: remoteBase, listener: localBase))

		// -- Step 5: A.4 bootstrap. Local owes it (holds the turn).
		#expect(localSession.turn == .weInitiate)
		#expect(remoteSession.turn == .theyInitiate)
		let kp = try localSession.begin(.finishBootstrap, rotating: nil)
		#expect(kp.kind == .finishBootstrap)
		// Bootstrap key-package frame tag.
		#expect(kp.payload.first == 0x11)

		let remoteClassicalBefore = remoteBase.epochs().classicalEpoch
		let remoteListenBeforeBootstrap = try remoteBase.shouldListenOn()
		let inbound = try remoteSession.ingest(kp.payload)
		#expect(inbound.kind == .finishBootstrap)
		// Responding stands the PQ half up immediately: new PQ group at epoch 1. The
		// classical epoch is untouched — A.4 is PQ-groups-only; the APQ-PSK binds into
		// the classical half at the next A.3 ratchet.
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

		let reply = try #require(try remoteSession.advance(after: inbound))
		#expect(reply.kind == .finishBootstrap)
		// Bootstrap bind frame tag (PQ welcome only — A.4 is PQ-groups-only).
		#expect(reply.payload.first == 0x13)
		// The parked reply is handed out exactly once.
		#expect(try remoteSession.advance(after: inbound) == nil)

		let localInbound = try localSession.ingest(reply.payload)
		#expect(localInbound.kind == .finishBootstrap)
		#expect(localBase.isFullyEstablished())
		// Local's recv mirror gained the PQ group id, and the turn passed to remote.
		#expect(try #require(localBase.receiveGroupId()).pq.bytes.isEmpty == false)
		#expect(!localBase.myPqTurn())
		#expect(remoteBase.myPqTurn())
		// The initiator's own send group was untouched by the bootstrap.
		#expect(localBase.epochs().pqEpoch == 1)

		// -- Step 6: exchanges still flow fully established.
		try localSession.exchange(with: remoteSession)

		// Routing: still matched after the post-bootstrap exchange rounds.
		#expect(try postAddressMatches(poster: localBase, listener: remoteBase))
		#expect(try postAddressMatches(poster: remoteBase, listener: localBase))
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
