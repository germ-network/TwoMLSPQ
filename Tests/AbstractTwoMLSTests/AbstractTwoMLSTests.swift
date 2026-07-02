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

		// -- Step 3: remote's first frame staples the return welcome; local joins in-band.
		try remoteSession.send(to: localSession)
		#expect(localBase.isEstablished())
		#expect(!localBase.isFullyEstablished())
		// Local's recv group mirrors the deferred half: classical id only, empty PQ slot.
		let localRecv = try #require(localBase.receiveGroupId())
		#expect(!localRecv.classical.bytes.isEmpty)
		#expect(localRecv.pq.bytes.isEmpty)

		// -- Step 4: classical exchanges proceed while the PQ bootstrap is pending.
		try localSession.exchange(with: remoteSession)

		// -- Step 5: A.4 bootstrap. Local owes it (holds the turn).
		#expect(localSession.turn == .weInitiate)
		#expect(remoteSession.turn == .theyInitiate)
		let kp = try localSession.begin(.finishBootstrap, rotating: nil)
		#expect(kp.kind == .finishBootstrap)
		// Bootstrap key-package frame tag.
		#expect(kp.payload.first == 0x11)

		let remoteClassicalBefore = remoteBase.epochs().classicalEpoch
		let inbound = try remoteSession.ingest(kp.payload)
		#expect(inbound.kind == .finishBootstrap)
		// Responding stands the PQ half up immediately: new PQ group at epoch 1, and
		// the APQ-PSK bind commit advances the send classical epoch by one.
		#expect(remoteBase.isFullyEstablished())
		#expect(remoteBase.epochs().pqEpoch == 1)
		#expect(remoteBase.epochs().classicalEpoch == remoteClassicalBefore + 1)

		let reply = try #require(try remoteSession.advance(after: inbound))
		#expect(reply.kind == .finishBootstrap)
		// Bootstrap bind frame tag (PQ welcome + classical bind commit).
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
	}
}
