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
		// reply already consumed the initial frame — the §A.1 envelope wrapping the APQ welcome (v8) — via pendingOutbound (take-once) into the sealed AppWelcome…
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
		#expect(updFrame.epochs == AbstractTwoMLS.APQEpochs(pqEpoch: 0, classicalEpoch: 1))
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
				== AbstractTwoMLS.APQEpochs(pqEpoch: 1, classicalEpoch: 2))
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
		let kp = try localSession.begin(.finishBootstrap, rotating: nil)
		#expect(kp.kind == .finishBootstrap)
		// Bootstrap key-package frame — classify by opening the seal (wire tag sealed, v7).
		#expect(try remoteBase.openIncoming(blob: kp.payload)?.kind == .pqSideBand(kind: .bootstrapKeyPackage))

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
		#expect(try localBase.openIncoming(blob: reply.payload)?.kind == .pqSideBand(kind: .bootstrapBind))
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

		// -- Step 7: A.5 rekey — PQ-group updatePath commits, isolated from the
		// classical ratchet. Remote holds the turn (local's A.4 completion passed it).
		#expect(remoteSession.turn == .weInitiate)
		let rekeyUpd = try remoteSession.begin(.rekey, rotating: nil)
		#expect(rekeyUpd.kind == .rekey)
		// Rekey Upd' proposal frame — classify by opening the seal (wire tag sealed, v7).
		#expect(try localBase.openIncoming(blob: rekeyUpd.payload)?.kind == .pqSideBand(kind: .rekeyUpdate))
		// The proposal alone moves no epochs on the initiator's side.
		#expect(remoteBase.epochs().pqEpoch == 1)

		// Local responds: commits Upd'(remote) on its own send-PQ with an updatePath
		// and the cross-injected PSK — pq epoch advances, classical is untouched,
		// and no listen addresses are minted (PQ-only commits, like A.4).
		let localClassicalBeforeRekey = localBase.epochs().classicalEpoch
		let localListenBeforeRekey = try localBase.shouldListenOn().rendezvousByEpoch.count
		let rekeyInbound1 = try localSession.ingest(rekeyUpd.payload)
		#expect(rekeyInbound1.kind == .rekey)
		#expect(localBase.epochs().pqEpoch == 2)
		#expect(localBase.epochs().classicalEpoch == localClassicalBeforeRekey)
		#expect(
			try localBase.shouldListenOn().rendezvousByEpoch.count
				== localListenBeforeRekey)

		// Local's parked reply carries its Commit' plus the counter-Upd'(local).
		let rekeyReply = try #require(try localSession.advance(after: rekeyInbound1))
		#expect(rekeyReply.kind == .rekey)
		// Rekey Commit' frame — classify by opening the seal (wire tag sealed, v7).
		#expect(try remoteBase.openIncoming(blob: rekeyReply.payload)?.kind == .pqSideBand(kind: .rekeyCommit))
		#expect(try localSession.advance(after: rekeyInbound1) == nil)

		// Remote applies local's Commit' to its recv mirror and commits the
		// counter-Upd' on its own send-PQ: its pq epoch advances too.
		let rekeyInbound2 = try remoteSession.ingest(rekeyReply.payload)
		#expect(rekeyInbound2.kind == .rekey)
		#expect(remoteBase.epochs().pqEpoch == 2)
		let rekeyFinal = try #require(try remoteSession.advance(after: rekeyInbound2))
		#expect(try localBase.openIncoming(blob: rekeyFinal.payload)?.kind == .pqSideBand(kind: .rekeyCommit))

		// Local applies the final Commit'; the operation completes and the turn
		// passes back to local.
		let rekeyInbound3 = try localSession.ingest(rekeyFinal.payload)
		#expect(rekeyInbound3.kind == .rekey)
		#expect(try localSession.advance(after: rekeyInbound3) == nil)
		#expect(localSession.turn == .weInitiate)
		#expect(remoteSession.turn == .theyInitiate)

		// -- Step 8: exchanges still flow on the rekeyed groups, and the next
		// send reports the bumped pq epoch.
		try localSession.exchange(with: remoteSession)
		_ = try remoteSession.prepareToEncrypt(proposing: nil)
		let postRekeyFrame = try remoteSession.encrypt(appMessage: Data("post-rekey".utf8))
		#expect(postRekeyFrame.epochs.pqEpoch == 2)
		_ = try localSession.processIncoming(ciphertext: postRekeyFrame.cipherText)
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
