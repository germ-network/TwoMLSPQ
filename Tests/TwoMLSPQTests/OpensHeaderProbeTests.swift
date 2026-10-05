//
//  OpensHeaderProbeTests.swift
//  TwoMLSPQ
//
//  Pins `PQSession.opensHeader(_:)`: the header receive-window ownership probe.
//  Ownership == header openability, so the owner's peer frame probes true, an
//  unrelated session probes false, and the probe consumes nothing. The throw→true
//  branch is unreachable from the public API with an honest peer (a post-auth
//  throw needs a key-authenticated blob with a bad inner tag) and is not
//  exercised here.
//

import CommProtocol
import Foundation
import Testing

@testable import TwoMLSPQ

struct OpensHeaderProbeTests {

	/// A fully classically-established pair: `initiator` and `acceptor` exchange
	/// message frames. Mirrors LifecycleTests' establishment through the shared
	/// TestSupport helpers rather than inventing a new flow.
	private func makeEstablishedPair() throws -> (
		initiator: PQSession, acceptor: PQSession
	) {
		let local = try ClientWrapper()
		let remote = try ClientWrapper()

		let (initiator, welcome, myKeyPackage, bootstrapKpCommitment) =
			try local.client.reply(
				keyPackageMessage: remote.currentInvitation.encodedKeyPackage
			)
		let dedicatedId: ClientID = .mock()
		let (acceptor, stapled) = try remote.currentInvitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: myKeyPackage,
			bootstrapKpCommitment: bootstrapKpCommitment,
			remoteClientId: try local.clientId,
			welcomeToken: WelcomeToken(PQDigest.over(welcome)),
			stapledMessage: nil,
			newClientId: dedicatedId
		)
		#expect(stapled == nil)
		try acceptor.installMockEstablishmentEnvelope()
		// The acceptor's first frame staples its enveloped return welcome; the
		// initiator pauses, verifies, and resumes — both sides now exchange messages.
		try initiator.acceptEstablishment(from: acceptor, dedicatedId: dedicatedId)
		return (initiator, acceptor)
	}

	/// A message frame the acceptor sealed — the initiator's peer, so the
	/// initiator's header receive window owns it.
	private func acceptorFrame(from acceptor: PQSession, message: Data) throws -> Data {
		_ = try acceptor.prepareToEncrypt(proposing: nil)
		return try acceptor.encrypt(appMessage: message).cipherText
	}

	@Test func ownerProbesTrue() throws {
		let (initiator, acceptor) = try makeEstablishedPair()
		let frame = try acceptorFrame(from: acceptor, message: Data("owner".utf8))
		#expect(initiator.opensHeader(frame))
	}

	@Test func siblingProbesFalse() throws {
		let (initiator, acceptor) = try makeEstablishedPair()
		let (siblingInitiator, _) = try makeEstablishedPair()
		let frame = try acceptorFrame(from: acceptor, message: Data("owner".utf8))
		// The owner's own frame probes true; an unrelated, independently-established
		// session holds no receive-window key for it — deterministically false.
		#expect(initiator.opensHeader(frame))
		#expect(!siblingInitiator.opensHeader(frame))
	}

	@Test func probeIsPureRead() throws {
		let (initiator, acceptor) = try makeEstablishedPair()
		let message = Data("still-consumable".utf8)
		let frame = try acceptorFrame(from: acceptor, message: message)

		// Probing does not consume the frame: the same blob still decrypts after.
		#expect(initiator.opensHeader(frame))
		let decrypted = try #require(try initiator.decrypt(frame))
		#expect(decrypted.applicationMessage?.appMessageData == message)
	}
}
