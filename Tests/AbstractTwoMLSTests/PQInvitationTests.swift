//
//  PQInvitationTests.swift
//  AbstractTwoMLS
//
//  Exercises the two-step receive path of the PQ conformance: the acceptor runs
//  entirely through the abstract PQInvitation, while the initiator drives the raw
//  TwoMLSPQ FFI directly (PQClient.reply is not wired yet).
//

import AbstractTwoMLS
import CommProtocol
import Foundation
import Testing

@testable import TwoMLSPQ

struct PQInvitationReceiveTests {

	@Test func receiveEstablishesSession() throws {
		// Acceptor: abstract client publishes an invitation, restored from its archive.
		let invitation = try AbstractTwoMLS.PQInvitation(
			archive: try AbstractTwoMLS.PQClient(clientId: .mock()).makeInvitation()
		)

		// Initiator (raw FFI): decode the acceptor's opaque published key package
		// and form the send group. The initiator cannot encrypt until both groups
		// are established, so there is no stapled message at receive time.
		let initiator = try TwoMlsPqIdentity(clientId: AbstractTwoMLS.ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair
		)
		let welcome = try #require(initiatorSession.pendingOutbound())

		// The initiator's own published key package (for the bound return group). Uses the
		// retaining generate path — the initiator's live session joins the return welcome
		// through its own client store, unlike an invitation-held key package.
		let initiatorKp = try initiator.generateCombinerKeyPackage()

		let (acceptorSession, plaintext) = try invitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: encodeCombinerKeyPackage(keyPackage: initiatorKp),
			remoteClientId: initiator.clientId().bytes,
			combinedWelcomeDigest: TypedDigest(prefix: .sha256, over: welcome),
			stapledMessage: nil,
			newClientId: .mock()
		)
		#expect(plaintext == nil)

		// Complete establishment: the acceptor's first frame staples its return
		// welcome; the initiator processes it in-band.
		_ = try acceptorSession.prepareToEncrypt(proposing: nil)
		let back = try acceptorSession.encrypt(appMessage: "hello back".utf8Data)
		let received = try #require(
			try initiatorSession.processIncoming(ciphertext: back.cipherText)
		)
		#expect(received.applicationMessage?.appMessageData == "hello back".utf8Data)

		// And a routine round now that the initiator is fully established.
		_ = try initiatorSession.prepareToEncrypt(proposing: nil)
		let routine = try initiatorSession.encrypt(appMessage: "routine".utf8Data)
		let decrypted = try acceptorSession.processIncoming(ciphertext: routine.cipherText)
		#expect(
			try decrypted.tryUnwrap.applicationMessage.tryUnwrap.appMessageData
				== "routine".utf8Data
		)
	}

	@Test func receiveRejectsDuplicateRemote() throws {
		let invitation = try AbstractTwoMLS.PQInvitation(
			archive: try AbstractTwoMLS.PQClient(clientId: .mock()).makeInvitation()
		)

		let initiator = try TwoMlsPqIdentity(clientId: AbstractTwoMLS.ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair
		)
		let welcome = try #require(initiatorSession.pendingOutbound())
		let initiatorKp = encodeCombinerKeyPackage(
			keyPackage: try initiator.generateCombinerKeyPackage()
		)
		let digest = TypedDigest(prefix: .sha256, over: welcome)

		_ = try invitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: initiatorKp,
			remoteClientId: initiator.clientId().bytes,
			combinedWelcomeDigest: digest,
			stapledMessage: nil,
			newClientId: .mock()
		)

		// A transport re-delivery of the same welcome is dropped.
		#expect(throws: (any Error).self) {
			_ = try invitation.receive(
				sendGroupWelcome: welcome,
				remoteKeyPackage: initiatorKp,
				remoteClientId: initiator.clientId().bytes,
				combinedWelcomeDigest: digest,
				stapledMessage: nil,
				newClientId: .mock()
			)
		}
	}

	@Test func receiveRejectsMismatchedIdentity() throws {
		let invitation = try AbstractTwoMLS.PQInvitation(
			archive: try AbstractTwoMLS.PQClient(clientId: .mock()).makeInvitation()
		)

		let initiator = try TwoMlsPqIdentity(clientId: AbstractTwoMLS.ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair
		)
		let welcome = try #require(initiatorSession.pendingOutbound())
		let initiatorKp = encodeCombinerKeyPackage(
			keyPackage: try initiator.generateCombinerKeyPackage()
		)

		// The key package's credential must match the authenticated remote identity.
		do {
			_ = try invitation.receive(
				sendGroupWelcome: welcome,
				remoteKeyPackage: initiatorKp,
				remoteClientId: .mock(),  // not the initiator's identity
				combinedWelcomeDigest: TypedDigest(prefix: .sha256, over: welcome),
				stapledMessage: nil,
				newClientId: .mock()
			)
			Issue.record("expected remoteIdentityMismatch")
		} catch TwoMLSPQConformanceError.remoteIdentityMismatch {
			// expected
		}
	}
}
