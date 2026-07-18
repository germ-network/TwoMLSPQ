//
//  PQInvitationTests.swift
//  TwoMLSPQ
//
//  Exercises the two-step receive path of the PQ conformance: the acceptor runs
//  entirely through the abstract PQInvitation, while the initiator drives the raw
//  TwoMLSPQ FFI directly (PQClient.reply is not wired yet).
//

import CommProtocol
import Foundation
import Testing

import TwoMLSPQ
import TwoMLSPQBinding

struct PQInvitationReceiveTests {

	@Test func receiveEstablishesSession() throws {
		// Acceptor: abstract client publishes an invitation, restored from its archive.
		let invitation = try PQInvitation(
			persisted: try PQClient(clientId: .mock()).makeInvitation()
		)

		// Initiator (raw FFI): decode the acceptor's opaque published key package
		// and form the send group. These tests deliver the PLAINTEXT welcome
		// (`initialWelcome`) with no app envelope and no staple — the bare two-step
		// receive path; the enveloped/stapled §A.1 flow is ReplierFirstDemo's.
		let initiator = try TwoMlsPqPrincipal(clientId: ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair,
			appBinding: nil
		)
		let welcome = try #require(initiatorSession.initialWelcome())

		// The initiator's own published key package (for the bound return group). Uses the
		// retaining generate path — the initiator's live session joins the return welcome
		// through its own client store, unlike an invitation-held key package.
		// v20: the return KP is the initiator's CLASSICAL bare KeyPackage (its PQ half
		// now travels in A.4, hash-bound to `bootstrapKpCommitment` — sourced from the
		// initiating session, which pre-commits it at `initiate`).
		let initiatorKp = try initiator.generateKeyPackage(suite: .x25519Chacha())

		let (acceptorSession, stapled) = try invitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: initiatorKp,
			bootstrapKpCommitment: try #require(initiatorSession.bootstrapKpCommitment()),
			remoteClientId: initiator.clientId().bytes,
			welcomeToken: WelcomeToken(TypedDigest(prefix: .sha256, over: welcome)),
			stapledMessage: nil,
			newClientId: .mock()
		)
		#expect(stapled == nil)

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
		let invitation = try PQInvitation(
			persisted: try PQClient(clientId: .mock()).makeInvitation()
		)

		let initiator = try TwoMlsPqPrincipal(clientId: ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair,
			appBinding: nil
		)
		let welcome = try #require(initiatorSession.initialWelcome())
		let initiatorKp = try initiator.generateKeyPackage(suite: .x25519Chacha())
		let commitment = try #require(initiatorSession.bootstrapKpCommitment())
		let token = WelcomeToken(TypedDigest(prefix: .sha256, over: welcome))

		_ = try invitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: initiatorKp,
			bootstrapKpCommitment: commitment,
			remoteClientId: initiator.clientId().bytes,
			welcomeToken: token,
			stapledMessage: nil,
			newClientId: .mock()
		)

		// A transport re-delivery of the same welcome is dropped.
		do {
			_ = try invitation.receive(
				sendGroupWelcome: welcome,
				remoteKeyPackage: initiatorKp,
				bootstrapKpCommitment: commitment,
				remoteClientId: initiator.clientId().bytes,
				welcomeToken: token,
				stapledMessage: nil,
				newClientId: .mock()
			)
			Issue.record("expected .duplicateWelcome")
		} catch {  // receive is throws(SessionError) — error is typed
			#expect(error.code == .duplicateWelcome)
			#expect(error.disposition == .discardFrame)
		}
	}

	@Test func receiveRejectsMismatchedIdentity() throws {
		let invitation = try PQInvitation(
			persisted: try PQClient(clientId: .mock()).makeInvitation()
		)

		let initiator = try TwoMlsPqPrincipal(clientId: ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair,
			appBinding: nil
		)
		let welcome = try #require(initiatorSession.initialWelcome())
		let initiatorKp = try initiator.generateKeyPackage(suite: .x25519Chacha())
		let commitment = try #require(initiatorSession.bootstrapKpCommitment())

		// The key package's credential must match the authenticated remote identity.
		do {
			_ = try invitation.receive(
				sendGroupWelcome: welcome,
				remoteKeyPackage: initiatorKp,
				bootstrapKpCommitment: commitment,
				remoteClientId: .mock(),  // not the initiator's identity
				welcomeToken: WelcomeToken(TypedDigest(prefix: .sha256, over: welcome)),
				stapledMessage: nil,
				newClientId: .mock()
			)
			Issue.record("expected .identityMismatch")
		} catch {  // receive is throws(SessionError) — error is typed
			// M4: the wrapper's own key-package guard and the crate's
			// RemoteIdentityMismatch both surface as one code.
			#expect(error.code == .identityMismatch)
			#expect(error.disposition == .rejectEstablishment)
		}
	}

	/// v20: a malformed bootstrap-KP commitment (not 32 bytes — the app read the wrong
	/// bytes out of the signed envelope) is rejected at `receive` before any invitation
	/// state is claimed, surfacing the crate's `BootstrapKpMismatch` as
	/// `.bootstrapKpMismatch`/`.discardFrame`; the invitation stays reusable, so the same
	/// welcome then establishes with the genuine commitment.
	@Test func receiveRejectsMalformedBootstrapCommitment() throws {
		let invitation = try PQInvitation(
			persisted: try PQClient(clientId: .mock()).makeInvitation()
		)

		let initiator = try TwoMlsPqPrincipal(clientId: ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair,
			appBinding: nil
		)
		let welcome = try #require(initiatorSession.initialWelcome())
		let initiatorKp = try initiator.generateKeyPackage(suite: .x25519Chacha())
		let token = WelcomeToken(TypedDigest(prefix: .sha256, over: welcome))

		do {
			_ = try invitation.receive(
				sendGroupWelcome: welcome,
				remoteKeyPackage: initiatorKp,
				bootstrapKpCommitment: Data(repeating: 0, count: 31),  // one byte short of a SHA-256
				remoteClientId: initiator.clientId().bytes,
				welcomeToken: token,
				stapledMessage: nil,
				newClientId: .mock()
			)
			Issue.record("expected .bootstrapKpMismatch")
		} catch {  // receive is throws(SessionError) — error is typed
			#expect(error.code == .bootstrapKpMismatch)
			#expect(error.disposition == .discardFrame)
			// The receive-surface mismatch carries an actionable message, not just
			// the bare code: it names the commitment and that the invitation survives.
			#expect(error.detail?.contains("commitment") == true)
			#expect(error.detail?.contains("NOT consumed") == true)
		}

		// The invitation was not consumed by the rejected receive: the genuine
		// commitment establishes on the same welcome, and the session round-trips.
		let (acceptorSession, stapled) = try invitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: initiatorKp,
			bootstrapKpCommitment: try #require(initiatorSession.bootstrapKpCommitment()),
			remoteClientId: initiator.clientId().bytes,
			welcomeToken: token,
			stapledMessage: nil,
			newClientId: .mock()
		)
		#expect(stapled == nil)

		_ = try acceptorSession.prepareToEncrypt(proposing: nil)
		let back = try acceptorSession.encrypt(appMessage: "established".utf8Data)
		let received = try #require(
			try initiatorSession.processIncoming(ciphertext: back.cipherText)
		)
		#expect(received.applicationMessage?.appMessageData == "established".utf8Data)
	}

	/// An empty dedicated-principal id is rejected BEFORE any invitation state is
	/// claimed: the same welcome then succeeds on retry with a valid id. (Staging
	/// used to run after `base.receive`, so this failure orphaned the established
	/// session and burned the welcome — retry got `DuplicateWelcome`.)
	@Test func receiveRejectsEmptyDedicatedPrincipalBeforeConsuming() throws {
		let invitation = try PQInvitation(
			persisted: try PQClient(clientId: .mock()).makeInvitation()
		)

		let initiator = try TwoMlsPqPrincipal(clientId: ClientID.mock())
		let acceptorPair = try decodeCombinerKeyPackage(bytes: invitation.encodedKeyPackage)
		let initiatorSession = try TwoMlsPqSession.initiate(
			client: initiator,
			theirKeyPackage: acceptorPair,
			appBinding: nil
		)
		let welcome = try #require(initiatorSession.initialWelcome())
		let initiatorKp = try initiator.generateKeyPackage(suite: .x25519Chacha())
		let commitment = try #require(initiatorSession.bootstrapKpCommitment())
		let token = WelcomeToken(TypedDigest(prefix: .sha256, over: welcome))

		do {
			_ = try invitation.receive(
				sendGroupWelcome: welcome,
				remoteKeyPackage: initiatorKp,
				bootstrapKpCommitment: commitment,
				remoteClientId: initiator.clientId().bytes,
				welcomeToken: token,
				stapledMessage: nil,
				newClientId: Data()
			)
			Issue.record("expected .invalidClientId")
		} catch {  // receive is throws(SessionError) — error is typed
			#expect(error.code == .invalidClientId)
		}

		// Nothing was consumed: the identical welcome establishes on retry.
		_ = try invitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: initiatorKp,
			bootstrapKpCommitment: commitment,
			remoteClientId: initiator.clientId().bytes,
			welcomeToken: token,
			stapledMessage: nil,
			newClientId: .mock()
		)
	}
}
