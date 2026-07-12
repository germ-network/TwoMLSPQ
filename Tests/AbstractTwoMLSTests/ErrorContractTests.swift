//
//  ErrorContractTests.swift
//  AbstractTwoMLS
//
//  Pins the SessionError contract: the abstract surface throws ONE type; every
//  backend error maps to a stable code with the documented disposition; and the
//  translation is total over the 21 TwoMlsPqError cases (a binding bump that
//  adds a case fails compilation in SessionError+TwoMLSPQ.swift, and this
//  totality test catches a silent remapping of an existing one).
//

import CommProtocol
import Foundation
import Testing

@testable import AbstractTwoMLS  // internal SessionError(pqError:at:) + PQErrorSurface
@testable import TwoMLSPQ  // public TwoMlsPqError cases

struct ErrorContractTests {

	// MARK: Code -> Disposition table (exhaustive; a new code forces a row)

	@Test func codeDispositionTable() {
		typealias E = AbstractTwoMLS.SessionError
		let table: [(E.Code, E.Disposition)] = [
			(.decryptionFailed, .retryLater),
			(.staleFrame, .discardFrame),
			(.duplicateWelcome, .discardFrame),
			(.unopenableFrame, .discardFrame),
			(.malformedFrame, .discardFrame),
			(.epochDesync, .reconnect),
			(.credentialRejected, .approveAndReprocess),
			(.invitationSpent, .discardArtifact),
			(.archiveInvalid, .discardArtifact),
			(.identityMismatch, .rejectEstablishment),
			(.pqUnavailable, .rejectEstablishment),
			(.cipherSuiteMismatch, .rejectEstablishment),
			(.invalidKeyPackage, .rejectEstablishment),
			(.apqInfoMismatch, .rejectEstablishment),
			(.unexpectedWelcome, .rejectEstablishment),
			(.misroutedFrame, .callerBug),
			(.sequenceViolation, .callerBug),
			(.sessionNotEstablished, .callerBug),
			(.invalidClientId, .callerBug),
			(.proposalRejected, .callerBug),
			(.rotationCannotRideRatchet, .callerBug),
			(.unsupportedCipherSuite, .callerBug),
			(.missingWelcome, .callerBug),
			(.sinkAlreadyInstalled, .callerBug),
			(.notImplemented, .callerBug),
			(.internalError, .fatal),
		]
		for (code, disposition) in table {
			#expect(code.disposition == disposition, "\(code) -> \(code.disposition)")
		}
	}

	// MARK: Totality over the 21 TwoMlsPqError cases

	/// Every crate case, mapped at a neutral surface. `SessionNotReady` is
	/// surface-dependent and covered separately below.
	@Test func everyCrateCaseMaps() {
		let expected: [(TwoMlsPqError, AbstractTwoMLS.SessionError.Code)] = [
			(.Mls, .internalError),
			(.PskBinding, .internalError),
			(.InvalidKeyPackage, .invalidKeyPackage),
			(.MissingWelcome, .missingWelcome),
			(.PqNotAvailable, .pqUnavailable),
			(.SessionNotEstablished, .sessionNotEstablished),
			(.ProposalRejected, .proposalRejected),
			(.DecryptionFailed, .decryptionFailed),
			(.ArchiveInvalid, .archiveInvalid),
			(.DuplicateWelcome, .duplicateWelcome),
			(.InvitationSpent, .invitationSpent),
			(.UnsupportedCipherSuite, .unsupportedCipherSuite),
			(.CipherSuiteMismatch, .cipherSuiteMismatch),
			(.EpochDesync, .epochDesync),
			(.UnexpectedWelcome, .unexpectedWelcome),
			(.InvalidClientId, .invalidClientId),
			(.RemoteIdentityMismatch, .identityMismatch),
			(.CredentialRejected, .credentialRejected),
			(.ApqInfoMismatch, .apqInfoMismatch),
			(.SinkAlreadyInstalled, .sinkAlreadyInstalled),
		]
		#expect(expected.count == 20)  // + SessionNotReady (per-surface) = 21 cases
		for (crate, code) in expected {
			let mapped = AbstractTwoMLS.SessionError(pqError: crate, at: .client)
			#expect(mapped.code == code, "\(crate) -> \(mapped.code)")
			#expect(mapped.underlying is TwoMlsPqError)
		}
	}

	/// The overloaded `SessionNotReady` disambiguates by surface: a misrouted
	/// frame at the receive doors, a sequencing violation at the send doors.
	@Test func sessionNotReadyIsSurfaceDependent() {
		let misrouted: [PQErrorSurface] = [.processIncoming, .forwarded, .ingest]
		for surface in misrouted {
			let e = AbstractTwoMLS.SessionError(pqError: TwoMlsPqError.SessionNotReady, at: surface)
			#expect(e.code == .misroutedFrame, "\(surface)")
		}
		let sequencing: [PQErrorSurface] = [.prepareToEncrypt, .encrypt, .pqOperation, .receive]
		for surface in sequencing {
			let e = AbstractTwoMLS.SessionError(pqError: TwoMlsPqError.SessionNotReady, at: surface)
			#expect(e.code == .sequenceViolation, "\(surface)")
		}
	}

	/// Anything that isn't a TwoMlsPqError falls through to `.internalError`
	/// (this absorbs the fileprivate UniffiInternalError / rustPanic too).
	@Test func unknownErrorsAreInternal() {
		struct Weird: Error {}
		let e = AbstractTwoMLS.SessionError(pqError: Weird(), at: .encrypt)
		#expect(e.code == .internalError)
		#expect(e.disposition == .fatal)
	}
}

// MARK: - Behavioral pins for the new persistence surfaces

struct ErrorContractBehaviorTests {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

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

	@Test func doubleInstallIsCallerBug() throws {
		let (_, remoteSession) = try establishPair()
		try remoteSession.installSink(RecordingSink())
		do {
			try remoteSession.installSink(RecordingSink())
			Issue.record("expected .sinkAlreadyInstalled")
		} catch {
			#expect(error.code == .sinkAlreadyInstalled)
			#expect(error.disposition == .callerBug)
		}
	}

	@Test func corruptedCheckpointRestoreIsDiscardArtifact() throws {
		do {
			_ = try AbstractTwoMLS.PQSession(
				persisted: .init(core: nil, checkpoint: Data("garbage".utf8)))
			Issue.record("expected .archiveInvalid")
		} catch {
			#expect(error.code == .archiveInvalid)
			#expect(error.disposition == .discardArtifact)
		}
	}

	@Test func misroutedSideBandIntoProcessIncoming() throws {
		let (localSession, remoteSession) = try establishPair()
		// Drive local to owe the A.4 bootstrap and take its side-band frame.
		let localPQ = localSession as any AbstractTwoMLS.PQRatchetingSession
		let outbound = try localPQ.begin(.finishBootstrap, rotating: nil)
		// Feeding a PQ side-band frame to the message door is a routing bug.
		do {
			_ = try remoteSession.processIncoming(ciphertext: outbound.payload)
			Issue.record("expected .misroutedFrame")
		} catch {
			#expect(error.code == .misroutedFrame)
		}
	}

	@Test func encryptWithoutPrepareIsSequenceViolation() throws {
		let (localSession, _) = try establishPair()
		do {
			_ = try localSession.encrypt(appMessage: Data("no prepare".utf8))
			Issue.record("expected .sequenceViolation")
		} catch {
			#expect(error.code == .sequenceViolation)
			#expect(error.disposition == .callerBug)
		}
	}
}
