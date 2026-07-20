//
//  ErrorContractTests.swift
//  TwoMLSPQ
//
//  Pins the SessionError contract: the abstract surface throws ONE type; every
//  backend error maps to a stable code with the documented disposition; and the
//  translation is total over the 22 TwoMlsPqError cases (a binding bump that
//  adds a case fails compilation in SessionErrorBridge.swift, and this
//  totality test catches a silent remapping of an existing one).
//

import CommProtocol
import Foundation
import Testing

import TwoMLSPQBinding  // public TwoMlsPqError cases

@testable import TwoMLSPQ  // internal SessionError(pqError:at:) + PQErrorSurface

struct ErrorContractTests {

	// MARK: Code -> Disposition table (exhaustive; a new code forces a row)

	@Test func codeDispositionTable() {
		typealias E = SessionError
		let table: [(E.Code, E.Disposition)] = [
			(.decryptionFailed, .retryLater),
			(.staleFrame, .discardFrame),
			(.duplicateWelcome, .discardFrame),
			(.unopenableFrame, .discardFrame),
			(.malformedFrame, .discardFrame),
			(.epochDesync, .reestablish),
			(.duplicateSideBand, .discardFrame),
			(.bindApplyFailed, .retryLater),
			(.bindDischargeFailed, .reestablish),
			(.credentialRejected, .approveAndReprocess),
			(.invitationSpent, .discardArtifact),
			(.archiveInvalid, .discardArtifact),
			(.identityMismatch, .rejectEstablishment),
			(.pqUnavailable, .rejectEstablishment),
			(.cipherSuiteMismatch, .rejectEstablishment),
			(.invalidKeyPackage, .rejectEstablishment),
			(.apqInfoMismatch, .rejectEstablishment),
			(.appBindingMismatch, .rejectEstablishment),
			(.unexpectedWelcome, .rejectEstablishment),
			(.misroutedFrame, .callerBug),
			(.sequenceViolation, .callerBug),
			(.sessionNotEstablished, .callerBug),
			(.invalidClientId, .callerBug),
			(.proposalRejected, .callerBug),
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

	// MARK: Totality over the 22 TwoMlsPqError cases

	/// Every crate case, mapped at a neutral surface. `SessionNotReady` is
	/// surface-dependent and covered separately below.
	@Test func everyCrateCaseMaps() {
		let expected: [(TwoMlsPqError, SessionError.Code)] = [
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
			(.AppBindingMismatch, .appBindingMismatch),
		]
		#expect(expected.count == 21)  // + SessionNotReady (per-surface) = 22 cases
		for (crate, code) in expected {
			let mapped = SessionError(pqError: crate, at: .client)
			#expect(mapped.code == code, "\(crate) -> \(mapped.code)")
			#expect(mapped.underlying is TwoMlsPqError)
		}
	}

	/// The overloaded `SessionNotReady` disambiguates by surface: a misrouted
	/// frame at the receive doors, a sequencing violation at the send doors.
	@Test func sessionNotReadyIsSurfaceDependent() {
		let misrouted: [PQErrorSurface] = [.processIncoming, .forwarded, .ingest]
		for surface in misrouted {
			let e = SessionError(pqError: TwoMlsPqError.SessionNotReady, at: surface)
			#expect(e.code == .misroutedFrame, "\(surface)")
		}
		let sequencing: [PQErrorSurface] = [.prepareToEncrypt, .encrypt, .pqOperation, .receive]
		for surface in sequencing {
			let e = SessionError(pqError: TwoMlsPqError.SessionNotReady, at: surface)
			#expect(e.code == .sequenceViolation, "\(surface)")
		}
	}

	/// Anything that isn't a TwoMlsPqError falls through to `.internalError`
	/// (this absorbs the fileprivate UniffiInternalError / rustPanic too).
	@Test func unknownErrorsAreInternal() {
		struct Weird: Error {}
		let e = SessionError(pqError: Weird(), at: .encrypt)
		#expect(e.code == .internalError)
		#expect(e.disposition == .fatal)
	}
}
