//
//  ErrorContractTests.swift
//  TwoMLSPQ
//
//  Pins the SessionError contract: the abstract surface throws ONE type; every
//  backend error maps to a stable code with the documented disposition; and the
//  translation is total over every TwoMlsPqError case (a binding bump that
//  adds a case fails compilation in SessionErrorBridge.swift, and this
//  totality test catches a silent remapping of an existing one). The two
//  surface-DEPENDENT cases (SessionNotReady, EstablishmentEnvelopeRequired)
//  are pinned per-surface below.
//

import Foundation
import Testing

import TwoMLSPQBinding  // public TwoMlsPqError cases

@testable import TwoMLSPQ  // internal SessionError(pqError:at:) + PQErrorSurface

struct ErrorContractTests {

	// MARK: Code -> Disposition table (a data pin, kept in sync by the totality
	// test below — the compiler forces the mapping in SessionError.swift; this
	// table catches a silent re-disposition)

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
			(.bootstrapKpMismatch, .discardFrame),
			(.establishmentEnvelopeRequired, .rejectEstablishment),
			(.establishmentCreatorMismatch, .rejectEstablishment),
			(.establishmentEnvelopeConflict, .callerBug),
			(.internalError, .fatal),
		]
		for (code, disposition) in table {
			#expect(code.disposition == disposition, "\(code) -> \(code.disposition)")
		}
	}

	// MARK: Totality over the TwoMlsPqError cases

	/// Every crate case, mapped at a neutral surface. `SessionNotReady` and
	/// `EstablishmentEnvelopeRequired` are surface-dependent and covered
	/// separately below.
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
			(.DuplicateSideBand, .duplicateSideBand),
			(.BindApplyFailed, .bindApplyFailed),
			(.BindDischargeFailed, .bindDischargeFailed),
			(.BootstrapKpMismatch, .bootstrapKpMismatch),
			(.EstablishmentCreatorMismatch, .establishmentCreatorMismatch),
			(.EstablishmentEnvelopeConflict, .establishmentEnvelopeConflict),
			(.StaleFrame, .staleFrame),
		]
		// + the two per-surface cases (SessionNotReady,
		// EstablishmentEnvelopeRequired) = all 30 crate cases
		#expect(expected.count == 28)
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

	/// Contract 26: `EstablishmentEnvelopeRequired` is likewise surface-dependent —
	/// at the receive doors it is the INITIATOR refusing an un-enveloped
	/// born-dedicated welcome (a peer-side establishment rejection); everywhere
	/// else it is the ACCEPTOR driven before installing its delegation (a
	/// caller-sequencing bug).
	@Test func establishmentEnvelopeRequiredIsSurfaceDependent() {
		for surface in [PQErrorSurface.processIncoming, .forwarded] {
			let e = SessionError(
				pqError: TwoMlsPqError.EstablishmentEnvelopeRequired, at: surface)
			#expect(e.code == .establishmentEnvelopeRequired, "\(surface)")
			#expect(e.disposition == .rejectEstablishment)
		}
		for surface in [PQErrorSurface.receive, .prepareToEncrypt, .encrypt, .pqOperation] {
			let e = SessionError(
				pqError: TwoMlsPqError.EstablishmentEnvelopeRequired, at: surface)
			#expect(e.code == .sequenceViolation, "\(surface)")
			#expect(e.disposition == .callerBug)
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
