//
//  SessionError+TwoMLSPQ.swift
//  AbstractTwoMLS
//
//  Total translation of the TwoMLSPQ backend's error families into the
//  abstract SessionError. This is the ONLY file allowed to name TwoMlsPqError;
//  every PQ wrapper method routes its throws through `mapPQErrors`.
//

import CommProtocol
import Foundation
import TwoMLSPQ

/// The wrapper surface an error escaped from — disambiguates the crate's
/// overloaded `SessionNotReady`, which means "you misrouted a frame" at the
/// receive entry points and "you called out of sequence" at the send/PQ ones.
enum PQErrorSurface {
	/// Receive entry points: a `SessionNotReady` here is a side-band frame fed
	/// to the wrong door (the crate's documented invariant).
	case processIncoming
	case forwarded
	/// Send / PQ-operation entry points: `SessionNotReady` is a turn/order
	/// violation.
	case prepareToEncrypt
	case encrypt
	case pqOperation
	/// Entry points where `SessionNotReady` is not expected; treat it as a
	/// sequencing violation (the honest fallback).
	case ingest
	case receive
	case decodeHeader
	case restore
	case installSink
	case invitation
	case client

	var sessionNotReadyCode: AbstractTwoMLS.SessionError.Code {
		switch self {
		case .processIncoming, .forwarded, .ingest:
			return .misroutedFrame
		default:
			return .sequenceViolation
		}
	}
}

extension AbstractTwoMLS.SessionError {
	/// Translate one backend error at a known surface. Exhaustive over
	/// `TwoMlsPqError`'s 25 cases — a binding bump that adds a case fails
	/// compilation HERE, which is part of the re-sync ritual (see the contract
	/// ladder in AbstractTwoMLS+TwoMLSPQ.swift). LinearEncodingError (from the
	/// digest lifts) and everything else — including the fileprivate
	/// UniffiInternalError / rustPanic — fall through to `.internalError`.
	init(pqError error: any Error, at surface: PQErrorSurface) {
		switch error {
		case let pq as TwoMlsPqError:
			let code: Code
			switch pq {
			case .Mls, .PskBinding:
				code = .internalError
			case .InvalidKeyPackage:
				code = .invalidKeyPackage
			case .MissingWelcome:
				code = .missingWelcome
			case .PqNotAvailable:
				code = .pqUnavailable
			case .SessionNotEstablished:
				code = .sessionNotEstablished
			case .SessionNotReady:
				code = surface.sessionNotReadyCode
			case .ProposalRejected:
				code = .proposalRejected
			case .DecryptionFailed:
				code = .decryptionFailed
			case .ArchiveInvalid:
				code = .archiveInvalid
			case .DuplicateWelcome:
				code = .duplicateWelcome
			case .InvitationSpent:
				code = .invitationSpent
			case .UnsupportedCipherSuite:
				code = .unsupportedCipherSuite
			case .CipherSuiteMismatch:
				code = .cipherSuiteMismatch
			case .EpochDesync:
				code = .epochDesync
			case .UnexpectedWelcome:
				code = .unexpectedWelcome
			case .InvalidClientId:
				code = .invalidClientId
			case .RemoteIdentityMismatch:
				code = .identityMismatch
			case .CredentialRejected:
				code = .credentialRejected
			case .ApqInfoMismatch:
				code = .apqInfoMismatch
			case .SinkAlreadyInstalled:
				code = .sinkAlreadyInstalled
			case .AppBindingMismatch:
				code = .appBindingMismatch
			case .DuplicateSideBand:
				code = .duplicateSideBand
			case .BindApplyFailed:
				code = .bindApplyFailed
			case .BindDischargeFailed:
				code = .bindDischargeFailed
			}
			self.init(code: code, underlying: pq)

		case let encoding as LinearEncodingError:
			self.init(
				code: .internalError, underlying: encoding,
				detail: "FFI digest/id convention violation (\(encoding))")

		default:
			self.init(
				code: .internalError, underlying: error,
				detail: "opaque backend failure at \(surface) — "
					+ "discard the session object, do not persist")
		}
	}
}

/// The choke point every throwing PQ wrapper member routes through: run the
/// body, and translate anything it throws (that isn't already a SessionError)
/// at this surface. Typed `throws(SessionError)` so the compiler proves the
/// translation is total.
func mapPQErrors<T>(
	_ surface: PQErrorSurface,
	_ body: () throws -> T
) throws(AbstractTwoMLS.SessionError) -> T {
	do {
		return try body()
	} catch let already as AbstractTwoMLS.SessionError {
		throw already
	} catch {
		throw AbstractTwoMLS.SessionError(pqError: error, at: surface)
	}
}
