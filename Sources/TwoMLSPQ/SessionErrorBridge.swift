//
//  SessionError+TwoMLSPQBinding.swift
//  TwoMLSPQ
//
//  Total translation of the TwoMLSPQ backend's error families into the
//  abstract SessionError. This is the ONLY file allowed to name TwoMlsPqError;
//  every PQ wrapper method routes its throws through `mapPQErrors`.
//

import Foundation
import TwoMLSPQBinding

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
	/// The side-band entry point. `SessionNotReady` here is an ill-timed
	/// frame (v18 narrowed `DuplicateSideBand` to steps PROVABLY done, so
	/// merely ill-timed re-sends still surface as `SessionNotReady`) — mapped
	/// to `.misroutedFrame` so its disposition stays a frame-level discard
	/// rather than a caller bug; retention means the peer re-sends until
	/// answered, so discarding is lossless.
	case ingest
	case receive
	case decodeHeader
	case restore
	case installSink
	case invitation
	case client

	var sessionNotReadyCode: SessionError.Code {
		switch self {
		case .processIncoming, .forwarded, .ingest:
			return .misroutedFrame
		default:
			return .sequenceViolation
		}
	}
}

extension SessionError {
	/// Translate one backend error at a known surface. Exhaustive over every
	/// `TwoMlsPqError` case — a binding bump that adds a case fails compilation
	/// HERE (no `default`), which is part of the re-sync ritual (see the contract
	/// ladder in PQSession.swift). Everything else — including the fileprivate
	/// UniffiInternalError / rustPanic — falls through to `.internalError`.
	/// (The digest lift/strip helpers in PQDigest.swift throw `SessionError`
	/// directly, so they bypass this translation.)
	init(pqError error: any Error, at surface: PQErrorSurface) {
		switch error {
		case let pq as TwoMlsPqError:
			let code: Code
			// Most crate cases are self-describing via `code`; a few carry a
			// surface-aware `detail` because the SAME crate variant means
			// different things (and calls for different handling) depending on
			// which door threw it.
			var detail: String? = nil
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
			case .StaleFrame:
				code = .staleFrame
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
			case .BootstrapKpMismatch:
				code = .bootstrapKpMismatch
				switch surface {
				case .receive:
					// Establishment door: the commitment the host threaded in from
					// the signed AppWelcome is not a valid H(A.3 key package).
					detail = "bootstrap-KP commitment is not H(the initiator's PQ "
						+ "key package): a malformed or mis-read 32-byte value, or a "
						+ "tampered AppWelcome. The invitation is NOT consumed — "
						+ "re-read the commitment from the signed envelope and retry."
				default:
					// A.3 side-band: a KP′ that hashes to something other than the
					// commitment the signed envelope pinned.
					detail = "A.3 bootstrap key package (KP′) does not hash to the "
						+ "commitment the signed establishment envelope carried — a "
						+ "substituted or tampered KP′. Discard the frame; the genuine "
						+ "re-stapled KP′ still applies, session state untouched."
				}
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
			case .EstablishmentEnvelopeRequired:
				// Contract 26, dual meaning by surface (like BootstrapKpMismatch):
				switch surface {
				case .processIncoming, .forwarded:
					// Initiator: a bare welcome whose creator differs from the invitation
					// identity — a born-dedicated establishment must arrive enveloped.
					code = .establishmentEnvelopeRequired
					detail = "a born-dedicated establishment arrived un-enveloped (creator "
						+ "leaf differs from the invitation identity); refused so an "
						+ "undelegated credential cannot be admitted on the weld alone."
				default:
					// Acceptor: an emission door was driven before the signed delegation
					// was installed — a caller-sequencing bug.
					code = .sequenceViolation
					detail = "born-dedicated session is non-emittable until "
						+ "installEstablishmentEnvelope supplies the signed delegation; "
						+ "mint and install it before sending."
				}
			case .EstablishmentCreatorMismatch:
				code = .establishmentCreatorMismatch
				detail = "the admitted creator id does not match the welcome's creator leaf: "
					+ "the delegation is genuine but names a different key. The join was "
					+ "discarded whole; do not retry with the same admittedCreator."
			case .EstablishmentEnvelopeConflict:
				code = .establishmentEnvelopeConflict
				detail = "a different establishment envelope is already installed on this "
					+ "session; one session binds exactly one envelope."
			}
			self.init(code: code, underlying: pq, detail: detail)

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
) throws(SessionError) -> T {
	do {
		return try body()
	} catch let already as SessionError {
		throw already
	} catch {
		throw SessionError(pqError: error, at: surface)
	}
}
