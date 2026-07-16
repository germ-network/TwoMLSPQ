//
//  SessionError.swift
//  AbstractTwoMLS
//
//  The single error type the abstract surface throws. Every conformance
//  translates its backend's errors into one of these; NO backend error type
//  (TwoMlsPqError, MlSrsError, uniffi internals, …) crosses the boundary.
//  Discriminate on `code` / `disposition` — never on `underlying`.
//

import Foundation

extension AbstractTwoMLS {

	public struct SessionError: Error, Sendable {

		/// What the app should DO about the error — the recovery axis. Derived
		/// from `code`; drive your recovery loop off this, use `code` for UI /
		/// telemetry / precise handling.
		public enum Disposition: Sendable, Equatable, Hashable {
			/// Transient: redelivery or reordering heals it. Retry.
			case retryLater
			/// Drop this frame; the session/invitation is unaffected. (See
			/// `.unopenableFrame` for the reconnect-run heuristic.)
			case discardFrame
			/// The direction is desynced past self-healing — run the reconnect
			/// path (re-establish the send/receive pairing).
			case reconnect
			/// A peer credential needs authorizing: approve the fresh proposal
			/// (`queueProposal`) and reprocess — the staple re-rides.
			case approveAndReprocess
			/// The object (invitation / persisted blobs) is spent or unusable;
			/// discard it and regenerate / re-establish.
			case discardArtifact
			/// Refuse this establishment (identity / capability / downgrade).
			/// The invitation is NOT consumed on `.identityMismatch` — retry
			/// with the correct peer is possible.
			case rejectEstablishment
			/// A contract misuse at the call site (sequencing, empty id, double
			/// install, …). Fix the caller; not runtime-recoverable.
			case callerBug
			/// Opaque / internal failure. Discard the live session object — do
			/// NOT persist or archive it; its state may be inconsistent.
			case fatal
		}

		public enum Code: Sendable, Equatable, Hashable {
			/// Transient decrypt failure (a frame overtook its A.3 bind, or a
			/// replay/tamper) — redelivery heals it.
			case decryptionFailed
			/// A duplicate or already-consumed frame from a string-only backend
			/// (reserved for the deprecated classical shim's consumed-key
			/// substrings; no PQ path emits it).
			case staleFrame
			/// A different welcome for an already-joined receive group — a
			/// benign per-remote replay guard. Nothing to do.
			case duplicateWelcome
			/// A side-band frame for a step this session already took. Retention
			/// (v18) makes these steady-state traffic — the peer re-sends its
			/// frame until our answer lands — so a duplicate is a discard, never
			/// a routing signal. Nothing to do.
			case duplicateSideBand
			/// A header frame that no receive-window key opens. One alone may be
			/// a stranger's garbage; treat a RUN of these on a live session as a
			/// reconnect signal (count them at the call site).
			case unopenableFrame
			/// A structurally malformed frame (truncated header, bad length).
			case malformedFrame
			/// A stapled commit is ahead of the receive group — reconnect.
			case epochDesync
			/// A peer bind staple failed to apply AFTER the round's secret was
			/// consumed: receiving is poisoned (every further processIncoming
			/// refuses; the peer re-staples the same unappliable bind), while
			/// SENDING is unaffected. Not reachable from an honest peer. Healed
			/// by restoring the last persisted state — poll `isReceiveBroken`
			/// to decide urgency by role (receive-critical: now; send-mostly:
			/// deferred).
			case bindApplyFailed
			/// Our own owed bind failed mid-commit after its reservation was
			/// consumed: the exporter leaf is spent, no retry can rebuild the
			/// round, and the peer waits in its responded state forever. Not
			/// reachable from any honest flow (it takes an internal MLS failure
			/// mid-commit). The session's PQ binding is permanently broken —
			/// route to re-establishment.
			case bindDischargeFailed
			/// The AS rejected a credential succession — authorize the fresh
			/// proposal (`queueProposal`) and reprocess.
			case credentialRejected
			/// A single-use invitation is spent. Discard it (use last-resort).
			case invitationSpent
			/// Persisted blobs are corrupt / incompatible (version or PQ-epoch
			/// manifest mismatch). Discard and re-establish; regenerate state.
			case archiveInvalid
			/// The remote key package's credential doesn't match the
			/// authenticated identity. The invitation is NOT consumed.
			case identityMismatch
			/// The peer's combiner key package carries no PQ half.
			case pqUnavailable
			/// The peer's cipher-suite pair is not the pinned one.
			case cipherSuiteMismatch
			/// A key package failed to parse / bind.
			case invalidKeyPackage
			/// Missing or inconsistent APQInfo — a welcome without one is a
			/// downgrade attempt.
			case apqInfoMismatch
			/// The welcome's app-state binding does not match the caller's stated
			/// expectation (wrong relationship, or a strip/downgrade attempt). The
			/// invitation is NOT consumed — retry with the right expectation works.
			case appBindingMismatch
			/// A different welcome on a live session — a mis-route or unexpected
			/// re-invite (same-welcome re-deliveries are idempotent, not this).
			case unexpectedWelcome
			/// A side-band frame reached `processIncoming`/`forwarded`, or vice
			/// versa — a routing bug at the call site.
			case misroutedFrame
			/// An operation was driven out of turn / order (encrypt before
			/// prepare, begin off-turn, …).
			case sequenceViolation
			/// A PQ side-band operation requires a fully-established session.
			case sessionNotEstablished
			/// An empty / invalid principal client id was supplied.
			case invalidClientId
			/// The app declined a proposal.
			case proposalRejected
			/// A rotation was asked to ride the A.3 ratchet, which has no
			/// updatePath to carry a credential (use `.rekey`/`.finishBootstrap`).
			case rotationCannotRideRatchet
			/// The crypto provider can't back the required suite — a build /
			/// provider-config bug, never a healthy-runtime condition.
			case unsupportedCipherSuite
			/// A welcome was expected but absent.
			case missingWelcome
			/// A persistence sink was installed twice (the second orphans the
			/// first). Install once, right after construction/restore.
			case sinkAlreadyInstalled
			/// No backend surface implements this member yet.
			case notImplemented
			/// Opaque / internal failure: an MLS protocol error, a PSK-binding
			/// failure, an FFI decode error, or a Rust panic. Discard the
			/// session object; do not persist it.
			case internalError

			public var disposition: Disposition {
				switch self {
				case .decryptionFailed:
					return .retryLater
				case .staleFrame, .duplicateWelcome, .duplicateSideBand,
					.unopenableFrame, .malformedFrame:
					return .discardFrame
				case .epochDesync, .bindApplyFailed, .bindDischargeFailed:
					return .reconnect
				case .credentialRejected:
					return .approveAndReprocess
				case .invitationSpent, .archiveInvalid:
					return .discardArtifact
				case .identityMismatch, .pqUnavailable, .cipherSuiteMismatch,
					.invalidKeyPackage, .apqInfoMismatch, .appBindingMismatch,
					.unexpectedWelcome:
					return .rejectEstablishment
				case .misroutedFrame, .sequenceViolation, .sessionNotEstablished,
					.invalidClientId, .proposalRejected, .rotationCannotRideRatchet,
					.unsupportedCipherSuite, .missingWelcome, .sinkAlreadyInstalled,
					.notImplemented:
					return .callerBug
				case .internalError:
					return .fatal
				}
			}
		}

		public let code: Code
		/// The backend's original error, for diagnostics only — NEVER
		/// discriminate on it (that defeats the abstraction).
		public let underlying: (any Error)?
		public let detail: String?

		public var disposition: Disposition { code.disposition }

		public init(code: Code, underlying: (any Error)? = nil, detail: String? = nil) {
			self.code = code
			self.underlying = underlying
			self.detail = detail
		}
	}
}

extension AbstractTwoMLS.SessionError: LocalizedError, CustomStringConvertible {
	public var description: String {
		var s = "SessionError(\(code)/\(disposition))"
		if let detail { s += ": \(detail)" }
		if let underlying { s += " | underlying: \(underlying)" }
		return s
	}

	public var errorDescription: String? { description }
}
