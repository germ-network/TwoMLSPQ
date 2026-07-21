//
//  PQRatchetTypes.swift
//  TwoMLSPQ
//
//  The value types the PQ side-band surface exchanges, aligned with the book's Protocol Flows
//  chapter, Appendix A. (The `PQRatchet`/`PQRatchetingSession` PROTOCOLS live in the
//  `AbstractTwoMLS` package; these are the concrete payload/effect types they reference.)
//
//  PQ messages are whole `Data` here; chunking and reassembly are the transport's job.
//

import Foundation

/// The two epochs APQInfo tracks. Replaces the single `EncryptResult.epoch`, which couldn't
/// say which epoch it meant.
public struct APQEpochs: Sendable, Equatable {
	public var pqEpoch: UInt64  // pq_epoch
	public var classicalEpoch: UInt64  // t_epoch

	public init(pqEpoch: UInt64, classicalEpoch: UInt64) {
		self.pqEpoch = pqEpoch
		self.classicalEpoch = classicalEpoch
	}
}

/// Which APQ send group an operation runs on, relative to self. `ours` = ASG (we commit),
/// `theirs` = BSG (we only propose into).
public enum SendGroupRole: Sendable, Equatable { case ours, theirs }

/// Whose move it is for the next PQ operation. The diagram's flip-flop made explicit.
public enum PQTurn: Sendable, Equatable { case weInitiate, theyInitiate }

/// Disambiguates the three PQ flows, which the old `received(pqProposal:)`/`received(pqCommit:)`
/// pair collapsed together.
public enum PQOperationKind: Sendable, Equatable {
	case ratchet  // A.4 — KEM EK/CT, PSK injection, no updatePath, staple-able
	case finishBootstrap  // A.3 — stand up the deferred ASG-PQ
	case rekey  // A.5 — updatePath commit (+ credential rotation), isolated
}

/// An outbound PQ payload. Whole bytes — chunking is the transport's job.
public struct PQOutbound: Sendable {
	public let kind: PQOperationKind
	public let payload: Data

	public init(kind: PQOperationKind, payload: Data) {
		self.kind = kind
		self.payload = payload
	}
}

/// How a retained side-band frame is sealed per hand-out (v18 retention). `.fresh` re-seals
/// every time — repeated sends of one retained frame are distinct on the wire, so a stalled
/// round's re-sends cannot be correlated. `.stable` seals once and repeats the bytes while the
/// frame is unchanged, which CHUNKING requires: chunks cut from two different seals never
/// reassemble.
///
/// The correlation-vs-chunking trade is even, but `.stable` also carries a LIVENESS bound
/// `.fresh` does not: the cached seal keeps the epoch it was first sealed at. That is roomy for
/// PQ-sealed frames (the key advances only when the peer commits), but the one frame sealed under
/// the CLASSICAL fallback key — the pre-A.3 `BOOTSTRAP_KP`, whose epoch ordinary messaging
/// advances — must complete its `.stable` pass inside the peer's classical header window, or the
/// reassembled frame opens for no key and re-handing the same bytes never heals.
public enum SideBandSealing: Sendable, Equatable {
	case fresh
	case stable
}

/// A received-and-applied PQ message and its effects.
public struct PQInbound: Sendable {
	public let kind: PQOperationKind
	/// The round's TARGET group — the one this operation exists to move. NOTE this can
	/// under-describe a closing leg: `.rekeyCommit` reports `.theirs` (the peer's group was
	/// re-keyed) even though applying it ALSO partial-commits our own send-PQ eagerly (the ACK's
	/// PQ half). `newEpochs` and `owesBind` carry that; do not dispatch own-group work off this
	/// field alone.
	public let advancedGroup: SendGroupRole
	/// This side's SEND group epoch pair after the apply (nil when nothing of ours moved). It
	/// answers "what are MY epochs now", not "what did the advanced group move to" — and on a
	/// closing leg our own pq half HAS moved even when `advancedGroup == .theirs` (see above).
	public let newEpochs: APQEpochs?
	public let rotatedCredential: ClientID?  // A.3/A.5 principal handoff
	/// TRUE on every closing leg (`.bootstrapWelcome`, `.ratchetCiphertext`, `.rekeyCommit`
	/// ingests): our send-PQ committed eagerly and the classical half is now OWED — it discharges
	/// only inside our next classical COMMIT (v19: which a current-epoch peer offer licenses). The
	/// host MUST eventually drive a committing send; an idle session never discharges, the peer
	/// re-sends its last frame forever (each one a `.duplicateSideBand` discard), and the turn
	/// never flips. This flag is the moment to arrange that send. It is transient — nothing
	/// re-exposes it after a restore (the crate offers no owed-bind query yet), so act on it or
	/// record it.
	public let owesBind: Bool

	public init(
		kind: PQOperationKind,
		advancedGroup: SendGroupRole,
		newEpochs: APQEpochs?,
		rotatedCredential: ClientID?,
		owesBind: Bool = false
	) {
		self.kind = kind
		self.advancedGroup = advancedGroup
		self.newEpochs = newEpochs
		self.rotatedCredential = rotatedCredential
		self.owesBind = owesBind
	}
}
