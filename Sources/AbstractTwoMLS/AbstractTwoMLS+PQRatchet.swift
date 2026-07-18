//
//  AbstractTwoMLS+PQRatchet.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/23/26.
//
//  The PQ side-band state machine for the AbstractTwoMLS family, aligned with
//  the TwoMLSPQ book's Protocol Flows chapter, Appendix A.
//
//  PQ messages are whole `Data` here; chunking and reassembly are the
//  transport's job, below this layer.
//

import CommProtocol
import Foundation

extension AbstractTwoMLS {

	// MARK: - Shared value types

	/// The two epochs APQInfo tracks. Replaces the single `EncryptResult.epoch`,
	/// which couldn't say which epoch it meant.
	public struct APQEpochs: Sendable, Equatable {
		public var pqEpoch: UInt64  // pq_epoch
		public var classicalEpoch: UInt64  // t_epoch

		public init(pqEpoch: UInt64, classicalEpoch: UInt64) {
			self.pqEpoch = pqEpoch
			self.classicalEpoch = classicalEpoch
		}
	}

	/// Which APQ send group an operation runs on, relative to self.
	/// `ours` = ASG (we commit), `theirs` = BSG (we only propose into).
	public enum SendGroupRole: Sendable, Equatable { case ours, theirs }

	/// Whose move it is for the next PQ operation. The diagram's flip-flop
	/// ("turn flips when each direction finishes receiving") made explicit.
	public enum PQTurn: Sendable, Equatable { case weInitiate, theyInitiate }

	/// Disambiguates the three PQ flows, which the old
	/// `received(pqProposal:)` / `received(pqCommit:)` pair collapsed together.
	public enum PQOperationKind: Sendable, Equatable {
		case ratchet  // A.3 — KEM EK/CT, PSK injection, no updatePath, staple-able
		case finishBootstrap  // A.4 — stand up the deferred ASG-PQ
		case rekey  // A.5 — updatePath commit (+ credential rotation), isolated
	}

	// MARK: - PQ messages

	/// An outbound PQ payload. Whole bytes — chunking is the transport's job.
	public struct PQOutbound: Sendable {
		public let kind: PQOperationKind
		public let payload: Data

		public init(kind: PQOperationKind, payload: Data) {
			self.kind = kind
			self.payload = payload
		}
	}

	/// How a retained side-band frame is sealed per hand-out (v18 retention).
	/// `.fresh` re-seals every time — repeated sends of one retained frame are
	/// distinct on the wire, so a stalled round's re-sends cannot be correlated.
	/// `.stable` seals once and repeats the bytes while the frame is unchanged,
	/// which CHUNKING requires: chunks cut from two different seals never
	/// reassemble.
	///
	/// The correlation-vs-chunking trade is even, but `.stable` also carries a
	/// LIVENESS bound `.fresh` does not: the cached seal keeps the epoch it was
	/// first sealed at. That is roomy for PQ-sealed frames (the key advances
	/// only when the peer commits), but the one frame sealed under the
	/// CLASSICAL fallback key — the pre-A.4 `BOOTSTRAP_KP`, whose epoch
	/// ordinary messaging advances — must complete its `.stable` pass inside
	/// the peer's classical header window, or the reassembled frame opens for
	/// no key and re-handing the same bytes never heals. A chunking transport
	/// should pause classical sends across a `.stable` pass over the KP', or
	/// use `.fresh` for it and chunk only steady-state frames.
	public enum SideBandSealing: Sendable, Equatable {
		case fresh
		case stable
	}

	/// A received-and-applied PQ message and its effects.
	public struct PQInbound: Sendable {
		public let kind: PQOperationKind
		/// The round's TARGET group — the one this operation exists to move.
		/// NOTE this can under-describe a closing leg: `.rekeyCommit` reports
		/// `.theirs` (the peer's group was re-keyed) even though applying it
		/// ALSO partial-commits our own send-PQ eagerly (the ACK's PQ half).
		/// `newEpochs` and `owesBind` carry that; do not dispatch own-group
		/// work off this field alone.
		public let advancedGroup: SendGroupRole
		/// This side's SEND group epoch pair after the apply (nil when nothing
		/// of ours moved). It answers "what are MY epochs now", not "what did
		/// the advanced group move to" — and on a closing leg our own pq half
		/// HAS moved even when `advancedGroup == .theirs` (see above).
		public let newEpochs: APQEpochs?
		public let rotatedCredential: ClientID?  // A.4/A.5 principal handoff
		/// TRUE on every closing leg (`.bootstrapWelcome`, `.ratchetCiphertext`,
		/// `.rekeyCommit` ingests): our send-PQ committed eagerly and the
		/// classical half is now OWED — it discharges only inside our next
		/// classical COMMIT (v19: which a current-epoch peer offer licenses).
		/// The host MUST eventually drive a committing send; an idle session
		/// never discharges, the peer re-sends its last frame forever (each one
		/// a `.duplicateSideBand` discard), and the turn never flips. This flag
		/// is the moment to arrange that send. It is transient — nothing
		/// re-exposes it after a restore (the crate offers no owed-bind query
		/// yet), so act on it or record it.
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

	// MARK: - PQ-capable session

	/// A `Session` that additionally drives the PQ side-band. Kept separate from
	/// `Session` so non-PQ implementations (e.g. the classical backend) need not
	/// provide a `pqRatchet`.
	public protocol PQRatchetingSession: Session, PQRatchet {}

	// MARK: - PQ ratchet state machine

	/// Explicit initiator/responder flow for the PQ side-band, replacing
	/// currentPQInflight() / received(pqProposal:) / received(pqCommit:).
	// Deliberately NOT Sendable: a session is a single-driver state machine
	// (one parked reply slot, one pending-proposal slot), and while the wrapped
	// uniffi object is lock-serialized (memory-safe), concurrent drivers can
	// interleave silently — a second prepareToEncrypt replaces the staged
	// proposal with no signal to the first, and racing advance/ingest can
	// mislabel a parked frame. Withholding Sendable makes the compiler refuse
	// to move a session across task boundaries; the CONTAINING type (typically
	// an actor that owns the session and serializes all driving) asserts its
	// own Sendable conformance instead.
	public protocol PQRatchet {
		var turn: PQTurn { get }
		var epochs: APQEpochs { get }
		/// True once both send groups are full APQ pairs (post-A.4).
		var isFullyEstablished: Bool { get }

		// --- Initiator (we hold the turn) ---
		/// First outbound of the operation we owe: EK for `.ratchet`,
		/// KP' for `.finishBootstrap`, Upd' for `.rekey`. `rotating` carries a
		/// new credential for the A.4/A.5 handoff.
		func begin(_ kind: PQOperationKind, rotating: ClientID?) throws -> PQOutbound

		/// The Part 3 parallel A.4 delivery: this initiator's pre-committed KP′
		/// sealed as a §A.1 bootstrap envelope, to ship ALONGSIDE the establishment
		/// reply — the acceptor is already reading the invitation channel, so it can
		/// answer A.4 (and staple `Welcome'` onto its return welcome) one round trip
		/// sooner than waiting for the side-band. `nil` when there is nothing to ship:
		/// an acceptor session, a session already past establishment, or a backend
		/// without A.4. `begin(.finishBootstrap)` stays valid and idempotent afterward
		/// — both carry the SAME pre-committed KP′, only the outer framing differs — so
		/// keeping the steady-state side-band kickoff alongside this is safe. Read any
		/// bootstrap-KP commitment BEFORE calling: the first call registers the A.4
		/// round and consumes the KP (re-calls re-seal the same frame, fresh HPKE).
		func bootstrapEnvelope() throws -> Data?

		/// Hand out the reply a responding `ingest` parked (CT after an EK,
		/// Welcome' after a KP', Commit' after an Upd'), CONSUMING it — the
		/// retained copy included, so a re-staple driver should prefer
		/// `pendingSideBand(sealing:)`. Returns nil when nothing is parked —
		/// which is every closing leg: the bind rides the next classical commit
		/// as the message-frame staple rather than parking here (`inbound
		/// .owesBind` is the explicit signal). Cannot fail; the take is a pure
		/// read-and-clear.
		func advance(after inbound: PQInbound) -> PQOutbound?

		/// The retained side-band frame, sealed, WITHOUT consuming it — the
		/// re-send path (v18 retention). Safe to call on every send; advances no
		/// protocol state.
		func pendingSideBand(sealing: SideBandSealing) -> Data?

		/// Whether receiving is poisoned by a peer bind staple that failed after
		/// its round's secret was consumed (`.bindApplyFailed` on every further
		/// receive; sending unaffected; healed by restoring the last persisted
		/// state). A query so the host can decide urgency by role.
		var isReceiveBroken: Bool { get }

		// --- Responder (peer holds the turn) ---
		/// Apply a whole received PQ message.
		func ingest(_ message: Data) throws -> PQInbound
	}
}
