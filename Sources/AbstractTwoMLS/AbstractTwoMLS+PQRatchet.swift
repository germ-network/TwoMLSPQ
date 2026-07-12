//
//  AbstractTwoMLS+PQRatchet.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/23/26.
//
//  The PQ side-band state machine for the AbstractTwoMLS family, aligned with
//  docs/08-twoMLSPQ-APQ.md Appendix A.
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

	/// A received-and-applied PQ message and its effects.
	public struct PQInbound: Sendable {
		public let kind: PQOperationKind
		public let advancedGroup: SendGroupRole
		/// This side's SEND group epoch pair after the apply (nil when nothing
		/// moved). NOTE: when `advancedGroup == .theirs` the group that advanced
		/// is the peer's — this field still reports our own send group's pair,
		/// which is unchanged by such an apply. It answers "what are MY epochs
		/// now", not "what did the advanced group move to".
		public let newEpochs: APQEpochs?
		public let rotatedCredential: ClientID?  // A.4/A.5 principal handoff
		/// The app message stapled onto an A.3 bind, decrypted while applying it.
		/// Always nil through this backend today: `ingest` applies binds with an
		/// empty payload and `begin(.ratchet)` offers no way to supply one — the
		/// crate supports the stapled A.3 app message, but the wrapper does not
		/// yet expose sending it (deliberate follow-up).
		public let plaintext: Data?

		public init(
			kind: PQOperationKind,
			advancedGroup: SendGroupRole,
			newEpochs: APQEpochs?,
			rotatedCredential: ClientID?,
			plaintext: Data? = nil
		) {
			self.kind = kind
			self.advancedGroup = advancedGroup
			self.newEpochs = newEpochs
			self.rotatedCredential = rotatedCredential
			self.plaintext = plaintext
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
	// Sendable is sound (the wrapped uniffi `TwoMlsPqSession` is `@unchecked Sendable`:
	// Rust Send+Sync, FFI calls lock-serialized) — but it buys memory safety, not ordering.
	// The begin → ingest → advance ratchet has one parked reply slot: drive it sequentially.
	public protocol PQRatchet: Sendable {
		var turn: PQTurn { get }
		var epochs: APQEpochs { get }
		/// True once both send groups are full APQ pairs (post-A.4).
		var isFullyEstablished: Bool { get }

		// --- Initiator (we hold the turn) ---
		/// First outbound of the operation we owe: EK for `.ratchet`,
		/// KP' for `.finishBootstrap`, Upd' for `.rekey`. `rotating` carries a
		/// new credential for the A.4/A.5 handoff.
		func begin(_ kind: PQOperationKind, rotating: ClientID?) throws -> PQOutbound

		/// Drive the next step once the peer's reply has been ingested (e.g.
		/// produce the stapled bind commit after receiving CT in A.3). Returns
		/// nil when the operation is complete and the turn has flipped.
		func advance(after inbound: PQInbound) throws -> PQOutbound?

		// --- Responder (peer holds the turn) ---
		/// Apply a whole received PQ message.
		func ingest(_ message: Data) throws -> PQInbound
	}
}
