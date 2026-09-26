import Foundation

// The randomized differential harness's operation DSL. A script is an ordered array of
// ops plus a fixed establishment topology; the harness replays it identically on both
// engines and compares the normalized outcomes. Kept deliberately small (see
// README.md, "Adding an op"): every op must be expressible through the API surface
// present in BOTH the deployed pin's binding and main's.

/// Which member of the pair an op addresses: `.a` is the initiator, `.b` the acceptor.
enum Role: String, Codable, CaseIterable, Sendable {
	case a
	case b

	var peer: Role { self == .a ? .b : .a }
}

/// How the pair is established. Chosen once per script, never an in-script op.
enum Topology: String, Codable, CaseIterable, Sendable {
	/// Plain §A.1 establishment: the acceptor joins under the invitation identity.
	case plain
	/// The acceptor is born under a dedicated client id and staples the `0x0B` handoff.
	case bornDedicated
}

/// One scripted operation. `index` fields address a lane position (0 = front); a
/// negative index counts from the back (-1 = newest), so a generator need not know the
/// lane length when it emits the op.
enum DiffOp: Codable, Equatable, Sendable {
	/// `prepareToEncrypt` + `encrypt` on `role`, enqueuing the frame toward the peer.
	/// `rotate` proposes a fresh client id in the same call (rotation is a parameter on
	/// both engines, never a separate op).
	case send(role: Role, payload: String, rotate: Bool)
	/// Like `send`, but proposes a rotation even when frames are in flight toward the peer —
	/// the only way to offer a SECOND authorization change mid-double-commit-window (a plain
	/// Update folds without committing once the peer's leaf is already canonical). Still
	/// gated on `!hasPendingRotation()`, so it never manufactures a `.rotationInFlight`
	/// differential.
	case sendRotating(role: Role, payload: String)
	/// Fold the oldest outstanding remote proposal the peer offered to `role`.
	case queueProposal(role: Role)
	/// Deliver the `index`-th queued frame awaiting `role` from its peer.
	case deliver(role: Role, index: Int)
	/// Drain every queued frame awaiting `role`, in order.
	case deliverAll(role: Role)
	/// Drop (discard) the `index`-th queued frame awaiting `role`.
	case drop(role: Role, index: Int)
	/// Duplicate the `index`-th queued frame awaiting `role` (a re-delivery fault).
	case duplicate(role: Role, index: Int)
	/// Move the `index`-th queued frame awaiting `role` to position `to`.
	case reorder(role: Role, index: Int, to: Int)
	/// Hand out `role`'s outstanding side-band leg into the side-band lane toward the peer.
	case handOutSideBand(role: Role)
	/// Deliver the `index`-th queued side-band leg awaiting `role`.
	case deliverSideBand(role: Role, index: Int)
	/// Discard the session and restore it to a legal recorded checkpoint. `depth` is how
	/// many checkpoints back from the latest legal one to go (0 = latest, 1 = one back …),
	/// so a script reaches intermediate legal points (peer-away windows) without knowing
	/// seqs at generation time. The runner's legality gate picks only points at/above every
	/// delivered frame's `dependsOnSeq`.
	case crashAndRestore(role: Role, depth: UInt64)
	/// Restore to a point BEHIND already-delivered state — a negative test whose
	/// expectation is clean classification (stale/epochDesync/re-establish), never a
	/// misparse or a brick. `depth` is ignored; the runner picks the furthest checkpoint
	/// below the delivered watermark.
	case restoreBehindDelivery(role: Role, depth: UInt64)
	/// Quiescence check: drain both lanes, then one round-trip both directions.
	case probe

	var role: Role? {
		switch self {
		case .send(let r, _, _), .sendRotating(let r, _), .queueProposal(let r),
			.deliver(let r, _),
			.deliverAll(let r), .drop(let r, _), .duplicate(let r, _),
			.reorder(let r, _, _), .handOutSideBand(let r), .deliverSideBand(let r, _),
			.crashAndRestore(let r, _), .restoreBehindDelivery(let r, _):
			return r
		case .probe:
			return nil
		}
	}
}

/// A complete scenario: a topology plus the op script.
struct DiffScript: Codable, Equatable, Sendable {
	var topology: Topology
	var ops: [DiffOp]

	/// The compact replay blob a failure prints. JSON, stable field order.
	func encodedBlob() -> String {
		let encoder = JSONEncoder()
		encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
		// The script is fully Codable with no throwing shapes; a failure here is a bug.
		return String(decoding: try! encoder.encode(self), as: UTF8.self)
	}

	static func decoded(fromBlob blob: String) throws -> DiffScript {
		try JSONDecoder().decode(DiffScript.self, from: Data(blob.utf8))
	}
}

/// The repro line for a failing seed: seed + op-script blob + binding contract version
/// + pin sha, so any run replays against exactly the same Rust.
struct ReproLine: CustomStringConvertible {
	let seed: UInt64
	let blob: String
	let bindingContractVersion: UInt64
	let rustSha: String

	var description: String {
		"Differential repro:\n  seed=\(seed)\n  contract=\(bindingContractVersion)"
			+ " rustSha=\(rustSha)\n  script=\(blob)"
	}
}

/// SplitMix64 — a small, dependency-free, fully deterministic PRNG. Not cryptographic:
/// only the op-script generation is seeded; the engines' own key generation and ML-KEM
/// stay live, so comparison is semantic, never byte-level.
struct SplitMix64: RandomNumberGenerator {
	private var state: UInt64

	init(seed: UInt64) { self.state = seed }

	mutating func next() -> UInt64 {
		state &+= 0x9E37_79B9_7F4A_7C15
		var z = state
		z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
		z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
		return z ^ (z >> 31)
	}
}
