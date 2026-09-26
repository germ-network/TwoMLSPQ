import Foundation

// The engine-external delivery scheduler. Frames produced by either engine sit here until
// a `deliver` op routes them to the peer; drop/duplicate/reorder mutate these lanes. Two
// lanes per direction: the main message path and the side-band path (A.3/A.4/A.5 legs),
// which is where the engines' "retain and re-mint" behavior lives.

struct FrameRecord: Sendable {
	let bytes: Data
	let from: Role
	let opIndex: Int
	/// The emitting state-advancing call's durability seq — the earliest restore point
	/// that can still receive this frame.
	let dependsOnSeq: UInt64
	/// Whether the emitting `prepareToEncrypt` reported a commit.
	let isCommit: Bool
	/// The sender's group epoch at emission (classical send epoch).
	let epoch: UInt64
}

struct SideBandLeg: Sendable {
	let bytes: Data
	let from: Role
	let opIndex: Int
}

/// A proposal a peer surfaced to `role`, with the full shape needed to decide whether it is
/// still foldable (its `context` must equal the folder's current `proposalContext()`).
struct OfferRecord: Sendable, Equatable {
	let digest: Data
	let proposing: Data?
	let context: Data?
	let sender: Data?
	let isCatchUp: Bool?
	/// The op that surfaced it, and the folder's send epoch at surface time.
	let offeredAtOp: Int
	let offeredAtSendEpoch: UInt64
	/// The SENDER's (peer's) send epoch when the offer was surfaced. If the sender has
	/// committed since, the offer predates an epoch move and is no longer live.
	let senderSendEpochAtOffer: UInt64
	/// The engine that surfaced it (the peer of the folding role).
	let surfacedBy: EngineIdentity
}

struct DeliveryScheduler {
	/// Frames awaiting delivery to `role` (i.e. produced by `role.peer`).
	private(set) var lanes: [Role: [FrameRecord]] = [:]
	/// Side-band legs awaiting delivery to `role`.
	private(set) var sideLanes: [Role: [SideBandLeg]] = [:]
	/// Offers surfaced to `role` and not yet folded.
	private(set) var outstandingOffers: [Role: [OfferRecord]] = [:]
	/// Digests already folded by `role` — an Update is idempotent, so a host never folds
	/// the same proposal twice even if a reordered/duplicated frame re-offers it.
	private var foldedOffers: [Role: Set<Data>] = [:]
	/// The highest `dependsOnSeq` among frames already delivered to `role`.
	private(set) var maxDeliveredDependsOnSeq: [Role: UInt64] = [:]

	func mainCount(_ role: Role) -> Int { lanes[role]?.count ?? 0 }
	func sideCount(_ role: Role) -> Int { sideLanes[role]?.count ?? 0 }
	func hasOutstandingOffer(_ role: Role) -> Bool { !(outstandingOffers[role] ?? []).isEmpty }

	/// Everything still needing a scheduler action: queued frames + side-band legs +
	/// unfoldable offers. The probe's quiescence fixpoint loops until this hits 0.
	func queuedUnits() -> Int {
		Role.allCases.reduce(0) { $0 + mainCount($1) + sideCount($1) }
			+ Role.allCases.reduce(0) { $0 + (outstandingOffers[$1]?.count ?? 0) }
	}

	mutating func enqueue(_ frame: FrameRecord, to role: Role) {
		lanes[role, default: []].append(frame)
	}

	mutating func enqueueSideBand(_ leg: SideBandLeg, to role: Role) {
		sideLanes[role, default: []].append(leg)
	}

	mutating func offer(_ record: OfferRecord, to role: Role) {
		// Single-occupancy, latest-wins — both engines surface at most one pending offer
		// (a new offer replaces the previous), so a host folds only the latest and never a
		// digest it already folded.
		guard !(foldedOffers[role]?.contains(record.digest) ?? false) else { return }
		outstandingOffers[role] = [record]
	}

	mutating func popOffer(_ role: Role) -> OfferRecord? {
		guard var offers = outstandingOffers[role], !offers.isEmpty else { return nil }
		let record = offers.removeFirst()
		outstandingOffers[role] = offers
		foldedOffers[role, default: []].insert(record.digest)
		return record
	}

	/// Forget an outstanding offer without folding it (used to drop an offer the folder can
	/// no longer legally apply).
	mutating func discardOffer(_ role: Role) {
		outstandingOffers[role] = []
	}

	/// Resolves an op's index against a lane: 0-based from the front, negative from the
	/// back (-1 = newest). `nil` when out of range, so a generator that guessed wrong is
	/// a no-op rather than a crash.
	func resolve(_ index: Int, count: Int) -> Int? {
		let i = index < 0 ? count + index : index
		return (i >= 0 && i < count) ? i : nil
	}

	mutating func takeMain(_ role: Role, index: Int) -> FrameRecord? {
		guard let lane = lanes[role], let i = resolve(index, count: lane.count) else {
			return nil
		}
		let frame = lane[i]
		lanes[role] = lane.enumerated().filter { $0.offset != i }.map(\.element)
		maxDeliveredDependsOnSeq[role] = max(
			maxDeliveredDependsOnSeq[role] ?? 0, frame.dependsOnSeq)
		return frame
	}

	mutating func takeSide(_ role: Role, index: Int) -> SideBandLeg? {
		guard let lane = sideLanes[role], let i = resolve(index, count: lane.count) else {
			return nil
		}
		let leg = lane[i]
		sideLanes[role] = lane.enumerated().filter { $0.offset != i }.map(\.element)
		return leg
	}

	mutating func drop(_ role: Role, index: Int) {
		guard let lane = lanes[role], let i = resolve(index, count: lane.count) else {
			return
		}
		lanes[role] = lane.enumerated().filter { $0.offset != i }.map(\.element)
	}

	mutating func duplicate(_ role: Role, index: Int) {
		guard let lane = lanes[role], let i = resolve(index, count: lane.count) else {
			return
		}
		lanes[role, default: []].insert(lane[i], at: i + 1)
	}

	mutating func reorder(_ role: Role, index: Int, to: Int) {
		guard var lane = lanes[role], let i = resolve(index, count: lane.count),
			let j = resolve(to, count: lane.count)
		else { return }
		let frame = lane.remove(at: i)
		lane.insert(frame, at: min(j, lane.count))
		lanes[role] = lane
	}

	/// The distinct commit epochs currently queued toward `role` — two at once is the
	/// "sender committed twice while the peer was away" shape that yields an
	/// unbridgeable staple.
	func commitEpochsInFlight(_ role: Role) -> Set<UInt64> {
		Set((lanes[role] ?? []).filter(\.isCommit).map(\.epoch))
	}

	/// Whether restoring `role` to `seq` keeps every already-delivered frame receivable —
	/// the gate `crashAndRestore` picks its targets through, and asserts against.
	func isLegalRestore(_ role: Role, seq: UInt64) -> Bool {
		seq >= (maxDeliveredDependsOnSeq[role] ?? 0)
	}
}
