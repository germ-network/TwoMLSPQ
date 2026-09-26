import Foundation

// The randomized runner. Executes one script against one established pair and records a
// per-call transcript of normalized outcomes. The differential test runs the SAME script
// in both mixed directions and compares the two transcripts: the engines are swapped, so
// any difference is an engine divergence, not a script artifact.

/// A transcript entry: the engine that produced it, the receiver's role, and the normalized
/// outcome of one engine call. `engine` is what lets a mismatch be attributed to a specific
/// engine rather than excused for either.
struct TranscriptEntry: Sendable {
	let opIndex: Int
	let role: Role
	let engine: EngineIdentity
	let call: String
	let outcome: ComparableOutcome
}

/// The projection of `OutcomeStep` actually compared across engines. Proposals' digests
/// are content-dependent and differ between runs, so only their PRESENCE is compared, not
/// their value.
struct ComparableOutcome: Equatable, Sendable {
	var payloads: [Data]
	var joined: Bool
	var pendingEstablishment: Bool
	var hadOffer: Bool
	var commitApplied: Bool
	var error: ErrorClass?
	/// The raw error description — diagnostics only; never participates in comparison.
	var errorText: String?

	init(_ step: OutcomeStep) {
		payloads = step.appPayloads
		joined = step.joined
		pendingEstablishment = step.pendingEstablishment
		hadOffer = step.offeredDigest != nil
		commitApplied = step.remoteCommitApplied
		error = step.errorClass
		errorText = step.errorText
	}

	/// Equatable ignores `errorText` — it is diagnostics only.
	static func == (l: ComparableOutcome, r: ComparableOutcome) -> Bool {
		l.payloads == r.payloads && l.joined == r.joined
			&& l.pendingEstablishment == r.pendingEstablishment
			&& l.hadOffer == r.hadOffer
			&& l.commitApplied == r.commitApplied && l.error == r.error
	}

	/// The `OutcomeStep` fields whose values differ, for ledger matching.
	func mismatches(_ other: ComparableOutcome) -> [String] {
		var fields: [String] = []
		if payloads != other.payloads { fields.append("appPayloads") }
		if joined != other.joined { fields.append("joined") }
		if pendingEstablishment != other.pendingEstablishment {
			fields.append("pendingEstablishment")
		}
		if hadOffer != other.hadOffer { fields.append("offeredDigest") }
		if commitApplied != other.commitApplied { fields.append("remoteCommitApplied") }
		if error != other.error { fields.append("errorClass") }
		return fields
	}
}

/// A transcript site where a direction had NO live offer to fold, or no frame to deliver —
/// i.e. an offer/frame-PRESENCE limitation, not a handling difference. Used to classify
/// cross-direction count differences as expected noise rather than findings.
struct PresenceSite: Hashable, Sendable {
	let op: Int
	let role: String
	let call: String
}

struct RunResult {
	var transcript: [TranscriptEntry] = []
	/// Healing-invariant and probe violations, each with a one-line description.
	var violations: [String] = []
	/// Sites where this direction had no live offer (queueProposal) or no frame to deliver.
	var presenceLimited: Set<PresenceSite> = []
	/// Per-restore record for the row-3 wedge analysis.
	var restores: [RestoreRecord] = []
	/// End-of-run state per role, for convergence ("heals") checks.
	var endState: [String: RoleEndState] = [:]
	/// Whether any probe in this run reported a violation (quiescence failure = wedge).
	var probeViolations = 0
	/// Restores that found no legal checkpoint and were skipped (visible, not silent).
	var restoreSkips = 0
	/// role -> op of the last `restoreBehindDelivery` that actually FIRED (behind-restore
	/// attribution for designed-wedge reclassification).
	var behindRestoredAt: [String: Int] = [:]
	/// Violations attributable to a behind-restore (designed wedge) — reported, not failed.
	var designedWedgeViolations: [String] = []
}

struct RestoreRecord: Sendable {
	let op: Int
	let role: String
	let kind: String
	let depth: UInt64
	let targetSeq: UInt64
	let legalThisRole: Bool
	let legalOtherRole: Bool
	let maxDeliveredThisRole: UInt64
	let stateSeqBefore: UInt64
	let inFlightSeqs: [UInt64]
}

struct RoleEndState: Sendable {
	let stateSeq: UInt64
	let sendEpoch: UInt64
	let fullyEstablished: Bool
	let heldOffer: String
}

@available(macOS 26, iOS 26, *)
struct DifferentialRun {
	let pair: Pair
	let script: DiffScript
	let seed: UInt64
	let direction: Direction

	private var scheduler = DeliveryScheduler()
	private var rotationCounter = 0
	/// The most recent frame delivered to each role, for the restoreBehindDelivery negative
	/// test's re-delivery probe.
	private var lastDelivered: [Role: FrameRecord] = [:]
	/// Every peer client id seen proposed to each role — a fold is only applied to an offer
	/// naming the peer's CURRENT canonical id or a genuinely NEW id, never a superseded one.
	private var seenPeerIDs: [Role: Set<Data>] = [:]
	/// Frame bytes already delivered to each role — a repeat is a protocol-legal re-delivery
	/// (duplicate), whose rejection rides on app-message consumption, not ciphertext dedup.
	private var deliveredFrames: [Role: Set<Data>] = [:]
	private var debugDeliveries:
		[(op: Int, role: String, engine: String, first: Bool, offer: Bool, err: String)] =
			[]

	init(pair: Pair, script: DiffScript, seed: UInt64, direction: Direction) {
		self.pair = pair
		self.script = script
		self.seed = seed
		self.direction = direction
	}

	mutating func run() -> RunResult {
		var result = RunResult()
		for (opIndex, op) in script.ops.enumerated() {
			execute(op, opIndex: opIndex, into: &result)
		}
		// Reclassify violations structurally attributable to a behind-restore as DESIGNED
		// WEDGE (the negative op asserts clean classification, not convergence).
		let behindOps = Set(result.behindRestoredAt.values)
		if !behindOps.isEmpty {
			let (designed, hard) = result.violations.reduce(
				into: ([String](), [String]())
			) {
				acc, v in
				let op = DifferentialRun.opIndex(inFinding: v)
				if let op, behindOps.contains(where: { $0 < op }) {
					acc.0.append(v)
				} else {
					acc.1.append(v)
				}
			}
			result.designedWedgeViolations = designed
			result.violations = hard
		}
		for role in Role.allCases {
			let s = pair.session(role)
			result.endState[role.rawValue] = RoleEndState(
				stateSeq: s.lastStateSeq(), sendEpoch: s.sendEpoch(),
				fullyEstablished: s.isFullyEstablished(),
				heldOffer: s.debugHeldOfferDigest()?.hexPrefix ?? "-")
		}
		if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_RESTORE"] != nil {
			let a = result.endState[Role.a.rawValue]!
			let b = result.endState[Role.b.rawValue]!
			FileHandle.standardError.write(
				Data(
					"DBG runend seed=\(seed) dir=\(direction.rawValue) probeViolations=\(result.probeViolations) A(seq=\(a.stateSeq) epoch=\(a.sendEpoch) full=\(a.fullyEstablished) offer=\(a.heldOffer)) B(seq=\(b.stateSeq) epoch=\(b.sendEpoch) full=\(b.fullyEstablished) offer=\(b.heldOffer))\n"
						.utf8))
		}
		return result
	}

	private mutating func debugState(op: Int) {
		guard ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_SIDEBAND"] != nil
		else { return }
		FileHandle.standardError.write(
			Data(
				"DBG state dir=\(direction.rawValue) seed=\(seed) op=\(op) A[\(pair.initiator.debugStateLine())] B[\(pair.acceptor.debugStateLine())]\n"
					.utf8))
	}

	private mutating func execute(_ op: DiffOp, opIndex: Int, into result: inout RunResult) {
		debugState(op: opIndex)
		switch op {
		case .send(let role, let payload, let rotate):
			send(
				role: role, payload: payload, rotate: rotate, forceRotate: false,
				opIndex: opIndex, into: &result)
		case .sendRotating(let role, let payload):
			send(
				role: role, payload: payload, rotate: true, forceRotate: true,
				opIndex: opIndex, into: &result)
		case .queueProposal(let role):
			guard let offer = scheduler.popOffer(role) else {
				if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_FOLDS"]
					!= nil
				{
					FileHandle.standardError.write(
						Data(
							"DBG fold seed=\(seed) op=\(opIndex) role=\(role.rawValue) folderEngine=\(pair.session(role).engine.rawValue) NO-OFFER\n"
								.utf8))
				}
				return
			}
			fold(offer: offer, role: role, opIndex: opIndex, into: &result)
		case .deliver(let role, let index):
			guard let frame = scheduler.takeMain(role, index: index) else {
				markPresence(
					op: opIndex, role: role, call: "deliver", into: &result)
				debugDeliverNoFrame(op: opIndex, role: role)
				return
			}
			deliver(role: role, frame: frame, opIndex: opIndex, into: &result)
		case .deliverAll(let role):
			let before = result.transcript.count
			while let frame = scheduler.takeMain(role, index: 0) {
				deliver(role: role, frame: frame, opIndex: opIndex, into: &result)
			}
			if result.transcript.count == before {
				markPresence(
					op: opIndex, role: role, call: "deliver", into: &result)
			}
		case .drop(let role, let index):
			scheduler.drop(role, index: index)
		case .duplicate(let role, let index):
			scheduler.duplicate(role, index: index)
		case .reorder(let role, let index, let to):
			scheduler.reorder(role, index: index, to: to)
		case .handOutSideBand(let role):
			handOutSideBand(role: role, opIndex: opIndex, into: &result)
		case .deliverSideBand(let role, let index):
			guard let leg = scheduler.takeSide(role, index: index) else {
				if ProcessInfo.processInfo.environment[
					"DIFFERENTIAL_DEBUG_SIDEBAND"] != nil
				{
					FileHandle.standardError.write(
						Data(
							"DBG sb dir=\(direction.rawValue) seed=\(seed) op=\(opIndex) NOSIDE-LEG role=\(role.rawValue) laneCount=\(scheduler.sideCount(role))\n"
								.utf8))
				}
				return
			}
			deliverSideBand(leg: leg, receiver: role, opIndex: opIndex, into: &result)
		case .crashAndRestore(let role, let depth):
			debugRestore(op: opIndex, role: role, kind: "crash")
			restore(
				role: role, depth: depth, opIndex: opIndex, behind: false,
				into: &result)
		case .restoreBehindDelivery(let role, let depth):
			debugRestore(op: opIndex, role: role, kind: "behind")
			restore(
				role: role, depth: depth, opIndex: opIndex, behind: true,
				into: &result)
		case .probe:
			probe(opIndex: opIndex, into: &result)
		}
	}

	private mutating func send(
		role: Role, payload: String, rotate: Bool, forceRotate: Bool, opIndex: Int,
		into result: inout RunResult
	) {
		let session = pair.session(role)
		let proposing: Data?
		// Propose a rotation only from a clean slate: nothing of ours in flight and no
		// outstanding offer. This is HARNESS state alone, so both engine directions decide
		// identically — an engine-state gate (e.g. hasPendingRotation) can disagree across
		// engines and would itself create a false differential. `forceRotate` bypasses the
		// lane clauses (the double-commit window needs a second authorization change while a
		// commit is in flight) but never bypasses `hasPendingRotation`.
		let cleanSlate =
			scheduler.mainCount(role) == 0 && scheduler.mainCount(role.peer) == 0
			&& !scheduler.hasOutstandingOffer(role)
			&& !scheduler.hasOutstandingOffer(role.peer)
		if rotate && !session.hasPendingRotation() && (forceRotate || cleanSlate) {
			proposing = Data("rot-\(role.rawValue)-\(rotationCounter)".utf8)
			rotationCounter += 1
		} else {
			proposing = nil
		}
		do {
			let prep = try session.prepareToEncrypt(proposing: proposing)
			let frame = try session.encrypt(Data(payload.utf8))
			// Persist-before-send: the emitter must have persisted the state this frame
			// depends on BEFORE sending it. A violation here is the harness wedging on the
			// emitter's behalf.
			let persisted = session.maxPersistedSeq()
			let persistViolation = session.lastStateSeq() > persisted
			if persistViolation {
				result.violations.append(
					"persist-before-send: emitter \(role.rawValue) sent seq \(session.lastStateSeq()) > persisted \(persisted) at op \(opIndex)"
				)
			}
			scheduler.enqueue(
				FrameRecord(
					bytes: frame.bytes, from: role, opIndex: opIndex,
					// The session's current durability watermark at emit — engine-symmetric:
					// Rust's `encrypt.dependsOnSeq` is an earlier persisted seq while Swift's
					// `update.stateSeq` is the just-bumped one, so neither is used raw here.
					dependsOnSeq: session.lastStateSeq(),
					isCommit: prep.didCommit,
					epoch: session.sendEpoch(),
					persistViolation: persistViolation),
				to: role.peer)
			if scheduler.commitEpochsInFlight(role.peer).count > 1 {
				result.violations.append(
					"no-double-commit-in-flight: \(role.rawValue) committed twice while its peer stayed away (op \(opIndex))"
				)
			}
			record(opIndex, role, "send", OutcomeStep(), into: &result)
		} catch {
			record(opIndex, role, "send", error, into: &result)
		}
	}

	private mutating func deliver(
		role: Role, frame: FrameRecord, opIndex: Int, into result: inout RunResult
	) {
		lastDelivered[role] = frame
		let firstDelivery = !(deliveredFrames[role]?.contains(frame.bytes) ?? false)
		deliveredFrames[role, default: []].insert(frame.bytes)
		// The receiver's OWN watermark BEFORE this frame is applied — the state a restore
		// must not rewind past for this frame to remain receivable. Same engine, same space.
		let receiverPreSeq = pair.session(role).lastStateSeq()
		do {
			let session = pair.session(role)
			let step = try session.processIncoming(frame.bytes)
			scheduler.noteDeliveredReceiverSeq(role, seq: receiverPreSeq)
			debugDeliver(
				op: opIndex, role: role, tag: frame.bytes.hexPrefix,
				srcOp: frame.opIndex,
				first: firstDelivery,
				offer: step.offeredDigest != nil, err: "-")
			if let digest = step.offeredDigest {
				scheduler.offer(
					OfferRecord(
						digest: digest, proposing: step.offeredProposing,
						context: step.offeredContext,
						sender: step.offeredSender,
						isCatchUp: step.offerIsCatchUp,
						offeredAtOp: opIndex,
						offeredAtSendEpoch: session.sendEpoch(),
						senderSendEpochAtOffer: pair.session(role.peer)
							.sendEpoch(),
						surfacedBy: session.engine),
					to: role)
			} else {
				// The engine reported NO offer on this frame, which is authoritative: the
				// offer it previously held is gone (a plain Update that canonicalized, an
				// idempotent re-ride, …). Keeping our older record would make the harness fold
				// an offer the engine no longer holds — the fidelity gap behind most spurious
				// fold-rejections (Rust's `proposal` is optional, Swift's is not).
				scheduler.discardOffer(role)
			}
			record(opIndex, role, "deliver", step, into: &result)
		} catch {
			debugDeliver(
				op: opIndex, role: role, tag: frame.bytes.hexPrefix,
				srcOp: frame.opIndex,
				first: firstDelivery,
				offer: false,
				err:
					"\(errorClass(error)?.rawValue ?? "nil"):\(String(describing: error).prefix(40))"
			)
			record(opIndex, role, "deliver", error, into: &result)
		}
	}

	/// Fold a surfaced offer, with an optional diagnostic dump (`DIFFERENTIAL_DEBUG_FOLDS`)
	/// of the attempt's legality inputs: the offer's shape, the folder's current context and
	/// send epoch, and the outcome. This is what classifies a fold divergence as stale /
	/// consumed / catch-up / genuinely-valid.
	private mutating func fold(
		offer: OfferRecord, role: Role, opIndex: Int, into result: inout RunResult
	) {
		let session = pair.session(role)
		// Liveness gate (host-faithful): an offer surfaced before the SENDER's last commit
		// predates an epoch move and is no longer foldable. A well-behaved host folds promptly
		// and drops such a stale offer rather than feeding it to the engine, so the harness
		// does too — folding it would manufacture a fold-legality divergence that is a harness
		// artifact, not an engine one.
		let senderEpochNow = pair.session(role.peer).sendEpoch()
		// A host folds an offer promptly, before its own later state can supersede it. An
		// offer that has sat while the folder committed (its own commit can canonicalize a
		// LATER candidate, e.g. rot-b-1 while the parked offer proposes rot-b-0) is no longer
		// live even though the engine still holds it — folding it manufactures a reject that
		// is a harness artifact. So: fold only in the op that surfaced it or the next one.
		let isSuperseded = opIndex - offer.offeredAtOp > 1
		// A well-behaved host never authorises a SUPERSEDED candidate: an offer whose
		// `proposing` id the peer has already moved past (neither its current canonical id
		// nor a new one) is stale, however recently it was surfaced (an old parked frame can
		// be re-delivered late). Folding it is a harness artifact — the engine rightly
		// refuses it as a rollback.
		let theirs = session.principalStateIDs().theirs
		let seen = seenPeerIDs[role] ?? []
		let proposingIsStaleCandidate =
			offer.proposing != nil && offer.proposing != theirs
			&& seen.contains(offer.proposing!)
		if let proposing = offer.proposing {
			seenPeerIDs[role, default: []].insert(proposing)
		}
		// The residual fold rejects were `verifying(proposal:) → wrongEpoch(expected: N,
		// actual: N-1)`: an offer staged at the PREVIOUS group epoch, which no host would
		// fold. `offerStillVerifies()` is the engine's own "is this still foldable" answer
		// (nil where the engine exposes no equivalent).
		let stillVerifiable = session.offerStillVerifies()
		if isSuperseded || proposingIsStaleCandidate
			|| senderEpochNow != offer.senderSendEpochAtOffer
			|| stillVerifiable == false
		{
			markPresence(op: opIndex, role: role, call: "queueProposal", into: &result)
			scheduler.discardOffer(role)
			if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_FOLDS"] != nil {
				FileHandle.standardError.write(
					Data(
						"DBG fold seed=\(seed) op=\(opIndex) role=\(role.rawValue) folderEngine=\(session.engine.rawValue) NOT-LIVE atOp=\(offer.offeredAtOp) superseded=\(isSuperseded) senderEpochThen=\(offer.senderSendEpochAtOffer) senderEpochNow=\(senderEpochNow) stillVerifies=\(stillVerifiable.map(String.init) ?? "-")\n"
							.utf8))
			}
			record(opIndex, role, "queueProposal", OutcomeStep(), into: &result)
			return
		}
		let contextNow = session.proposalContext()
		let contextMatch = (contextNow == offer.context)
		if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_FOLDS"] != nil {
			let line =
				"DBG fold seed=\(seed) op=\(opIndex) role=\(role.rawValue) folderEngine=\(session.engine.rawValue)"
				+ " offeredBy=\(offer.surfacedBy.rawValue) atOp=\(offer.offeredAtOp)"
				+ " sendEpoch=\(session.sendEpoch()) offeredAtEpoch=\(offer.offeredAtSendEpoch)"
				+ " digest=\(offer.digest.hexPrefix) proposing=\(offer.proposing?.hexPrefix ?? "-")"
				+ " sender=\(offer.sender?.hexPrefix ?? "-")"
				+ " ctxMatch=\(contextMatch) ctxNow=\(contextNow?.hexPrefix ?? "-")"
				+ " ctxOffer=\(offer.context?.hexPrefix ?? "-")"
				+ " isCatchUp=\(offer.isCatchUp.map(String.init) ?? "-")"
				+ " proposingEqSender=\(offer.proposing != nil && offer.proposing == offer.sender)"
				+ " heldNow=\(session.debugHeldOfferDigest()?.hexPrefix ?? "nil")"
				+ " heldMatchesFolded=\(session.debugHeldOfferDigest() == offer.digest)"
				+ " mine=\(session.principalStateIDs().mine?.hexPrefix ?? "-")"
				+ " theirs=\(session.principalStateIDs().theirs?.hexPrefix ?? "-")"
				+ " proposingEqTheirs=\(offer.proposing != nil && offer.proposing == session.principalStateIDs().theirs)"
				+ " proposingEqMine=\(offer.proposing != nil && offer.proposing == session.principalStateIDs().mine)\n"
			FileHandle.standardError.write(Data(line.utf8))
		}
		if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_ADVERTS"] != nil,
			let replica = session.debugReplicaGuards()
		{
			FileHandle.standardError.write(
				Data(
					"DBG advert seed=\(seed) op=\(opIndex) role=\(role.rawValue) engine=\(session.engine.rawValue) offeredBy=\(offer.surfacedBy.rawValue) \(replica)\n"
						.utf8))
		}
		do {
			try session.queueProposal(digest: offer.digest)
			if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_FOLDS"] != nil {
				FileHandle.standardError.write(
					Data(
						"DBG fold seed=\(seed) op=\(opIndex) role=\(role.rawValue) OUTCOME=ok\n"
							.utf8))
			}
			record(opIndex, role, "queueProposal", OutcomeStep(), into: &result)
		} catch {
			if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_FOLDS"] != nil {
				FileHandle.standardError.write(
					Data(
						"DBG fold seed=\(seed) op=\(opIndex) role=\(role.rawValue) OUTCOME=err class=\(errorClass(error)?.rawValue ?? "nil") text=\(String(describing: error))\n"
							.utf8))
				if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_GUARDS"]
					!= nil,
					let replica = session.debugReplicaGuards()
				{
					FileHandle.standardError.write(
						Data(
							"DBG guards seed=\(seed) op=\(opIndex) role=\(role.rawValue) engine=\(session.engine.rawValue) \(replica)\n"
								.utf8))
				}
			}
			record(opIndex, role, "queueProposal", error, into: &result)
		}
	}

	private mutating func handOutSideBand(
		role: Role, opIndex: Int, into result: inout RunResult
	) {
		do {
			guard let leg = try pair.session(role).sideBandLeg() else {
				if ProcessInfo.processInfo.environment[
					"DIFFERENTIAL_DEBUG_SIDEBAND"] != nil
				{
					FileHandle.standardError.write(
						Data(
							"DBG sb dir=\(direction.rawValue) seed=\(seed) op=\(opIndex) HANDOUT role=\(role.rawValue) engine=\(pair.session(role).engine.rawValue) NO-LEG\n"
								.utf8))
				}
				return
			}
			let kind = try? pair.session(role).openKind(leg)
			if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_SIDEBAND"] != nil
			{
				FileHandle.standardError.write(
					Data(
						"DBG sb dir=\(direction.rawValue) seed=\(seed) op=\(opIndex) HANDOUT role=\(role.rawValue) engine=\(pair.session(role).engine.rawValue) firstByte=\(leg.hexPrefix.prefix(2)) len=\(leg.count) selfOpenKind=\(kind?.rawValue ?? "-") ->lane(\(role.peer.rawValue))\n"
							.utf8))
			}
			scheduler.enqueueSideBand(
				SideBandLeg(bytes: leg, from: role, opIndex: opIndex), to: role.peer
			)
			record(opIndex, role, "handOutSideBand", OutcomeStep(), into: &result)
		} catch {
			record(opIndex, role, "handOutSideBand", error, into: &result)
		}
	}

	private mutating func deliverSideBand(
		leg: SideBandLeg, receiver: Role, opIndex: Int, into result: inout RunResult
	) {
		let session = pair.session(receiver)
		let dbg = ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_SIDEBAND"] != nil
		do {
			let kind = try session.openKind(leg.bytes)
			if dbg {
				FileHandle.standardError.write(
					Data(
						"DBG sb dir=\(direction.rawValue) seed=\(seed) op=\(opIndex) DELIVER firstByte=\(leg.bytes.hexPrefix.prefix(2)) len=\(leg.bytes.count) srcRole=\(leg.from.rawValue) srcOp=\(leg.opIndex) receiver=\(receiver.rawValue) engine=\(session.engine.rawValue) openKind=\(kind?.rawValue ?? "nil")\n"
							.utf8))
			}
			if kind == nil {
				// Not sealable for this receiver — an opaque leg is a scheduler no-op.
				return
			}
			if Self.isOpener(kind!) {
				if let answer = try session.sideBandRespond(leg.bytes) {
					scheduler.enqueueSideBand(
						SideBandLeg(
							bytes: answer, from: receiver,
							opIndex: opIndex),
						to: leg.from)
				}
				record(
					opIndex, receiver, "sideBandRespond", OutcomeStep(),
					into: &result)
			} else {
				try session.sideBandApply(leg.bytes)
				record(
					opIndex, receiver, "sideBandApply", OutcomeStep(),
					into: &result)
			}
		} catch {
			record(opIndex, receiver, "deliverSideBand", error, into: &result)
		}
	}

	// MARK: - Restore dimension

	/// Restores `role` to a recorded checkpoint. `depth` is how many legal checkpoints back
	/// from the latest to go (0 = latest). For `behind`, the target is the FURTHEST recorded
	/// checkpoint below the delivered watermark — deliberately a point behind state the peer
	/// already saw, a negative test whose expectation is clean classification.
	private mutating func restore(
		role: Role, depth: UInt64, opIndex: Int, behind: Bool, into result: inout RunResult
	) {
		let session = pair.session(role)
		let delivered = scheduler.maxDeliveredReceiverSeq[role] ?? 0
		let checkpoints =
			session.recordedBlobs()
			.filter { $0.kind == .checkpoint }
			.map(\.seq)
			.filter { behind ? $0 < delivered : $0 >= delivered }
			.sorted()
		let call = behind ? "restoreBehind" : "restore"

		guard !checkpoints.isEmpty else {
			result.restoreSkips += 1
			if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_RESTORE"] != nil
			{
				FileHandle.standardError.write(
					Data(
						"DBG restore-skip seed=\(seed) dir=\(direction.rawValue) op=\(opIndex) role=\(role.rawValue) engine=\(session.engine.rawValue) kind=\(call) reason=no-legal-checkpoint receiverWatermark=\(scheduler.maxDeliveredReceiverSeq[role] ?? 0) mySeq=\(session.lastStateSeq()) checkpoints=\(session.recordedBlobs().filter { $0.kind == .checkpoint }.map(\.seq).sorted())\n"
							.utf8))
			}
			record(opIndex, role, call, OutcomeStep(), into: &result)
			return
		}
		let target: UInt64
		if behind {
			target = checkpoints[0]
		} else {
			let back = Int(min(depth, UInt64(checkpoints.count - 1)))
			target = checkpoints[checkpoints.count - 1 - back]
		}
		// The legality gate: a non-behind restore must never target a point behind a
		// delivered frame's dependency (that is what restoreBehindDelivery is for).
		if !behind && !scheduler.isLegalRestore(role, seq: target) {
			result.violations.append(
				"restore offered an illegal point (seq \(target) < delivered \(scheduler.maxDeliveredReceiverSeq[role] ?? 0)) at op \(opIndex)"
			)
			record(opIndex, role, call, OutcomeStep(), into: &result)
			return
		}

		let otherRole = role.peer
		result.restores.append(
			RestoreRecord(
				op: opIndex, role: role.rawValue, kind: behind ? "behind" : "crash",
				depth: depth, targetSeq: target,
				legalThisRole: scheduler.isLegalRestore(role, seq: target),
				legalOtherRole: scheduler.isLegalRestore(
					otherRole,
					seq: scheduler.maxDeliveredReceiverSeq[otherRole] ?? 0),
				maxDeliveredThisRole: scheduler.maxDeliveredReceiverSeq[role] ?? 0,
				stateSeqBefore: session.lastStateSeq(),
				inFlightSeqs: (scheduler.lanes[role] ?? []).map(\.dependsOnSeq)))
		let restoreDebug =
			ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_RESTORE"] != nil
		let targetForDebug = target
		let seqBeforeForDebug = session.lastStateSeq()
		do {
			try session.restore(toSeq: target)
			if behind { result.behindRestoredAt[role.rawValue] = opIndex }
			// Dumped AFTER the attempt, so it reports only restores that FIRED — the same
			// set `behindRestoredAt` records. (Dumping before the attempt made an offline
			// analysis count throwing/short-circuiting restores and over-estimate the
			// behind-restore attribution window.)
			if restoreDebug {
				let inFlight = (scheduler.lanes[role] ?? []).map {
					String($0.dependsOnSeq)
				}
				FileHandle.standardError.write(
					Data(
						"DBG restore-detail seed=\(seed) dir=\(direction.rawValue) op=\(opIndex) role=\(role.rawValue) engine=\(session.engine.rawValue) kind=\(call) depth=\(depth) target=\(targetForDebug) seqBefore=\(seqBeforeForDebug) maxDelivered=\(scheduler.maxDeliveredReceiverSeq[role] ?? 0) legal=\(scheduler.isLegalRestore(role, seq: targetForDebug)) inFlightSeq=[\(inFlight.joined(separator: ","))] FIRED=true\n"
							.utf8))
			}
			if ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_RESTORE"] != nil
			{
				FileHandle.standardError.write(
					Data(
						"DBG postrestore seed=\(seed) dir=\(direction.rawValue) op=\(opIndex) role=\(role.rawValue) stateSeq=\(session.lastStateSeq()) sendEpoch=\(session.sendEpoch()) heldOffer=\(session.debugHeldOfferDigest()?.hexPrefix ?? "-") maxPersisted=\(session.maxPersistedSeq())\n"
							.utf8))
			}
			record(opIndex, role, call, OutcomeStep(), into: &result)
			if behind {
				assertCleanClassification(
					role: role, opIndex: opIndex, into: &result)
			}
		} catch {
			record(opIndex, role, call, errorStep(error), into: &result)
			if behind && (errorClass(error) ?? .other) == .other {
				result.violations.append(
					"restoreBehindDelivery(\(role)) threw an unclassified error at op \(opIndex): \(error)"
				)
			}
		}
	}

	/// The negative-op expectation: after a restore BEHIND delivered state, re-delivering an
	/// already-seen frame must never MISPARSE or brick. A clean apply or a clean ignore
	/// (Rust `nil` → no error) is HEALING, not a violation — the plan's nil→ignored rule. Only
	/// an error that is actually THROWN and classifies as unclassified `.other` (a bogus tag,
	/// a codec failure — nothing the equivalence table recognizes) is the misparse signal we
	/// fail on.
	private mutating func assertCleanClassification(
		role: Role, opIndex: Int, into result: inout RunResult
	) {
		guard let frame = lastDelivered[role] else { return }
		do {
			_ = try pair.session(role).processIncoming(frame.bytes)
		} catch {
			if (errorClass(error) ?? .other) == .other {
				result.violations.append(
					"restoreBehindDelivery(\(role)) produced an unclassified error on re-delivery at op \(opIndex): \(error)"
				)
			}
		}
	}

	// MARK: - Probe / quiescence

	private mutating func probe(opIndex: Int, into result: inout RunResult) {
		let violationsBefore = result.violations.count
		drainQuiescent(opIndex: opIndex, into: &result)

		let aEstablished = pair.initiator.isFullyEstablished()
		let bEstablished = pair.acceptor.isFullyEstablished()
		if aEstablished != bEstablished {
			result.violations.append(
				"probe: isFullyEstablished disagrees (a=\(aEstablished) b=\(bEstablished)) at op \(opIndex)"
			)
		}

		// One round-trip each way; the two engines must agree on whether it lands.
		let aToB = roundTrip(from: .a, opIndex: opIndex, into: &result)
		let bToA = roundTrip(from: .b, opIndex: opIndex, into: &result)
		if aToB != bToA {
			result.violations.append(
				"probe: round-trip asymmetry a->b=\(aToB) b->a=\(bToA) at op \(opIndex)"
			)
		}
		if !aToB && !bToA {
			// Quiescence requires a fresh round-trip to LAND. Both directions failing is not
			// symmetry — it is a wedge (a symmetric pair of failures previously passed).
			result.violations.append(
				"probe: quiescent round-trip FAILED both directions at op \(opIndex) — wedge"
			)
		}
		if result.violations.count > violationsBefore { result.probeViolations += 1 }
	}

	/// A full quiescence drain: repeatedly fold every outstanding offer and drain the
	/// side-band + main lanes until nothing is left — a fixpoint, since a delivery can
	/// surface a NEW offer (and a side-band round-trip can re-mint a leg, so folding while
	/// draining is what actually reaches quiescence). Folds ARE recorded in the transcript,
	/// so a fold divergence during a probe is visible rather than swallowed. Bounded only to
	/// stop a genuine re-mint cycle spinning forever; hitting the bound with work left is
	/// recorded.
	private mutating func drainQuiescent(opIndex: Int, into result: inout RunResult) {
		var iterations = 0
		while true {
			let before = scheduler.queuedUnits()
			for role in Role.allCases {
				while let offer = scheduler.popOffer(role) {
					fold(
						offer: offer, role: role, opIndex: opIndex,
						into: &result)
				}
			}
			for role in Role.allCases {
				if let leg = scheduler.takeSide(role, index: 0) {
					deliverSideBand(
						leg: leg, receiver: role, opIndex: opIndex,
						into: &result)
				}
			}
			for role in Role.allCases {
				let beforeDrain = result.transcript.count
				while let frame = scheduler.takeMain(role, index: 0) {
					deliver(
						role: role, frame: frame, opIndex: opIndex,
						into: &result)
				}
				if result.transcript.count == beforeDrain {
					markPresence(
						op: opIndex, role: role, call: "deliver",
						into: &result)
				}
			}
			if scheduler.queuedUnits() == 0 { break }
			guard scheduler.queuedUnits() < before || iterations < 64 else {
				result.violations.append(
					"probe: quiescence never reached (\(iterations) iterations, \(scheduler.queuedUnits()) units left) at op \(opIndex)"
				)
				break
			}
			iterations += 1
		}
	}

	private mutating func roundTrip(from role: Role, opIndex: Int, into result: inout RunResult)
		-> Bool
	{
		let session = pair.session(role)
		let peer = pair.session(role.peer)
		do {
			_ = try session.prepareToEncrypt(proposing: nil)
			let frame = try session.encrypt(Data("probe-\(role.rawValue)".utf8))
			let step = try peer.processIncoming(frame.bytes)
			if let digest = step.offeredDigest {
				scheduler.offer(
					OfferRecord(
						digest: digest, proposing: step.offeredProposing,
						context: step.offeredContext,
						sender: step.offeredSender,
						isCatchUp: step.offerIsCatchUp,
						offeredAtOp: opIndex,
						offeredAtSendEpoch: peer.sendEpoch(),
						senderSendEpochAtOffer: session.sendEpoch(),
						surfacedBy: peer.engine),
					to: role.peer)
			}
			record(opIndex, role.peer, "probeRoundTrip", step, into: &result)
			return step.appPayloads.contains(Data("probe-\(role.rawValue)".utf8))
		} catch {
			record(opIndex, role.peer, "probeRoundTrip", error, into: &result)
			return false
		}
	}

	private mutating func record(
		_ opIndex: Int, _ role: Role, _ call: String, _ error: Error,
		into result: inout RunResult
	) {
		record(opIndex, role, call, errorStep(error), into: &result)
	}

	private func errorStep(_ error: Error) -> OutcomeStep {
		var step = OutcomeStep(errorClass: errorClass(error) ?? .other)
		step.errorText = String(describing: error)
		return step
	}

	private mutating func record(
		_ opIndex: Int, _ role: Role, _ call: String, _ step: OutcomeStep,
		into result: inout RunResult
	) {
		result.transcript.append(
			TranscriptEntry(
				opIndex: opIndex, role: role, engine: pair.session(role).engine,
				call: call,
				outcome: ComparableOutcome(step)))
	}

	private func markPresence(
		op: Int, role: Role, call: String, into result: inout RunResult
	) {
		result.presenceLimited.insert(
			PresenceSite(op: op, role: role.rawValue, call: call))
	}

	private func debugRestore(op: Int, role: Role, kind: String) {
		guard ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_DELIVER"] != nil
		else { return }
		FileHandle.standardError.write(
			Data(
				"DBG restore seed=\(seed) op=\(op) role=\(role.rawValue) kind=\(kind)\n"
					.utf8))
	}

	private func debugDeliverNoFrame(op: Int, role: Role) {
		guard ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_DELIVER"] != nil
		else { return }
		FileHandle.standardError.write(
			Data(
				"DBG deliv dir=\(direction.rawValue) seed=\(seed) op=\(op) role=\(role.rawValue) engine=\(pair.session(role).engine.rawValue) NO-FRAME\n"
					.utf8))
	}

	private func debugDeliver(
		op: Int, role: Role, tag: String, srcOp: Int, first: Bool, offer: Bool,
		epoch: UInt64? = nil, err: String
	) {
		guard ProcessInfo.processInfo.environment["DIFFERENTIAL_DEBUG_DELIVER"] != nil
		else { return }
		FileHandle.standardError.write(
			Data(
				"DBG deliv dir=\(direction.rawValue) seed=\(seed) op=\(op) role=\(role.rawValue) engine=\(pair.session(role).engine.rawValue) tag=\(tag) firstByte=\(tag.prefix(2)) srcOp=\(srcOp) first=\(first) offer=\(offer) epoch=\(epoch.map(String.init) ?? "-") err=\(err)\n"
					.utf8))
	}

	/// Extract the first `op N` from a finding/violation string (nil if absent).
	static func opIndex(inFinding text: String) -> Int? {
		guard let r = text.range(of: #"op ([0-9]+)"#, options: .regularExpression) else {
			return nil
		}
		return Int(text[r].dropFirst(3))
	}

	private static func isOpener(_ kind: SideBandKind) -> Bool {
		switch kind {
		case .bootstrapKP, .ratchetEK, .rekeyUpd: return true
		case .bootstrapWelcome, .ratchetCT, .rekeyCommit: return false
		}
	}
}

extension Data {
	/// A short hex prefix for diagnostic dumps.
	var hexPrefix: String { map { String(format: "%02x", $0) }.prefix(12).joined() }
}
