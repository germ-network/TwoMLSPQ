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

struct RunResult {
	var transcript: [TranscriptEntry] = []
	/// Healing-invariant and probe violations, each with a one-line description.
	var violations: [String] = []
}

@available(macOS 26, iOS 26, *)
struct DifferentialRun {
	let pair: Pair
	let script: DiffScript
	let seed: UInt64

	private var scheduler = DeliveryScheduler()
	private var rotationCounter = 0
	/// The most recent frame delivered to each role, for the restoreBehindDelivery negative
	/// test's re-delivery probe.
	private var lastDelivered: [Role: FrameRecord] = [:]

	init(pair: Pair, script: DiffScript, seed: UInt64) {
		self.pair = pair
		self.script = script
		self.seed = seed
	}

	mutating func run() -> RunResult {
		var result = RunResult()
		for (opIndex, op) in script.ops.enumerated() {
			execute(op, opIndex: opIndex, into: &result)
		}
		return result
	}

	private mutating func execute(_ op: DiffOp, opIndex: Int, into result: inout RunResult) {
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
			guard let digest = scheduler.popOffer(role) else { return }
			do {
				try pair.session(role).queueProposal(digest: digest)
				record(opIndex, role, "queueProposal", OutcomeStep(), into: &result)
			} catch {
				record(opIndex, role, "queueProposal", error, into: &result)
			}
		case .deliver(let role, let index):
			guard let frame = scheduler.takeMain(role, index: index) else { return }
			deliver(role: role, frame: frame, opIndex: opIndex, into: &result)
		case .deliverAll(let role):
			while let frame = scheduler.takeMain(role, index: 0) {
				deliver(role: role, frame: frame, opIndex: opIndex, into: &result)
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
			guard let leg = scheduler.takeSide(role, index: index) else { return }
			deliverSideBand(leg: leg, receiver: role, opIndex: opIndex, into: &result)
		case .crashAndRestore(let role, let depth):
			restore(
				role: role, depth: depth, opIndex: opIndex, behind: false,
				into: &result)
		case .restoreBehindDelivery(let role, let depth):
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
			scheduler.enqueue(
				FrameRecord(
					bytes: frame.bytes, from: role, opIndex: opIndex,
					// The session's current durability watermark at emit — engine-symmetric:
					// Rust's `encrypt.dependsOnSeq` is an earlier persisted seq while Swift's
					// `update.stateSeq` is the just-bumped one, so neither is used raw here.
					dependsOnSeq: session.lastStateSeq(),
					isCommit: prep.didCommit,
					epoch: session.sendEpoch()),
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
		do {
			let step = try pair.session(role).processIncoming(frame.bytes)
			if let digest = step.offeredDigest { scheduler.offer(digest, to: role) }
			record(opIndex, role, "deliver", step, into: &result)
		} catch {
			record(opIndex, role, "deliver", error, into: &result)
		}
	}

	private mutating func handOutSideBand(
		role: Role, opIndex: Int, into result: inout RunResult
	) {
		do {
			guard let leg = try pair.session(role).sideBandLeg() else { return }
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
		do {
			let kind = try session.openKind(leg.bytes)
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
		let delivered = scheduler.maxDeliveredDependsOnSeq[role] ?? 0
		let checkpoints =
			session.recordedBlobs()
			.filter { $0.kind == .checkpoint }
			.map(\.seq)
			.filter { behind ? $0 < delivered : $0 >= delivered }
			.sorted()
		let call = behind ? "restoreBehind" : "restore"

		guard !checkpoints.isEmpty else {
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
				"restore offered an illegal point (seq \(target) < delivered \(scheduler.maxDeliveredDependsOnSeq[role] ?? 0)) at op \(opIndex)"
			)
			record(opIndex, role, call, OutcomeStep(), into: &result)
			return
		}

		do {
			try session.restore(toSeq: target)
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
				while let digest = scheduler.popOffer(role) {
					do {
						try pair.session(role).queueProposal(digest: digest)
						record(
							opIndex, role, "queueProposal",
							OutcomeStep(), into: &result)
					} catch {
						record(
							opIndex, role, "queueProposal", error,
							into: &result)
					}
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
				while let frame = scheduler.takeMain(role, index: 0) {
					deliver(
						role: role, frame: frame, opIndex: opIndex,
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
				scheduler.offer(digest, to: role.peer)
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

	private static func isOpener(_ kind: SideBandKind) -> Bool {
		switch kind {
		case .bootstrapKP, .ratchetEK, .rekeyUpd: return true
		case .bootstrapWelcome, .ratchetCT, .rekeyCommit: return false
		}
	}
}
