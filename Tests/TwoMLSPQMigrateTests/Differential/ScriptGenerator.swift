import Foundation

// Phase-biased script generation. Uniform random ops almost never reach the late states
// (fully established + rotated + A.5 catch-up) where every late defect in GER-2566 lived,
// so the generator walks explicit phases that drive the pair forward before introducing
// faults.
enum ScriptGenerator {
	static func generate(seed: UInt64) -> DiffScript {
		var rng = SplitMix64(seed: seed)
		var ops: [DiffOp] = []

		// Warm: alternate sends, always delivered, so both groups advance to a steady
		// epoch before any fault is possible.
		for i in 0..<6 {
			let role: Role = i % 2 == 0 ? .a : .b
			ops.append(.send(role: role, payload: "warm-\(i)", rotate: false))
			ops.append(.deliverAll(role: role.peer))
		}

		// Steady-state messaging with scheduler faults.
		for i in 0..<12 {
			switch Int.random(in: 0..<10, using: &rng) {
			case 0...3:
				ops.append(
					.send(
						role: pick(&rng), payload: "steady-\(i)",
						rotate: false))
			case 4:
				ops.append(.duplicate(role: pick(&rng), index: -1))
			case 5:
				ops.append(.drop(role: pick(&rng), index: 0))
			case 6:
				ops.append(.reorder(role: pick(&rng), index: -1, to: 0))
			case 7:
				ops.append(.queueProposal(role: pick(&rng)))
			case 8:
				ops.append(.deliver(role: pick(&rng), index: 0))
			default:
				ops.append(.probe)
			}
			if Int.random(in: 0..<3, using: &rng) == 0 {
				ops.append(.deliverAll(role: pick(&rng)))
			}
		}

		// Rotation-heavy: mid-script rotations, the shape GER-2531's one-sided stall
		// lives in.
		ops.append(.deliverAll(role: .a))
		ops.append(.deliverAll(role: .b))
		for i in 0..<8 {
			let role = pick(&rng)
			ops.append(.send(role: role, payload: "rot-\(i)", rotate: true))
			ops.append(.deliverAll(role: role.peer))
			ops.append(.queueProposal(role: role.peer))
			ops.append(.deliverAll(role: role))
			if i % 3 == 2 { ops.append(.probe) }
		}

		// Double-commit window: two distinct commit epochs must sit in flight toward `peer`
		// at once — the "sender committed twice while the peer was away" shape the
		// no-double-commit-in-flight invariant guards. A commit needs to fold a proposal
		// that changes a leaf's authorization; a plain `Upd(self)` folds WITHOUT committing
		// once the peer's leaf is already canonical, so the peer proposes a ROTATION
		// (`sendRotating`) mid-window, delivered and folded on `role` between the two
		// commits. The first commit stays queued (never delivered) throughout.
		for i in 0..<3 {
			let role = pick(&rng)
			let peer = role.peer
			ops.append(.deliverAll(role: role))
			ops.append(.sendRotating(role: peer, payload: "dc-\(i)-open"))
			ops.append(.deliverAll(role: role))
			ops.append(.queueProposal(role: role))
			ops.append(.send(role: role, payload: "dc-\(i)-1", rotate: false))
			ops.append(.sendRotating(role: peer, payload: "dc-\(i)-mid"))
			ops.append(.deliverAll(role: role))
			ops.append(.queueProposal(role: role))
			ops.append(.send(role: role, payload: "dc-\(i)-2", rotate: false))
			ops.append(.deliverAll(role: peer))
		}

		// PQ-round-heavy: hand the side-band lane around, restore at intermediate and
		// behind-delivery points, probe.
		for i in 0..<10 {
			let role = pick(&rng)
			switch Int.random(in: 0..<7, using: &rng) {
			case 0, 1:
				ops.append(.handOutSideBand(role: role))
				ops.append(.deliverSideBand(role: role.peer, index: 0))
			case 2:
				ops.append(.deliverAll(role: role))
			case 3:
				// Latest legal point.
				ops.append(.crashAndRestore(role: role, depth: 0))
			case 4:
				// An intermediate legal point (peer-away window).
				ops.append(.crashAndRestore(role: role, depth: 2))
				ops.append(.deliverAll(role: role))
			case 5:
				// The negative op: restore behind delivered state.
				ops.append(.restoreBehindDelivery(role: role, depth: 0))
				ops.append(.probe)
			case 6:
				ops.append(.duplicate(role: role, index: -1))
			default:
				ops.append(.probe)
			}
			if i % 2 == 1 { ops.append(.deliverAll(role: pick(&rng))) }
		}

		ops.append(.deliverAll(role: .a))
		ops.append(.deliverAll(role: .b))
		ops.append(.probe)

		return DiffScript(topology: .plain, ops: ops)
	}

	private static func pick(_ rng: inout SplitMix64) -> Role {
		Int.random(in: 0..<2, using: &rng) == 0 ? .a : .b
	}
}
