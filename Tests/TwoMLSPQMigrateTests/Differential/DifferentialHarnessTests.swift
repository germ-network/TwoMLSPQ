import Foundation
import Testing
import TwoMLSPQBinding

// The randomized differential suite. Every test here is DISABLED unless
// `DIFFERENTIAL_DEPLOYED_PIN=1` is set — the recipe that swaps in the deployed pin's
// binding + xcframework sets it. The standard `swift test` under main's binding therefore
// stays green: a swap never breaks the main suite, it only enables these tests.
//
// Diagnostics: `DIFFERENTIAL_SEED_MAX` (default 60) widens the sweep; a failing run prints
// the seed, the op-script blob, the binding contract version, and the pin sha, so the
// exact scenario replays via `DIFFERENTIAL_REPLAY_SEED` + `DIFFERENTIAL_REPLAY_BLOB`.
//
// Swift Testing's `@Test`/`@Suite` macros reject `@available` on the annotated declaration,
// so the macOS-26 engine work lives in the `@available` `DifferentialChecks` helper and
// each test guards on `#available` before calling it.

@Suite(.serialized)
struct DifferentialHarnessTests {
	static let pinEnabled =
		ProcessInfo.processInfo.environment["DIFFERENTIAL_DEPLOYED_PIN"] != nil
	static let seedMax = max(
		1,
		UInt64(ProcessInfo.processInfo.environment["DIFFERENTIAL_SEED_MAX"] ?? "60") ?? 60)
	static let seeds = Array(UInt64(1)...seedMax)

	@Test(.enabled(if: pinEnabled))
	func bindingContractMatchesLedger() throws {
		guard #available(macOS 26, *) else { return }
		let ledger = try DivergenceLedger.load()
		#expect(bindingContractVersion() == ledger.bindingContractVersion)
	}

	/// A mixed-pair differential: run one script in both engine directions and require the
	/// transcripts to agree, minus ledgered divergences.
	@Test(.enabled(if: pinEnabled), arguments: seeds)
	func mixedPairDifferential(seed: UInt64) throws {
		guard #available(macOS 26, *) else { return }
		let ledger = try DivergenceLedger.load()
		let cmp = try DifferentialChecks.mixedFindings(
			script: ScriptGenerator.generate(seed: seed), seed: seed, ledger: ledger)
		print("seed \(seed) \(cmp.summary)")
		#expect(
			cmp.findings.isEmpty,
			Comment(
				rawValue: DifferentialChecks.replayPrefix(
					seed: seed, ledger: ledger) + "\n" + cmp.summary + "\n"
					+ cmp.findings.joined(separator: "\n")))
	}

	/// Pure-pair oracles. They prove nothing about a single engine's correctness; they
	/// attribute a mixed-pair mismatch to the script (a fault the pure pair also hits)
	/// versus the engine boundary. Always runs at least the last seed, so it is never
	/// vacuous on a narrow `DIFFERENTIAL_SEED_MAX`.
	@Test(.enabled(if: pinEnabled))
	func purePairOracles() throws {
		guard #available(macOS 26, *) else { return }
		let sampled = Self.seeds.filter { $0 % 5 == 0 || $0 == Self.seeds.last }
		for seed in sampled {
			let run = try DifferentialChecks.purePair(seed: seed)
			#expect(
				run.violations.isEmpty,
				Comment(
					rawValue: DifferentialChecks.reproPrefix(seed)
						+ " \(run.violations)"))
		}
	}

	/// A standalone replay entry point for a single failure. Runs the FULL mixed-pair
	/// comparison — both directions plus ledger — so it reproduces every finding the sweep
	/// would, not just per-direction violations.
	@Test(.enabled(if: pinEnabled))
	func replayScript() throws {
		guard #available(macOS 26, *) else { return }
		let env = ProcessInfo.processInfo.environment
		guard let blob = env["DIFFERENTIAL_REPLAY_BLOB"],
			let seed = UInt64(env["DIFFERENTIAL_REPLAY_SEED"] ?? "0")
		else { return }
		let ledger = try DivergenceLedger.load()
		let script = try DiffScript.decoded(fromBlob: blob)
		let cmp = try DifferentialChecks.mixedFindings(
			script: script, seed: seed, ledger: ledger)
		print("replay seed \(seed) \(cmp.summary)")
		#expect(
			cmp.findings.isEmpty,
			Comment(
				rawValue: DifferentialChecks.replayPrefix(
					seed: seed, ledger: ledger) + "\n" + cmp.summary + "\n"
					+ cmp.findings.joined(separator: "\n")))
	}
}

/// The transcript alignment key: an op, the call label, and the role.
struct DifferentialKey: Hashable, Comparable {
	let op: Int
	let call: String
	let role: String

	static func < (l: DifferentialKey, r: DifferentialKey) -> Bool {
		(l.op, l.call, l.role) < (r.op, r.call, r.role)
	}
}

@available(macOS 26, iOS 26, *)
enum DifferentialChecks {
	static func replayPrefix(seed: UInt64, ledger: DivergenceLedger) -> String {
		ReproLine(
			seed: seed, blob: ScriptGenerator.generate(seed: seed).encodedBlob(),
			bindingContractVersion: bindingContractVersion(),
			rustSha: ledger.pin.twoMlsPqSha
		).description
	}

	static func reproPrefix(_ seed: UInt64) -> String {
		ReproLine(
			seed: seed, blob: ScriptGenerator.generate(seed: seed).encodedBlob(),
			bindingContractVersion: bindingContractVersion(),
			rustSha: (try? DivergenceLedger.load())?.pin.twoMlsPqSha ?? "unknown"
		).description
	}

	/// The result of a mixed-pair comparison: real findings, plus the count of
	/// offer/frame-presence divergences that were excluded.
	struct MixedComparison {
		var findings: [String] = []
		var presenceExcluded = 0
		var presenceByCall: [String: Int] = [:]
		var designedWedgeExcluded = 0
		var summary: String {
			let detail =
				presenceByCall.sorted { $0.key < $1.key }.map {
					"\($0.key)=\($0.value)"
				}
				.joined(separator: ",")
			return
				"offer-presence-divergences excluded: \(presenceExcluded) [\(detail)]"
				+ "  designed-wedge findings excluded: \(designedWedgeExcluded)"
				+ "  failing findings: \(findings.count)"
		}
	}

	/// Run the script in both mixed directions and return every finding.
	///
	/// COMPARISON CONTRACT (option a): cross-direction OFFER-PRESENCE divergence is excluded
	/// — a site where one direction had no live offer to fold (or no frame to deliver) is a
	/// presence difference, not a handling difference, and is reported as a NON-finding in
	/// the summary line. Per-frame offer HANDLING (both sides had the frame/offer), payloads,
	/// remoteCommitApplied, errorClass and the probe invariants still fail. Presence
	/// comparison stays live in the pure-pair oracles, where it is meaningful.
	static func mixedFindings(script: DiffScript, seed: UInt64, ledger: DivergenceLedger) throws
		-> MixedComparison
	{
		let swift = try run(script: script, seed: seed, direction: .swiftInitiator)
		let rust = try run(script: script, seed: seed, direction: .rustInitiator)

		var cmp = MixedComparison()
		cmp.findings = swift.violations + rust.violations
		cmp.designedWedgeExcluded =
			swift.designedWedgeViolations.count + rust.designedWedgeViolations.count
		// Behind-restore attribution: `op` postdates a fired behind-restore in either
		// direction. The negative op asserts CLEAN CLASSIFICATION, so a divergence that is
		// behind-attributed AND cleanly classified is a DESIGNED-WEDGE outcome.
		let behindOps =
			Array(swift.behindRestoredAt.values) + Array(rust.behindRestoredAt.values)
		func behindAttributed(_ op: Int) -> Bool { behindOps.contains { $0 < op } }
		// A misparse is never excused: an unclassified `.other`, or an unsupported tag the
		// error table does not equate.
		// `unsupportedFrameTag(_)` is a CLASSIFIED clean rejection — the engine recognised
		// the shape is wrong and refused — and `aeadOpenFailed` now equates to Rust's
		// `DecryptionFailed`. Only a genuinely unclassified `.other` (or a no-error wrong
		// behaviour) stays unclassified.
		func unclassified(_ o: ComparableOutcome) -> Bool {
			o.error == .other
		}

		// Align by (op, role, call). A key present in one direction and absent in the other —
		// or with a different multiplicity — is normally a divergence, but when the cause is
		// offer/frame PRESENCE it is classified out (see the contract above).
		func presenceLimited(_ key: DifferentialKey, _ run: RunResult) -> Bool {
			run.presenceLimited.contains(
				PresenceSite(op: key.op, role: key.role, call: key.call))
		}
		func classifyPresence(_ key: DifferentialKey) {
			cmp.presenceExcluded += 1
			cmp.presenceByCall[key.call, default: 0] += 1
		}

		let groups = [swift.transcript, rust.transcript].map(grouped)
		for key in Set(groups[0].keys).union(groups[1].keys).sorted() {
			let a = groups[0][key] ?? []
			let b = groups[1][key] ?? []
			let presenceDivergent =
				presenceLimited(key, swift) || presenceLimited(key, rust)
			if a.count != b.count {
				// A fold/deliver CALL-COUNT difference is BY CONSTRUCTION an offer/frame
				// PRESENCE difference: the op folds (or delivers) whatever is present, so a
				// differing multiplicity means the two directions had different numbers of
				// live offers (or queued frames) — never different handling of the same one.
				// Handling is compared only where both directions recorded the call.
				if presenceDivergent || key.call == "queueProposal"
					|| key.call == "deliver"
				{
					classifyPresence(key)
					continue
				}
				cmp.findings.append(
					"op \(key.op) \(key.call) role \(key.role): call count differs swiftInitiator=\(a.count) rustInitiator=\(b.count)"
				)
				continue
			}
			for i in 0..<min(a.count, b.count) {
				for field in a[i].outcome.mismatches(b[i].outcome) {
					// `offeredDigest` is compared as PRESENCE only (digests are
					// content-dependent and differ between runs by construction), so a
					// mismatch here IS an offer-presence difference — excluded.
					if field == "offeredDigest" {
						classifyPresence(key)
						continue
					}
					// Attribute to the ENGINE at that role in each direction, and require BOTH
					// sides to be documented before excusing.
					let excusedA =
						ledger.matches(
							field: field, engine: a[i].engine,
							call: key.call) != nil
					let excusedB =
						ledger.matches(
							field: field, engine: b[i].engine,
							call: key.call) != nil
					if excusedA && excusedB { continue }
					// A mismatch whose cause is one side having NO live offer/frame is a
					// presence difference, not a handling one.
					if presenceDivergent {
						classifyPresence(key)
						continue
					}
					if behindAttributed(key.op)
						&& !unclassified(a[i].outcome)
						&& !unclassified(b[i].outcome)
					{
						cmp.designedWedgeExcluded += 1
						continue
					}
					cmp.findings.append(
						"op \(key.op) \(key.call) role \(key.role): field \(field) — swiftInitiator[\(a[i].engine)]=\(a[i].outcome) rustInitiator[\(b[i].engine)]=\(b[i].outcome)"
							+ " [swiftInitiatorErr=\(a[i].outcome.errorText ?? "-") rustInitiatorErr=\(b[i].outcome.errorText ?? "-")]"
					)
				}
			}
		}
		return cmp
	}

	static func purePair(seed: UInt64) throws -> RunResult {
		let script = ScriptGenerator.generate(seed: seed)
		return try run(
			script: script, seed: seed,
			direction: seed % 2 == 0 ? .swiftPair : .rustPair)
	}

	private static func run(script: DiffScript, seed: UInt64, direction: Direction) throws
		-> RunResult
	{
		let pair = try PairFactory.make(direction, seed: seed)
		var run = DifferentialRun(
			pair: pair, script: script, seed: seed, direction: direction)
		return run.run()
	}

	private static func grouped(_ transcript: [TranscriptEntry]) -> [DifferentialKey:
		[TranscriptEntry]]
	{
		var groups: [DifferentialKey: [TranscriptEntry]] = [:]
		for entry in transcript {
			let key = DifferentialKey(
				op: entry.opIndex, call: entry.call, role: entry.role.rawValue)
			groups[key, default: []].append(entry)
		}
		return groups
	}
}
