import Foundation

// The known-divergence ledger. A mixed-pair mismatch whose field+engine matches an entry
// is recorded, not failed (the entry states the healing condition); anything else is a
// finding. Shipped as a JSON resource so `swift format lint` never has to digest a large
// Swift literal.

struct DivergenceLedger: Decodable {
	struct Entry: Decodable {
		let id: String
		let anomaly: String
		let title: String
		let engines: [String]
		/// The `OutcomeStep` fields this anomaly can explain.
		let fields: [String]
		/// The calls (`DifferentialRun`'s transcript `call` labels) the anomaly can surface on.
		let calls: [String]
		let healing: String
	}

	struct Pin: Decodable {
		let twoMlsPqSha: String
		let mlsRsSha: String
	}

	let bindingContractVersion: UInt64
	let pin: Pin
	let entries: [Entry]

	static func load() throws -> DivergenceLedger {
		guard
			let url = Bundle.module.url(
				forResource: "DivergenceLedger", withExtension: "json",
				subdirectory: "DifferentialResources")
		else { throw LedgerError.resourceMissing }
		return try JSONDecoder().decode(DivergenceLedger.self, from: Data(contentsOf: url))
	}

	/// The entry (if any) that excuses a mismatch on `field` attributable to `engine` on
	/// `call`. Narrowed by call so a field match cannot suppress an unrelated divergence.
	func matches(field: String, engine: EngineIdentity, call: String) -> Entry? {
		entries.first {
			$0.fields.contains(field) && $0.engines.contains(engine.rawValue)
				&& $0.calls.contains(call)
		}
	}

	enum LedgerError: Error { case resourceMissing }
}
