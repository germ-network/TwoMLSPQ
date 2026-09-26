import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQSession

// Internal engine guards are replicated directly, so this file is @testable.
@testable import TwoMLSPQSession

// A test-side REPLICA of the Swift engine's `validateOfferedUpdate` guard sequence, run on
// a dumped offered proposal so a `proposalRejected` fold rejection can be pinned to the
// exact guard that fires — without touching engine source. Read-only: it only verifies.
//
// The engine lumps several guards into `.proposalRejected`, so the replica runs each check
// independently and reports every failure (not just the first), plus the leaf's advertised
// capabilities, which is the evidence for the Rust-side advert question.

@available(macOS 26, iOS 26, *)
enum FoldGuardReplica {
	struct Result {
		var checks: [(name: String, ok: Bool, detail: String)] = []
		var verdict: String { checks.first { !$0.ok }?.name ?? "all-pass" }
		var failing: [String] { checks.filter { !$0.ok }.map(\.name) }
	}

	static func run(
		message: Data,
		session: TwoMLSSession,
		classicalProvider: any MLS.CipherSuiteProvider
	) -> Result {
		var r = Result()
		func note(_ name: String, _ ok: Bool, _ detail: String = "") {
			r.checks.append((name, ok, detail))
		}

		guard let send = session.sendGroup?.classical else {
			note("send-group-present", false)
			return r
		}
		note("send-group-present", true)

		guard let msg = try? MLS.RFC9420.Message(mlsEncoded: message),
			case .publicMessage(let pub) = msg
		else {
			note("decode-public-message", false)
			return r
		}
		note("decode-public-message", true)

		let verified: MLS.RFC9420.VerifiedProposal
		do {
			verified = try send.verifying(classicalProvider, proposal: pub)
		} catch {
			note("verifying(proposal:)", false, "\(error)")
			return r
		}
		note("verifying(proposal:)", true)

		guard case .update(let leafNode) = verified.proposal,
			case .member(let senderLeaf) = verified.sender
		else {
			note("proposal-is-peer-update", false)
			return r
		}
		note("proposal-is-peer-update", true)

		guard senderLeaf != send.myLeafIndex else {
			note("sender-is-not-me", false)
			return r
		}
		note("sender-is-not-me", true)

		guard let currentRecord = send.tree.leaf(at: senderLeaf),
			let currentLeaf = try? MLS.RFC9420.LeafNode(
				mlsEncoded: currentRecord.encoded)
		else {
			note("current-leaf-present", false)
			return r
		}
		note("current-leaf-present", true)

		// The five extra guards, each run individually.
		do {
			try leafNode.verifySignature(
				classicalProvider,
				placement: .inGroup(
					groupID: send.context.groupID, leafIndex: senderLeaf))
			note("verifySignature", true)
		} catch {
			note("verifySignature", false, "\(error)")
		}

		let leaves = send.tree.nonBlankLeaves()
		var byLeaf: [MLS.LeafIndex: MLS.RFC9420.Capabilities] = [:]
		var credentialTypes: Set<MLS.RFC9420.CredentialType> = []
		for entry in leaves {
			guard
				let n = try? MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded)
			else { continue }
			byLeaf[entry.index] = n.capabilities
			credentialTypes.insert(n.credential.credentialType)
		}
		do {
			try leafNode.validatePolicy(
				.updateProposal(replacing: currentLeaf),
				groupRequirements: try send.context.extensions
					.requiredCapabilities(),
				memberCredentialTypes: credentialTypes,
				memberCapabilities: Array(byLeaf.values))
			note("validatePolicy", true)
		} catch {
			note("validatePolicy", false, "\(error)")
		}

		// The advert family. NOTE: in the engine these throw `leafCapabilityUnadvertised`,
		// NOT `proposalRejected` — so a `proposalRejected` rejection cannot originate here.
		let codepoints = session.codepoints
		let advertAPQ =
			leafNode.capabilities.extensions.contains(codepoints.apqInfoExtensionType)
			&& leafNode.capabilities.proposals.contains(
				MLS.RFC9420.ProposalType(.appDataUpdate))
		let appBound = (try? AppBinding.read(fromExtensionsOf: send.context)) != nil
		let advertAppBinding =
			!appBound
			|| leafNode.capabilities.extensions.contains(
				MLS.RFC9420.ExtensionType(rawValue: 0xF0A2))
		let recordedProfile =
			(try? SessionProfile.recorded(in: send.context)) ?? .deployedCompatible
		let advertProfile =
			recordedProfile.extensionType.map {
				leafNode.capabilities.extensions.contains($0)
			} ?? true
		note("advert-APQInfo+AppDataUpdate", advertAPQ, "appBound=\(appBound)")
		note("advert-AppBinding", advertAppBinding)
		note("advert-profile", advertProfile)

		guard case .basic(let offeredID) = leafNode.credential else {
			note("credential-is-basic", false, "non-basic credential")
			return r
		}
		note("credential-is-basic", true)

		// Evidence: what the leaf actually advertises.
		let exts = leafNode.capabilities.extensions.map {
			String(format: "0x%04X", $0.rawValue)
		}
		let props = leafNode.capabilities.proposals.map {
			String(format: "0x%04X", $0.rawValue)
		}
		note(
			"leaf-advertised", true,
			"extensions=[\(exts.joined(separator: ","))] proposals=[\(props.joined(separator: ","))] appBound=\(appBound) profile=\(recordedProfile) offeredID=\(offeredID.hexShort)"
		)

		let presentationChanged =
			currentLeaf.credential != leafNode.credential
			|| currentLeaf.signatureKey != leafNode.signatureKey
		let currentID = (try? basicIdentifier(currentLeaf.credential)) ?? Data()
		note(
			"presentation-changed", true,
			"changed=\(presentationChanged) sameID=\(currentID == offeredID)"
		)
		return r
	}
}

extension Data {
	var hexShort: String { map { String(format: "%02x", $0) }.prefix(10).joined() }
}
