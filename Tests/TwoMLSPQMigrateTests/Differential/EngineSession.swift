import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQBinding
import TwoMLSPQSession

// Testable only to read the Swift engine's internal currently-held offer, for the
// fold-staleness diagnostic (no public accessor exists).
@testable import TwoMLSPQSession

// The unified session facade. One protocol over the Swift engine (`TwoMLSSession`, the
// twomlspq-swift dependency) and the Rust engine (`TwoMLSPQBinding.TwoMlsPqSession`),
// mapping both onto a normalized `OutcomeStep` so the runner can compare them op by op.
//
// API-INTERSECTION CONSTRAINT (plan step 1): this file compiles against BOTH main's
// binding and the deployed pin's (c501f9d) binding. The pin's session surface is a
// strict subset of main's — the only main-only additions are `migrationExport()` and the
// `SessionMigration*` record types — so the facade must never touch either. Verified by
// diffing the public protocol surface of the two bindings (see README.md).

enum EngineIdentity: String, Sendable {
	case swift
	case rust
}

/// The normalized error classes the harness equates across engines. Everything else folds
/// into `.other` (see the equivalence table in `errorClass`).
enum ErrorClass: String, Codable, Equatable, Sendable {
	case stale
	case duplicate
	case epochDesync
	case decryptionFailed
	case misrouted
	case unopenable
	case notReady
	/// Swift refuses a rotation proposed while an earlier one is still in flight; the
	/// deployed Rust engine has no such guard (a real differential).
	case rotationInFlight
	case other
}

/// One op's normalized observable outcome, for either engine.
struct OutcomeStep: Equatable, Sendable {
	/// Application payloads surfaced by this call, in order. Kept separate from `joined`
	/// so the approved-handoff payload asymmetry (Rust surfaces the stapled payload,
	/// Swift's `.joined` carries none) is observable rather than conflated.
	var appPayloads: [Data] = []
	/// Whether this call performed a first join (or an approved handoff join).
	var joined = false
	/// Whether this call paused on a `0x0B` establishment handoff.
	var pendingEstablishment = false
	/// The peer's staged proposal digest, when one was surfaced.
	var offeredDigest: Data?
	/// Diagnostics only (never compared): the surfaced offer's full shape, so a fold can be
	/// classified as stale / consumed / catch-up.
	var offeredProposing: Data?
	var offeredContext: Data?
	var offeredSender: Data?
	var offerIsCatchUp: Bool?
	/// Whether this call applied a remote commit.
	var remoteCommitApplied = false
	/// The error class, when the call threw.
	var errorClass: ErrorClass?
	/// The raw error description, for diagnostics only (never compared).
	var errorText: String?
}

/// A session's outstanding side-band round kind, normalized across engines.
enum SideBandKind: String, Sendable, CaseIterable {
	case bootstrapKP
	case bootstrapWelcome
	case ratchetEK
	case ratchetCT
	case rekeyUpd
	case rekeyCommit
}

struct PrepareOutcome: Equatable, Sendable {
	let didCommit: Bool
}

struct EmittedFrame: Equatable, Sendable {
	let bytes: Data
}

enum BlobSnapshotKind: String, Sendable {
	case core
	case checkpoint
}

/// Metadata for a persistable blob the harness captured, keyed by durability seq. The
/// payload itself stays in each adapter (Rust `Archive` bytes, Swift `SecretArchive`), so
/// the scheduler can reason about legal restore points without touching secrets.
struct RecordedBlob: Sendable, Equatable {
	let seq: UInt64
	let kind: BlobSnapshotKind
}

@available(macOS 26, iOS 26, *)
protocol EngineSession: AnyObject {
	var engine: EngineIdentity { get }
	func isFullyEstablished() -> Bool
	/// Whether a rotation this party authored is still un-canonicalized — a real host does
	/// not propose a second rotation while one is in flight, so the harness gates on this.
	func hasPendingRotation() -> Bool
	/// The sender's classical send-group epoch (for the double-commit-in-flight check).
	func sendEpoch() -> UInt64
	/// The durability seq of the most recent state-advancing call (0 before any).
	func lastStateSeq() -> UInt64
	/// Every blob this session has handed back so far (for legal restore points).
	func recordedBlobs() -> [RecordedBlob]
	/// The highest durability seq the host has actually PERSISTED for this session — what
	/// "persist before send" must be checked against.
	func maxPersistedSeq() -> UInt64

	@discardableResult func prepareToEncrypt(proposing: Data?) throws -> PrepareOutcome
	func encrypt(_ payload: Data) throws -> EmittedFrame
	func processIncoming(_ frame: Data) throws -> OutcomeStep
	func processIncomingApproved(
		_ frame: Data, envelope: Data, welcome: Data, creator: Data
	) throws -> OutcomeStep
	func queueProposal(digest: Data) throws
	/// This session's SEND-group classical context — the value an offer's `context` field
	/// must equal for the offer to be foldable here (a mismatch means the offer came from a
	/// stale send-group epoch).
	func proposalContext() -> Data?
	/// Diagnostics: the digest of the offer the engine currently holds, or nil if none/unknown.
	func debugHeldOfferDigest() -> Data?
	/// Diagnostics: this session's own and the peer's canonical client ids.
	func principalStateIDs() -> (mine: Data?, theirs: Data?)
	/// Diagnostics: a compact state line (durability seq, send epoch, PQ turn, wedged flag,
	/// established flags) for the row-3 first-divergent-op search.
	func debugStateLine() -> String
	/// Diagnostics: the raw bytes of the offer the Swift engine currently holds (for the
	/// fold-guard replica). Rust exposes no equivalent.
	func debugHeldOfferMessage() -> Data?
	/// Diagnostics: run the fold-guard replica on the currently-held offer, returning a
	/// one-line report. Nil when unavailable (Rust, or nothing held).
	func debugReplicaGuards() -> String?
	/// Whether the engine still holds an offer that VERIFIES at the current group epoch —
	/// a host's "is this still foldable" check. Nil when the engine exposes no equivalent.
	func offerStillVerifies() -> Bool?

	// Side-band. `sideBandLeg` peeks the pending outbound (an auto-staged A.4/A.5 leg or
	// a parked A.3 welcome'); `sideBandRespond` answers a peer's opener leg and returns this
	// side's answering leg (nil when the engine holds nothing to send back); `sideBandApply`
	// applies the peer's answering leg; `openKind` classifies a leg the way a host routes it.
	func sideBandLeg() throws -> Data?
	func sideBandRespond(_ opener: Data) throws -> Data?
	func sideBandApply(_ leg: Data) throws
	func openKind(_ blob: Data) throws -> SideBandKind?

	/// Restore this session in place from its own recorded blobs at `seq`.
	func restore(toSeq seq: UInt64) throws
}

// MARK: - Rust adapter

/// Captures the Rust engine's push-sink blobs. A restored Rust session has no sink, so the
/// adapter re-installs this SAME instance after a restore — keeping every blob already
/// recorded resolvable, so a later restore targeting a pre-restore seq still finds it.
@available(macOS 26, iOS 26, *)
final class RecordingSink: ArchiveSink, @unchecked Sendable {
	private let lock = NSLock()
	private var blobs: [RecordedBlob] = []
	private var payloads: [String: Data] = [:]

	func persist(seq: UInt64, kind: TwoMLSPQBinding.BlobKind, archive: Data) {
		let snapshotKind: BlobSnapshotKind = kind == .core ? .core : .checkpoint
		lock.lock()
		blobs.append(RecordedBlob(seq: seq, kind: snapshotKind))
		payloads[RecordedBlob(seq: seq, kind: snapshotKind).key] = archive
		lock.unlock()
	}

	func recorded() -> [RecordedBlob] {
		lock.lock()
		defer { lock.unlock() }
		return blobs
	}

	func payload(seq: UInt64, kind: BlobSnapshotKind) -> Data? {
		lock.lock()
		defer { lock.unlock() }
		return payloads[RecordedBlob(seq: seq, kind: kind).key]
	}
}

extension RecordedBlob {
	var key: String { "\(kind.rawValue)#\(seq)" }
}

@available(macOS 26, iOS 26, *)
final class RustEngineSession: EngineSession {
	let engine: EngineIdentity = .rust
	private var session: TwoMLSPQBinding.TwoMlsPqSession
	private var sink = RecordingSink()
	private var lastSeq: UInt64 = 0

	init(session: TwoMLSPQBinding.TwoMlsPqSession) throws {
		self.session = session
		try session.installSink(sink: sink)
		lastSeq = session.stateSeq()
	}

	private func drainSink() { lastSeq = max(lastSeq, session.stateSeq()) }

	func isFullyEstablished() -> Bool { session.isFullyEstablished() }
	func hasPendingRotation() -> Bool {
		if case .pending = session.myPrincipalState() { return true }
		return false
	}
	func sendEpoch() -> UInt64 { session.epochs().classicalEpoch }
	func lastStateSeq() -> UInt64 { max(lastSeq, session.stateSeq()) }
	func recordedBlobs() -> [RecordedBlob] { sink.recorded() }
	func maxPersistedSeq() -> UInt64 { sink.recorded().map(\.seq).max() ?? 0 }

	func prepareToEncrypt(proposing: Data?) throws -> PrepareOutcome {
		let result = try session.prepareToEncrypt(
			proposing: proposing.map { TwoMLSPQBinding.ClientId(bytes: $0) })
		drainSink()
		return PrepareOutcome(didCommit: result.didCommit)
	}

	func encrypt(_ payload: Data) throws -> EmittedFrame {
		let result = try session.encrypt(appMessage: payload)
		drainSink()
		return EmittedFrame(bytes: result.cipherText)
	}

	func processIncoming(_ frame: Data) throws -> OutcomeStep {
		let result = try session.processIncoming(ciphertext: frame)
		drainSink()
		return Self.normalize(result)
	}

	func processIncomingApproved(
		_ frame: Data, envelope: Data, welcome: Data, creator: Data
	) throws -> OutcomeStep {
		let result = try session.processIncomingApproved(
			ciphertext: frame,
			approvedEnvelopeDigest: Data(SHA256.hash(data: envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: welcome)),
			expectedCreator: creator)
		drainSink()
		var step = Self.normalize(result)
		// Canonical rule: an approved handoff always counts as a join, on both engines.
		step.joined = true
		return step
	}

	func queueProposal(digest: Data) throws {
		try session.queueProposal(digest: digest)
		drainSink()
	}

	func proposalContext() -> Data? { session.proposalContext() }
	/// The Rust binding exposes no held-offer accessor; the fold outcome itself reports it.
	func debugHeldOfferDigest() -> Data? { nil }
	func debugHeldOfferMessage() -> Data? { nil }
	func debugReplicaGuards() -> String? { nil }
	func offerStillVerifies() -> Bool? { nil }
	func debugStateLine() -> String {
		"seq=\(lastStateSeq()) epoch=\(session.epochs().classicalEpoch) pqTurn=\(session.myPqTurn()) wedged=\(session.pqSideBandWedged()) est=\(session.isEstablished()) full=\(session.isFullyEstablished())"
	}
	func principalStateIDs() -> (mine: Data?, theirs: Data?) {
		func id(_ s: TwoMLSPQBinding.PrincipalState) -> Data {
			switch s {
			case .sync(let c): return c.bytes
			case .pending(let old, _): return old.bytes
			}
		}
		return (id(session.myPrincipalState()), id(session.theirPrincipalState()))
	}

	func sideBandLeg() throws -> Data? {
		let leg = session.pqPendingOutbound(sealing: .fresh)
		drainSink()
		return leg
	}

	func sideBandRespond(_ opener: Data) throws -> Data? {
		switch try openKind(opener) {
		case .bootstrapKP:
			try session.pqBootstrapRespond(kpMsg: opener)
		case .ratchetEK:
			try session.pqRatchetRespond(ekMsg: opener)
		case .rekeyUpd:
			_ = try session.pqRekeyRespond(updMsg: opener)
		default:
			return nil
		}
		let leg = session.pqTakePendingOutbound()
		drainSink()
		return leg
	}

	func sideBandApply(_ leg: Data) throws {
		switch try openKind(leg) {
		case .bootstrapWelcome:
			try session.pqBootstrapBind(welcomeMsg: leg)
		case .ratchetCT:
			try session.pqRatchetBind(ctMsg: leg)
		case .rekeyCommit:
			try session.pqRekeyApply(msg: leg)
		default:
			throw HarnessError.unexpectedSideBandLeg
		}
		drainSink()
	}

	func openKind(_ blob: Data) throws -> SideBandKind? {
		guard let opened = try session.openIncoming(blob: blob) else { return nil }
		guard case .pqSideBand(let kind) = opened.kind else { return nil }
		return Self.normalize(kind)
	}

	func restore(toSeq seq: UInt64) throws {
		let core = latestBlob(kind: .core, atOrBefore: seq)
		let checkpoint = latestBlob(kind: .checkpoint, atOrBefore: seq)
		// No checkpoint recorded at or before `seq`: a no-op, so both engines behave
		// identically for a restore point neither can reach.
		guard checkpoint != nil else { return }
		session = try TwoMLSPQBinding.TwoMlsPqSession.restore(
			core: core.map { TwoMLSPQBinding.Archive(bytes: $0) },
			checkpoint: checkpoint.map { TwoMLSPQBinding.Archive(bytes: $0) })
		// A restored session has no sink. Re-install the SAME sink (never a fresh one), so
		// the blobs already recorded stay resolvable — otherwise a second restore targeting
		// a pre-restore seq would no-op on Rust while Swift still resolves it.
		try session.installSink(sink: sink)
		lastSeq = session.stateSeq()
	}

	private func latestBlob(kind: BlobSnapshotKind, atOrBefore seq: UInt64) -> Data? {
		sink.recorded()
			.filter { $0.kind == kind && $0.seq <= seq }
			.max { $0.seq < $1.seq }
			.flatMap { sink.payload(seq: $0.seq, kind: $0.kind) }
	}

	private static func normalize(_ result: TwoMLSPQBinding.DecryptResult?) -> OutcomeStep {
		guard let result else { return OutcomeStep() }
		var step = OutcomeStep()
		if let app = result.applicationMessage {
			step.appPayloads.append(app.appMessageData)
		}
		if let proposal = result.proposal {
			step.offeredDigest = proposal.digest
			step.offeredProposing = proposal.proposing.bytes
			step.offeredContext = proposal.context
			step.offeredSender = proposal.sender.bytes
		}
		if result.remoteCommit != nil { step.remoteCommitApplied = true }
		if result.pendingEstablishment != nil { step.pendingEstablishment = true }
		return step
	}

	private static func normalize(_ kind: TwoMLSPQBinding.PqFrameKind) -> SideBandKind {
		switch kind {
		case .bootstrapKeyPackage: return .bootstrapKP
		case .bootstrapWelcome: return .bootstrapWelcome
		case .ratchetEphemeralKey: return .ratchetEK
		case .ratchetCiphertext: return .ratchetCT
		case .rekeyUpdate: return .rekeyUpd
		case .rekeyCommit: return .rekeyCommit
		}
	}
}

// MARK: - Swift adapter

@available(macOS 26, iOS 26, *)
final class SwiftEngineSession: EngineSession {
	let engine: EngineIdentity = .swift
	private var session: TwoMLSSession
	private let classicalProvider: any MLS.CipherSuiteProvider
	private let pqProvider: any MLS.CipherSuiteProvider
	private var lastSeq: UInt64 = 0
	private var metas: [RecordedBlob] = []
	private var payloads: [String: SecretArchive] = [:]

	init(
		session: TwoMLSSession,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) {
		self.session = session
		self.classicalProvider = classicalProvider
		self.pqProvider = pqProvider
	}

	private func record(_ update: TwoMLSPQSession.StateUpdate) {
		let kind: BlobSnapshotKind = update.kind == .core ? .core : .checkpoint
		let meta = RecordedBlob(seq: update.stateSeq, kind: kind)
		metas.append(meta)
		payloads[meta.key] = update.archive
		lastSeq = max(lastSeq, update.stateSeq)
	}

	func isFullyEstablished() -> Bool { session.isFullyEstablished }
	func hasPendingRotation() -> Bool {
		if case .pending = session.myPrincipalState { return true }
		return false
	}
	func sendEpoch() -> UInt64 { session.epochs.classicalEpoch }
	func lastStateSeq() -> UInt64 { lastSeq }
	func recordedBlobs() -> [RecordedBlob] { metas }
	func maxPersistedSeq() -> UInt64 { metas.map(\.seq).max() ?? 0 }

	func prepareToEncrypt(proposing: Data?) throws -> PrepareOutcome {
		let result = try session.prepareToEncrypt(rotating: proposing)
		record(result.update)
		return PrepareOutcome(didCommit: result.didCommit)
	}

	func encrypt(_ payload: Data) throws -> EmittedFrame {
		let result = try session.encrypt(payload)
		record(result.update)
		return EmittedFrame(bytes: result.frame)
	}

	func processIncoming(_ frame: Data) throws -> OutcomeStep {
		Self.normalize(try session.processIncoming(frame))
	}

	func processIncomingApproved(
		_ frame: Data, envelope: Data, welcome: Data, creator: Data
	) throws -> OutcomeStep {
		let result = try session.processIncomingApproved(
			frame,
			approvedEnvelopeDigest: Data(SHA256.hash(data: envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: welcome)),
			expectedCreator: creator)
		var step = Self.normalize(result)
		step.joined = true
		return step
	}

	func queueProposal(digest: Data) throws {
		record(try session.queueProposal(digest: digest))
	}

	func proposalContext() -> Data? { session.proposalContext() }
	func debugHeldOfferDigest() -> Data? { session.offeredProposal?.digest }
	func debugHeldOfferMessage() -> Data? { session.offeredProposal?.message }
	func offerStillVerifies() -> Bool? {
		guard let message = session.offeredProposal?.message,
			let send = session.sendGroup?.classical,
			let msg = try? MLS.RFC9420.Message(mlsEncoded: message),
			case .publicMessage(let pub) = msg
		else { return false }
		return (try? send.verifying(classicalProvider, proposal: pub)) != nil
	}
	func debugReplicaGuards() -> String? {
		guard let message = session.offeredProposal?.message else { return nil }
		let r = FoldGuardReplica.run(
			message: message, session: session, classicalProvider: classicalProvider)
		let failing =
			r.checks.filter { !$0.ok }.map { "\($0.name)(\($0.detail))" }.joined(
				separator: "; ")
		let advert = r.checks.last { $0.name == "leaf-advertised" }?.detail ?? ""
		let pres = r.checks.last { $0.name == "presentation-changed" }?.detail ?? ""
		return "replicaVerdict=\(r.verdict) failing=[\(failing)] \(advert) \(pres)"
	}
	func principalStateIDs() -> (mine: Data?, theirs: Data?) {
		(session.myPrincipalState.clientID, session.theirPrincipalState.clientID)
	}
	func debugStateLine() -> String {
		"seq=\(lastSeq) epoch=\(session.epochs.classicalEpoch) pqTurn=\(session.myPQTurn) wedged=\(session.pqSideBandWedged) est=\(session.isEstablished) full=\(session.isFullyEstablished)"
	}

	func sideBandLeg() throws -> Data? { session.pqPendingOutbound() }

	func sideBandRespond(_ opener: Data) throws -> Data? {
		guard let kind = try openKind(opener) else { return nil }
		let result: TwoMLSPQSession.SideBandResult
		switch kind {
		case .bootstrapKP: result = try session.pqBootstrapRespond(opener)
		case .ratchetEK: result = try session.pqRatchetRespond(opener)
		case .rekeyUpd: result = try session.pqRekeyRespond(opener)
		default: return nil
		}
		record(result.update)
		return result.frame
	}

	func sideBandApply(_ leg: Data) throws {
		switch try openKind(leg) {
		case .bootstrapWelcome: record(try session.pqBootstrapJoin(leg))
		case .ratchetCT: record(try session.pqRatchetBind(leg))
		case .rekeyCommit: record(try session.pqRekeyApply(leg))
		default: throw HarnessError.unexpectedSideBandLeg
		}
	}

	func openKind(_ blob: Data) throws -> SideBandKind? {
		guard let opened = try session.openIncoming(blob) else { return nil }
		guard case .pqSideBand(let kind) = opened.kind else { return nil }
		return Self.normalize(kind)
	}

	func restore(toSeq seq: UInt64) throws {
		let core = latestArchive(kind: .core, atOrBefore: seq)
		// No checkpoint recorded at or before `seq`: a no-op, so both engines behave
		// identically for a restore point neither can reach.
		guard let checkpoint = latestArchive(kind: .checkpoint, atOrBefore: seq) else {
			return
		}
		session = try TwoMLSSession.restore(
			core: core,
			checkpoint: checkpoint,
			classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		lastSeq = seq
	}

	private func latestArchive(kind: BlobSnapshotKind, atOrBefore seq: UInt64) -> SecretArchive?
	{
		metas
			.filter { $0.kind == kind && $0.seq <= seq }
			.max { $0.seq < $1.seq }
			.flatMap { payloads[$0.key] }
	}

	private static func normalize(_ result: TwoMLSPQSession.IncomingResult) -> OutcomeStep {
		var step = OutcomeStep()
		switch result {
		case .decrypted(let decrypted):
			step.appPayloads.append(decrypted.applicationMessage)
			step.offeredDigest = decrypted.queuedProposal.digest
			step.offeredProposing = decrypted.queuedProposal.proposing
			step.offeredContext = decrypted.queuedProposal.context
			step.offerIsCatchUp = decrypted.queuedProposal.isCatchUp
			step.remoteCommitApplied = decrypted.didApplyRemoteCommit
		case .joined:
			step.joined = true
		case .pendingEstablishment:
			step.pendingEstablishment = true
		case .ignored:
			break
		case .preEstablishment(let message):
			step.appPayloads.append(message.applicationMessage)
		}
		return step
	}

	private static func normalize(_ kind: TwoMLSSession.PqFrameKind) -> SideBandKind {
		switch kind {
		case .bootstrapKP: return .bootstrapKP
		case .bootstrapWelcome: return .bootstrapWelcome
		case .ratchetEK: return .ratchetEK
		case .ratchetCT: return .ratchetCT
		case .rekeyUpd: return .rekeyUpd
		case .rekeyCommit: return .rekeyCommit
		}
	}
}

// MARK: - Error-class equivalence table

enum HarnessError: Error {
	case unexpectedSideBandLeg
	case missingBlob
}

/// The written equivalence table over the ~60 Swift and ~32 Rust error cases. Only the
/// handful that matter for scheduler faults are equated; everything else maps to
/// `.other`, which the runner treats as a divergence when the two engines disagree on it.
func errorClass(_ error: Error) -> ErrorClass? {
	if let swift = error as? TwoMLSError {
		switch swift {
		case .staleFrame: return .stale
		case .duplicateWelcome, .duplicateSideBand: return .duplicate
		case .epochDesync: return .epochDesync
		case .decryptionFailed: return .decryptionFailed
		case .misroutedSpawnToken: return .misrouted
		case .unexpectedWelcome, .unsupportedFrameTag, .unsupportedStapleTag,
			.unsupportedSideBandTag, .unsupportedEstablishmentTag,
			.malformedSideBandMessage, .malformedEstablishmentMessage:
			return .unopenable
		case .sessionNotReady, .notEstablished: return .notReady
		case .rotationInFlight: return .rotationInFlight
		default: return .other
		}
	}
	if let rust = error as? TwoMlsPqError {
		switch rust {
		case .StaleFrame: return .stale
		case .DuplicateWelcome, .DuplicateSideBand: return .duplicate
		case .EpochDesync: return .epochDesync
		case .DecryptionFailed: return .decryptionFailed
		case .UnexpectedWelcome, .MissingWelcome, .InvalidKeyPackage, .Mls:
			return .unopenable
		case .SessionNotReady, .SessionNotEstablished: return .notReady
		default: return .other
		}
	}
	let text = String(describing: error)
	// The Swift engine sometimes surfaces an underlying MLS error un-wrapped, where Rust
	// classifies the same condition with its own case — equate them by text so the
	// difference is not mistaken for a divergence.
	if text.contains("generationAlreadyConsumed") { return .stale }
	// Same rejection as Rust's `DecryptionFailed`: AEAD open failure.
	if text.contains("aeadOpenFailed") { return .decryptionFailed }
	return nil
}
