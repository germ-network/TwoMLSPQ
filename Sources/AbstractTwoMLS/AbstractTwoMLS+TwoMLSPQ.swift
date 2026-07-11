//
//  AbstractTwoMLS+TwoMLSPQ.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/23/26.
//
//  Conforms the TwoMLSPQ UniFFI types to the AbstractTwoMLS protocol surface.
//
//  The abstraction speaks `Data`/`TypedDigest` while TwoMLSPQ wraps identity
//  bytes in single-field structs (`ClientId`, …), and several abstract members
//  collide with the generated methods only on return type — so the conformances
//  are thin adapter types in the `AbstractTwoMLS` namespace rather than
//  extensions on the generated classes. The generated module stays pristine.
//
//  Status (TwoMLSPQ 0.0.10 binding):
//   - `PQSession`, the six result adapters, `PQClient`, and `PQInvitation` are wired:
//     routing (`shouldListenOn`/`sendRendezvous`), the true APQ epoch pair on encrypt
//     results, A.5 rekey (`begin(.rekey)`); agent rotation — `receive(newClientId:)`
//     stages the dedicated agent, `prepareToEncrypt(proposing:)` commits the Phase 8
//     handoff, `begin(.rekey/.finishBootstrap, rotating:)` moves the PQ leaves (the
//     peer reads `PQInbound.rotatedCredential`); forward routing — a replayed initial
//     frame decodes as `.forward` via the invitation's spawn-token table
//     (the `WelcomeToken` opaque token), acknowledged by the
//     spawned session via `forwarded(headerDecrypted:)`.
//   - Session archive/restore is total: `PQSession.archive` / `init(archive:)` ride
//     0.0.10's self-contained `fromArchive(archive:)` (no owning client).
//

import CommProtocol
import Foundation
import TwoMLSPQ

// MARK: - Errors

public enum TwoMLSPQConformanceError: Error {
	/// The remote key package's credential does not match the authenticated
	/// remote identity extracted from the validated welcome.
	case remoteIdentityMismatch
	/// The initial-message header envelope failed to parse.
	case malformedHeaderFrame
	/// A.3 ratchet rounds inject a PSK with no updatePath, so `begin(.ratchet,
	/// rotating:)` has nothing to carry a new leaf credential — rotations ride
	/// `.rekey` (A.5) or `.finishBootstrap` (A.4).
	case rotationCannotRideRatchet
	/// No TwoMLSPQ FFI surface backs this abstract member yet.
	case notImplemented(String)
}

// MARK: - Binding/binary pairing guard

/// The uniffi Record-shape contract this vendored binding was generated against.
/// Must equal TwoMLSPQ's `BINDING_CONTRACT_VERSION`; update it as part of the
/// binding re-sync ritual (binding + binary from the SAME build).
///
/// Uniffi's own load-time checksums cover function signatures only — a Record
/// can change shape with every checksum unchanged, and the mismatch then traps
/// at the first FFI buffer read mid-flow. This check fails fast instead, at the
/// first client/invitation construction.
// v2: TwoMlsPqDigest removed from the FFI — digests are raw 32-byte SHA-256 values,
// typed on this side by `liftDigest`.
// v3: TwoMlsPqError gained UnsupportedCipherSuite.
// v4: TwoMlsPqError gained CipherSuiteMismatch; MlsCipherSuite.isSupported -> isCombinerPq;
//     AgentState -> PrincipalState.
// v5: TwoMlsPqError gained InvitationSpent; generateInvitation gained a lastResort flag.
// v6: wire format v2 — one message frame (0x03) with a mandatory commit-or-welcome staple;
//     PQ side-band tags renumbered to 0x05–0x11 (classify via PqFrameKind, never raw bytes);
//     TwoMlsPqError gained EpochDesync and UnexpectedWelcome.
// v7: header encryption — every rendezvous-channel frame leaves the library sealed; the host
//     removes the seal with openIncoming(blob:) -> OpenedFrame { kind, frame } and routes
//     `frame` by `kind` (OpenedFrameKind: message | pqSideBand(kind: PqFrameKind)).
// v8: initiate-side envelope — initiate gained appPayload: Data?; its initial frame comes back
//     from pendingOutbound already HPKE-enveloped; TwoMlsPqInvitation.openInitial(blob:) ->
//     InitialFrame { appPayload, welcome } opens it (decrypt-only, non-consuming).
// v9–v10: receive gained newClientId: Data? (establish under a dedicated per-session
//     principal) and expectedRemote: Data? (crate-side identity pin, checked before any
//     invitation state is claimed); queuedRemoteSuccessor() -> ClientId? exposes the
//     approval tally; TwoMlsPqError gained CredentialRejected, InvalidClientId, and
//     RemoteIdentityMismatch.
// v11–v12: draft-ietf-mls-combiner-02 conformance — APQInfo GroupContext extension,
//     AppDataUpdate epoch attestation on FULL commits, SafeExportSecret application-PSK
//     recipe, event-driven cross-party injection; combiner key package framing v2 and
//     session archive v8 (old key packages and archives are rejected — regenerate);
//     TwoMlsPqError gained ApqInfoMismatch. No call-shape changes.
private let expectedBindingContract: UInt64 = 12

enum TwoMLSPQBindingContract {
	static let verified: Void = {
		let actual = bindingContractVersion()
		precondition(
			actual == expectedBindingContract,
			"""
			TwoMLSPQ binding/binary mismatch: the vendored two_mls_pq.swift expects \
			contract \(expectedBindingContract) but the loaded binary provides \(actual). \
			Re-sync Sources/TwoMLSPQ/two_mls_pq.swift and the TwoMLSPQ xcframework \
			from the SAME build.
			"""
		)
	}()
}

// MARK: - Scalar conversions

/// Lift a raw FFI digest into a `CommProtocol.TypedDigest`. The FFI's documented
/// convention is SHA-256-32 over the stated object (see the note above
/// `PrepareEncryptResult` in TwoMLSPQ's lib.rs); the type tag is applied HERE — the
/// Rust crate carries no app-layer digest-type values.
private func liftDigest(_ raw: Data) throws -> TypedDigest {
	try TypedDigest(prefix: .sha256, checkedData: raw)
}

extension TwoMLSPQ.ClientId {
	var clientID: AbstractTwoMLS.ClientID { bytes }
}

extension AbstractTwoMLS.ClientID {
	var pqClientId: TwoMLSPQ.ClientId { .init(bytes: self) }
}

// MARK: - Result adapters

extension AbstractTwoMLS {

	public struct PQEncryptResult: EncryptResultProtocol {
		public let cipherText: Data
		public let sender: AbstractTwoMLS.ClientID
		public let recipient: AbstractTwoMLS.ClientID
		public let epochs: APQEpochs

		init(_ base: TwoMLSPQ.EncryptResult) {
			cipherText = base.cipherText
			sender = base.sender.bytes
			recipient = base.recipient.bytes
			epochs = APQEpochs(
				pqEpoch: base.epochs.pqEpoch,
				classicalEpoch: base.epochs.classicalEpoch
			)
		}
	}

	public struct PQPrepareEncryptResult: PrepareEncryptResultProtocol {
		public let proposalHash: TypedDigest
		// NB: protocol spells this `commitedRemoteClientId` (single "t");
		// the FFI struct spells it `committedRemoteClientId`.
		public let commitedRemoteClientId: AbstractTwoMLS.ClientID?
		public let didCommit: Bool

		init(_ base: TwoMLSPQ.PrepareEncryptResult) throws {
			proposalHash = try liftDigest(base.proposalHash)
			commitedRemoteClientId = base.committedRemoteClientId?.bytes
			didCommit = base.didCommit
		}
	}

	public struct PQSenderMessage: MLSSenderMessageProtocol {
		public let appMessageData: Data
		public let senderClientId: AbstractTwoMLS.ClientID
		public let epoch: UInt64

		init(_ base: TwoMLSPQ.MlsSenderMessage) {
			appMessageData = base.appMessageData
			senderClientId = base.senderClientId.bytes
			epoch = base.epoch
		}
	}

	public struct PQQueuedRemoteProposal: QueuedRemoteProposalProtocol {
		public let digest: TypedDigest
		public let sender: AbstractTwoMLS.ClientID
		public let proposing: AbstractTwoMLS.ClientID
		public let context: TypedDigest

		init(_ base: TwoMLSPQ.QueuedRemoteProposal) throws {
			digest = try liftDigest(base.digest)
			sender = base.sender.bytes
			proposing = base.proposing.bytes
			context = try liftDigest(base.context)
		}
	}

	public struct PQCommitResult: CommitResultProtocol {
		public let newSender: AbstractTwoMLS.ClientID?
		public let newRecipient: AbstractTwoMLS.ClientID

		init(_ base: TwoMLSPQ.CommitResult) {
			newSender = base.newSender?.bytes
			newRecipient = base.newRecipient.bytes
		}
	}

	public struct PQDecryptResult: DecryptResultProtocol {
		public let applicationMessage: PQSenderMessage?
		public let proposal: PQQueuedRemoteProposal?
		public let remoteCommit: PQCommitResult?

		init(_ base: TwoMLSPQ.DecryptResult) throws {
			applicationMessage = base.applicationMessage.map(PQSenderMessage.init)
			proposal = try base.proposal.map(PQQueuedRemoteProposal.init)
			remoteCommit = base.remoteCommit.map(PQCommitResult.init)
		}
	}
}

// MARK: - Session

extension AbstractTwoMLS {

	/// Adapter wrapping a `TwoMLSPQ.TwoMlsPqSession`.
	public struct PQSession: AbstractTwoMLS.PQRatchetingSession {
		public typealias Archive = Data

		let base: TwoMLSPQ.TwoMlsPqSession

		init(_ base: TwoMLSPQ.TwoMlsPqSession) {
			self.base = base
		}

		// MARK: Archivable

		public var archive: Data {
			get throws { try base.archive().bytes }
		}

		public init(archive: Data) throws {
			// `fromArchive(archive:)` (TwoMLSPQ 0.0.10) restores from the blob alone —
			// no owning client. Seal-before-persisting + latest-only discipline is the
			// caller's, as with invitation archives.
			self.init(
				try TwoMlsPqSession.fromArchive(
					archive: TwoMLSPQ.Archive(bytes: archive)))
		}

		// MARK: State

		public var proposalContext: TypedDigest? {
			// Non-throwing per the protocol; FFI digests are always well-formed
			// 32-byte values, so a conversion failure is treated as "no context".
			guard let digest = base.proposalContext() else { return nil }
			return try? liftDigest(digest)
		}

		public var sendRendezvous: AbstractTwoMLS.RendezvousID? {
			get throws { try base.sendRendezvous()?.bytes }
		}

		// MARK: Encrypt / decrypt

		public func prepareToEncrypt(
			proposing: AbstractTwoMLS.ClientID?
		) throws -> PQPrepareEncryptResult? {
			let result = try base.prepareToEncrypt(
				proposing: proposing?.pqClientId
			)
			return try PQPrepareEncryptResult(result)
		}

		public func encrypt(appMessage: Data) throws -> PQEncryptResult {
			PQEncryptResult(try base.encrypt(appMessage: appMessage))
		}

		public func processIncoming(ciphertext: Data) throws -> PQDecryptResult? {
			try base.processIncoming(ciphertext: ciphertext)
				.map(PQDecryptResult.init)
		}

		public func queueProposal(digest: TypedDigest) throws {
			try base.queueProposal(digest: digest.digest)
		}

		public func forwarded(headerDecrypted: Data) throws -> PQSenderMessage? {
			// The forward table and this session's spawn token are keyed by the
			// app-layer digest of the header-decrypted frame; recompute it here so the
			// FFI stays digest-convention-agnostic (opaque token). Always nil for the
			// PQ backend today: a replayed initial frame carries nothing undelivered.
			try base.forwarded(
				spawnToken: TypedDigest(prefix: .sha256, over: headerDecrypted)
					.wireFormat
			)
			.map(PQSenderMessage.init)
		}

		public func shouldListenOn() throws -> (
			AbstractTwoMLS.GroupID, [UInt64: AbstractTwoMLS.RendezvousID]
		) {
			let channels = try base.shouldListenOn()
			// CombinerGroupId carries both halves; the abstraction wants one GroupID.
			// Use the classical half: it exists from creation for both roles, whereas
			// the acceptor's PQ half is empty until the A.4 bootstrap — keying app
			// listen-state off it would hand out an empty id that changes mid-session.
			let groupId = channels.sendGroup.classical.bytes
			// rendezvousByEpoch has one address per epoch, so keys are unique; the closure is a
			// defensive tie-break that shouldn't fire — keep the first (arbitrary but stable).
			let rendezvous = Dictionary(
				channels.rendezvousByEpoch.map {
					($0.epoch, $0.rendezvousId.bytes)
				},
				uniquingKeysWith: { first, _ in first }
			)
			return (groupId, rendezvous)
		}

		// MARK: PQRatchet

		// The FFI is call-per-step (begin/respond/bind/apply); the abstract surface is
		// ingest/advance. A responder's reply produced during `ingest` is parked inside
		// the Rust session (single slot, enforced there) until `advance` consumes it.

		public var turn: PQTurn {
			base.myPqTurn() ? .weInitiate : .theyInitiate
		}

		public var epochs: APQEpochs {
			let pair = base.epochs()
			return APQEpochs(pqEpoch: pair.pqEpoch, classicalEpoch: pair.classicalEpoch)
		}

		public var isFullyEstablished: Bool {
			base.isFullyEstablished()
		}

		public func begin(
			_ kind: PQOperationKind,
			rotating: AbstractTwoMLS.ClientID?
		) throws -> PQOutbound {
			// `rotating` is the A.4/A.5 credential handoff: it must name the session's
			// CURRENT agent (the Phase 8 classical rotation — receive staging +
			// prepareToEncrypt(proposing:) — has already swapped to it), and the
			// operation then moves the PQ leaves to that agent's signing key. The
			// peer observes it as PQInbound.rotatedCredential on the rekey Upd'.
			switch kind {
			case .finishBootstrap:
				return PQOutbound(
					kind: kind,
					payload: try base.pqBootstrapBegin(
						rotating: rotating?.pqClientId)
				)
			case .ratchet:
				// A.3 injects a PSK with no updatePath — nothing carries a new
				// leaf credential.
				guard rotating == nil else {
					throw TwoMLSPQConformanceError.rotationCannotRideRatchet
				}
				return PQOutbound(kind: kind, payload: try base.pqRatchetBegin())
			case .rekey:
				return PQOutbound(
					kind: kind,
					payload: try base.pqRekeyBegin(
						rotating: rotating?.pqClientId)
				)
			}
		}

		public func advance(after inbound: PQInbound) throws -> PQOutbound? {
			base.pqTakePendingOutbound().map {
				PQOutbound(kind: inbound.kind, payload: $0)
			}
		}

		public func ingest(_ message: Data) throws -> PQInbound {
			// Frames leave the peer sealed (header encryption, contract v7): the leading
			// tag is no longer in the clear, so classify by removing the outer seal and
			// reading the routing `kind` rather than switching on `message.first`. The
			// pq_* receivers open the seal transparently, so hand them the sealed blob.
			guard let opened = try base.openIncoming(blob: message) else {
				// No header key opened it — a stranger's frame or a reconnect-gap frame
				// for an epoch we no longer hold a key for.
				throw TwoMLSPQConformanceError.malformedHeaderFrame
			}
			guard case let .pqSideBand(kind) = opened.kind else {
				// A message-path frame (welcome/0x03) reached the side-band entry point.
				throw TwoMLSPQConformanceError.malformedHeaderFrame
			}
			switch kind {
			case .rekeyUpdate:
				// A.5 responder: commit the initiator's Upd' on our send-PQ; the
				// [Commit'][counter-Upd'] reply parks for `advance` to hand out.
				// A credential handoff announces the initiator's (already Phase
				// 8-rotated) agent id in the Upd' — by the time this returns, the
				// initiator's leaf in our send-PQ has moved to that agent's key.
				let rotated = try base.pqRekeyRespond(updMsg: message)
				return PQInbound(
					kind: .rekey, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: rotated?.bytes)
			case .rekeyCommit:
				// Mid-operation (initiator: counter-Upd' present) our own send-PQ also
				// committed and the final Commit' parks for `advance`; final (responder:
				// empty counter) only our recv mirror advanced and the turn is ours.
				let continued = try base.pqRekeyApply(msg: message)
				return PQInbound(
					kind: .rekey, advancedGroup: continued ? .ours : .theirs,
					newEpochs: epochs, rotatedCredential: nil)
			case .bootstrapKeyPackage:
				try base.pqBootstrapRespond(kpMsg: message)
				return PQInbound(
					kind: .finishBootstrap, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: nil)
			case .bootstrapBind:
				try base.pqBootstrapApply(bindMsg: message)
				return PQInbound(
					kind: .finishBootstrap, advancedGroup: .theirs,
					newEpochs: epochs, rotatedCredential: nil)
			case .ratchetEphemeralKey:
				try base.pqRatchetRespond(ekMsg: message)
				return PQInbound(
					kind: .ratchet, advancedGroup: .theirs,
					newEpochs: nil, rotatedCredential: nil)
			case .ratchetCiphertext:
				try base.pqRatchetBind(ctMsg: message, app: Data())
				return PQInbound(
					kind: .ratchet, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: nil)
			case .ratchetBind:
				let plaintext = try base.pqRatchetApply(bindMsg: message)
				return PQInbound(
					kind: .ratchet, advancedGroup: .theirs,
					newEpochs: epochs, rotatedCredential: nil,
					plaintext: plaintext.isEmpty ? nil : plaintext)
			}
		}
	}

}

// MARK: - Invitation (stub)

extension AbstractTwoMLS {

	/// Opaque Codable archive for a PQ invitation: the `TwoMlsPqInvitation` archive bytes —
	/// signing identity, both combiner key packages' private material (opaque to the
	/// abstraction), and the consumed set. The archive alone restores a fully receivable
	/// invitation.
	public struct PQInvitationArchive: Codable, Sendable {
		public var bytes: Data

		public init(bytes: Data) {
			self.bytes = bytes
		}
	}

	public struct PQInvitation: AbstractTwoMLS.Invitation {
		public typealias Client = PQClient
		public typealias Session = PQSession
		public typealias Archive = PQInvitationArchive

		let base: TwoMLSPQ.TwoMlsPqInvitation

		init(base: TwoMLSPQ.TwoMlsPqInvitation) {
			_ = TwoMLSPQBindingContract.verified
			self.base = base
		}

		// MARK: Archivable

		public var archive: PQInvitationArchive {
			get throws { PQInvitationArchive(bytes: try base.archive()) }
		}

		public init(archive: PQInvitationArchive) throws {
			self.init(base: try TwoMlsPqInvitation(archive: archive.bytes))
		}

		// MARK: Invitation

		public init(clientId: AbstractTwoMLS.ClientID) throws {
			// Fresh invitation: mint a client for this identity and capture a combiner
			// key package into a self-contained archive. Last-resort (reusable), so a
			// single-use invitation's `InvitationSpent` never surfaces here.
			let archive = try TwoMlsPqPrincipal(clientId: clientId).generateInvitation(lastResort: true)
			self.init(base: try TwoMlsPqInvitation(archive: archive))
		}

		public var clientId: AbstractTwoMLS.ClientID {
			base.clientId().bytes
		}

		public var encodedKeyPackage: Data {
			// The combiner's two key packages travel as one opaque blob; only TwoMLSPQ
			// reads the halves back out (decodeCombinerKeyPackage).
			encodeCombinerKeyPackage(keyPackage: base.combinerKeyPackage())
		}

		public func decodeHeader(
			ciphertext: Data
		) throws -> AbstractTwoMLS.HeaderDecryptResult {
			// Strip the outer HPKE layer with this invitation's key-package init key
			// (info defaults to this ClientId, matching the sender's seal).
			let (kemOutput, sealed) = try decodeHeaderFrame(ciphertext)
			let decrypted = try base.hpkeOpen(
				kemOutput: kemOutput,
				ciphertext: sealed,
				info: nil,
				aad: nil
			)
			// The digest doubles as the FFI's opaque spawn token: receive() keyed the
			// forward table with it, so a transport re-delivery of an already-accepted
			// frame routes to the spawned session (the group this frame's welcome
			// created) instead of re-surfacing as a fresh AppWelcome. The sha256
			// convention lives entirely on this side; the Rust crate never interprets
			// the token.
			let digest = TypedDigest(prefix: .sha256, over: decrypted)
			if let spawned = base.forwardGroupId(spawnToken: digest.wireFormat) {
				return .forward(
					groupId: try DataIdentifier(
						prefix: .bits256,
						checkedData: spawned.bytes
					),
					mlsMessageData: decrypted
				)
			}
			// The PQ initiator cannot staple a private message pre-establishment.
			return .appWelcome(
				welcomeToken: WelcomeToken(digest),
				appWelcome: decrypted,
				stapledPrivateMessage: nil
			)
		}

		public func receive(
			sendGroupWelcome: Data,
			remoteKeyPackage: Data,
			remoteClientId: AbstractTwoMLS.ClientID,
			welcomeToken: WelcomeToken,
			stapledMessage: Data?,
			newClientId: AbstractTwoMLS.ClientID
		) throws -> (PQSession, plaintext: Data?) {
			let pair = try decodeCombinerKeyPackage(bytes: remoteKeyPackage)

			// Bind the key package to the authenticated identity from the validated
			// welcome (also checks the pair's two halves agree on one credential).
			let parsed = try parseCombinerKeyPackage(kp: pair)
			guard parsed.clientId.bytes == remoteClientId else {
				throw TwoMLSPQConformanceError.remoteIdentityMismatch
			}

			// Joins both halves from the APQ welcome and stands up the bound return
			// send group; the invitation dedups repeat welcomes per remote. The
			// welcome token keys the forward table as the FFI's opaque spawn
			// token, so a transport re-delivery of the same initial frame decodes as
			// `.forward` to this session.
			// The `WelcomeToken` type enforces the round-trip: `receive` accepts only the
			// token `decodeHeader` returned, so a caller cannot substitute a digest
			// recomputed over the wrong bytes (e.g. a re-serialized welcome) and
			// silently break replay forwarding.
			// `sendGroupWelcome` is the crate's §A.1 envelope (contract v8), not a bare
			// APQ welcome: unwrap it with `openInitial` (decrypt-only, does not consume
			// the invitation) to recover the MLS welcome `receive` joins from. The
			// app-layer payload rides this backend's own outer frame, so it is empty here.
			let opened = try base.openInitial(blob: sendGroupWelcome)
			// v12 `receive` grew `newClientId:` (establish directly under the dedicated
			// principal) and `expectedRemote:` (crate-side identity pin, checked before
			// any invitation state is claimed). Adopted mechanically as nil/nil for now:
			// this wrapper still pins the remote via the key-package guard above and
			// stages the dedicated principal for the Phase 8 rotation below — switching
			// those to the crate-side path is a deliberate follow-up, not a re-pin.
			let session = PQSession(
				try base.receive(
					welcome: opened.welcome,
					theirKeyPackage: pair,
					spawnToken: welcomeToken.wireFormat,
					newClientId: nil,
					expectedRemote: nil
				))

			// Deliberately fail open on the staple: an untrusted, optional early-delivery
			// of the acceptor's first app message. One that fails to decrypt/parse is
			// dropped — the session still establishes and the peer re-sends in-band —
			// with no security loss (it isn't authenticated to this group yet). For the
			// PQ backend `stapledMessage` is always nil (the initiator can't staple
			// pre-establishment); this is defensive parity with classical receiveWelcome.
			let plaintext: Data? = stapledMessage.flatMap { staple in
				guard let result = try? session.processIncoming(ciphertext: staple)
				else { return nil }
				return result.applicationMessage?.appMessageData
			}

			// Stage the app-spawned session-dedicated agent for the Phase 8 rotation.
			// The handoff commits when the app drives the first reply with
			// `prepareToEncrypt(proposing: newClientId)`; the PQ leaves catch up at
			// the next `begin(.rekey, rotating: newClientId)` (A.5).
			try session.base.stageRotation(newClientId: newClientId)

			return (session, plaintext)
		}
	}
}

// MARK: - Client (stub)

extension AbstractTwoMLS {

	public struct PQClient: AbstractTwoMLS.Client {
		public typealias Invitation = PQInvitation

		let base: TwoMLSPQ.TwoMlsPqPrincipal

		init(base: TwoMLSPQ.TwoMlsPqPrincipal) {
			_ = TwoMLSPQBindingContract.verified
			self.base = base
		}

		public init(clientId: AbstractTwoMLS.ClientID) throws {
			self.init(base: try TwoMlsPqPrincipal(clientId: clientId))
		}

		public func makeInvitation() throws -> PQInvitation.Archive {
			// The client captures a combiner key package into a self-contained invitation
			// archive; it keeps no key-package private material. Last-resort
			// (reusable) — a single-use invitation's `InvitationSpent` is unreachable here.
			PQInvitationArchive(bytes: try base.generateInvitation(lastResort: true))
		}

		public static func parseKeyPackageSuite(
			encoded: Data
		) -> AbstractTwoMLS.RawSuites? {
			// An opaque combiner blob reports its PQ half's suite; fall back to a bare
			// MLS key package message. Returns nil when the bytes are neither — callers
			// distinguish "unparseable" from a real suite without a magic 0 sentinel.
			if let pair = try? decodeCombinerKeyPackage(bytes: encoded) {
				return try? parseMlsKeyPackage(bytes: pair.pq).cipherSuite.value()
			}
			return try? parseMlsKeyPackage(bytes: encoded).cipherSuite.value()
		}

		public static var supportedSuites: [AbstractTwoMLS.RawSuites] {
			// 0x0003 = X25519+ChaCha20Poly1305 (classical), 0xFDEA = ML-KEM-768 (pq)
			[0x0003, 0xFDEA]
		}

		public func reply(
			keyPackageMessage: Data
		) throws -> (
			sendGroup: PQSession,
			welcomeMessage: Data,
			myKeyPackage: Data
		) {
			let pair = try decodeCombinerKeyPackage(bytes: keyPackageMessage)
			// `appPayload: nil` — this backend carries the app-layer AppWelcome in its own
			// outer HPKE frame (createTwoMLSGroup/decodeHeader), so the crate's envelope
			// wraps only the APQ welcome. `pendingOutbound` returns that opaque §A.1
			// envelope (contract v8); `PQInvitation.receive` unwraps it with `openInitial`.
			let session = try TwoMlsPqSession.initiate(
				client: base, theirKeyPackage: pair, appPayload: nil)
			guard let welcome = session.pendingOutbound() else {
				throw TwoMLSPQConformanceError.notImplemented(
					"PQClient.reply — initiate produced no envelope"
				)
			}
			// The return-group key package uses the retaining generate path: this live
			// session joins the acceptor's return welcome through its own client store
			// (an invitation-held key package would be purged from the client).
			let myKeyPackage = encodeCombinerKeyPackage(
				keyPackage: try base.generateCombinerKeyPackage()
			)
			return (PQSession(session), welcome, myKeyPackage)
		}

		public func createTwoMLSGroup(
			remoteAgentId: AbstractTwoMLS.ClientID,
			mySendGroup: PQSession,
			theirKeyPackageMessage: Data,
			appWelcome: Data
		) throws -> (PQSession, encryptedCombinedWelcome: Data) {
			// Bind the published key package to the remote identity the app is
			// addressing, then seal the AppWelcome to its (classical) init key.
			let pair = try decodeCombinerKeyPackage(bytes: theirKeyPackageMessage)
			guard try parseCombinerKeyPackage(kp: pair).clientId.bytes == remoteAgentId
			else {
				throw TwoMLSPQConformanceError.remoteIdentityMismatch
			}
			// info defaults to the recipient's ClientId (from the key package
			// credential), matching the invitation's hpkeOpen default.
			let sealed = try hpkeSealToKeyPackage(
				keyPackage: pair,
				plaintext: appWelcome,
				info: nil,
				aad: nil
			)
			return (mySendGroup, encryptedCombinedWelcome: encodeHeaderFrame(sealed))
		}
	}
}

// MARK: - Initial-message header envelope

/// Wire frame for the HPKE-sealed initial message:
/// `[version][u32-LE kem-len][kem_output][ciphertext…]` (ciphertext runs to the end).
/// Produced by `createTwoMLSGroup`, consumed by `PQInvitation.decodeHeader`.
private let pqHeaderFrameVersion: UInt8 = 1

private func encodeHeaderFrame(_ sealed: TwoMLSPQ.HpkeSealed) -> Data {
	var out = Data([pqHeaderFrameVersion])
	var kemLength = UInt32(sealed.kemOutput.count).littleEndian
	withUnsafeBytes(of: &kemLength) { out.append(contentsOf: $0) }
	out.append(sealed.kemOutput)
	out.append(sealed.ciphertext)
	return out
}

private func decodeHeaderFrame(_ data: Data) throws -> (kemOutput: Data, ciphertext: Data) {
	var rest = data[...]
	guard rest.popFirst() == pqHeaderFrameVersion, rest.count >= 4 else {
		throw TwoMLSPQConformanceError.malformedHeaderFrame
	}
	let kemLength = Int(
		rest.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
	)
	rest = rest.dropFirst(4)
	guard rest.count >= kemLength else {
		throw TwoMLSPQConformanceError.malformedHeaderFrame
	}
	return (Data(rest.prefix(kemLength)), Data(rest.dropFirst(kemLength)))
}
