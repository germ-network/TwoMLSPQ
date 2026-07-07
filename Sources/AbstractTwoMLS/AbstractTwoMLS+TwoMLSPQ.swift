//
//  AbstractTwoMLS+TwoMLSPQ.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/23/26.
//
//  Conforms the TwoMLSPQ UniFFI types to the AbstractTwoMLS protocol surface.
//
//  Because the abstraction speaks in `Data`/`TypedDigest` while TwoMLSPQ wraps
//  those in single-field structs (`ClientId`, `TwoMlsPqDigest`, …), and because
//  several abstract members collide with the generated methods only on return
//  type, the conformances are provided by thin adapter types in the
//  `AbstractTwoMLS` namespace rather than by extending the generated classes
//  directly. The generated module stays pristine.
//
//  Status:
//   - `PQSession` + the six result adapters are fully wired.
//   - `PQClient` / `PQInvitation` are stubbed where TwoMLSPQ has no equivalent
//     (see `notImplemented` throws and the GAP comments).
//

import CommProtocol
import Foundation
import TwoMLSPQ

// MARK: - Errors

public enum TwoMLSPQConformanceError: Error {
	/// A `TwoMlsPqDigest.hashType` byte did not map to a known `DigestTypes`.
	case unknownDigestType(UInt8)
	/// TwoMLSPQ restores a session via `fromArchive(archive:client:)`, which
	/// needs the owning client; the parameterless `Archivable.init(archive:)`
	/// cannot supply it.
	case clientRequiredForRestore
	/// The remote key package's credential does not match the authenticated
	/// remote identity extracted from the validated welcome.
	case remoteIdentityMismatch
	/// The initial-message header envelope failed to parse.
	case malformedHeaderFrame
	/// No TwoMLSPQ FFI surface backs this abstract member yet.
	case notImplemented(String)
}

// MARK: - Scalar conversions

extension TwoMLSPQ.TwoMlsPqDigest {
	/// Lift the FFI digest into a `CommProtocol.TypedDigest`.
	func toTypedDigest() throws -> TypedDigest {
		guard let prefix = DigestTypes(rawValue: hashType) else {
			throw TwoMLSPQConformanceError.unknownDigestType(hashType)
		}
		return try TypedDigest(prefix: prefix, checkedData: digest)
	}
}

extension TypedDigest {
	/// Lower a `TypedDigest` into the FFI digest shape.
	var pqDigest: TwoMLSPQ.TwoMlsPqDigest {
		.init(hashType: type.rawValue, digest: digest)
	}
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
			proposalHash = try base.proposalHash.toTypedDigest()
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
			digest = try base.digest.toTypedDigest()
			sender = base.sender.bytes
			proposing = base.proposing.bytes
			context = try base.context.toTypedDigest()
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
			// GAP: TwoMlsPqSession.fromArchive(archive:client:) also needs the
			// owning client, which this initializer cannot supply.
			throw TwoMLSPQConformanceError.clientRequiredForRestore
		}

		// MARK: State

		public var proposalContext: TypedDigest? {
			// Non-throwing per the protocol; FFI digests are always well-formed
			// sha256, so a conversion failure is treated as "no context".
			guard let digest = base.proposalContext() else { return nil }
			return try? digest.toTypedDigest()
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
			try base.queueProposal(digest: digest.pqDigest)
		}

		public func forwarded(headerDecrypted: Data) throws -> PQSenderMessage? {
			try base.forwarded(headerDecrypted: headerDecrypted)
				.map(PQSenderMessage.init)
		}

		public func shouldListenOn() throws -> (
			AbstractTwoMLS.GroupID, [UInt64: AbstractTwoMLS.RendezvousID]
		) {
			let channels = try base.shouldListenOn()
			// CombinerGroupId carries both halves; the abstraction wants a single
			// GroupID. Use the classical half: it exists from group creation for
			// both roles, whereas the acceptor's PQ half is empty until the A.4
			// bootstrap — keying app listen-state off it would hand the app an
			// empty id that then changes mid-session.
			let groupId = channels.sendGroup.classical.bytes
			let rendezvous = Dictionary(
				channels.rendezvousByEpoch.map { ($0.epoch, $0.rendezvousId.bytes) },
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
			guard rotating == nil else {
				throw TwoMLSPQConformanceError.notImplemented(
					"PQRatchet.begin(rotating:) — A.4/A.5 credential handoff"
				)
			}
			switch kind {
			case .finishBootstrap:
				return PQOutbound(kind: kind, payload: try base.pqBootstrapBegin())
			case .ratchet:
				return PQOutbound(kind: kind, payload: try base.pqRatchetBegin())
			case .rekey:
				throw TwoMLSPQConformanceError.notImplemented(
					"PQRatchet.begin(.rekey) — A.5 has no FFI surface yet"
				)
			}
		}

		public func advance(after inbound: PQInbound) throws -> PQOutbound? {
			base.pqTakePendingOutbound().map {
				PQOutbound(kind: inbound.kind, payload: $0)
			}
		}

		public func ingest(_ message: Data) throws -> PQInbound {
			// PQ side-band frame tags (session.rs): EK 0x0B, CT 0x0D, bind 0x0F,
			// bootstrap KP 0x11, bootstrap bind 0x13.
			switch message.first {
			case 0x11:
				try base.pqBootstrapRespond(kpMsg: message)
				return PQInbound(
					kind: .finishBootstrap, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: nil)
			case 0x13:
				try base.pqBootstrapApply(bindMsg: message)
				return PQInbound(
					kind: .finishBootstrap, advancedGroup: .theirs,
					newEpochs: epochs, rotatedCredential: nil)
			case 0x0B:
				try base.pqRatchetRespond(ekMsg: message)
				return PQInbound(
					kind: .ratchet, advancedGroup: .theirs,
					newEpochs: nil, rotatedCredential: nil)
			case 0x0D:
				try base.pqRatchetBind(ctMsg: message, app: Data())
				return PQInbound(
					kind: .ratchet, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: nil)
			case 0x0F:
				let plaintext = try base.pqRatchetApply(bindMsg: message)
				return PQInbound(
					kind: .ratchet, advancedGroup: .theirs,
					newEpochs: epochs, rotatedCredential: nil,
					plaintext: plaintext.isEmpty ? nil : plaintext)
			default:
				throw TwoMLSPQConformanceError.malformedHeaderFrame
			}
		}
	}

}

// MARK: - Invitation (stub)

extension AbstractTwoMLS {

	/// Opaque Codable archive for a PQ invitation: the `TwoMlsPqInvitation` archive bytes —
	/// the signing identity, both combiner key packages' private material, and the consumed
	/// set. The combiner's two key packages are opaque to the abstraction, and the archive
	/// on its own restores a fully receivable invitation.
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
			// A fresh invitation: mint a client for this identity, have it generate and
			// capture a combiner key package, and hold the resulting self-contained archive.
			let archive = try TwoMlsPqClient(clientId: clientId).generateInvitation()
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
			// GAP: the `.forward` case (routing to already-spawned groups) needs the
			// spawned-group table; every successful decrypt is an AppWelcome for now.
			// The PQ initiator cannot staple a private message pre-establishment.
			return .appWelcome(
				appWelcomeDigest: TypedDigest(prefix: .sha256, over: decrypted),
				appWelcome: decrypted,
				stapledPrivateMessage: nil
			)
		}

		public func receive(
			sendGroupWelcome: Data,
			remoteKeyPackage: Data,
			remoteClientId: AbstractTwoMLS.ClientID,
			combinedWelcomeDigest: TypedDigest,
			stapledMessage: Data?,
			newClientId: AbstractTwoMLS.ClientID
		) throws -> (PQSession, plaintext: Data?) {
			// NB: `combinedWelcomeDigest` (receive-group bookkeeping) and `newClientId`
			// (rotation staging) are not yet threaded into the FFI receive; the classical
			// flow uses them and the PQ backend will grow equivalents.
			let pair = try decodeCombinerKeyPackage(bytes: remoteKeyPackage)

			// Bind the key package to the authenticated identity from the validated
			// welcome (also checks the pair's two halves agree on one credential).
			let parsed = try parseCombinerKeyPackage(kp: pair)
			guard parsed.clientId.bytes == remoteClientId else {
				throw TwoMLSPQConformanceError.remoteIdentityMismatch
			}

			// Joins both halves from the APQ welcome and stands up the bound return
			// send group; the invitation dedups repeat welcomes per remote.
			let session = PQSession(try base.receive(
				welcome: sendGroupWelcome,
				theirKeyPackage: pair
			))

			// Fail open on the stapled message — the session proceeds even if the
			// staple does not process (mirrors the classical receiveWelcome).
			let plaintext: Data? = stapledMessage.flatMap { staple in
				guard let result = try? session.processIncoming(ciphertext: staple)
				else { return nil }
				return result.applicationMessage?.appMessageData
			}

			return (session, plaintext)
		}
	}
}

// MARK: - Client (stub)

extension AbstractTwoMLS {

	public struct PQClient: AbstractTwoMLS.Client {
		public typealias Invitation = PQInvitation

		let base: TwoMLSPQ.TwoMlsPqClient

		init(base: TwoMLSPQ.TwoMlsPqClient) {
			self.base = base
		}

		public init(clientId: AbstractTwoMLS.ClientID) throws {
			self.init(base: try TwoMlsPqClient(clientId: clientId))
		}

		public func makeInvitation() throws -> PQInvitation.Archive {
			// The client captures a combiner key package into a self-contained invitation
			// archive; it keeps no key-package private material.
			PQInvitationArchive(bytes: try base.generateInvitation())
		}

		public static func parseKeyPackageSuite(
			encoded: Data
		) -> AbstractTwoMLS.RawSuites {
			// An opaque combiner blob reports its PQ half's suite; fall back to a bare
			// MLS key package message.
			if let pair = try? decodeCombinerKeyPackage(bytes: encoded) {
				return (try? parseMlsKeyPackage(bytes: pair.pq).cipherSuite.value()) ?? 0
			}
			return (try? parseMlsKeyPackage(bytes: encoded).cipherSuite.value()) ?? 0
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
			let session = try TwoMlsPqSession.initiate(client: base, theirKeyPackage: pair)
			guard let welcome = session.pendingOutbound() else {
				throw TwoMLSPQConformanceError.notImplemented(
					"PQClient.reply — initiate produced no welcome"
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
