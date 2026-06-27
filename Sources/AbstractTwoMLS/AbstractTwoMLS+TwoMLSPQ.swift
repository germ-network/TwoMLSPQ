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
			// GAP: the FFI EncryptResult reports a single epoch; the pq/classical
			// split is not yet exported.
			epochs = APQEpochs(pqEpoch: base.epoch, classicalEpoch: base.epoch)
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
		public typealias Invitation = PQInvitation
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
			// GroupID — use the PQ half, which is the primary send group.
			let groupId = channels.sendGroup.pq.bytes
			let rendezvous = Dictionary(
				channels.rendezvousByEpoch.map { ($0.epoch, $0.rendezvousId.bytes) },
				uniquingKeysWith: { first, _ in first }
			)
			return (groupId, rendezvous)
		}

		// MARK: PQRatchet

		// The action methods have no FFI surface yet (GAP); `isFullyEstablished`
		// maps to the session's own established flag, and `turn`/`epochs` return
		// placeholders.

		public var turn: PQTurn {
			// GAP: no FFI accessor for whose PQ turn it is.
			.weInitiate
		}

		public var epochs: APQEpochs {
			// GAP: no FFI accessor for the APQInfo epoch pair.
			APQEpochs(pqEpoch: 0, classicalEpoch: 0)
		}

		public var isFullyEstablished: Bool {
			base.isEstablished()
		}

		public func begin(
			_ kind: PQOperationKind,
			rotating: AbstractTwoMLS.ClientID?
		) throws -> PQOutbound {
			throw TwoMLSPQConformanceError.notImplemented(
				"PQRatchet.begin(\(kind)) — no TwoMLSPQ FFI equivalent yet"
			)
		}

		public func advance(after inbound: PQInbound) throws -> PQOutbound? {
			throw TwoMLSPQConformanceError.notImplemented(
				"PQRatchet.advance — no TwoMLSPQ FFI equivalent yet"
			)
		}

		public func ingest(_ message: Data) throws -> PQInbound {
			throw TwoMLSPQConformanceError.notImplemented(
				"PQRatchet.ingest — no TwoMLSPQ FFI equivalent yet"
			)
		}
	}
}

// MARK: - Invitation (stub)

extension AbstractTwoMLS {

	/// Codable archive for a PQ invitation: the published combiner key package
	/// plus the agent's client id. NB: the corresponding HPKE private keys live
	/// inside the `TwoMlsPqClient`, so an archive alone cannot reconstruct a
	/// receivable invitation.
	public struct PQInvitationArchive: Codable, Sendable {
		public var clientId: Data
		public var classicalKeyPackage: Data
		public var pqKeyPackage: Data

		public init(clientId: Data, classicalKeyPackage: Data, pqKeyPackage: Data) {
			self.clientId = clientId
			self.classicalKeyPackage = classicalKeyPackage
			self.pqKeyPackage = pqKeyPackage
		}
	}

	public struct PQInvitation: AbstractTwoMLS.Invitation {
		public typealias Client = PQClient
		public typealias Session = PQSession
		public typealias Archive = PQInvitationArchive

		let client: TwoMLSPQ.TwoMlsPqClient
		let keyPackage: TwoMLSPQ.CombinerKeyPackage

		init(
			client: TwoMLSPQ.TwoMlsPqClient,
			keyPackage: TwoMLSPQ.CombinerKeyPackage
		) {
			self.client = client
			self.keyPackage = keyPackage
		}

		// MARK: Archivable

		public var archive: PQInvitationArchive {
			get throws {
				PQInvitationArchive(
					clientId: client.clientId().bytes,
					classicalKeyPackage: keyPackage.classical,
					pqKeyPackage: keyPackage.pq
				)
			}
		}

		public init(archive: PQInvitationArchive) throws {
			// GAP: rebuilding a usable invitation needs the client's private HPKE
			// keys, which the public archive does not carry.
			throw TwoMLSPQConformanceError.clientRequiredForRestore
		}

		// MARK: Invitation

		public init(clientId: AbstractTwoMLS.ClientID) throws {
			// GAP: TwoMlsPqClient is constructed from a *signing key*, not the
			// public client id.
			throw TwoMLSPQConformanceError.notImplemented(
				"PQInvitation.init(clientId:) — needs the signing key"
			)
		}

		public var clientId: AbstractTwoMLS.ClientID {
			client.clientId().bytes
		}

		public var encodedKeyPackage: Data {
			// GAP: the abstraction expects one encoded key package; a combiner
			// invitation publishes two (classical + pq). Returning the PQ half.
			keyPackage.pq
		}

		public func decodeHeader(
			ciphertext: Data
		) throws -> AbstractTwoMLS.HeaderDecryptResult {
			throw TwoMLSPQConformanceError.notImplemented(
				"PQInvitation.decodeHeader — no FFI equivalent"
			)
		}

		public func receive(
			sendGroupWelcome: Data,
			combinedWelcomeDigest: TypedDigest,
			stapledMessage: Data?,
			newClientId: AbstractTwoMLS.ClientID
		) throws -> (PQSession.Archive, plaintext: Data?) {
			// GAP: closest FFI surface is TwoMlsPqSession.accept(client:welcome:
			// theirKeyPackage:), but the parameter shape differs.
			throw TwoMLSPQConformanceError.notImplemented(
				"PQInvitation.receive — maps to TwoMlsPqSession.accept"
			)
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
			// GAP: TwoMlsPqClient(signingKey:) needs the private signing key, not
			// the public client id.
			throw TwoMLSPQConformanceError.notImplemented(
				"PQClient.init(clientId:) — needs the signing key"
			)
		}

		public func makeInvitation() throws -> PQInvitation.Archive {
			let keyPackage = try base.generateCombinerKeyPackage()
			return PQInvitationArchive(
				clientId: base.clientId().bytes,
				classicalKeyPackage: keyPackage.classical,
				pqKeyPackage: keyPackage.pq
			)
		}

		public static func parseKeyPackageSuite(
			encoded: Data
		) -> AbstractTwoMLS.RawSuites {
			(try? parseMlsKeyPackage(bytes: encoded).cipherSuite.value()) ?? 0
		}

		public static var supportedSuites: [AbstractTwoMLS.RawSuites] {
			// 0x0003 = X25519+ChaCha20Poly1305 (classical), 0xFDEA = ML-KEM-768 (pq)
			[0x0003, 0xFDEA]
		}

		public func reply(
			keyPackageMessage: Data
		) throws -> (
			sendGroupArchive: PQSession.Archive,
			welcomeMessage: Data,
			myKeyPackage: Data
		) {
			// GAP: maps to TwoMlsPqSession.initiate(client:theirKeyPackage:) +
			// .archive()/.pendingOutbound(), but `theirKeyPackage` is a
			// CombinerKeyPackage, not raw Data.
			throw TwoMLSPQConformanceError.notImplemented(
				"PQClient.reply — maps to TwoMlsPqSession.initiate"
			)
		}

		public func createTwoMLSGroup(
			remoteAgentId: AbstractTwoMLS.ClientID,
			mySendGroupArchive: PQSession.Archive,
			theirKeyPackageMessage: Data,
			appWelcome: Data
		) throws -> (PQSession.Archive, encryptedCombinedWelcome: Data) {
			// GAP: maps to TwoMlsPqSession.accept(client:welcome:theirKeyPackage:),
			// parameter shape differs.
			throw TwoMLSPQConformanceError.notImplemented(
				"PQClient.createTwoMLSGroup — maps to TwoMlsPqSession.accept"
			)
		}
	}
}
