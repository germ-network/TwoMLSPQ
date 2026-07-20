//
//  TestSupport.swift
//  TwoMLSPQ
//
//  Shared helpers for the concrete/FFI test suites. These drive the concrete PQ types
//  directly (no abstract protocols); the AbstractTwoMLS package's own suites use their
//  protocol-generic equivalents.
//

import CommProtocol
import CryptoKit
import Foundation
import Testing
import TwoMLSPQ
import TwoMLSPQBinding

extension ClientID {
	/// A random 32-byte client id, standing in for an app-minted identity.
	static func mock() -> Self {
		SymmetricKey(size: .bits256).rawRepresentation
	}
}

enum TestErrors: Error {
	case unexpected
}

// MARK: - Born-dedicated establishment (contract 26)

/// The opaque signed-delegation blob the app would mint by signing over the
/// acceptor's `pendingEstablishmentWelcome`. The backend treats it as bytes, so
/// a fixed blob suffices to drive the install → pause → resume seam end to end.
let mockEstablishmentEnvelope = Data("mock-signed-establishment-delegation".utf8)

extension PQSession {
	/// Install the mock delegation on a freshly-received born-dedicated acceptor,
	/// returning the bytes for the peer-side approval.
	@discardableResult
	func installMockEstablishmentEnvelope() throws -> Data {
		#expect(pendingEstablishmentWelcome != nil, "a born-dedicated acceptor owes a welcome")
		try installEstablishmentEnvelope(mockEstablishmentEnvelope)
		return mockEstablishmentEnvelope
	}

	/// Drive one born-dedicated establishment frame from `acceptor` into `self`
	/// (a wrapped initiator): the acceptor emits, `self` PAUSES on the `0x0B`
	/// handoff, "verifies" the surfaced envelope by byte-equality, and resumes,
	/// admitting `dedicatedId`. Returns the resumed decrypt.
	@discardableResult
	func acceptEstablishment(
		from acceptor: PQSession,
		dedicatedId: ClientID,
		message: Data = Data("establish".utf8)
	) throws -> PQDecryptResult? {
		_ = try acceptor.prepareToEncrypt(proposing: nil)
		let frame = try acceptor.encrypt(appMessage: message)
		guard case .pendingEstablishment(let pending) = try processIncoming(ciphertext: frame.cipherText)
		else {
			Issue.record("expected a born-dedicated establishment pause")
			throw TestErrors.unexpected
		}
		#expect(pending.envelope == mockEstablishmentEnvelope)
		#expect(pending.welcome.first == 0x01, "the surfaced welcome is a bare APQWelcome_A")
		return try pending.resume(admittedCreator: dedicatedId)
	}
}

/// The raw-FFI initiator's approval of a born-dedicated establishment frame:
/// assert the pause, then re-feed with digests over the surfaced bytes.
@discardableResult
func approveEstablishmentRaw(
	initiator: TwoMlsPqSession,
	ciphertext: Data,
	dedicatedId: ClientID
) throws -> DecryptResult? {
	let paused = try #require(try initiator.processIncoming(ciphertext: ciphertext))
	let pending = try #require(paused.pendingEstablishment)
	#expect(pending.envelope == mockEstablishmentEnvelope)
	#expect(pending.welcome.first == 0x01)
	return try initiator.processIncomingApproved(
		ciphertext: ciphertext,
		approvedEnvelopeDigest: Data(SHA256.hash(data: pending.envelope)),
		approvedWelcomeDigest: Data(SHA256.hash(data: pending.welcome)),
		expectedCreator: dedicatedId
	)
}

/// A freshly minted client plus its first published invitation — the two ends of an
/// establishment handshake. Specialised to the concrete `PQClient`.
struct ClientWrapper {
	let agentKey = AgentPrivateKey()
	let client: PQClient
	let currentInvitation: PQInvitation

	init() throws {
		client = try PQClient(clientId: agentKey.publicKey.wireFormat)
		currentInvitation = try .init(persisted: try client.makeInvitation())
	}

	var clientId: Data {
		get throws {
			agentKey.publicKey.wireFormat
		}
	}
}

extension PQSession {
	/// Steady-state receive: assert the frame is a decrypt (not an establishment
	/// pause) and return its payload. For frames past establishment, where a pause
	/// cannot occur — a pause here is a test-setup bug, surfaced loudly.
	func decrypt(_ ciphertext: Data) throws -> PQDecryptResult? {
		guard case .decrypted(let result) = try processIncoming(ciphertext: ciphertext) else {
			Issue.record("unexpected establishment pause on a post-establishment frame")
			throw TestErrors.unexpected
		}
		return result
	}

	/// Send one round-tripping app message to `remote`, asserting it decrypts intact.
	/// Doubles as the establishment nudge: the sender's first frame staples its return
	/// welcome, so the peer completes establishment in-band.
	func send(to remote: PQSession) throws {
		let outgoing = UUID().uuidString.utf8Data
		_ = try prepareToEncrypt(proposing: nil)
		let encryptedOutgoing = try encrypt(appMessage: outgoing)

		// Post-establishment: the receiver decrypts. (A born-dedicated first frame
		// pauses instead — that path is `acceptEstablishment`, not `send`.)
		guard case .decrypted(let decrypted) = try remote.processIncoming(
			ciphertext: encryptedOutgoing.cipherText
		) else {
			Issue.record("unexpected establishment pause in a steady-state send")
			throw TestErrors.unexpected
		}

		let applicationMessage = try decrypted.tryUnwrap.applicationMessage.tryUnwrap

		#expect(applicationMessage.appMessageData == outgoing)
	}

	/// One round each way.
	func exchange(with remote: PQSession) throws {
		try send(to: remote)
		try remote.send(to: self)
	}
}
