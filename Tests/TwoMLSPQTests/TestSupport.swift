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

extension ClientID {
	/// A random 32-byte client id, standing in for an app-minted identity.
	static func mock() -> Self {
		SymmetricKey(size: .bits256).rawRepresentation
	}
}

enum TestErrors: Error {
	case unexpected
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
	/// Send one round-tripping app message to `remote`, asserting it decrypts intact.
	/// Doubles as the establishment nudge: the sender's first frame staples its return
	/// welcome, so the peer completes establishment in-band.
	func send(to remote: PQSession) throws {
		let outgoing = UUID().uuidString.utf8Data
		_ = try prepareToEncrypt(proposing: nil)
		let encryptedOutgoing = try encrypt(appMessage: outgoing)

		let decrypted = try remote.processIncoming(
			ciphertext: encryptedOutgoing.cipherText
		).tryUnwrap

		let applicationMessage = try decrypted.applicationMessage.tryUnwrap

		#expect(applicationMessage.appMessageData == outgoing)
	}

	/// One round each way.
	func exchange(with remote: PQSession) throws {
		try send(to: remote)
		try remote.send(to: self)
	}
}
