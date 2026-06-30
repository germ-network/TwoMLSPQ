import AbstractTwoMLS
import CommProtocol
import CryptoKit
import Foundation
import Testing

//wraps an agent key, and a default invitation
struct ClientWrapper<C: AbstractTwoMLS.Client> {
	let agentKey = AgentPrivateKey()
	let client: C
	let currentInvitation: C.Invitation
	
	init() throws {
		client = try C(clientId: agentKey.publicKey.wireFormat)
		currentInvitation = try .init(archive: try client.makeInvitation())
	}
	
	var clientId: Data {
		get throws {
			agentKey.publicKey.wireFormat
		}
	}
}

struct APIDemo {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}
	@Test func apiDemo() async throws {
		let (localSession, _) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)

		//test it as a stapled message
		let encryptResult = try localSession.encrypt(
			appMessage: "Reply".utf8Data
		)

		//process in in the invitation:
		let (remoteSession, stapledMessage) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptResult.cipherText,
			expecting: encryptResult.sender
		)

		//localSesson and remoteSession should both be in a consistent state:
		//local APQ send group, remote classical send group derived from
		//the local APQ send group

		//local so far:
		//- fetched an (A)PQ keyPackage for remote
		//- formed an (A)PQ group and sent the APQ welcome
		//- staped a proposal for a classical keyPackage for remote to setup their send
		//  group with
		//local will now also send, slowly, a PQ keyPackage so that remote
		//can stand up their own APQ group
		//the PQ side-band is a separate capability from the base Session
		guard
			let localPQ = localSession as? any AbstractTwoMLS.PQRatchetingSession,
			let remotePQ = remoteSession as? any AbstractTwoMLS.PQRatchetingSession
		else {
			throw TestErrors.unexpected
		}

		//local holds the turn and owes the PQ bootstrap of remote's send group
		guard localPQ.turn == .weInitiate else {
			throw TestErrors.unexpected
		}
		let localOutbound = try localPQ.begin(.finishBootstrap, rotating: nil)

		//remote has no PQ group of its own yet
		guard !remotePQ.isFullyEstablished else {
			throw TestErrors.unexpected
		}

		//can round trip without blocking on PQ
		try localSession.exchange(with: remoteSession)

		//the PQ payload finally arrived at remote
		let remoteInbound = try remotePQ.ingest(localOutbound.payload)
		guard remoteInbound.kind == .finishBootstrap else {
			throw TestErrors.unexpected
		}

		//remote replies, advancing the operation
		_ = try remotePQ.advance(after: remoteInbound)

		try localSession.exchange(with: remoteSession)
	}
}

struct MockAppWelcome: Codable, Sendable {
	let mySendGroupWelcome: Data
	let myKeyPackage: Data
}

//test helper for a generic 2-steps
extension AbstractTwoMLS.Client {
	func reply(
		remoteClientId: AbstractTwoMLS.ClientID,
		encodedRemoteKpkg: Data
	) throws -> (Invitation.Session, encryptedCombinedWelcome: Data) {
		//local parses the keyPackage
		//APQ: this should be an APQKeyPackage
		let keyPackageSuite = Self.parseKeyPackageSuite(
			encoded: encodedRemoteKpkg
		)

		guard Self.supportedSuites.contains(keyPackageSuite) else {
			throw TestErrors.unexpected
		}

		//APQ: the sendWelcome should be an APQWelcome
		let (sendGroupArchive, sendWelcome, myKeyPackage) = try reply(
			keyPackageMessage: encodedRemoteKpkg
		)

		//construct the TwoMLS group and encrypted, combined welcome
		let mockAppWelcome = MockAppWelcome(
			mySendGroupWelcome: sendWelcome,
			myKeyPackage: myKeyPackage
		)
		let (localSendGroupArchive, encryptedCombinedWelcome) = try createTwoMLSGroup(
			remoteAgentId: remoteClientId,
			mySendGroupArchive: sendGroupArchive,
			theirKeyPackageMessage: encodedRemoteKpkg,
			appWelcome: try JSONEncoder().encode(mockAppWelcome)
		)

		let localSendGroup = try Invitation.Session(
			archive: localSendGroupArchive
		)

		return (localSendGroup, encryptedCombinedWelcome)
	}
}

extension AbstractTwoMLS.Invitation {
	func receiveReply(
		ciphertext: Data,
		expecting remoteClientId: AbstractTwoMLS.ClientID
	) throws -> (Session, Data?) {
		let headerDecrypted = try decodeHeader(
			ciphertext: ciphertext
		)

		guard
			case .appWelcome(
				appWelcomeDigest: let appWelcomeDigest,
				appWelcome: let appWelcome,
				stapledPrivateMessage: let stapledPrivateMessage
			) = headerDecrypted
		else {
			throw TestErrors.unexpected
		}

		let decoded = try JSONDecoder().decode(
			MockAppWelcome.self,
			from: appWelcome
		)

		let (sessionArchive, stapledMessageBody) = try receive(
			sendGroupWelcome: decoded.mySendGroupWelcome,
			combinedWelcomeDigest: appWelcomeDigest,
			stapledMessage: stapledPrivateMessage,
			newClientId: remoteClientId
		)

		return (try .init(archive: sessionArchive), stapledMessageBody)
	}
}

extension AbstractTwoMLS.Session {
	func exchange(with remote: some AbstractTwoMLS.Session) throws {
		try send(to: remote)
		try remote.send(to: self)
	}

	func send(to remote: some AbstractTwoMLS.Session) throws {
		let outgoing = UUID().uuidString.utf8Data
		let encryptedOutgoing = try encrypt(appMessage: outgoing)

		let decrypted = try remote.processIncoming(
			ciphertext: encryptedOutgoing.cipherText
		).tryUnwrap

		let applicationMessage = try decrypted.applicationMessage.tryUnwrap

		#expect(applicationMessage.appMessageData == outgoing)
	}
}

enum TestErrors: LocalizedError {
	case notImplemented
	case unexpected

	package var errorDescription: String? {
		switch self {
		case .notImplemented: "Not implemented"
		case .unexpected: "Unexpected"
		}
	}
}

extension AbstractTwoMLS.ClientID {
	static func mock() -> Self {
		SymmetricKey(size: .bits256).rawRepresentation
	}
}
