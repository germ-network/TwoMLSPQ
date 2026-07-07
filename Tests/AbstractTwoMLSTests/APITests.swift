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
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)

		//the session tells the transport where to listen: one address per epoch
		//of our send group. Listening works from birth; there is nowhere to
		//*post* until the peer's return welcome stands up our recv group
		let (_, listenAtBirth) = try localSession.shouldListenOn()
		guard try localSession.sendRendezvous == nil,
			listenAtBirth.count == 1
		else {
			throw TestErrors.unexpected
		}

		//deliver the HPKE-sealed combined welcome to the invitation
		//(the initiator cannot staple an app message before establishment)
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId
		)

		//remote's first frame staples its return welcome; local joins in-band,
		//completing establishment before any further exchange
		try remoteSession.send(to: localSession)

		//established both ways, routing is symmetric: my post address is my recv
		//group's exporter — the same MLS group as the peer's send group — so each
		//side's post address appears in the other side's listen set
		let (localGroupId, localListen) = try localSession.shouldListenOn()
		let (remoteGroupId, remoteListen) = try remoteSession.shouldListenOn()
		guard !localGroupId.isEmpty, !remoteGroupId.isEmpty,
			let localPost = try localSession.sendRendezvous,
			let remotePost = try remoteSession.sendRendezvous,
			remoteListen.values.contains(localPost),
			localListen.values.contains(remotePost)
		else {
			throw TestErrors.unexpected
		}

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

		//remote replies, advancing the operation; local applies it, completing A.4
		guard let remoteReply = try remotePQ.advance(after: remoteInbound) else {
			throw TestErrors.unexpected
		}
		_ = try localPQ.ingest(remoteReply.payload)
		guard localPQ.isFullyEstablished, remotePQ.isFullyEstablished else {
			throw TestErrors.unexpected
		}

		try localSession.exchange(with: remoteSession)

		//routing follows the ratchet: when the peer's stapled Upd(self) is
		//approved (queueProposal) the next send commits it, advancing our send
		//group's epoch and minting a new listen address; the peer's post address
		//migrates onto it, and older epochs stay listed for in-flight traffic
		_ = try remoteSession.prepareToEncrypt(proposing: nil)
		let updFrame = try remoteSession.encrypt(appMessage: Data("upd".utf8))
		guard
			let updDecrypted = try localSession.processIncoming(
				ciphertext: updFrame.cipherText),
			let offered = updDecrypted.proposal
		else {
			throw TestErrors.unexpected
		}
		try localSession.queueProposal(digest: offered.digest)
		_ = try localSession.prepareToEncrypt(proposing: nil)
		let commitFrame = try localSession.encrypt(appMessage: Data("commit".utf8))
		_ = try remoteSession.processIncoming(ciphertext: commitFrame.cipherText)

		let (_, localListenLater) = try localSession.shouldListenOn()
		guard localListenLater.count == localListen.count + 1,
			let remotePostLater = try remoteSession.sendRendezvous,
			remotePostLater != remotePost,
			localListenLater.values.contains(remotePostLater),
			localListenLater.values.contains(remotePost)
		else {
			throw TestErrors.unexpected
		}

		//the encrypt result reports the APQ epoch pair (pq side-band / classical
		//message group) — the initiator's full pair after its commit — and the
		//commit's classical epoch keys the listen address the commit minted
		guard
			commitFrame.epochs
				== AbstractTwoMLS.APQEpochs(pqEpoch: 1, classicalEpoch: 2),
			localListenLater[commitFrame.epochs.classicalEpoch] == remotePostLater
		else {
			throw TestErrors.unexpected
		}

		//A.5 rekey: updatePath commits run on the PQ groups alone, so the
		//classical ratchet is never blocked behind a large ML-KEM updatePath.
		//remote holds the turn (local's bootstrap completion passed it)
		guard remotePQ.turn == .weInitiate else { throw TestErrors.unexpected }
		let rekey = try remotePQ.begin(.rekey, rotating: nil)
		let rekeyIn1 = try localPQ.ingest(rekey.payload)
		guard let rekeyReply = try localPQ.advance(after: rekeyIn1) else {
			throw TestErrors.unexpected
		}
		let rekeyIn2 = try remotePQ.ingest(rekeyReply.payload)
		guard let rekeyFinal = try remotePQ.advance(after: rekeyIn2) else {
			throw TestErrors.unexpected
		}
		_ = try localPQ.ingest(rekeyFinal.payload)
		guard localPQ.epochs.pqEpoch == 2, remotePQ.epochs.pqEpoch == 2 else {
			throw TestErrors.unexpected
		}

		//and the session still messages both ways on the rekeyed groups
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
		let (sendGroup, sendWelcome, myKeyPackage) = try reply(
			keyPackageMessage: encodedRemoteKpkg
		)

		//construct the TwoMLS group and encrypted, combined welcome
		let mockAppWelcome = MockAppWelcome(
			mySendGroupWelcome: sendWelcome,
			myKeyPackage: myKeyPackage
		)
		let (localSendGroup, encryptedCombinedWelcome) = try createTwoMLSGroup(
			remoteAgentId: remoteClientId,
			mySendGroup: sendGroup,
			theirKeyPackageMessage: encodedRemoteKpkg,
			appWelcome: try JSONEncoder().encode(mockAppWelcome)
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

		//the app validated the welcome; hand back the remote's key package and
		//authenticated client id extracted from it (anchor/card unification)
		return try receive(
			sendGroupWelcome: decoded.mySendGroupWelcome,
			remoteKeyPackage: decoded.myKeyPackage,
			remoteClientId: remoteClientId,
			combinedWelcomeDigest: appWelcomeDigest,
			stapledMessage: stapledPrivateMessage,
			newClientId: remoteClientId
		)
	}
}

extension AbstractTwoMLS.Session {
	func exchange(with remote: some AbstractTwoMLS.Session) throws {
		try send(to: remote)
		try remote.send(to: self)
	}

	func send(to remote: some AbstractTwoMLS.Session) throws {
		let outgoing = UUID().uuidString.utf8Data
		_ = try prepareToEncrypt(proposing: nil)
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
