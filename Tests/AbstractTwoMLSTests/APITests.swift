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
		currentInvitation = try .init(persisted: try client.makeInvitation())
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
		#expect(try localSession.sendRendezvous == nil)
		#expect(listenAtBirth.count == 1)

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
		#expect(!localGroupId.isEmpty)
		#expect(!remoteGroupId.isEmpty)
		let localPost = try #require(try localSession.sendRendezvous)
		let remotePost = try #require(try remoteSession.sendRendezvous)
		#expect(remoteListen.values.contains(localPost))
		#expect(localListen.values.contains(remotePost))

		//consistent state so far: local holds an APQ send group; remote's classical
		//send group derives from it. Local fetched remote's (A)PQ keyPackage, formed
		//the (A)PQ group, sent the APQ welcome, and stapled a proposal for the
		//classical keyPackage backing remote's send group. It will now also send,
		//slowly, a PQ keyPackage so remote can stand up its own APQ group.

		//the PQ side-band is a separate capability from the base Session;
		//PQSession always conforms, so take the abstract PQ view directly
		let localPQ = localSession as any AbstractTwoMLS.PQRatchetingSession
		let remotePQ = remoteSession as any AbstractTwoMLS.PQRatchetingSession

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
		#expect(localPQ.isFullyEstablished)
		#expect(remotePQ.isFullyEstablished)

		try localSession.exchange(with: remoteSession)

		//routing follows the ratchet: when the peer's stapled Upd(self) is
		//approved (queueProposal) the next send commits it, advancing our send
		//group's epoch and minting a new listen address; the peer's post address
		//migrates onto it, and older epochs stay listed for in-flight traffic
		_ = try remoteSession.prepareToEncrypt(proposing: nil)
		let updFrame = try remoteSession.encrypt(appMessage: Data("upd".utf8))
		let updDecrypted = try #require(
			try localSession.processIncoming(ciphertext: updFrame.cipherText))
		let offered = try #require(updDecrypted.proposal)
		try localSession.queueProposal(digest: offered.digest)
		_ = try localSession.prepareToEncrypt(proposing: nil)
		let commitFrame = try localSession.encrypt(appMessage: Data("commit".utf8))
		_ = try remoteSession.processIncoming(ciphertext: commitFrame.cipherText)

		let (_, localListenLater) = try localSession.shouldListenOn()
		#expect(localListenLater.count == localListen.count + 1)
		let remotePostLater = try #require(try remoteSession.sendRendezvous)
		#expect(remotePostLater != remotePost)
		#expect(localListenLater.values.contains(remotePostLater))
		#expect(localListenLater.values.contains(remotePost))

		//the encrypt result reports the APQ epoch pair (pq side-band / classical
		//message group) — the initiator's full pair after its commit — and the
		//commit's classical epoch keys the listen address the commit minted
		#expect(
			commitFrame.epochs
				== AbstractTwoMLS.APQEpochs(pqEpoch: 1, classicalEpoch: 2))
		#expect(localListenLater[commitFrame.epochs.classicalEpoch] == remotePostLater)

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
		#expect(localPQ.epochs.pqEpoch == 2)
		#expect(remotePQ.epochs.pqEpoch == 2)

		//and the session still messages both ways on the rekeyed groups
		try localSession.exchange(with: remoteSession)
	}
}

//Increment B: agent rotation. Phase 8 (classical) rides the session surface —
//receive(newClientId:) stages the dedicated agent, prepareToEncrypt(proposing:)
//puts the candidate on the wire, and the PEER's approval + commit canonicalizes
//it (contract v9 candidate lifecycle; see `rotate(to:peer:)`) — then the PQ
//side-band catches the PQ leaves up via begin(.rekey, rotating:), which the peer
//observes as PQInbound.rotatedCredential.
struct RotationDemo {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func acceptorRotatesToDedicatedAgent() async throws {
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)

		//the app spawns a dedicated agent for this session and passes its id in;
		//receive stages it for the Phase 8 rotation
		let dedicatedAgentId = AbstractTwoMLS.ClientID.mock()
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId,
			newClientId: dedicatedAgentId
		)

		//Phase 8, contract v9+ candidate lifecycle: the acceptor's first reply
		//CARRIES the candidate proposal (and staples the return welcome); the
		//initiator's approval + commit canonicalizes it, and the staple back
		//completes the handoff — see `rotate(to:peer:)`.
		try remoteSession.rotate(to: dedicatedAgentId, peer: localSession)

		//messaging still flows both ways under the rotated agent
		try localSession.exchange(with: remoteSession)
	}

	@Test func rekeyCarriesCredentialHandoff() async throws {
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let dedicatedAgentId = AbstractTwoMLS.ClientID.mock()
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId,
			newClientId: dedicatedAgentId
		)

		//Phase 8 first, contract v9+ dance: the classical rotation canonicalizes
		//the dedicated agent and swaps the session client — the dance's closing
		//staple doubles as the confirming reply (see `rotate(to:peer:)`)
		try remoteSession.rotate(to: dedicatedAgentId, peer: localSession)

		//PQSession always conforms; take the abstract PQ view directly
		let localPQ = localSession as any AbstractTwoMLS.PQRatchetingSession
		let remotePQ = remoteSession as any AbstractTwoMLS.PQRatchetingSession

		//A.4: local owes the bootstrap; remote's new send-PQ half is born under
		//the dedicated agent
		let kp = try localPQ.begin(.finishBootstrap, rotating: nil)
		let bootIn = try remotePQ.ingest(kp.payload)
		guard let bootReply = try remotePQ.advance(after: bootIn) else {
			throw TestErrors.unexpected
		}
		_ = try localPQ.ingest(bootReply.payload)
		#expect(remotePQ.isFullyEstablished)
		#expect(remotePQ.turn == .weInitiate)

		//A.3 cannot carry a rotation — no updatePath rides the ratchet
		do {
			_ = try remotePQ.begin(.ratchet, rotating: dedicatedAgentId)
			Issue.record("expected .rotationCannotRideRatchet")
		} catch let error as AbstractTwoMLS.SessionError {
			#expect(error.code == .rotationCannotRideRatchet)
			#expect(error.disposition == .callerBug)
		}

		//A.5 with the credential handoff: the rekey hands remote's PQ leaves to
		//the dedicated agent; local observes the announced credential
		let rekey = try remotePQ.begin(.rekey, rotating: dedicatedAgentId)
		let rekeyIn1 = try localPQ.ingest(rekey.payload)
		#expect(rekeyIn1.kind == .rekey)
		#expect(rekeyIn1.rotatedCredential == dedicatedAgentId)
		guard let rekeyReply = try localPQ.advance(after: rekeyIn1) else {
			throw TestErrors.unexpected
		}
		let rekeyIn2 = try remotePQ.ingest(rekeyReply.payload)
		guard rekeyIn2.rotatedCredential == nil else { throw TestErrors.unexpected }
		guard let rekeyFinal = try remotePQ.advance(after: rekeyIn2) else {
			throw TestErrors.unexpected
		}
		_ = try localPQ.ingest(rekeyFinal.payload)
		#expect(localPQ.epochs.pqEpoch == 2)
		#expect(remotePQ.epochs.pqEpoch == 2)

		//the rekeyed, rotated groups keep working — and a rotation-less rekey
		//(local's turn) reports no credential
		try localSession.exchange(with: remoteSession)
		guard localPQ.turn == .weInitiate else { throw TestErrors.unexpected }
		let plain = try localPQ.begin(.rekey, rotating: nil)
		let plainIn = try remotePQ.ingest(plain.payload)
		guard plainIn.rotatedCredential == nil else { throw TestErrors.unexpected }
		guard let plainReply = try remotePQ.advance(after: plainIn) else {
			throw TestErrors.unexpected
		}
		let plainIn2 = try localPQ.ingest(plainReply.payload)
		guard let plainFinal = try localPQ.advance(after: plainIn2) else {
			throw TestErrors.unexpected
		}
		_ = try remotePQ.ingest(plainFinal.payload)
	}
}

//Increment C: forward routing. A transport re-delivery of the initial sealed frame
//decodes as .forward to the already-spawned session instead of a fresh AppWelcome;
//the owning session acknowledges the replay via forwarded(headerDecrypted:) — for the
//PQ backend a replay never carries an undelivered payload (the initiator cannot
//staple a private message pre-establishment), so the acknowledgment is nil.
struct ForwardRoutingDemo {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func replayedInitialFrameForwardsToSpawnedSession() async throws {
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)

		//before the welcome is accepted, the frame decodes as a fresh AppWelcome
		guard
			case .appWelcome = try remote.currentInvitation.decodeHeader(
				ciphertext: encryptedCombinedWelcome)
		else { throw TestErrors.unexpected }

		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId
		)

		//a transport re-delivery of the same frame now routes to the spawned
		//session; the payload is the header-decrypted frame for `forwarded`
		guard
			case .forward(let groupId, let mlsMessageData) =
				try remote.currentInvitation.decodeHeader(
					ciphertext: encryptedCombinedWelcome)
		else { throw TestErrors.unexpected }
		#expect(groupId.identifier.count == 32)
		#expect(!mlsMessageData.isEmpty)

		//the spawned session acknowledges the replay — nothing new inside
		guard try remoteSession.forwarded(headerDecrypted: mlsMessageData) == nil else {
			throw TestErrors.unexpected
		}
		//a mis-routed forward is refused: an initiator-side session has no spawn
		//token, so `forwarded` must *throw* — not silently return nil. The crate's
		//SessionNotReady at the forwarded surface maps to `.misroutedFrame`.
		do {
			_ = try localSession.forwarded(headerDecrypted: mlsMessageData)
			throw TestErrors.unexpected
		} catch let error as AbstractTwoMLS.SessionError {
			#expect(error.code == .misroutedFrame)
		}

		//forwarding survives invitation restore — the post-receive state (spawn
		//table included) leaves only via the sink; restore from its newest
		//checkpoint. (The sink arrives after receive: the install-time baseline
		//captures the already-mutated state.)
		let invitationSink = RecordingSink()
		try remote.currentInvitation.installSink(invitationSink)
		let restored = try AbstractTwoMLS.PQInvitation(
			persisted: invitationSink.invitationPersisted()
		)
		guard
			case .forward = try restored.decodeHeader(
				ciphertext: encryptedCombinedWelcome)
		else { throw TestErrors.unexpected }

		//a fresh frame from a different initiator still decodes as an AppWelcome
		let third = try ClientWrapper<AbstractTwoMLS.PQClient>()
		let (_, freshWelcome) = try third.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		guard
			case .appWelcome = try remote.currentInvitation.decodeHeader(
				ciphertext: freshWelcome)
		else { throw TestErrors.unexpected }

		//and the spawned session still messages normally after the replay (the
		//acceptor's first frame staples its return welcome, completing the
		//initiator's side of establishment)
		try remoteSession.exchange(with: localSession)
	}
}

//Session persist/restore round-trips (contract 13, push): the sink's newest
//Core/Checkpoint pair rebuilds a working session that keeps talking to the peer.
struct SessionArchiveDemo {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func restoredSessionContinuesTheConversation() throws {
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId
		)
		// Complete establishment, then confirm a routine round-trip works.
		try remoteSession.send(to: localSession)
		try localSession.exchange(with: remoteSession)

		// Restore the acceptor from its sink's newest slots into a fresh object.
		let snapshot = remoteSession.epochs
		let restored = try roundTripPush(remoteSession)

		// The restored session picks up exactly where the pushed state left off...
		#expect(restored.epochs.pqEpoch == snapshot.pqEpoch)
		#expect(restored.epochs.classicalEpoch == snapshot.classicalEpoch)
		#expect(restored.isFullyEstablished == remoteSession.isFullyEstablished)

		// ...and keeps talking to the peer. Single-writer discipline: drive
		// `restored`, not the superseded `remoteSession` (its ratchet position
		// is now behind the pushed state — exactly the H1 hazard the push
		// model exists to prevent).
		try localSession.send(to: restored)
		try restored.send(to: localSession)
	}
}

//The suite classifier: a combiner blob reports its PQ half; anything unparseable
//returns nil (no magic sentinel).
struct CipherSuiteParsingTests {
	@Test func combinerKeyPackageReportsItsPqSuite() throws {
		let invitation = try AbstractTwoMLS.PQInvitation(
			persisted: try AbstractTwoMLS.PQClient(clientId: .mock()).makeInvitation()
		)
		let suite = try #require(
			AbstractTwoMLS.PQClient.parseKeyPackageSuite(
				encoded: invitation.encodedKeyPackage)
		)
		#expect(suite == 0xFDEA)  // ML-KEM-768
		#expect(AbstractTwoMLS.PQClient.supportedSuites.contains(suite))
	}

	@Test func supportedSuitesAreTheCombinerPair() {
		//0x0003 = X25519+ChaCha20Poly1305 (classical), 0xFDEA = ML-KEM-768 (pq)
		#expect(AbstractTwoMLS.PQClient.supportedSuites == [0x0003, 0xFDEA])
	}

	@Test func unparseableKeyPackageReturnsNil() {
		#expect(
			AbstractTwoMLS.PQClient.parseKeyPackageSuite(
				encoded: Data([0xDE, 0xAD, 0xBE, 0xEF])) == nil
		)
	}
}

//`createTwoMLSGroup` binds the published key package to the identity the app is
//addressing, refusing before it seals the AppWelcome to a stranger. (The receive-side
//counterpart is covered by PQInvitationTests.receiveRejectsMismatchedIdentity.)
struct InitiatorIdentityBindingDemo {
	@Test func createGroupRejectsMismatchedRemoteIdentity() throws {
		let acceptor = try ClientWrapper<AbstractTwoMLS.PQClient>()
		let initiator = try AbstractTwoMLS.PQClient(clientId: .mock())
		let (sendGroup, _, _) = try initiator.reply(
			keyPackageMessage: acceptor.currentInvitation.encodedKeyPackage
		)
		do {
			_ = try initiator.createTwoMLSGroup(
				remoteAgentId: .mock(),  // not the acceptor's authenticated id
				mySendGroup: sendGroup,
				theirKeyPackageMessage: acceptor.currentInvitation.encodedKeyPackage,
				appWelcome: Data("welcome".utf8)
			)
			Issue.record("expected .identityMismatch")
		} catch {  // createTwoMLSGroup is throws(SessionError) — error is typed
			#expect(error.code == .identityMismatch)
		}
	}
}

//The defining last-resort capability: one invitation onboards more than one distinct
//initiator, each pairing establishing and exchanging independently. (`lastResort: true`
//is hardcoded in PQClient.makeInvitation / PQInvitation.init.)
struct LastResortReuseDemo {
	@Test func oneInvitationEstablishesWithTwoDistinctRemotes() throws {
		let acceptor = try ClientWrapper<AbstractTwoMLS.PQClient>()

		for _ in 0..<2 {
			let initiator = try ClientWrapper<AbstractTwoMLS.PQClient>()
			let (initiatorSession, encryptedCombinedWelcome) = try initiator.client.reply(
				remoteClientId: acceptor.clientId,
				encodedRemoteKpkg: acceptor.currentInvitation.encodedKeyPackage
			)
			let (acceptorSession, _) = try acceptor.currentInvitation.receiveReply(
				ciphertext: encryptedCombinedWelcome,
				expecting: try initiator.clientId
			)
			//complete establishment and confirm a routine round-trip, per pairing
			try acceptorSession.send(to: initiatorSession)
			try initiatorSession.exchange(with: acceptorSession)
		}
	}
}

//Digest-surface cleanup: the binding values the backends expose through the
//TypedDigest slots are honest sha256 digests with cross-side coherence — the
//classical backend's semantics, now matched by the PQ backend (previously an
//exporter nonce / raw group ids wearing the label).
struct ProposalBindingDemo {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func proposalBindingIsCoherentAcrossSides() async throws {
		let (localSession, encryptedCombinedWelcome) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: encryptedCombinedWelcome,
			expecting: try local.clientId
		)
		//remote's first frame staples the return welcome; local joins in-band
		try remoteSession.send(to: localSession)

		//the sender's proposalHash is the sha256 of the staged Upd(self) proposal,
		//so the receiver's independently derived digest equals it
		let prep = try #require(try remoteSession.prepareToEncrypt(proposing: nil))
		let frame = try remoteSession.encrypt(appMessage: Data("staple".utf8))
		let decrypted = try #require(
			try localSession.processIncoming(ciphertext: frame.cipherText)
		)
		let offered = try #require(decrypted.proposal)
		#expect(prep.proposalHash == offered.digest)
		#expect(prep.proposalHash.type == .sha256)

		//the receiver's ordering context equals its own proposalContext (sha256 of
		//its recv group's classical group id) — self-consistent across surfaces
		#expect(offered.context == localSession.proposalContext)
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
		guard let keyPackageSuite = Self.parseKeyPackageSuite(encoded: encodedRemoteKpkg),
			Self.supportedSuites.contains(keyPackageSuite)
		else {
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
	// `newClientId` is the fresh session-dedicated agent the acceptor stages for
	// rotation (the app spawns it — see AuthDIDManager.createSession); the default
	// mirrors that for tests that never drive the rotation.
	func receiveReply(
		ciphertext: Data,
		expecting remoteClientId: AbstractTwoMLS.ClientID,
		newClientId: AbstractTwoMLS.ClientID = .mock()
	) throws -> (Session, Data?) {
		let headerDecrypted = try decodeHeader(
			ciphertext: ciphertext
		)

		guard
			case .appWelcome(
				welcomeToken: let welcomeToken,
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
			welcomeToken: welcomeToken,
			stapledMessage: stapledPrivateMessage,
			newClientId: newClientId
		)
	}
}

extension AbstractTwoMLS.Session {
	/// Phase 8 classical rotation — the contract v9+ candidate lifecycle, mirroring
	/// the crate's `rotate_round` test helper. The rotating party's frame CARRIES the
	/// staged candidate as its Upd proposal (the proposer never commits its own
	/// rotation); the peer's approval (`queueProposal`) plus commit defines the
	/// canonical next credential; the staple back canonicalizes this side onto it
	/// (including the session-client swap).
	func rotate(
		to newClientId: AbstractTwoMLS.ClientID,
		peer: some AbstractTwoMLS.Session
	) throws {
		// Propose: no commit rides this frame.
		_ = try prepareToEncrypt(proposing: newClientId)
		let frame = try encrypt(appMessage: Data("rotate".utf8))
		let got = try peer.processIncoming(ciphertext: frame.cipherText).tryUnwrap
		let offered = try got.proposal.tryUnwrap
		guard offered.proposing == newClientId else { throw TestErrors.unexpected }
		// Approve + commit: the peer's commit folds the Upd and defines the
		// canonical next credential. Approval populates the tally (M6 truth
		// surface); the commit consumes it.
		try peer.queueProposal(digest: offered.digest)
		guard peer.queuedRemoteSuccessor == newClientId else {
			throw TestErrors.unexpected
		}
		let prepared = try peer.prepareToEncrypt(proposing: nil).tryUnwrap
		guard prepared.didCommit, prepared.commitedRemoteClientId == newClientId
		else { throw TestErrors.unexpected }
		guard peer.theirPrincipalState == .sync(newClientId) else {
			throw TestErrors.unexpected
		}
		let back = try peer.encrypt(appMessage: Data("canonicalize".utf8))
		// The staple back canonicalizes the rotating side onto the new principal —
		// remoteCommit is the one-shot hint; the principal state is the truth.
		let confirmed = try processIncoming(ciphertext: back.cipherText).tryUnwrap
		guard confirmed.remoteCommit?.newRecipient == newClientId
		else { throw TestErrors.unexpected }
		guard myPrincipalState == .sync(newClientId) else {
			throw TestErrors.unexpected
		}
	}

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
