import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import TwoMLSPQSession
import XCTest

// Fresh §A.1 establishment across engines, both ways. The reply's welcome halves and its
// return key package are MLSMessages, the form the deployed engine emits and requires, so
// each engine must accept what the other sends: plain, with the parallel A.3 bootstrap, from
// a migrated pre-join initiator, and through a born-dedicated acceptor's handoff.
//
// Suite note: `two_mls_pq` type names collide with this package's wrapper names, so FFI
// record types are module-qualified throughout.

@available(macOS 26, iOS 26, *)
final class EstablishmentFramingCrossEngineTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()

	// MARK: - Plain establishment

	func testNativeInitiatorEstablishesWithRustAcceptor() throws {
		let (bobInvitation, their) = try rustInvitation("efx-bob")
		var alice = try nativeInitiator("efx-alice", to: their)
		let commitment = try alice.bootstrapKPCommitment()
		let frame = try establishmentFrame(
			bobInvitation.openInitial(blob: try alice.pendingOutbound()))

		// The return key package goes to Rust exactly as native framed it.
		let bob = try bobInvitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try XCTUnwrap(frame.returnKeyPackage),
			bootstrapKpCommitment: commitment, spawnToken: Data("efx-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		_ = try alice.processIncoming(try XCTUnwrap(alice.openIncoming(bobFirst)).frame)
		XCTAssertTrue(alice.isEstablished)
	}

	func testRustInitiatorEstablishesWithNativeAcceptor() throws {
		let (bobInvitation, rustKP) = try nativeInvitation("efr-bob")
		var invitation = bobInvitation
		let alice = try rustInitiator("efr-alice", to: rustKP)
		let commitment = try XCTUnwrap(alice.bootstrapKpCommitment())
		let frame = try nativeEstablishmentFrame(
			invitation.openInitial(try XCTUnwrap(alice.pendingOutbound())))

		var bob = try invitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try keyPackage(
				fromMessage: try XCTUnwrap(frame.returnKeyPackage)),
			bootstrapKPCommitment: commitment, spawnToken: Data("efr-spawn".utf8)
		).session
		_ = try bob.prepareToEncrypt()
		let bobFirst = try bob.encrypt(Data("b1".utf8)).frame
		let got = try XCTUnwrap(alice.processIncoming(ciphertext: bobFirst))
		XCTAssertEqual(got.applicationMessage?.appMessageData, Data("b1".utf8))
	}

	// MARK: - A migrated pre-join initiator

	/// A Rust initiator exported before the acceptor's welcome arrives joins it natively.
	/// The export carries the host-shaped app payload a real pre-join initiator holds.
	func testMigratedPreJoinInitiatorJoinsRustAcceptorsWelcome() throws {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("efm-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("efm-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))
		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let returnKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		try aliceSession.setInitialAppPayload(payload: Data("efm-host-signed".utf8))
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let welcomeA = try XCTUnwrap(aliceSession.initialWelcome())

		let export = try aliceSession.migrationExport()
		XCTAssertNil(export.recvGroup)
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeAlice = try TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let bob = try bobInvitation.receive(
			welcome: welcomeA, theirClassicalKeyPackage: returnKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("efm-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		_ = try nativeAlice.processIncoming(
			try XCTUnwrap(nativeAlice.openIncoming(bobFirst)).frame)
		XCTAssertTrue(nativeAlice.isEstablished)
	}

	// MARK: - Sends before establishment

	func testNativePreJoinSendsReachRustAcceptor() throws {
		let (bobInvitation, their) = try rustInvitation("pxa-bob")
		var alice = try nativeInitiator("pxa-alice", to: their)
		let commitment = try alice.bootstrapKPCommitment()
		_ = try alice.prepareToEncrypt()
		let e1 = try alice.encrypt(Data("a1".utf8)).frame
		_ = try alice.prepareToEncrypt()
		let e2 = try alice.encrypt(Data("a2".utf8)).frame
		let f2 = try establishmentFrame(bobInvitation.openInitial(blob: e2))
		let f1 = try establishmentFrame(bobInvitation.openInitial(blob: e1))
		let bob = try bobInvitation.receive(
			welcome: try XCTUnwrap(f2.welcome),
			theirClassicalKeyPackage: try XCTUnwrap(f2.returnKeyPackage),
			bootstrapKpCommitment: commitment, spawnToken: Data("pxa".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		let got2 = try XCTUnwrap(
			bob.processIncoming(ciphertext: try XCTUnwrap(f2.stapledMessage)))
		XCTAssertEqual(got2.applicationMessage?.appMessageData, Data("a2".utf8))
		let got1 = try XCTUnwrap(
			bob.processIncoming(ciphertext: try XCTUnwrap(f1.stapledMessage)))
		XCTAssertEqual(got1.applicationMessage?.appMessageData, Data("a1".utf8))
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		_ = try alice.processIncoming(try XCTUnwrap(alice.openIncoming(bobFirst)).frame)
		XCTAssertTrue(alice.isEstablished)
		_ = try alice.prepareToEncrypt()
		let post = try alice.encrypt(Data("a3".utf8)).frame
		let got3 = try XCTUnwrap(
			bob.processIncoming(
				ciphertext: try XCTUnwrap(bob.openIncoming(blob: post)).frame))
		XCTAssertEqual(got3.applicationMessage?.appMessageData, Data("a3".utf8))
	}

	func testNativePayloadShapeSendReachesRustAcceptor() throws {
		let (bobInvitation, their) = try rustInvitation("pxp-bob")
		let principal = try Principal.generate(
			clientID: Data("pxp-alice".utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let est = try TwoMLSSession.initiate(principal: principal, their: their)
		var alice = est.session
		_ = try alice.setInitialAppPayload(Data("host-signed".utf8))
		_ = try alice.prepareToEncrypt()
		let e = try alice.encrypt(Data("a1".utf8)).frame
		let f = try establishmentFrame(bobInvitation.openInitial(blob: e))
		XCTAssertEqual(f.appPayload, Data("host-signed".utf8))
		XCTAssertNil(f.welcome)
		let bob = try bobInvitation.receive(
			welcome: est.welcome,
			theirClassicalKeyPackage: try MLS.RFC9420.Message.keyPackage(
				est.returnKeyPackage
			).mlsEncoded(),
			bootstrapKpCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: Data("pxp".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		let got = try XCTUnwrap(
			bob.processIncoming(ciphertext: try XCTUnwrap(f.stapledMessage)))
		XCTAssertEqual(got.applicationMessage?.appMessageData, Data("a1".utf8))
	}

	func testRustPreJoinSendReachesNativeAcceptor() throws {
		let (bobInvitation, rustKP) = try nativeInvitation("pxr-bob")
		var invitation = bobInvitation
		let alice = try rustInitiator("pxr-alice", to: rustKP)
		let commitment = try XCTUnwrap(alice.bootstrapKpCommitment())
		_ = try alice.prepareToEncrypt(proposing: nil)
		let e1 = try alice.encrypt(appMessage: Data("r1".utf8)).cipherText
		let f1 = try nativeEstablishmentFrame(invitation.openInitial(e1))
		XCTAssertEqual(f1.stapledMessage?.first, 0x09)
		var bob = try invitation.receive(
			welcome: try XCTUnwrap(f1.welcome),
			theirClassicalKeyPackage: try keyPackage(
				fromMessage: try XCTUnwrap(f1.returnKeyPackage)),
			bootstrapKPCommitment: commitment, spawnToken: Data("pxr".utf8)
		).session
		guard
			case .preEstablishment(let m) = try bob.processIncoming(
				try XCTUnwrap(f1.stapledMessage))
		else { return XCTFail("expected preEstablishment") }
		XCTAssertEqual(m.applicationMessage, Data("r1".utf8))
		XCTAssertEqual(
			m.authenticatedData, try classicalProvider.hash(try XCTUnwrap(f1.welcome)))
	}

	func testMigratedPreJoinInitiatorSendsWithCarriedPayload() throws {
		let alice = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data("pxm-alice".utf8))
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(
			clientId: Data("pxm-bob".utf8))
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))
		let aliceSession = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alice, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		let returnKP = try alice.generateKeyPackage(suite: .init(value: 0x0003))
		try aliceSession.setInitialAppPayload(payload: Data("pxm-host-signed".utf8))
		let commitment = try XCTUnwrap(aliceSession.bootstrapKpCommitment())
		let welcomeA = try XCTUnwrap(aliceSession.initialWelcome())
		let export = try aliceSession.migrationExport()
		let archive = try SessionMigrator.mint(
			kind: .checkpoint, from: export,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).archive
		var nativeAlice = try TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		_ = try nativeAlice.prepareToEncrypt()
		let e = try nativeAlice.encrypt(Data("m1".utf8)).frame
		let f = try establishmentFrame(bobInvitation.openInitial(blob: e))
		XCTAssertEqual(f.appPayload, Data("pxm-host-signed".utf8))
		let bob = try bobInvitation.receive(
			welcome: welcomeA, theirClassicalKeyPackage: returnKP,
			bootstrapKpCommitment: commitment, spawnToken: Data("pxm-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		let got = try XCTUnwrap(
			bob.processIncoming(ciphertext: try XCTUnwrap(f.stapledMessage)))
		XCTAssertEqual(got.applicationMessage?.appMessageData, Data("m1".utf8))
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		guard
			case .decrypted(let d) = try nativeAlice.processIncoming(
				try XCTUnwrap(nativeAlice.openIncoming(bobFirst)).frame)
		else { return XCTFail("expected native alice to decrypt bob's first frame") }
		_ = try TwoMLSSession.restore(
			core: d.update.kind == .core ? d.update.archive : nil, checkpoint: archive,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
	}

	// MARK: - The parallel A.3 bootstrap

	func testParallelA3CompletesFromNativeInitiatorToRustAcceptor() throws {
		let (bobInvitation, their) = try rustInvitation("efpn-bob")
		var alice = try nativeInitiator("efpn-alice", to: their)
		let commitment = try alice.bootstrapKPCommitment()
		let kpEnvelope = try XCTUnwrap(alice.pqBootstrapEnvelope())

		guard
			case .bootstrapKp(let heldKP) = try bobInvitation.openInitial(
				blob: kpEnvelope)
		else {
			return XCTFail("expected the parallel bootstrap KP")
		}
		let frame = try establishmentFrame(
			bobInvitation.openInitial(blob: try alice.pendingOutbound()))
		let bob = try bobInvitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try XCTUnwrap(frame.returnKeyPackage),
			bootstrapKpCommitment: commitment, spawnToken: Data("efpn-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		XCTAssertNotNil(bobInvitation.bootstrapKpGroupId(kpFrame: heldKP))
		try bob.pqBootstrapRespond(kpMsg: heldKP)
		let welcomePrime = try XCTUnwrap(bob.pqPendingOutbound(sealing: .fresh))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		_ = try alice.processIncoming(try XCTUnwrap(alice.openIncoming(bobFirst)).frame)
		XCTAssertTrue(alice.isEstablished)
		let opened = try XCTUnwrap(alice.openIncoming(welcomePrime))
		XCTAssertEqual(opened.kind, .pqSideBand(.bootstrapWelcome))
		_ = try alice.pqBootstrapJoin(opened.frame)
		XCTAssertTrue(alice.isFullyEstablished)

		// Alice's next frame carries the bind, which completes A.3 on the Rust side.
		_ = try alice.prepareToEncrypt()
		_ = try bob.processIncoming(ciphertext: try alice.encrypt(Data("a1".utf8)).frame)
		XCTAssertTrue(bob.isFullyEstablished())
	}

	func testParallelA3CompletesFromRustInitiatorToNativeAcceptor() throws {
		let (bobInvitation, rustKP) = try nativeInvitation("efpr-bob")
		var invitation = bobInvitation
		let alice = try rustInitiator("efpr-alice", to: rustKP)
		let commitment = try XCTUnwrap(alice.bootstrapKpCommitment())
		let kpEnvelope = try alice.pqBootstrapEnvelope()

		guard case .bootstrapKP(let heldKP) = try invitation.openInitial(kpEnvelope) else {
			return XCTFail("expected the parallel bootstrap KP")
		}
		let frame = try nativeEstablishmentFrame(
			invitation.openInitial(try XCTUnwrap(alice.pendingOutbound())))
		var bob = try invitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try keyPackage(
				fromMessage: try XCTUnwrap(frame.returnKeyPackage)),
			bootstrapKPCommitment: commitment, spawnToken: Data("efpr-spawn".utf8)
		).session
		XCTAssertNotNil(invitation.bootstrapKPGroupID(kpFrame: heldKP))
		_ = try bob.pqBootstrapRespond(heldKP)

		_ = try bob.prepareToEncrypt()
		let bobFirst = try bob.encrypt(Data("b1".utf8)).frame
		let welcomePrime = try XCTUnwrap(bob.pqPendingOutbound())
		_ = try alice.processIncoming(ciphertext: bobFirst)
		try alice.pqBootstrapBind(welcomeMsg: welcomePrime)
		XCTAssertTrue(alice.isFullyEstablished())

		// Alice's next frame carries the bind, which completes A.3 on the native side.
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceFirst = try alice.encrypt(appMessage: Data("a1".utf8)).cipherText
		_ = try bob.processIncoming(try XCTUnwrap(bob.openIncoming(aliceFirst)).frame)
		XCTAssertTrue(bob.isFullyEstablished)
	}

	// MARK: - A born-dedicated acceptor's handoff

	/// A Rust acceptor born under a dedicated id staples the `0x0B` handoff on its first
	/// frame. The native initiator pauses on it, and once approved, joins the welcome it wraps.
	func testRustBornDedicatedHandoffJoinsNativeInitiator() throws {
		let (bobInvitation, their) = try rustInvitation("efbn-bob")
		var alice = try nativeInitiator("efbn-alice", to: their)
		let commitment = try alice.bootstrapKPCommitment()
		let frame = try establishmentFrame(
			bobInvitation.openInitial(blob: try alice.pendingOutbound()))
		let dedicatedID = Data("efbn-bob-dedicated".utf8)
		let bob = try bobInvitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try XCTUnwrap(frame.returnKeyPackage),
			bootstrapKpCommitment: commitment, spawnToken: Data("efbn-spawn".utf8),
			newClientId: dedicatedID, expectedRemote: nil, expectedAppBinding: nil)
		let signedEnvelope = Data("efbn-signed-delegation".utf8)
		try bob.installEstablishmentEnvelope(envelope: signedEnvelope)

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		let opened = try XCTUnwrap(alice.openIncoming(bobFirst))
		guard
			case .pendingEstablishment(let pending) = try alice.processIncoming(
				opened.frame)
		else {
			return XCTFail("expected the handoff to pause for approval")
		}
		XCTAssertEqual(pending.envelope, signedEnvelope)
		_ = try alice.processIncomingApproved(
			opened.frame,
			approvedEnvelopeDigest: Data(SHA256.hash(data: pending.envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: pending.welcome)),
			expectedCreator: dedicatedID)
		XCTAssertTrue(alice.isEstablished)
	}

	/// A native acceptor born under a dedicated id staples the `0x0B` handoff. The Rust
	/// initiator pauses on it, and once approved, joins and decrypts the same frame.
	func testNativeBornDedicatedHandoffJoinsRustInitiator() throws {
		let (bobInvitation, rustKP) = try nativeInvitation("efbr-bob")
		var invitation = bobInvitation
		let alice = try rustInitiator("efbr-alice", to: rustKP)
		let commitment = try XCTUnwrap(alice.bootstrapKpCommitment())
		let frame = try nativeEstablishmentFrame(
			invitation.openInitial(try XCTUnwrap(alice.pendingOutbound())))
		let dedicatedID = Data("efbr-bob-dedicated".utf8)
		var bob = try invitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try keyPackage(
				fromMessage: try XCTUnwrap(frame.returnKeyPackage)),
			bootstrapKPCommitment: commitment, spawnToken: Data("efbr-spawn".utf8),
			newClientID: dedicatedID
		).session
		let signedEnvelope = Data("efbr-signed-delegation".utf8)
		_ = try bob.installEstablishmentEnvelope(signedEnvelope)

		_ = try bob.prepareToEncrypt()
		let bobFirst = try bob.encrypt(Data("b1".utf8)).frame
		let paused = try XCTUnwrap(alice.processIncoming(ciphertext: bobFirst))
		let pending = try XCTUnwrap(paused.pendingEstablishment)
		XCTAssertEqual(pending.envelope, signedEnvelope)
		let resumed = try alice.processIncomingApproved(
			ciphertext: bobFirst,
			approvedEnvelopeDigest: Data(SHA256.hash(data: pending.envelope)),
			approvedWelcomeDigest: Data(SHA256.hash(data: pending.welcome)),
			expectedCreator: dedicatedID)
		XCTAssertEqual(resumed?.applicationMessage?.appMessageData, Data("b1".utf8))
	}

	// MARK: - Scaffolding

	/// A Rust invitation, and its combiner key package as native reads it.
	private func rustInvitation(
		_ clientID: String
	) throws -> (TwoMLSPQBinding.TwoMlsPqInvitation, TwoMLSPQSession.CombinerKeyPackage) {
		let principal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data(clientID.utf8))
		let invitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: principal.generateInvitation(lastResort: false))
		let their = try XCTUnwrap(
			TwoMLSPQSession.CombinerKeyPackage(
				publishedBlob: TwoMLSPQBinding.encodeCombinerKeyPackage(
					keyPackage: invitation.combinerKeyPackage())))
		return (invitation, their)
	}

	/// A native invitation, and its published combiner key package as Rust reads it.
	private func nativeInvitation(
		_ clientID: String
	) throws -> (TwoMLSPQSession.Invitation, TwoMLSPQBinding.CombinerKeyPackage) {
		let principal = try Principal.generate(
			clientID: Data(clientID.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let (invitation, _) = try principal.generateInvitation(lastResort: false)
		let published = try XCTUnwrap(invitation.combinerKeyPackage)
		let rustKP = try TwoMLSPQBinding.decodeCombinerKeyPackage(
			bytes: try published.publishedBlob())
		return (invitation, rustKP)
	}

	private func nativeInitiator(
		_ clientID: String, to their: TwoMLSPQSession.CombinerKeyPackage
	) throws -> TwoMLSSession {
		let principal = try Principal.generate(
			clientID: Data(clientID.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		return try TwoMLSSession.initiate(principal: principal, their: their).session
	}

	/// A Rust initiator whose host attaches its return key package, as a real host does.
	private func rustInitiator(
		_ clientID: String, to rustKP: TwoMLSPQBinding.CombinerKeyPackage
	) throws -> TwoMLSPQBinding.TwoMlsPqSession {
		let principal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: Data(clientID.utf8))
		let session = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: principal, theirKeyPackage: rustKP, appBinding: nil)
		try session.setInitialReturnKeyPackage(
			keyPackage: try principal.generateKeyPackage(suite: .init(value: 0x0003)))
		return session
	}

	private func establishmentFrame(
		_ opened: TwoMLSPQBinding.OpenedInitial
	) throws -> TwoMLSPQBinding.InitialFrame {
		guard case .establishment(let frame) = opened else {
			throw frameError("expected an establishment envelope, got \(opened)")
		}
		return frame
	}

	private func nativeEstablishmentFrame(
		_ opened: TwoMLSPQSession.OpenedInitial
	) throws -> TwoMLSPQSession.InitialFrame {
		guard case .establishment(let frame) = opened else {
			throw frameError("expected an establishment envelope, got \(opened)")
		}
		return frame
	}

	private func keyPackage(fromMessage bytes: Data) throws -> MLS.RFC9420.KeyPackage {
		guard case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(mlsEncoded: bytes)
		else {
			throw frameError("expected an MLSMessage holding a key package")
		}
		return keyPackage
	}

	private func frameError(_ description: String) -> NSError {
		NSError(domain: "efx", code: 1, userInfo: [NSLocalizedDescriptionKey: description])
	}
}
