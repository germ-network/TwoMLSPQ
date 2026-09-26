import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQSession

// Builds an established pair for a given engine direction, using the exact establishment
// sequences the cross-engine suites already prove (EstablishmentFramingCrossEngineTests):
// plain §A.1 establishment plus the parallel A.3 bootstrap, both ways, up to fully
// established. Establishment happens before the randomized script runs, so the DSL itself
// stays a steady-state op set.

/// Which engine initiates. The differential compares the two directions under one script.
enum Direction: String, CaseIterable, Sendable {
	case swiftInitiator
	case rustInitiator
	case swiftPair
	case rustPair

	var isMixed: Bool { self == .swiftInitiator || self == .rustInitiator }
}

@available(macOS 26, iOS 26, *)
struct Pair {
	let initiator: EngineSession
	let acceptor: EngineSession

	func session(_ role: Role) -> EngineSession { role == .a ? initiator : acceptor }
}

@available(macOS 26, iOS 26, *)
enum PairFactory {
	static let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	static let pqProvider = MLKEM768CipherSuiteProvider()

	static func make(_ direction: Direction, seed: UInt64) throws -> Pair {
		switch direction {
		case .swiftInitiator: return try swiftInitiatorRustAcceptor(seed: seed)
		case .rustInitiator: return try rustInitiatorSwiftAcceptor(seed: seed)
		case .swiftPair: return try swiftPair(seed: seed)
		case .rustPair: return try rustPair(seed: seed)
		}
	}

	// MARK: - Swift initiator -> Rust acceptor

	private static func swiftInitiatorRustAcceptor(seed: UInt64) throws -> Pair {
		let aliceID = Data("diff-swift-a-\(seed)".utf8)
		let bobID = Data("diff-swift-b-\(seed)".utf8)
		let alice = try Principal.generate(
			clientID: aliceID, classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: bobID)
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))
		let their = try unwrap(
			TwoMLSPQSession.CombinerKeyPackage(
				publishedBlob: TwoMLSPQBinding.encodeCombinerKeyPackage(
					keyPackage: bobInvitation.combinerKeyPackage())))

		let est = try TwoMLSSession.initiate(principal: alice, their: their)
		var aliceSession = est.session
		let commitment = try aliceSession.bootstrapKPCommitment()
		let kpEnvelope = try unwrap(aliceSession.pqBootstrapEnvelope())
		guard
			case .bootstrapKp(let heldKP) = try bobInvitation.openInitial(
				blob: kpEnvelope)
		else { throw HarnessError.unexpectedSideBandLeg }

		_ = try aliceSession.prepareToEncrypt()
		let aliceFirst = try aliceSession.encrypt(Data("establish-a".utf8)).frame
		guard
			case .establishment(let frame) = try bobInvitation.openInitial(
				blob: aliceFirst)
		else { throw HarnessError.unexpectedSideBandLeg }

		let bob = try bobInvitation.receive(
			welcome: try unwrap(frame.welcome),
			theirClassicalKeyPackage: try unwrap(frame.returnKeyPackage),
			bootstrapKpCommitment: commitment,
			spawnToken: Data("diff-swift-spawn-\(seed)".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		try bob.pqBootstrapRespond(kpMsg: heldKP)
		let welcomePrime = try unwrap(bob.pqPendingOutbound(sealing: .fresh))

		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("establish-b".utf8)).cipherText
		_ = try aliceSession.processIncoming(
			try unwrap(aliceSession.openIncoming(bobFirst)).frame)
		let openedWelcome = try unwrap(aliceSession.openIncoming(welcomePrime))
		guard case .pqSideBand(.bootstrapWelcome) = openedWelcome.kind else {
			throw HarnessError.unexpectedSideBandLeg
		}
		_ = try aliceSession.pqBootstrapJoin(openedWelcome.frame)
		_ = try aliceSession.prepareToEncrypt()
		_ = try bob.processIncoming(
			ciphertext: try aliceSession.encrypt(Data("establish-a2".utf8)).frame)

		return Pair(
			initiator: SwiftEngineSession(
				session: aliceSession, classicalProvider: classicalProvider,
				pqProvider: pqProvider),
			acceptor: try RustEngineSession(session: bob))
	}

	// MARK: - Rust initiator -> Swift acceptor

	private static func rustInitiatorSwiftAcceptor(seed: UInt64) throws -> Pair {
		let aliceID = Data("diff-rust-a-\(seed)".utf8)
		let bobID = Data("diff-rust-b-\(seed)".utf8)
		let alicePrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: aliceID)
		let bobPrincipal = try Principal.generate(
			clientID: bobID, classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let published = try unwrap(invitation.combinerKeyPackage)
		let rustKP = try TwoMLSPQBinding.decodeCombinerKeyPackage(
			bytes: try published.publishedBlob())

		let alice = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alicePrincipal, theirKeyPackage: rustKP, appBinding: nil)
		try alice.setInitialReturnKeyPackage(
			keyPackage: try alicePrincipal.generateKeyPackage(
				suite: .init(value: 0x0003)))
		let commitment = try unwrap(alice.bootstrapKpCommitment())
		let kpEnvelope = try alice.pqBootstrapEnvelope()
		guard case .bootstrapKP(let heldKP) = try invitation.openInitial(kpEnvelope) else {
			throw HarnessError.unexpectedSideBandLeg
		}

		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceFirst = try alice.encrypt(appMessage: Data("establish-a".utf8)).cipherText
		guard case .establishment(let frame) = try invitation.openInitial(aliceFirst) else {
			throw HarnessError.unexpectedSideBandLeg
		}
		var bob = try invitation.receive(
			welcome: try unwrap(frame.welcome),
			theirClassicalKeyPackage: try keyPackage(
				fromMessage: try unwrap(frame.returnKeyPackage)),
			bootstrapKPCommitment: commitment,
			spawnToken: Data("diff-rust-spawn-\(seed)".utf8)
		).session
		_ = try bob.pqBootstrapRespond(heldKP)

		_ = try bob.prepareToEncrypt()
		let bobFirst = try bob.encrypt(Data("establish-b".utf8)).frame
		let welcomePrime = try unwrap(bob.pqPendingOutbound())
		_ = try alice.processIncoming(ciphertext: bobFirst)
		try alice.pqBootstrapBind(welcomeMsg: welcomePrime)
		_ = try alice.prepareToEncrypt(proposing: nil)
		_ = try bob.processIncoming(
			try unwrap(
				bob.openIncoming(
					try alice.encrypt(appMessage: Data("establish-a2".utf8))
						.cipherText)
			).frame)

		return Pair(
			initiator: try RustEngineSession(session: alice),
			acceptor: SwiftEngineSession(
				session: bob, classicalProvider: classicalProvider,
				pqProvider: pqProvider))
	}

	// MARK: - Pure pairs (oracles)

	private static func swiftPair(seed: UInt64) throws -> Pair {
		let aliceID = Data("diff-sw-a-\(seed)".utf8)
		let bobID = Data("diff-sw-b-\(seed)".utf8)
		let alice = try Principal.generate(
			clientID: aliceID, classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: bobID, classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let their = try unwrap(
			TwoMLSPQSession.CombinerKeyPackage(
				publishedBlob: try unwrap(invitation.combinerKeyPackage)
					.publishedBlob()))

		let est = try TwoMLSSession.initiate(principal: alice, their: their)
		var aliceSession = est.session
		let commitment = try aliceSession.bootstrapKPCommitment()
		let kpEnvelope = try unwrap(aliceSession.pqBootstrapEnvelope())
		guard case .bootstrapKP(let heldKP) = try invitation.openInitial(kpEnvelope) else {
			throw HarnessError.unexpectedSideBandLeg
		}
		_ = try aliceSession.prepareToEncrypt()
		let aliceFirst = try aliceSession.encrypt(Data("establish-a".utf8)).frame
		guard case .establishment(let frame) = try invitation.openInitial(aliceFirst) else {
			throw HarnessError.unexpectedSideBandLeg
		}
		var bobSession = try invitation.receive(
			welcome: try unwrap(frame.welcome),
			theirClassicalKeyPackage: try keyPackage(
				fromMessage: try unwrap(frame.returnKeyPackage)),
			bootstrapKPCommitment: commitment,
			spawnToken: Data("diff-sw-spawn-\(seed)".utf8)
		).session
		_ = try bobSession.pqBootstrapRespond(heldKP)
		_ = try bobSession.prepareToEncrypt()
		let bobFirst = try bobSession.encrypt(Data("establish-b".utf8)).frame
		let welcomePrime = try unwrap(bobSession.pqPendingOutbound())
		_ = try aliceSession.processIncoming(
			try unwrap(aliceSession.openIncoming(bobFirst)).frame)
		_ = try aliceSession.pqBootstrapJoin(
			try unwrap(aliceSession.openIncoming(welcomePrime)).frame)
		_ = try aliceSession.prepareToEncrypt()
		_ = try bobSession.processIncoming(
			try unwrap(
				bobSession.openIncoming(
					try aliceSession.encrypt(Data("establish-a2".utf8)).frame)
			).frame)

		return Pair(
			initiator: SwiftEngineSession(
				session: aliceSession, classicalProvider: classicalProvider,
				pqProvider: pqProvider),
			acceptor: SwiftEngineSession(
				session: bobSession, classicalProvider: classicalProvider,
				pqProvider: pqProvider))
	}

	private static func rustPair(seed: UInt64) throws -> Pair {
		let aliceID = Data("diff-rr-a-\(seed)".utf8)
		let bobID = Data("diff-rr-b-\(seed)".utf8)
		let alicePrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: aliceID)
		let bobPrincipal = try TwoMLSPQBinding.TwoMlsPqPrincipal(clientId: bobID)
		let bobInvitation = try TwoMLSPQBinding.TwoMlsPqInvitation.restore(
			archive: bobPrincipal.generateInvitation(lastResort: true))

		let alice = try TwoMLSPQBinding.TwoMlsPqSession.initiate(
			client: alicePrincipal, theirKeyPackage: bobInvitation.combinerKeyPackage(),
			appBinding: nil)
		try alice.setInitialReturnKeyPackage(
			keyPackage: try alicePrincipal.generateKeyPackage(
				suite: .init(value: 0x0003)))
		let commitment = try unwrap(alice.bootstrapKpCommitment())
		let kpEnvelope = try alice.pqBootstrapEnvelope()
		guard
			case .bootstrapKp(let heldKP) = try bobInvitation.openInitial(
				blob: kpEnvelope)
		else {
			throw HarnessError.unexpectedSideBandLeg
		}
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceFirst = try alice.encrypt(appMessage: Data("establish-a".utf8)).cipherText
		guard
			case .establishment(let frame) = try bobInvitation.openInitial(
				blob: aliceFirst)
		else {
			throw HarnessError.unexpectedSideBandLeg
		}
		let bob = try bobInvitation.receive(
			welcome: try unwrap(frame.welcome),
			theirClassicalKeyPackage: try unwrap(frame.returnKeyPackage),
			bootstrapKpCommitment: commitment,
			spawnToken: Data("diff-rr-spawn-\(seed)".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		_ = try bob.pqBootstrapRespond(kpMsg: heldKP)
		let welcomePrime = try unwrap(bob.pqTakePendingOutbound())
		_ = try bob.prepareToEncrypt(proposing: nil)
		_ = try alice.processIncoming(
			ciphertext: try bob.encrypt(appMessage: Data("establish-b".utf8)).cipherText
		)
		try alice.pqBootstrapBind(welcomeMsg: welcomePrime)
		_ = try alice.prepareToEncrypt(proposing: nil)
		_ = try bob.processIncoming(
			ciphertext: try alice.encrypt(appMessage: Data("establish-a2".utf8))
				.cipherText)

		return Pair(
			initiator: try RustEngineSession(session: alice),
			acceptor: try RustEngineSession(session: bob))
	}

	// MARK: - Scaffolding

	private static func keyPackage(fromMessage bytes: Data) throws -> MLS.RFC9420.KeyPackage {
		guard case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(mlsEncoded: bytes)
		else { throw HarnessError.unexpectedSideBandLeg }
		return keyPackage
	}

	static func unwrap<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line)
		throws -> T
	{
		guard let value else {
			throw NSError(
				domain: "differential", code: 1,
				userInfo: [
					NSLocalizedDescriptionKey:
						"unexpected nil at \(file):\(line)"
				])
		}
		return value
	}
}
