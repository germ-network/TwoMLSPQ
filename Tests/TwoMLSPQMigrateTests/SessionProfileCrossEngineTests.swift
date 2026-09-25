import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQBinding
import TwoMLSPQCrypto
import TwoMLSPQMigrate
import XCTest

// Testable only to read native groups and leaves, which have no public accessor.
@testable import TwoMLSPQSession

// A native client advertises the correct session profile on its classical key-package
// leaf. The deployed engine advertises none, so every session with it stays
// deployed-compatible: nothing is recorded, the A.5 announce reaches Rust, and the
// reciprocal A.5 waits for Rust's own. Each direction runs the return welcome, the
// parallel A.3, A.4 both ways, and A.5 rounds opened by both engines.

@available(macOS 26, iOS 26, *)
final class SessionProfileCrossEngineTests: XCTestCase {
	private let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519ChaCha)!
	private let pqProvider = MLKEM768CipherSuiteProvider()
	private let correctType = MLS.RFC9420.ExtensionType(rawValue: 0xF0A3)

	// MARK: - Swift initiator -> Rust acceptor

	func testNativeInitiatorRustAcceptorFullLifecycle() throws {
		let (bobInvitation, their) = try rustInvitation("pc-n2r-bob")
		var alice = try nativeInitiator("pc-n2r-alice", to: their)
		let commitment = try alice.bootstrapKPCommitment()
		let kpEnvelope = try XCTUnwrap(alice.pqBootstrapEnvelope())
		guard
			case .bootstrapKp(let heldKP) = try bobInvitation.openInitial(
				blob: kpEnvelope)
		else { return XCTFail("expected the parallel bootstrap KP") }
		let frame = try establishmentFrame(
			bobInvitation.openInitial(blob: try alice.pendingOutbound()))

		// The carrier: the return KP's classical leaf, exactly as Rust received it.
		let returnKP = try keyPackage(fromMessage: try XCTUnwrap(frame.returnKeyPackage))
		XCTAssertTrue(returnKP.leafNode.capabilities.extensions.contains(correctType))
		XCTAssertFalse(returnKP.leafNode.capabilities.extensions.isEmpty)
		XCTAssertEqual(alice.profile, .deployedCompatible, "Rust's KP does not advertise")

		let bob = try bobInvitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: try XCTUnwrap(frame.returnKeyPackage),
			bootstrapKpCommitment: commitment, spawnToken: Data("pc-n2r-spawn".utf8),
			newClientId: nil, expectedRemote: nil, expectedAppBinding: nil)
		try bob.pqBootstrapRespond(kpMsg: heldKP)
		let welcomePrime = try XCTUnwrap(bob.pqPendingOutbound(sealing: .fresh))
		_ = try bob.prepareToEncrypt(proposing: nil)
		let bobFirst = try bob.encrypt(appMessage: Data("b1".utf8)).cipherText
		_ = try alice.processIncoming(try XCTUnwrap(alice.openIncoming(bobFirst)).frame)
		XCTAssertTrue(alice.isEstablished)
		_ = try alice.pqBootstrapJoin(try XCTUnwrap(alice.openIncoming(welcomePrime)).frame)
		_ = try alice.prepareToEncrypt()
		let a1 = try alice.encrypt(Data("a1".utf8)).frame
		_ = try XCTUnwrap(bob.processIncoming(ciphertext: a1))
		XCTAssertTrue(bob.isFullyEstablished())
		XCTAssertTrue(alice.isFullyEstablished)

		var duo = ProfileDuo(native: alice, rust: bob, test: self)
		try runLifecycle(
			&duo, nativeRotated: Data("pc-n2r-alice-2".utf8),
			rustRotated: Data("pc-n2r-bob-2".utf8))
	}

	// MARK: - Rust initiator -> Swift acceptor

	func testRustInitiatorNativeAcceptorFullLifecycle() throws {
		let (bobInvitation, rustKP) = try nativeInvitation("pc-r2n-bob")
		var invitation = bobInvitation
		// The carrier: the classical half of the native acceptor's published KP.
		XCTAssertTrue(
			try XCTUnwrap(invitation.combinerKeyPackage).classical.leafNode.capabilities
				.extensions.contains(correctType))
		let alice = try rustInitiator("pc-r2n-alice", to: rustKP)
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
			bootstrapKPCommitment: commitment, spawnToken: Data("pc-r2n-spawn".utf8)
		).session
		XCTAssertEqual(bob.profile, .deployedCompatible)
		_ = try bob.pqBootstrapRespond(heldKP)
		_ = try bob.prepareToEncrypt()
		let bobFirst = try bob.encrypt(Data("b1".utf8)).frame
		let welcomePrime = try XCTUnwrap(bob.pqPendingOutbound())
		_ = try alice.processIncoming(ciphertext: bobFirst)
		try alice.pqBootstrapBind(welcomeMsg: welcomePrime)
		XCTAssertTrue(alice.isFullyEstablished())
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceFirst = try alice.encrypt(appMessage: Data("a1".utf8)).cipherText
		_ = try bob.processIncoming(try XCTUnwrap(bob.openIncoming(aliceFirst)).frame)
		XCTAssertTrue(bob.isFullyEstablished)

		var duo = ProfileDuo(native: bob, rust: alice, test: self)
		try runLifecycle(
			&duo, nativeRotated: Data("pc-r2n-bob-2".utf8),
			rustRotated: Data("pc-r2n-alice-2".utf8))
	}

	// MARK: - The lifecycle pump

	private func runLifecycle(_ duo: inout ProfileDuo, nativeRotated: Data, rustRotated: Data)
		throws
	{
		// A.4 both ways.
		for i in 0..<6 {
			if i % 2 == 0 {
				try duo.nativeSend("warm-n\(i)")
			} else {
				try duo.rustSend("warm-r\(i)")
			}
		}
		XCTAssertGreaterThan(duo.nativeA4, 0, "native opened an A.4: \(duo.trace)")
		XCTAssertGreaterThan(duo.rustA4, 0, "rust opened an A.4: \(duo.trace)")

		// Native rotates; its own A.5 carries the new id onto its recv-PQ leaf (Upd').
		duo.nativeRotate = nativeRotated
		var guardCount = 0
		while !duo.announcedToRust.contains(nativeRotated) {
			guardCount += 1
			guard guardCount < 20 else {
				return XCTFail("native A.5 never landed: \(duo.trace)")
			}
			if guardCount % 2 == 1 {
				try duo.nativeSend("nrot\(guardCount)")
			} else {
				try duo.rustSend("nrot\(guardCount)")
			}
		}

		// Rust rotates; Rust opens its A.5 (native answers with Commit'), then native's
		// reciprocal A.5 moves Rust's leaf in native's recv-PQ.
		duo.rustRotate = rustRotated
		let nativeA5Before = duo.nativeA5
		guardCount = 0
		while !(duo.announcedToNative.contains(rustRotated)
			&& duo.nativeA5 > nativeA5Before)
		{
			guardCount += 1
			guard guardCount < 30 else {
				return XCTFail("rust A.5 / reciprocal never landed: \(duo.trace)")
			}
			if guardCount % 2 == 1 {
				try duo.rustSend("rrot\(guardCount)")
			} else {
				try duo.nativeSend("rrot\(guardCount)")
			}
		}
		for i in 0..<4 {
			if i % 2 == 0 {
				try duo.nativeSend("tail-n\(i)")
			} else {
				try duo.rustSend("tail-r\(i)")
			}
		}

		// Every native own leaf still advertises the type after all those moves.
		let native = duo.native
		let groups: [(String, MLS.RFC9420.Group?)] = [
			("sendClassical", native.sendGroup?.classical),
			("sendPQ", native.sendGroup?.pq),
			("recvClassical", native.recvGroup?.classical),
			("recvPQ", native.recvGroup?.pq),
		]
		for (name, group) in groups {
			let g = try XCTUnwrap(group, name)
			let expected = name.hasSuffix("Classical")
			XCTAssertEqual(
				try TwoMLSSession.ownLeaf(of: g).capabilities.extensions.contains(
					correctType),
				expected, name)
			XCTAssertEqual(
				try SessionProfile.recorded(in: g.context), .deployedCompatible,
				name)
		}
		// C1 reached Rust: its responder returned the announced id.
		XCTAssertTrue(duo.announcedToRust.contains(nativeRotated), "\(duo.trace)")
	}

	// MARK: - The native turn-holder defers the reciprocal until Rust's own A.5 lands

	/// Fresh session (no migration): Rust rotates, native folds, and native's next
	/// turn must open a plain A.4, not the reciprocal A.5, until Rust's own A.5 has
	/// landed (C2, deployed-compatible: Rust never advertises). Then the reciprocal opens.
	func testNativeTurnHolderDefersReciprocalUntilRustOwnA5Lands() throws {
		let (bobInvitation, rustKP) = try nativeInvitation("x3-bob")
		var invitation = bobInvitation
		let alice = try rustInitiator("x3-alice", to: rustKP)
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
			bootstrapKPCommitment: commitment, spawnToken: Data("x3-spawn".utf8)
		).session
		XCTAssertEqual(bob.profile, .deployedCompatible)
		_ = try bob.pqBootstrapRespond(heldKP)
		_ = try bob.prepareToEncrypt()
		let bobFirst = try bob.encrypt(Data("b1".utf8)).frame
		let welcomePrime = try XCTUnwrap(bob.pqPendingOutbound())
		_ = try alice.processIncoming(ciphertext: bobFirst)
		try alice.pqBootstrapBind(welcomeMsg: welcomePrime)
		_ = try alice.prepareToEncrypt(proposing: nil)
		let aliceFirst = try alice.encrypt(appMessage: Data("a1".utf8)).cipherText
		_ = try bob.processIncoming(try XCTUnwrap(bob.openIncoming(aliceFirst)).frame)
		XCTAssertTrue(bob.isFullyEstablished)

		var duo = ProfileDuo(native: bob, rust: alice, test: self)
		for i in 0..<4 {
			if i % 2 == 0 {
				try duo.nativeSend("warm-n\(i)")
			} else {
				try duo.rustSend("warm-r\(i)")
			}
		}
		let rustRotated = Data("x3-alice-2".utf8)
		duo.rustRotate = rustRotated
		try duo.rustSend("rot-offer")
		let before = duo.trace.count
		// native folds the rotation; its send self-drives. Before Rust's own A.5 has
		// landed, that must be an A.4, never the reciprocal A.5.
		var guardCount = 0
		while !duo.announcedToNative.contains(rustRotated) {
			guardCount += 1
			guard guardCount < 30 else {
				return XCTFail("rust A.5 never landed: \(duo.trace)")
			}
			if guardCount % 2 == 1 {
				try duo.nativeSend("fold\(guardCount)")
			} else {
				try duo.rustSend("fold\(guardCount)")
			}
			XCTAssertFalse(
				duo.trace[before...].contains { $0.hasPrefix("n:A5") },
				"native opened the reciprocal before Rust's own A.5 landed: \(duo.trace)"
			)
		}
		XCTAssertTrue(duo.trace[before...].contains("n:A4"), "\(duo.trace)")
		// Rust's own A.5 has landed (its leaf in native's send-PQ presents the new id):
		// native's next turn opens the reciprocal.
		let nativeA5Before = duo.nativeA5
		guardCount = 0
		while duo.nativeA5 == nativeA5Before {
			guardCount += 1
			guard guardCount < 10 else {
				return XCTFail("reciprocal never opened: \(duo.trace)")
			}
			if guardCount % 2 == 1 {
				try duo.nativeSend("rec\(guardCount)")
			} else {
				try duo.rustSend("rec\(guardCount)")
			}
		}
		let recvPQ = try XCTUnwrap(duo.native.recvGroup?.pq)
		let rustLeaf = try XCTUnwrap(
			recvPQ.tree.nonBlankLeaves().first { $0.index != recvPQ.myLeafIndex })
		XCTAssertEqual(
			try basicIdentifier(
				try MLS.RFC9420.LeafNode(mlsEncoded: rustLeaf.record.encoded)
					.credential),
			rustRotated, "\(duo.trace)")
	}

	// MARK: - The opt-in reaches the published key package, and Rust preserves it

	func testOptInIsLiveInEmittedKeyPackagesAndRustPreservesIt() throws {
		let (invitation, rustKP) = try nativeInvitation("nc-bob")
		let published = try XCTUnwrap(invitation.combinerKeyPackage).publishedBlob()
		let reparsed = try XCTUnwrap(CombinerKeyPackage(publishedBlob: published))
		XCTAssertTrue(
			reparsed.classical.leafNode.capabilities.extensions.contains(correctType))
		XCTAssertFalse(reparsed.pq.leafNode.capabilities.extensions.contains(correctType))
		let roundTripped = try XCTUnwrap(
			CombinerKeyPackage(
				publishedBlob: TwoMLSPQBinding.encodeCombinerKeyPackage(
					keyPackage: rustKP)))
		XCTAssertTrue(
			roundTripped.classical.leafNode.capabilities.extensions.contains(
				correctType))
		XCTAssertEqual(try roundTripped.publishedBlob(), published)
		// Default (no opt-in): absent.
		let quiet = try Principal.generate(
			clientID: Data("nc-quiet".utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		XCTAssertFalse(
			try XCTUnwrap(
				quiet.generateInvitation(lastResort: false).invitation
					.combinerKeyPackage
			)
			.classical.leafNode.capabilities.extensions.contains(correctType))
		// Rust's own KP never lists it.
		let (_, their) = try rustInvitation("nc-rust")
		XCTAssertFalse(
			their.classical.leafNode.capabilities.extensions.contains(correctType))
	}

	// MARK: - Scaffolding (from EstablishmentFramingCrossEngineTests)

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

	private func nativeInvitation(
		_ clientID: String
	) throws -> (TwoMLSPQSession.Invitation, TwoMLSPQBinding.CombinerKeyPackage) {
		let principal = try Principal.generate(
			clientID: Data(clientID.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider, advertisesCorrectProfile: true)
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
			pqProvider: pqProvider, advertisesCorrectProfile: true)
		return try TwoMLSSession.initiate(principal: principal, their: their).session
	}

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
			throw profileTestError("expected an establishment envelope, got \(opened)")
		}
		return frame
	}

	private func nativeEstablishmentFrame(
		_ opened: TwoMLSPQSession.OpenedInitial
	) throws -> TwoMLSPQSession.InitialFrame {
		guard case .establishment(let frame) = opened else {
			throw profileTestError("expected an establishment envelope, got \(opened)")
		}
		return frame
	}

	private func keyPackage(fromMessage bytes: Data) throws -> MLS.RFC9420.KeyPackage {
		guard case .keyPackage(let keyPackage) = try MLS.RFC9420.Message(mlsEncoded: bytes)
		else { throw profileTestError("expected an MLSMessage holding a key package") }
		return keyPackage
	}
}

func profileTestError(_ description: String) -> NSError {
	NSError(domain: "profile-x", code: 1, userInfo: [NSLocalizedDescriptionKey: description])
}

/// A native session and a Rust session, driven by alternating sends. Every offer is
/// approved, and every PQ leg a send opens is answered and bound at once.
@available(macOS 26, iOS 26, *)
struct ProfileDuo {
	var native: TwoMLSSession
	let rust: TwoMLSPQBinding.TwoMlsPqSession
	let test: XCTestCase
	var trace: [String] = []
	var nativeRotate: Data?
	var rustRotate: Data?
	var nativeA4 = 0, nativeA5 = 0, rustA4 = 0, rustA5 = 0
	var announcedToRust: [Data] = []
	var announcedToNative: [Data] = []
	private var lastRustLeg: Data?

	init(native: TwoMLSSession, rust: TwoMLSPQBinding.TwoMlsPqSession, test: XCTestCase) {
		self.native = native
		self.rust = rust
		self.test = test
	}

	mutating func nativeSend(_ text: String) throws {
		let prep = try native.prepareToEncrypt(rotating: nativeRotate)
		if nativeRotate != nil { trace.append("n:rotate-offer") }
		nativeRotate = nil
		let frame = try native.encrypt(Data(text.utf8)).frame
		let got = try XCTUnwrap(rust.processIncoming(ciphertext: frame))
		XCTAssertEqual(got.applicationMessage?.appMessageData, Data(text.utf8))
		if let offer = got.proposal {
			try rust.queueProposal(digest: offer.digest)
		}
		trace.append("n:send\(prep.didCommit ? "+commit" : "")")
		try driveNativeLeg()
	}

	mutating func rustSend(_ text: String) throws {
		let prep = try rust.prepareToEncrypt(
			proposing: rustRotate.map { TwoMLSPQBinding.ClientId(bytes: $0) })
		if rustRotate != nil { trace.append("r:rotate-offer") }
		rustRotate = nil
		let frame = try rust.encrypt(appMessage: Data(text.utf8)).cipherText
		guard case .decrypted(let got) = try native.processIncoming(frame) else {
			throw profileTestError("native did not decrypt rust's frame")
		}
		XCTAssertEqual(got.applicationMessage, Data(text.utf8))
		_ = try native.queueProposal(digest: got.queuedProposal.digest)
		trace.append("r:send\(prep.didCommit ? "+commit" : "")")
		try driveRustLeg()
	}

	private mutating func driveNativeLeg() throws {
		switch native.pqInflight {
		case .some(.initiating):
			let leg = try XCTUnwrap(native.pqPendingOutbound())
			XCTAssertEqual(
				try rust.openIncoming(blob: leg)?.kind,
				.pqSideBand(kind: .ratchetEphemeralKey))
			try rust.pqRatchetRespond(ekMsg: leg)
			_ = try native.pqRatchetBind(try XCTUnwrap(rust.pqTakePendingOutbound()))
			nativeA4 += 1
			trace.append("n:A4")
		case .some(.rekeyInitiated):
			let leg = try XCTUnwrap(native.pqPendingOutbound())
			XCTAssertEqual(
				try rust.openIncoming(blob: leg)?.kind,
				.pqSideBand(kind: .rekeyUpdate))
			let announced = try rust.pqRekeyRespond(updMsg: leg)
			_ = try native.pqRekeyApply(try XCTUnwrap(rust.pqTakePendingOutbound()))
			if let announced { announcedToRust.append(announced.bytes) }
			nativeA5 += 1
			trace.append(
				"n:A5(\(announced.map { String(decoding: $0.bytes, as: UTF8.self) } ?? "-"))"
			)
		default:
			break
		}
	}

	private mutating func driveRustLeg() throws {
		guard let leg = rust.pqPendingOutbound(sealing: .stable) else { return }
		guard let opened = try native.openIncoming(leg) else {
			throw profileTestError("native could not open rust's leg")
		}
		if opened.frame == lastRustLeg { return }
		switch opened.kind {
		case .pqSideBand(.ratchetEK):
			try rust.pqRatchetBind(ctMsg: try native.pqRatchetRespond(leg).frame)
			rustA4 += 1
			trace.append("r:A4")
		case .pqSideBand(.rekeyUpd):
			let result = try native.pqRekeyRespond(leg)
			try rust.pqRekeyApply(msg: result.frame)
			if let rotated = result.rotatedCredential {
				announcedToNative.append(rotated)
			}
			rustA5 += 1
			trace.append(
				"r:A5(\(result.rotatedCredential.map { String(decoding: $0, as: UTF8.self) } ?? "-"))"
			)
		default:
			throw profileTestError("unexpected rust leg \(opened.kind)")
		}
		lastRustLeg = opened.frame
	}
}
