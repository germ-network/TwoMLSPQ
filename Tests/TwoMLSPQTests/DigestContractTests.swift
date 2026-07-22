//
//  DigestContractTests.swift
//  TwoMLSPQ
//
//  Pins the digest contract this package owns (PQDigest.swift): the Swift-side
//  derivation, the tagged encoding, and the FFI lift/strip conventions.
//
//  The load-bearing one is `digestDerivationMatchesTheCrate`. The crate derives
//  every digest from its suite (`TwoMlsSuite::CURRENT.digest`) and Swift restates
//  that choice in `PQDigest.over` — two declarations of one fact, in two
//  languages, with no shared symbol to hold them together. Rust's exhaustive
//  `match` forces the crate side to be revisited when a suite is added; NOTHING
//  forces this side. That is what this test is for: a suite whose digest is not
//  SHA-256 must fail here, loudly, rather than ship a Swift derivation that
//  silently disagrees with every digest the crate emits.
//

import CryptoKit
import Foundation
import Testing

@testable import TwoMLSPQ

struct DigestContractTests {

	// MARK: The cross-language canary

	/// A real FFI round trip: the digest the crate computed over the staged
	/// proposal must equal the one we derive over the same bytes — and the
	/// receiver's view of that proposal must carry the identical tagged value.
	@Test func digestDerivationMatchesTheCrate() throws {
		let local = try ClientWrapper()
		let remote = try ClientWrapper()

		let (localSession, welcome, myKeyPackage, bootstrapKpCommitment) =
			try local.client.reply(
				keyPackageMessage: remote.currentInvitation.encodedKeyPackage
			)
		let dedicatedId: ClientID = .mock()
		let (remoteSession, _) = try remote.currentInvitation.receive(
			sendGroupWelcome: welcome,
			remoteKeyPackage: myKeyPackage,
			bootstrapKpCommitment: bootstrapKpCommitment,
			remoteClientId: try local.clientId,
			welcomeToken: WelcomeToken(PQDigest.over(welcome)),
			stapledMessage: nil,
			newClientId: dedicatedId
		)
		try remoteSession.installMockEstablishmentEnvelope()
		try localSession.acceptEstablishment(from: remoteSession, dedicatedId: dedicatedId)
		try localSession.exchange(with: remoteSession)

		// Remote stages an Upd(self): a post-establishment prepare carries the real
		// proposal (the contract-15 pre-establishment round is the empty carve-out).
		let prep = try #require(try remoteSession.prepareToEncrypt(proposing: nil))
		#expect(!prep.proposalMessage.isEmpty)

		// THE PIN: our derivation over the crate's own proposal bytes reproduces the
		// crate's hash of them.
		#expect(PQDigest.over(prep.proposalMessage) == prep.proposalHash)

		// And the receiver independently surfaces the same tagged value, so an app
		// that approves by digest is comparing like with like across the two adapters.
		let frame = try remoteSession.encrypt(appMessage: Data("upd".utf8))
		let decrypted = try #require(try localSession.decrypt(frame.cipherText))
		let offered = try #require(decrypted.proposal)
		#expect(offered.digest == prep.proposalHash)
		// The digest round-trips back through the approval door it came from.
		try localSession.queueProposal(digest: offered.digest)
	}

	// MARK: Encoding

	/// Byte compatibility with the encoding this surface used before the split
	/// (`CommProtocol.TypedDigest.wireFormat` = `[0x01]` + SHA-256). Spawn tokens
	/// key the crate's ARCHIVED forward table and adopters persist routing ids, so
	/// these bytes are not free to move.
	@Test func taggedEncodingIsUnchanged() {
		let body = Data("some establishment vector".utf8)
		var expected = Data([0x01])
		expected.append(Data(SHA256.hash(data: body)))

		#expect(PQDigest.over(body) == expected)
		#expect(PQDigest.over(body).count == 33)
		#expect(PQDigest.raw(over: body) == expected.dropFirst())
	}

	@Test func liftAppliesTheTagAndStripRemovesIt() throws {
		let raw = Data(SHA256.hash(data: Data("x".utf8)))
		let tagged = try PQDigest.lift(ffi: raw)

		#expect(tagged.first == 0x01)
		#expect(tagged.dropFirst() == raw)
		#expect(try PQDigest.strip(tagged) == raw)
	}

	/// Retyping the surface to `Data` moved these checks from the type system to
	/// runtime — so the runtime checks have to actually be there.
	@Test func malformedDigestsAreRejected() {
		// Wrong width in from the FFI.
		#expect(throws: SessionError.self) {
			try PQDigest.lift(ffi: Data(repeating: 0, count: 31))
		}
		// Caller handed back something that is not one of our digests.
		#expect(throws: SessionError.self) {
			try PQDigest.strip(Data(repeating: 0, count: 33))
		}
		#expect(throws: SessionError.self) { try PQDigest.strip(Data([0x01])) }
		#expect(throws: SessionError.self) { try PQDigest.strip(Data()) }
		// A raw (untagged) digest is the likeliest caller mistake — it must not pass.
		#expect(throws: SessionError.self) {
			try PQDigest.strip(Data(SHA256.hash(data: Data("x".utf8))))
		}
	}

	/// Routing ids keep `DataIdentifier.Widths.bits256`'s tag: adopters persist
	/// them as spawned-session lookup keys.
	@Test func routingIdentifiersKeepTheirTag() throws {
		let raw = Data(repeating: 7, count: 32)
		let tagged = try PQIdentifier.tagged256(raw)

		#expect(tagged.first == 0x02)
		#expect(tagged.count == 33)
		#expect(tagged.dropFirst() == raw)
		#expect(throws: SessionError.self) {
			try PQIdentifier.tagged256(Data(repeating: 7, count: 16))
		}
	}
}
