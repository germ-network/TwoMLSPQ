import Foundation
import TwoMLSPQBinding
import XCTest

// Shared raw-FFI session helpers, adapted from `SessionMigrationTests`'s private `rustSay` /
// `dischargeBind` (kept small and generic so `LegacyRowFixtureTests` can reuse the shape
// without depending on that file's establishment scaffolding).
@available(macOS 26, iOS 26, *)
enum RustSessionTestHelpers {
	/// Prepare + encrypt on `session`, deliver to `deliverTo`, and assert the round trip.
	/// `file`/`line` thread through so a failure attributes to the CALLER, not this helper.
	static func rustSay(
		_ session: TwoMLSPQBinding.TwoMlsPqSession, _ text: String,
		deliverTo: TwoMLSPQBinding.TwoMlsPqSession,
		file: StaticString = #filePath, line: UInt = #line
	) throws {
		_ = try session.prepareToEncrypt(proposing: nil)
		let frame = try session.encrypt(appMessage: Data(text.utf8))
		let got = try XCTUnwrap(
			deliverTo.processIncoming(ciphertext: frame.cipherText), file: file,
			line: line)
		XCTAssertEqual(
			got.applicationMessage?.appMessageData, Data(text.utf8), file: file,
			line: line)
	}

	/// One committing round: `peer` offers an Upd, `binder` approves it and its next
	/// `prepareToEncrypt` reports `didCommit`. `file`/`line` thread through so a failure
	/// attributes to the CALLER, not this helper.
	static func committingRound(
		binder: TwoMLSPQBinding.TwoMlsPqSession, peer: TwoMLSPQBinding.TwoMlsPqSession,
		file: StaticString = #filePath, line: UInt = #line
	) throws {
		_ = try peer.prepareToEncrypt(proposing: nil)
		let upd = try peer.encrypt(appMessage: Data("upd".utf8))
		let offered = try XCTUnwrap(
			binder.processIncoming(ciphertext: upd.cipherText)?.proposal, file: file,
			line: line)
		try binder.queueProposal(digest: offered.digest)

		let prepared = try binder.prepareToEncrypt(proposing: nil)
		XCTAssertTrue(
			prepared.didCommit, "a committing round needs didCommit", file: file,
			line: line)
		let frame = try binder.encrypt(appMessage: Data("commit".utf8))
		let got = try XCTUnwrap(
			peer.processIncoming(ciphertext: frame.cipherText), file: file, line: line)
		XCTAssertEqual(
			got.applicationMessage?.appMessageData, Data("commit".utf8), file: file,
			line: line)
	}
}
