//
//  AttachmentCEKTests.swift
//  TwoMLSPQ
//
//  Swift-surface coverage for GER-1985's exportAttachmentCEKSend/Recv, over the concrete
//  PQSession wrapper. The Rust crate suite (two-mls-pq/src/session/tests.rs) already covers
//  the ledger/epoch-keying correctness in depth, including the delayed-frame mutation-verified
//  case; this file only pins that the SWIFT surface — argument/return marshalling, the typed
//  error mapping — reaches the same crate behavior.
//

import CommProtocol
import Foundation
import Testing

import TwoMLSPQBinding

@testable import TwoMLSPQ

struct AttachmentCEKTests {

	/// A classical-established pair (born-dedicated, PQ half deferred) — enough for the
	/// attachment CEK, which only ever touches the classical groups. Mirrors
	/// `LifecycleTests.testExchange`'s steps 1-3, trimmed to just the establishment.
	private func establishedPair() throws -> (local: PQSession, remote: PQSession) {
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

		return (localSession, remoteSession)
	}

	/// The common case: local derives send-side, remote decrypts local's frame and derives
	/// recv-side at that frame's own epoch — the two must agree.
	@Test func sendRecvAgreeForLiveEpoch() throws {
		let (local, remote) = try establishedPair()
		let keyId = Data(repeating: 0xAA, count: 32)

		_ = try local.prepareToEncrypt(proposing: nil)
		let cekSend = try local.exportAttachmentCEKSend(keyId: keyId)
		#expect(cekSend.count == 32)

		let frame = try local.encrypt(appMessage: Data("attachment-bearing".utf8))
		let decrypted = try #require(try remote.decrypt(frame.cipherText))
		let epoch = try decrypted.applicationMessage.tryUnwrap.epoch

		let cekRecv = try remote.exportAttachmentCEKRecv(keyId: keyId, epoch: epoch)
		#expect(cekSend == cekRecv, "send/recv CEKs disagree for the live-current epoch")
	}

	/// Two attachments riding the same epoch under different `keyId`s must derive distinct
	/// CEKs; the same `keyId` at the same epoch must re-derive identically.
	@Test func keyIdSeparatesCiphertextsWithinOneEpoch() throws {
		let (local, _) = try establishedPair()
		_ = try local.prepareToEncrypt(proposing: nil)

		let cekA = try local.exportAttachmentCEKSend(keyId: Data(repeating: 0x01, count: 32))
		let cekB = try local.exportAttachmentCEKSend(keyId: Data(repeating: 0x02, count: 32))
		#expect(cekA != cekB, "distinct key ids must not collide within one epoch")

		let cekAAgain = try local.exportAttachmentCEKSend(keyId: Data(repeating: 0x01, count: 32))
		#expect(cekA == cekAAgain, "the same (epoch, keyId) must re-derive identically")
	}

	/// An epoch the receiver never captured — neither still current nor ledgered — is a
	/// typed, discardable failure, never a silently wrong derivation.
	@Test func recvMissIsTypedNotSilent() throws {
		let (_, remote) = try establishedPair()
		do {
			_ = try remote.exportAttachmentCEKRecv(
				keyId: Data(repeating: 0, count: 32), epoch: 999)
			Issue.record("expected .attachmentComponentUnavailable")
		} catch {  // exportAttachmentCEKRecv is throws(SessionError) — error is typed
			#expect(error.code == .attachmentComponentUnavailable)
			#expect(error.disposition == .discardFrame)
		}
	}
}
