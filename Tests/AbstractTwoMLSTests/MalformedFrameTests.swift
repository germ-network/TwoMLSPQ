//
//  MalformedFrameTests.swift
//  AbstractTwoMLS
//
//  Negative tests for the two malformed-input guards: the initial-frame decoder
//  (decodeHeaderFrame) and the PQ side-band ingest tag switch.
//

import AbstractTwoMLS
import Foundation
import Testing

struct MalformedFrameTests {
	@Test func decodeHeaderRejectsMalformedFrames() throws {
		let invitation = try AbstractTwoMLS.PQInvitation(
			persisted: try AbstractTwoMLS.PQClient(clientId: .mock()).makeInvitation()
		)
		let bad: [Data] = [
			Data(),  // empty — no version byte
			Data([0x02, 0, 0, 0, 0]),  // wrong version (not 0x01)
			Data([0x01, 0x00]),  // right version, fewer than 4 length bytes
			Data([0x01, 0xFF, 0xFF, 0xFF, 0xFF]),  // kem-length overruns the frame
		]
		for frame in bad {
			do {
				_ = try invitation.decodeHeader(ciphertext: frame)
				Issue.record("expected malformedHeaderFrame, frame len \(frame.count)")
			} catch TwoMLSPQConformanceError.malformedHeaderFrame {
				// expected
			}
		}
	}

	@Test func ingestRejectsUnknownTag() throws {
		let local = try ClientWrapper<AbstractTwoMLS.PQClient>()
		let remote = try ClientWrapper<AbstractTwoMLS.PQClient>()
		let (session, _) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let pq = session as any AbstractTwoMLS.PQRatchetingSession
		for frame in [Data([0x00]), Data()] {  // unknown tag, then empty
			do {
				_ = try pq.ingest(frame)
				Issue.record("expected malformedHeaderFrame")
			} catch TwoMLSPQConformanceError.malformedHeaderFrame {
				// expected
			}
		}
	}
}
