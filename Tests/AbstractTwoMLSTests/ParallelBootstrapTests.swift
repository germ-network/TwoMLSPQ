//
//  ParallelBootstrapTests.swift
//  AbstractTwoMLS
//
//  Part 3 parallel A.4 delivery (contract 23): an initiator ships its pre-committed
//  KP′ as a §A.1 bootstrap envelope alongside the establishment reply, and the
//  acceptor's invitation self-routes it — by content, off the invitation's
//  H(KP′) -> group table — into the EXISTING `.forward`/`forwarded` surface, where it
//  answers A.4. The crate-level routing is proven in
//  key_packages.rs::test_invitation_bootstrap_kp_routing_*; these exercise the adapter
//  seam (the `bootstrapEnvelope()` emit and the `decodeHeader`/`forwarded` dispatch).
//

import AbstractTwoMLS
import CommProtocol
import Foundation
import Testing

struct ParallelBootstrapDemo {
	let local: ClientWrapper<AbstractTwoMLS.PQClient>
	let remote: ClientWrapper<AbstractTwoMLS.PQClient>

	init() throws {
		local = try .init()
		remote = try .init()
	}

	@Test func parallelBootstrapEnvelopeSelfRoutesAndAnswersA4() throws {
		// The initiator replies AND emits the parallel A.4 frame off the same fresh session.
		let (localSession, establishmentEnvelope) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let localPQ = localSession as any AbstractTwoMLS.PQRatchetingSession
		// The pre-committed KP′, sealed as a §A.1 bootstrap envelope, is available before
		// establishment; it is a distinct frame from the establishment reply (same outer
		// shape, different inner tag).
		let bootstrapEnvelope = try #require(try localPQ.bootstrapEnvelope())
		#expect(bootstrapEnvelope != establishmentEnvelope)

		// The acceptor joins from the establishment reply — `receive` pins
		// H(KP′) -> the spawned group, which is what lets the id-less envelope self-route.
		let (remoteSession, _) = try remote.currentInvitation.receiveReply(
			ciphertext: establishmentEnvelope,
			expecting: try local.clientId
		)
		let remotePQ = remoteSession as any AbstractTwoMLS.PQRatchetingSession

		// The parallel envelope now decodes as a `.forward` to that session — not an
		// `.appWelcome`, and not the malformed throw an UNRESOLVED KP′ gives.
		let routed = try remote.currentInvitation.decodeHeader(ciphertext: bootstrapEnvelope)
		guard case .forward(groupId: _, mlsMessageData: let mlsMessageData) = routed else {
			Issue.record("parallel bootstrap KP′ did not route as .forward: \(routed)")
			return
		}

		// Nothing is parked before the answer; `forwarded` runs `pqBootstrapRespond`, which
		// stands up the acceptor's send-PQ half and parks the Welcome' for the next hand-out
		// — and returns no app message.
		#expect(remotePQ.pendingSideBand(sealing: .fresh) == nil)
		#expect(try remoteSession.forwarded(headerDecrypted: mlsMessageData) == nil)
		let welcomePrime = try #require(remotePQ.pendingSideBand(sealing: .fresh))
		#expect(!welcomePrime.isEmpty)

		// A re-delivery (the side-band copy won a race, or a transport dup) is a benign
		// no-op — the crate's `DuplicateSideBand`, swallowed to nil — and the parked
		// Welcome' is untouched, so the acceptor still has one frame to hand out.
		#expect(try remoteSession.forwarded(headerDecrypted: mlsMessageData) == nil)
		#expect(remotePQ.pendingSideBand(sealing: .fresh) != nil)
	}

	@Test func unresolvedBootstrapEnvelopeIsMalformed() throws {
		let (localSession, establishmentEnvelope) = try local.client.reply(
			remoteClientId: remote.clientId,
			encodedRemoteKpkg: remote.currentInvitation.encodedKeyPackage
		)
		let localPQ = localSession as any AbstractTwoMLS.PQRatchetingSession
		let bootstrapEnvelope = try #require(try localPQ.bootstrapEnvelope())

		// BEFORE the acceptor receives the reply, its commitment table has no entry for this
		// KP′: the envelope opens (it is sealed to the invitation's own key package) but
		// resolves to no session, and must be rejected rather than mis-delivered.
		do {
			_ = try remote.currentInvitation.decodeHeader(ciphertext: bootstrapEnvelope)
			Issue.record("expected an unresolved bootstrap envelope to be malformed")
		} catch {
			#expect(error.code == .malformedFrame)
		}

		// Sanity (guards against a false positive where decodeHeader failed for an
		// unrelated reason): once the reply IS received, the SAME envelope resolves.
		_ = try remote.currentInvitation.receiveReply(
			ciphertext: establishmentEnvelope,
			expecting: try local.clientId
		)
		let routed = try remote.currentInvitation.decodeHeader(ciphertext: bootstrapEnvelope)
		guard case .forward = routed else {
			Issue.record("post-receive: expected the bootstrap envelope to resolve to .forward")
			return
		}
	}
}
