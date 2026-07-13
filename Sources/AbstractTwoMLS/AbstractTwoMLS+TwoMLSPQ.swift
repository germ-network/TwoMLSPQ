//
//  AbstractTwoMLS+TwoMLSPQ.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/23/26.
//
//  Conforms the TwoMLSPQ UniFFI types to the AbstractTwoMLS protocol surface.
//
//  The abstraction speaks `Data`/`TypedDigest` while TwoMLSPQ wraps identity
//  bytes in single-field structs (`ClientId`, …), and several abstract members
//  collide with the generated methods only on return type — so the conformances
//  are thin adapter types in the `AbstractTwoMLS` namespace rather than
//  extensions on the generated classes. The generated module stays pristine.
//
//  Status (TwoMLSPQ v0.4.0 binding, contract 16):
//   - `PQSession`, the six result adapters, `PQClient`, and `PQInvitation` are wired:
//     routing (`shouldListenOn`/`sendRendezvous`), the true APQ epoch pair on encrypt
//     results, A.5 rekey (`begin(.rekey)`); principal rotation — `receive(newClientId:)`
//     stages the dedicated principal, the contract-v9 candidate lifecycle canonicalizes
//     it, `begin(.rekey/.finishBootstrap, rotating:)` moves the PQ leaves (the
//     peer reads `PQInbound.rotatedCredential`); forward routing — a re-delivered
//     §A.1 envelope decodes as `.forward` via the invitation's spawn-token table
//     (the `WelcomeToken` opaque token, keyed over the envelope's STABLE PREFIX so
//     every pre-establishment re-staple resolves), and the spawned session both
//     acknowledges it and delivers its stapled app message via
//     `forwarded(headerDecrypted:)`.
//   - §A.1 replier-first (contract 15): the initiator sends app messages immediately
//     after `reply` — pre-establishment `prepareToEncrypt` is a no-op round and
//     `encrypt` emits a fresh §A.1 envelope re-stapling the AnchorWelcome-shaped app
//     payload plus the message; the acceptor's invitation decodes ANY such frame as
//     `.appWelcome(stapledPrivateMessage:)`, so one frame both establishes and
//     delivers. `createTwoMLSGroup` attaches the app welcome to the session
//     (`setInitialAppPayload`) and returns the crate-composed envelope — the wrapper's
//     own double-HPKE header frame is retired.
//   - Persistence is PUSH (contract 13): `installSink` attaches a `PersistenceSink`
//     (baseline checkpoint on install), sessions restore via
//     `init(persisted: Persisted{core?, checkpoint})` → `fromPersisted`, invitations
//     restore from their monolithic bytes; the pull `archive` getter no longer exists.
//     The retained pre-establishment state rides the archive, so a session captured at
//     reply restores send-ready — CAPTURE AFTER `createTwoMLSGroup` (the attach).
//

import CommProtocol
import Foundation
import TwoMLSPQ

// MARK: - Binding/binary pairing guard

/// The uniffi Record-shape contract this vendored binding was generated against.
/// Must equal TwoMLSPQ's `BINDING_CONTRACT_VERSION`; update it as part of the
/// binding re-sync ritual (binding + binary from the SAME build).
///
/// Uniffi's own load-time checksums cover function signatures only — a Record
/// can change shape with every checksum unchanged, and the mismatch then traps
/// at the first FFI buffer read mid-flow. This check fails fast instead, at the
/// first client/invitation construction.
// v2: TwoMlsPqDigest removed from the FFI — digests are raw 32-byte SHA-256 values,
// typed on this side by `liftDigest`.
// v3: TwoMlsPqError gained UnsupportedCipherSuite.
// v4: TwoMlsPqError gained CipherSuiteMismatch; MlsCipherSuite.isSupported -> isCombinerPq;
//     AgentState -> PrincipalState.
// v5: TwoMlsPqError gained InvitationSpent; generateInvitation gained a lastResort flag.
// v6: wire format v2 — one message frame (0x03) with a mandatory commit-or-welcome staple;
//     PQ side-band tags renumbered to 0x05–0x11 (classify via PqFrameKind, never raw bytes);
//     TwoMlsPqError gained EpochDesync and UnexpectedWelcome.
// v7: header encryption — every rendezvous-channel frame leaves the library sealed; the host
//     removes the seal with openIncoming(blob:) -> OpenedFrame { kind, frame } and routes
//     `frame` by `kind` (OpenedFrameKind: message | pqSideBand(kind: PqFrameKind)).
// v8: initiate-side envelope — initiate gained appPayload: Data?; its initial frame comes back
//     from pendingOutbound already HPKE-enveloped; TwoMlsPqInvitation.openInitial(blob:) ->
//     InitialFrame { appPayload, welcome } opens it (decrypt-only, non-consuming).
// v9–v10: receive gained newClientId: Data? (establish under a dedicated per-session
//     principal) and expectedRemote: Data? (crate-side identity pin, checked before any
//     invitation state is claimed); queuedRemoteSuccessor() -> ClientId? exposes the
//     approval tally; TwoMlsPqError gained CredentialRejected, InvalidClientId, and
//     RemoteIdentityMismatch.
// v11–v12: draft-ietf-mls-combiner-02 conformance — APQInfo GroupContext extension,
//     AppDataUpdate epoch attestation on FULL commits, SafeExportSecret application-PSK
//     recipe, event-driven cross-party injection; combiner key package framing v2 and
//     session archive v8 (old key packages and archives are rejected — regenerate);
//     TwoMlsPqError gained ApqInfoMismatch. No call-shape changes.
// v13: push persistence (security review H1) — pull archive()/fromArchive removed from
//     the FFI; ArchiveSink foreign trait (persist(seq, kind: BlobKind{core, checkpoint},
//     archive)) + installSink (once-only, baseline checkpoint; SinkAlreadyInstalled on a
//     second call) + static fromPersisted(core:checkpoint:) + stateSeq(); EncryptResult
//     gained dependsOnSeq (durability gate for key-material frames). SESSION_ARCHIVE 9 /
//     INVITATION 3 — persisted state not portable, regenerate.
// v14: PrepareEncryptResult gained proposalMessage (the raw staged Upd(self) proposal —
//     the exact message the paired encrypt staples; sha256 over it == proposalHash ==
//     the receiver's QueuedRemoteProposal.digest). Adopters digest the bytes themselves
//     (anchor agent-handoff signing). Record shape change only — no wire, archive, or
//     semantic change; persisted state carries over.
// v15: AppBinding — an optional app-state binding welded into a session at creation,
//     immutable for its lifetime (AppBinding GroupContext extension 0xF0A2 on the
//     classical halves): initiate gained appBinding, accept/receive gained
//     expectedAppBinding (verified on the joined welcome BEFORE invitation state is
//     claimed; the return group mirrors it; absence-against-expectation and
//     empty bindings reject); new appBinding() getter; TwoMlsPqError gained
//     AppBindingMismatch. Leaves advertise the extension: COMBINER_KEY_PACKAGE 3 /
//     INVITATION 4 — republish key packages, regenerate invitations. This wrapper
//     passes nil/unbound at reply/receive; threading a real binding through the
//     abstract surface is its own follow-up.
// v16: §A.1 pre-establishment sends — the initiator sends app messages before the
//     acceptor's return welcome. Pre-establishment prepareToEncrypt is a NO-OP round
//     (proposalMessage EMPTY; proposalHash is the WELCOME digest — the one carve-out on
//     the v14 hash==sha256(message) guarantee) and encrypt emits a fresh §A.1 envelope
//     per frame: tagged [0x15][u32 kem][kem][ct], plaintext = four optional sections
//     [appPayload][welcome][returnKp][stapledMessage] (either/or rule: a host payload
//     is establishment-self-sufficient and replaces the bare sections). initiate LOST
//     its appPayload parameter — attach post-hoc via setInitialAppPayload /
//     setInitialReturnKeyPackage (initiator-only, pre-establishment-only; the retained
//     state rides the archive — capture AFTER attaching); new initialWelcome() +
//     decodeInitialPlaintext(). InitialFrame reshaped (welcome now Optional; gained
//     returnKeyPackage/stapledMessage). Archive layout versions reset to the
//     pre-release floor (SESSION_ARCHIVE and INVITATION both → 1; the ladders carried
//     no compatibility value) — regenerate ALL persisted sessions and invitations;
//     the v15 key-package WIRE cut (a published artifact) is untouched.
private let expectedBindingContract: UInt64 = 16

enum TwoMLSPQBindingContract {
	static let verified: Void = {
		let actual = bindingContractVersion()
		precondition(
			actual == expectedBindingContract,
			"""
			TwoMLSPQ binding/binary mismatch: the vendored two_mls_pq.swift expects \
			contract \(expectedBindingContract) but the loaded binary provides \(actual). \
			Re-sync Sources/TwoMLSPQ/two_mls_pq.swift and the TwoMLSPQ xcframework \
			from the SAME build.
			"""
		)
	}()
}

// MARK: - Scalar conversions

/// Lift a raw FFI digest into a `CommProtocol.TypedDigest`. The FFI's documented
/// convention is SHA-256-32 over the stated object (see the note above
/// `PrepareEncryptResult` in TwoMLSPQ's lib.rs); the type tag is applied HERE — the
/// Rust crate carries no app-layer digest-type values.
private func liftDigest(_ raw: Data) throws -> TypedDigest {
	try TypedDigest(prefix: .sha256, checkedData: raw)
}

// MARK: - Persistence adapter

/// Bridges the abstract `PersistenceSink` onto the generated `ArchiveSink`
/// foreign trait (the binding's first — Rust holds the adapter via uniffi's
/// handle map for as long as the object holds the sink, so no wrapper-side
/// retention is needed). `final` + `let` ⇒ Sendable, matching the generated
/// protocol's `AnyObject, Sendable` bounds; the enqueue-only / non-blocking /
/// no-re-entry contract is the wrapped sink's to honor (documented on
/// `PersistenceSink`).
private final class PQSinkAdapter: TwoMLSPQ.ArchiveSink {
	private let wrapped: any AbstractTwoMLS.PersistenceSink

	init(_ wrapped: any AbstractTwoMLS.PersistenceSink) {
		self.wrapped = wrapped
	}

	func persist(seq: UInt64, kind: TwoMLSPQ.BlobKind, archive: Data) {
		wrapped.persist(
			seq: seq, slot: AbstractTwoMLS.PersistedSlot(kind), bytes: archive)
	}
}

extension AbstractTwoMLS.PersistedSlot {
	fileprivate init(_ kind: TwoMLSPQ.BlobKind) {
		switch kind {
		case .core: self = .core
		case .checkpoint: self = .checkpoint
		}
	}
}

extension AbstractTwoMLS.PrincipalState {
	init(_ base: TwoMLSPQ.PrincipalState) {
		switch base {
		case .sync(let clientId):
			self = .sync(clientId.bytes)
		case .pending(let old, let new):
			self = .pending(old: old.bytes, new: new.bytes)
		}
	}
}

extension TwoMLSPQ.ClientId {
	var clientID: AbstractTwoMLS.ClientID { bytes }
}

extension AbstractTwoMLS.ClientID {
	var pqClientId: TwoMLSPQ.ClientId { .init(bytes: self) }
}

// MARK: - Result adapters

extension AbstractTwoMLS {

	public struct PQEncryptResult: EncryptResultProtocol {
		public let cipherText: Data
		public let sender: AbstractTwoMLS.ClientID
		public let recipient: AbstractTwoMLS.ClientID
		public let epochs: APQEpochs
		public let dependsOnSeq: UInt64

		init(_ base: TwoMLSPQ.EncryptResult) {
			cipherText = base.cipherText
			sender = base.sender.bytes
			recipient = base.recipient.bytes
			epochs = APQEpochs(
				pqEpoch: base.epochs.pqEpoch,
				classicalEpoch: base.epochs.classicalEpoch
			)
			dependsOnSeq = base.dependsOnSeq
		}
	}

	public struct PQPrepareEncryptResult: PrepareEncryptResultProtocol {
		// The raw staged Upd(self) proposal — the exact message the paired
		// `encrypt` staples and the peer independently digests. Exposed as bytes
		// so the ADOPTER chooses the digest/wireformat (the anchor agent-handoff
		// signs over sha256 of these bytes; crate guarantee: that equals
		// `proposalHash` and the receiver's `QueuedRemoteProposal.digest`).
		// PRE-ESTABLISHMENT carve-out (contract 15): a replier's prepare before the
		// acceptor's return welcome is a NO-OP round — `proposalMessage` is EMPTY and
		// `proposalHash` is the WELCOME digest (the AAD binding each such message to
		// its establishment vector); the peer stages nothing from those frames.
		public let proposalMessage: Data
		public let proposalHash: TypedDigest
		// NB: protocol spells this `commitedRemoteClientId` (single "t");
		// the FFI struct spells it `committedRemoteClientId`.
		public let commitedRemoteClientId: AbstractTwoMLS.ClientID?
		public let didCommit: Bool

		init(_ base: TwoMLSPQ.PrepareEncryptResult) throws {
			proposalMessage = base.proposalMessage
			proposalHash = try liftDigest(base.proposalHash)
			commitedRemoteClientId = base.committedRemoteClientId?.bytes
			didCommit = base.didCommit
		}
	}

	public struct PQSenderMessage: MLSSenderMessageProtocol {
		public let appMessageData: Data
		public let senderClientId: AbstractTwoMLS.ClientID
		public let epoch: UInt64

		init(_ base: TwoMLSPQ.MlsSenderMessage) {
			appMessageData = base.appMessageData
			senderClientId = base.senderClientId.bytes
			epoch = base.epoch
		}
	}

	public struct PQQueuedRemoteProposal: QueuedRemoteProposalProtocol {
		public let digest: TypedDigest
		public let sender: AbstractTwoMLS.ClientID
		public let proposing: AbstractTwoMLS.ClientID
		public let context: TypedDigest

		init(_ base: TwoMLSPQ.QueuedRemoteProposal) throws {
			digest = try liftDigest(base.digest)
			sender = base.sender.bytes
			proposing = base.proposing.bytes
			context = try liftDigest(base.context)
		}
	}

	public struct PQCommitResult: CommitResultProtocol {
		public let newSender: AbstractTwoMLS.ClientID?
		public let newRecipient: AbstractTwoMLS.ClientID

		init(_ base: TwoMLSPQ.CommitResult) {
			newSender = base.newSender?.bytes
			newRecipient = base.newRecipient.bytes
		}
	}

	public struct PQDecryptResult: DecryptResultProtocol {
		public let applicationMessage: PQSenderMessage?
		public let proposal: PQQueuedRemoteProposal?
		public let remoteCommit: PQCommitResult?

		init(_ base: TwoMLSPQ.DecryptResult) throws {
			applicationMessage = base.applicationMessage.map(PQSenderMessage.init)
			proposal = try base.proposal.map(PQQueuedRemoteProposal.init)
			remoteCommit = base.remoteCommit.map(PQCommitResult.init)
		}
	}
}

// MARK: - Session

extension AbstractTwoMLS {

	/// Adapter wrapping a `TwoMLSPQ.TwoMlsPqSession`.
	public struct PQSession: AbstractTwoMLS.PQRatchetingSession {
		let base: TwoMLSPQ.TwoMlsPqSession

		init(_ base: TwoMLSPQ.TwoMlsPqSession) {
			// Warm-start restore is the likeliest FIRST FFI touch after an app
			// update, so the binding/binary pairing guard must run here too —
			// not only at client/invitation construction — or a mismatch traps at
			// the first Record buffer read instead of the precondition message.
			// (`init(persisted:)` delegates here, so this covers restore.)
			_ = TwoMLSPQBindingContract.verified
			self.base = base
		}

		// MARK: Archivable (push)

		/// The two persistence slots a session's sink receives. `checkpoint`
		/// is non-optional — the crate rejects a checkpoint-less restore as
		/// `ArchiveInvalid`; this struct moves that rule to compile time.
		public struct Persisted: Codable, Sendable {
			public var core: Data?
			public var checkpoint: Data

			public init(core: Data?, checkpoint: Data) {
				self.core = core
				self.checkpoint = checkpoint
			}
		}

		public init(persisted: Persisted) throws(AbstractTwoMLS.SessionError) {
			// PQ trees come from the checkpoint; identity/classical/meta from
			// whichever slot has the higher stateSeq; fails closed
			// (`.archiveInvalid`) on a PQ-epoch manifest mismatch. The restored
			// session has NO sink — installSink immediately, before use.
			let restored: TwoMlsPqSession
			do {
				restored = try TwoMlsPqSession.restore(
					core: persisted.core.map { TwoMLSPQ.Archive(bytes: $0) },
					checkpoint: TwoMLSPQ.Archive(bytes: persisted.checkpoint))
			} catch {
				throw AbstractTwoMLS.SessionError(pqError: error, at: .restore)
			}
			self.init(restored)
		}

		public func installSink(
			_ sink: any AbstractTwoMLS.PersistenceSink
		) throws(AbstractTwoMLS.SessionError) {
			// `.sinkAlreadyInstalled` on a second call.
			try mapPQErrors(.installSink) {
				try base.installSink(sink: PQSinkAdapter(sink))
			}
		}

		public var stateSeq: UInt64 {
			base.stateSeq()
		}

		// MARK: State

		public var proposalContext: TypedDigest? {
			// Non-throwing per the protocol; FFI digests are always well-formed
			// 32-byte values, so a conversion failure is treated as "no context".
			guard let digest = base.proposalContext() else { return nil }
			return try? liftDigest(digest)
		}

		// MARK: Principal state (truth surface)

		public var myPrincipalState: AbstractTwoMLS.PrincipalState {
			.init(base.myPrincipalState())
		}

		public var theirPrincipalState: AbstractTwoMLS.PrincipalState {
			.init(base.theirPrincipalState())
		}

		public var queuedRemoteSuccessor: AbstractTwoMLS.ClientID? {
			base.queuedRemoteSuccessor()?.bytes
		}

		public var sendRendezvous: AbstractTwoMLS.RendezvousID? {
			get throws(AbstractTwoMLS.SessionError) {
				try mapPQErrors(.pqOperation) { try base.sendRendezvous()?.bytes }
			}
		}

		// MARK: Encrypt / decrypt

		public func prepareToEncrypt(
			proposing: AbstractTwoMLS.ClientID?
		) throws(AbstractTwoMLS.SessionError) -> PQPrepareEncryptResult? {
			try mapPQErrors(.prepareToEncrypt) {
				try PQPrepareEncryptResult(
					base.prepareToEncrypt(proposing: proposing?.pqClientId))
			}
		}

		public func encrypt(
			appMessage: Data
		) throws(AbstractTwoMLS.SessionError) -> PQEncryptResult {
			try mapPQErrors(.encrypt) {
				PQEncryptResult(try base.encrypt(appMessage: appMessage))
			}
		}

		public func processIncoming(
			ciphertext: Data
		) throws(AbstractTwoMLS.SessionError) -> PQDecryptResult? {
			// `.misroutedFrame` if a PQ side-band frame lands here (route it to
			// `ingest`); `.decryptionFailed` is transient (retry); `.epochDesync`
			// means reconnect. After a `.retryLater` failure, reconcile identity
			// via `theirPrincipalState` — a staple may have applied.
			try mapPQErrors(.processIncoming) {
				try base.processIncoming(ciphertext: ciphertext)
					.map(PQDecryptResult.init)
			}
		}

		public func queueProposal(
			digest: TypedDigest
		) throws(AbstractTwoMLS.SessionError) {
			try mapPQErrors(.pqOperation) {
				try base.queueProposal(digest: digest.digest)
			}
		}

		public func forwarded(
			headerDecrypted: Data
		) throws(AbstractTwoMLS.SessionError) -> PQSenderMessage? {
			// `headerDecrypted` is the §A.1 envelope PLAINTEXT the invitation's
			// `decodeHeader` opened (the `.forward` payload). Re-derive the spawn
			// token over the STABLE PREFIX — the same convention `decodeHeader` keyed
			// the forward table with — so the FFI stays digest-convention-agnostic
			// (opaque token), and ack the re-delivery against the session's own token.
			// Contract 15: a pre-establishment frame staples the sender's CURRENT app
			// message, so a "replay" is usually a genuinely new 2nd..Nth message from
			// a not-yet-established peer — deliver it fail-open (a staple that fails
			// to decrypt is a duplicate or damage; the sender re-staples until its
			// first commit, so drops self-heal).
			return try mapPQErrors(.forwarded) {
				// Fail open on a malformed payload: this is replay/early-delivery
				// plumbing, and the honest pipeline hands over bytes `decodeHeader`
				// already parsed — surfacing a parse failure as an error would
				// misgrade garbage as fatal (the session itself is untouched).
				guard let frame = try? decodeInitialPlaintext(plaintext: headerDecrypted),
					let stablePrefix = frame.appPayload ?? frame.welcome
				else {
					return nil
				}
				let token = TypedDigest(prefix: .sha256, over: stablePrefix)
				if let acked = try base.forwarded(spawnToken: token.wireFormat) {
					return PQSenderMessage(acked)
				}
				guard let staple = frame.stapledMessage,
					let result = try? base.processIncoming(ciphertext: staple),
					let message = result.applicationMessage
				else { return nil }
				return PQSenderMessage(message)
			}
		}

		/// The receive group's classical (message-half) id, or nil before this side
		/// has joined one (the initiator, before processing the peer's stapled
		/// return welcome). Same currency as `shouldListenOn()`'s GroupID: the
		/// stable classical half — the acceptor's PQ half is empty until the A.4
		/// bootstrap. The card role's post-join envelope check compares this
		/// against the signed `AppWelcome.Content.groupId` (classical parity:
		/// MultiMLS checks `receiveGroup.groupId == welcome.groupId` inside
		/// `receiveWelcome`).
		public var receiveGroupId: AbstractTwoMLS.GroupID? {
			base.receiveGroupId()?.classical.bytes
		}

		public func shouldListenOn() throws(AbstractTwoMLS.SessionError) -> (
			AbstractTwoMLS.GroupID, [UInt64: AbstractTwoMLS.RendezvousID]
		) {
			return try mapPQErrors(.pqOperation) {
			let channels = try base.shouldListenOn()
			// CombinerGroupId carries both halves; the abstraction wants one GroupID.
			// Use the classical half: it exists from creation for both roles, whereas
			// the acceptor's PQ half is empty until the A.4 bootstrap — keying app
			// listen-state off it would hand out an empty id that changes mid-session.
			let groupId = channels.sendGroup.classical.bytes
			// rendezvousByEpoch has one address per epoch, so keys are unique; the closure is a
			// defensive tie-break that shouldn't fire — keep the first (arbitrary but stable).
			let rendezvous = Dictionary(
				channels.rendezvousByEpoch.map {
					($0.epoch, $0.rendezvousId.bytes)
				},
				uniquingKeysWith: { first, _ in first }
			)
			return (groupId, rendezvous)
			}
		}

		// MARK: PQRatchet

		// The FFI is call-per-step (begin/respond/bind/apply); the abstract surface is
		// ingest/advance. A responder's reply produced during `ingest` is parked inside
		// the Rust session (single slot, enforced there) until `advance` consumes it.

		public var turn: PQTurn {
			base.myPqTurn() ? .weInitiate : .theyInitiate
		}

		public var epochs: APQEpochs {
			let pair = base.epochs()
			return APQEpochs(pqEpoch: pair.pqEpoch, classicalEpoch: pair.classicalEpoch)
		}

		public var isFullyEstablished: Bool {
			base.isFullyEstablished()
		}

		public func begin(
			_ kind: PQOperationKind,
			rotating: AbstractTwoMLS.ClientID?
		) throws(AbstractTwoMLS.SessionError) -> PQOutbound {
			try mapPQErrors(.pqOperation) {
			// `rotating` is the A.4/A.5 credential handoff: it must name the session's
			// CURRENT principal — i.e. the Phase 8 classical rotation must have
			// COMPLETED first (contract v9+: proposing puts the candidate on the
			// wire, the peer's approval + commit canonicalizes, and the staple back
			// swaps the session client; proposing alone has not swapped anything —
			// `begin(rotating:)` before that round-trip returns SessionNotReady).
			// The operation then moves the PQ leaves to that principal's signing
			// key; the peer observes it as PQInbound.rotatedCredential on the
			// rekey Upd'.
			switch kind {
			case .finishBootstrap:
				return PQOutbound(
					kind: kind,
					payload: try base.pqBootstrapBegin(
						rotating: rotating?.pqClientId)
				)
			case .ratchet:
				// A.3 injects a PSK with no updatePath — nothing carries a new
				// leaf credential.
				guard rotating == nil else {
					throw AbstractTwoMLS.SessionError(
						code: .rotationCannotRideRatchet,
						detail: "A.3 has no updatePath; rotate via .rekey or .finishBootstrap")
				}
				return PQOutbound(kind: kind, payload: try base.pqRatchetBegin())
			case .rekey:
				return PQOutbound(
					kind: kind,
					payload: try base.pqRekeyBegin(
						rotating: rotating?.pqClientId)
				)
			}
			}
		}

		public func advance(
			after inbound: PQInbound
		) throws(AbstractTwoMLS.SessionError) -> PQOutbound? {
			base.pqTakePendingOutbound().map {
				PQOutbound(kind: inbound.kind, payload: $0)
			}
		}

		public func ingest(
			_ message: Data
		) throws(AbstractTwoMLS.SessionError) -> PQInbound {
			return try mapPQErrors(.ingest) {
			// Frames leave the peer sealed (header encryption, contract v7): the leading
			// tag is no longer in the clear, so classify by removing the outer seal and
			// reading the routing `kind` rather than switching on `message.first`. The
			// pq_* receivers open the seal transparently, so hand them the sealed blob.
			guard let opened = try base.openIncoming(blob: message) else {
				// No header key opened it (M2a). One alone may be a stranger's
				// garbage or a reconnect-gap frame; treat a RUN of these on a live
				// session as a reconnect signal (count at the call site).
				throw AbstractTwoMLS.SessionError(
					code: .unopenableFrame,
					detail: "no receive-window key opens this blob; "
						+ "a run of these is a reconnect signal")
			}
			guard case let .pqSideBand(kind) = opened.kind else {
				// A message-path frame reached the side-band entry point (M2b).
				throw AbstractTwoMLS.SessionError(
					code: .misroutedFrame,
					detail: "message-path frame at the PQ side-band entry — "
						+ "route to processIncoming")
			}
			switch kind {
			case .rekeyUpdate:
				// A.5 responder: commit the initiator's Upd' on our send-PQ; the
				// [Commit'][counter-Upd'] reply parks for `advance` to hand out.
				// A credential handoff announces the initiator's (already Phase
				// 8-rotated) agent id in the Upd' — by the time this returns, the
				// initiator's leaf in our send-PQ has moved to that agent's key.
				let rotated = try base.pqRekeyRespond(updMsg: message)
				return PQInbound(
					kind: .rekey, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: rotated?.bytes)
			case .rekeyCommit:
				// Mid-operation (initiator: counter-Upd' present) our own send-PQ also
				// committed and the final Commit' parks for `advance`; final (responder:
				// empty counter) only our recv mirror advanced and the turn is ours.
				let continued = try base.pqRekeyApply(msg: message)
				return PQInbound(
					kind: .rekey, advancedGroup: continued ? .ours : .theirs,
					newEpochs: epochs, rotatedCredential: nil)
			case .bootstrapKeyPackage:
				try base.pqBootstrapRespond(kpMsg: message)
				return PQInbound(
					kind: .finishBootstrap, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: nil)
			case .bootstrapBind:
				try base.pqBootstrapApply(bindMsg: message)
				return PQInbound(
					kind: .finishBootstrap, advancedGroup: .theirs,
					newEpochs: epochs, rotatedCredential: nil)
			case .ratchetEphemeralKey:
				try base.pqRatchetRespond(ekMsg: message)
				return PQInbound(
					kind: .ratchet, advancedGroup: .theirs,
					newEpochs: nil, rotatedCredential: nil)
			case .ratchetCiphertext:
				try base.pqRatchetBind(ctMsg: message, app: Data())
				return PQInbound(
					kind: .ratchet, advancedGroup: .ours,
					newEpochs: epochs, rotatedCredential: nil)
			case .ratchetBind:
				let plaintext = try base.pqRatchetApply(bindMsg: message)
				return PQInbound(
					kind: .ratchet, advancedGroup: .theirs,
					newEpochs: epochs, rotatedCredential: nil,
					plaintext: plaintext.isEmpty ? nil : plaintext)
			}
			}
		}
	}

}

// MARK: - Invitation (stub)

extension AbstractTwoMLS {

	/// Opaque Codable restore payload for a PQ invitation: `TwoMlsPqInvitation`
	/// bytes — either the mint artifact (`makeInvitation`/`generateInvitation`)
	/// or a checkpoint blob the invitation's sink pushed. Contains the signing
	/// identity and key-package private material; the bytes alone restore a
	/// fully receivable invitation (the invitation is monolithic — one slot).
	public struct PQInvitationArchive: Codable, Sendable {
		public var bytes: Data

		public init(bytes: Data) {
			self.bytes = bytes
		}
	}

	public struct PQInvitation: AbstractTwoMLS.Invitation {
		public typealias Client = PQClient
		public typealias Session = PQSession
		public typealias Persisted = PQInvitationArchive

		let base: TwoMLSPQ.TwoMlsPqInvitation

		init(base: TwoMLSPQ.TwoMlsPqInvitation) {
			_ = TwoMLSPQBindingContract.verified
			self.base = base
		}

		// MARK: Archivable (push)

		public init(persisted: PQInvitationArchive) throws(AbstractTwoMLS.SessionError) {
			do {
				self.init(base: try TwoMlsPqInvitation.restore(archive: persisted.bytes))
			} catch {
				throw AbstractTwoMLS.SessionError(pqError: error, at: .restore)
			}
		}

		/// Monolithic object: the sink receives only `.checkpoint` blobs (one
		/// per successful `receive`, plus the install-time baseline).
		public func installSink(
			_ sink: any AbstractTwoMLS.PersistenceSink
		) throws(AbstractTwoMLS.SessionError) {
			try mapPQErrors(.installSink) {
				try base.installSink(sink: PQSinkAdapter(sink))
			}
		}

		/// Bumps once per successful `receive`.
		public var stateSeq: UInt64 {
			base.stateSeq()
		}

		// MARK: Invitation

		public init(clientId: AbstractTwoMLS.ClientID) throws(AbstractTwoMLS.SessionError) {
			// Fresh invitation: mint a client for this identity and capture a combiner
			// key package into a self-contained archive. Last-resort (reusable), so a
			// single-use invitation's `InvitationSpent` never surfaces here.
			do {
				let archive = try TwoMlsPqPrincipal(clientId: clientId)
					.generateInvitation(lastResort: true)
				self.init(base: try TwoMlsPqInvitation.restore(archive: archive))
			} catch {
				throw AbstractTwoMLS.SessionError(pqError: error, at: .invitation)
			}
		}

		public var clientId: AbstractTwoMLS.ClientID {
			base.clientId().bytes
		}

		public var encodedKeyPackage: Data {
			// The combiner's two key packages travel as one opaque blob; only TwoMLSPQ
			// reads the halves back out (decodeCombinerKeyPackage).
			encodeCombinerKeyPackage(keyPackage: base.combinerKeyPackage())
		}

		public func decodeHeader(
			ciphertext: Data
		) throws(AbstractTwoMLS.SessionError) -> AbstractTwoMLS.HeaderDecryptResult {
			return try mapPQErrors(.decodeHeader) {
			// Split the crate's §A.1 envelope, strip the HPKE layer with this
			// invitation's key-package init key (info defaults to this ClientId,
			// matching the crate's seal), and parse the four optional sections.
			let (kemOutput, sealed) = try decodeEnvelopeFrame(ciphertext)
			let decrypted = try base.hpkeOpen(
				kemOutput: kemOutput,
				ciphertext: sealed,
				info: nil,
				aad: nil
			)
			let frame = try decodeInitialPlaintext(plaintext: decrypted)
			// The digest doubles as the FFI's opaque spawn token — computed over the
			// STABLE PREFIX (the app payload; the bare welcome for payload-less
			// envelopes), which is byte-identical across the initial frame and every
			// pre-establishment re-staple (each re-seal has a fresh HPKE ephemeral
			// and a different stapled message, so the whole plaintext is NOT stable).
			// receive() keys the forward table with it, so any later frame from the
			// same initiator routes to the spawned session instead of re-surfacing
			// as a fresh AppWelcome. The sha256 convention lives entirely on this
			// side; the Rust crate never interprets the token.
			guard let stablePrefix = frame.appPayload ?? frame.welcome else {
				// decodeInitialPlaintext rejects an envelope with neither section.
				throw AbstractTwoMLS.SessionError(
					code: .malformedFrame,
					detail: "§A.1 envelope with no establishment vector")
			}
			let digest = TypedDigest(prefix: .sha256, over: stablePrefix)
			if let spawned = base.forwardGroupId(spawnToken: digest.wireFormat) {
				return .forward(
					groupId: try DataIdentifier(
						prefix: .bits256,
						checkedData: spawned.bytes
					),
					// The envelope PLAINTEXT: `forwarded(headerDecrypted:)` re-parses
					// it to ack the replay and deliver the stapled app message.
					mlsMessageData: decrypted
				)
			}
			guard let appWelcome = frame.appPayload else {
				// This backend's adopters always attach an app-layer identity
				// envelope; a bare-welcome frame has nothing the app can verify.
				throw AbstractTwoMLS.SessionError(
					code: .malformedFrame,
					detail: "§A.1 envelope without an app payload at the app surface")
			}
			// A pre-establishment frame staples the sender's current app message
			// ([0x13]-tagged) — an optional early delivery, decryptable only AFTER
			// the join; `receive` hands it to the spawned session fail-open.
			return .appWelcome(
				welcomeToken: WelcomeToken(digest),
				appWelcome: appWelcome,
				stapledPrivateMessage: frame.stapledMessage
			)
			}
		}

		public func receive(
			sendGroupWelcome: Data,
			remoteKeyPackage: Data,
			remoteClientId: AbstractTwoMLS.ClientID,
			welcomeToken: WelcomeToken,
			stapledMessage: Data?,
			newClientId: AbstractTwoMLS.ClientID
		) throws(AbstractTwoMLS.SessionError) -> (PQSession, stapled: PQSenderMessage?) {
			return try mapPQErrors(.receive) {
			// Validate the dedicated principal id BEFORE any invitation state is
			// claimed: `stageRotation` (below) throws `.invalidClientId` on an empty
			// id, but by then `base.receive` has consumed the welcome — the session
			// would be orphaned and a retry refused as `.duplicateWelcome`. Same
			// error identity, fixed ordering.
			guard !newClientId.isEmpty else {
				throw AbstractTwoMLS.SessionError(
					code: .invalidClientId,
					detail: "dedicated principal id must be non-empty")
			}

			let pair = try decodeCombinerKeyPackage(bytes: remoteKeyPackage)

			// Bind the key package to the authenticated identity from the validated
			// welcome (also checks the pair's two halves agree on one credential).
			// M4: the crate's own RemoteIdentityMismatch (via base.receive) maps to
			// the SAME `.identityMismatch` — one code, both origins.
			let parsed = try parseCombinerKeyPackage(kp: pair)
			guard parsed.clientId.bytes == remoteClientId else {
				throw AbstractTwoMLS.SessionError(
					code: .identityMismatch,
					detail: "key package credential != authenticated remote id; "
						+ "invitation not consumed")
			}

			// Joins both halves from the APQ welcome and stands up the bound return
			// send group; the invitation dedups repeat welcomes per remote. The
			// welcome token keys the forward table as the FFI's opaque spawn
			// token, so a transport re-delivery of the same initial frame decodes as
			// `.forward` to this session.
			// The `WelcomeToken` type enforces the round-trip: `receive` accepts only the
			// token `decodeHeader` returned, so a caller cannot substitute a digest
			// recomputed over the wrong bytes (e.g. a re-serialized welcome) and
			// silently break replay forwarding.
			// `sendGroupWelcome` is the PLAINTEXT APQWelcome (contract 15): the app
			// verified it INSIDE the signed identity envelope (the same bytes `reply`
			// handed out), so the join consumes the authenticated copy — the envelope's
			// own unauthenticated sections never feed consequential state.
			// `expectedRemote:` is the crate's own identity pin, checked BEFORE any
			// invitation state is claimed — redundant with the key-package guard
			// above by construction, kept so the binding is enforced independently
			// on both sides of the FFI (defense-in-depth of two, not one).
			// `newClientId: nil` stays deliberate: passing it would establish
			// directly under the dedicated principal and retire the
			// stage→propose→approve dance below — a semantic change deferred to its
			// own follow-up.
			// `expectedAppBinding: nil` — unbound (v15's AppBinding): this surface does
			// not state a binding yet, and the crate never silently accepts a
			// binding-carrying welcome against a nil expectation.
			let session = PQSession(
				try base.receive(
					welcome: sendGroupWelcome,
					theirKeyPackage: pair,
					spawnToken: welcomeToken.wireFormat,
					newClientId: nil,
					expectedRemote: remoteClientId,
					expectedAppBinding: nil
				))

			// Deliberately fail open on the staple: an untrusted, optional early-delivery
			// of the initiator's app message ([0x13]-tagged, contract 16 — every
			// pre-establishment frame staples the sender's current message). One that
			// fails to decrypt/parse is dropped — the session still establishes and the
			// peer re-staples its CURRENT message until its first commit — with no
			// security loss (the MLS ciphertext authenticates inside the just-joined
			// group or not at all). A successful decrypt CONSUMES the message's ratchet
			// generation, so it is returned as the full typed sender message (the same
			// currency `processIncoming` yields) — the caller must deliver it; a
			// re-delivered copy of this frame cannot yield it again.
			let stapled: PQSenderMessage? = stapledMessage.flatMap { staple in
				guard let result = try? session.processIncoming(ciphertext: staple)
				else { return nil }
				return result.applicationMessage
			}

			// Stage the app-spawned session-dedicated principal for the Phase 8
			// rotation (contract v9+ candidate lifecycle): `prepareToEncrypt(
			// proposing: newClientId)` puts the candidate on the wire as this
			// side's Upd proposal — the PEER's approval (`queueProposal`) plus
			// commit canonicalizes it, and the staple back swaps the session
			// client. Only then do the PQ leaves catch up at the next
			// `begin(.rekey, rotating: newClientId)` (A.5).
			try session.base.stageRotation(newClientId: newClientId)

			return (session, stapled)
			}
		}
	}
}

// A session is a single-driver state machine — see the PQRatchet doc. This
// unavailable conformance makes the non-Sendability explicit and blocks a
// consumer from retroactively re-adding it; the containing type (typically an
// actor owning the session) asserts its own Sendable story instead.
@available(*, unavailable)
extension AbstractTwoMLS.PQSession: Sendable {}

// MARK: - Client (stub)

extension AbstractTwoMLS {

	public struct PQClient: AbstractTwoMLS.Client {
		public typealias Invitation = PQInvitation

		let base: TwoMLSPQ.TwoMlsPqPrincipal

		init(base: TwoMLSPQ.TwoMlsPqPrincipal) {
			_ = TwoMLSPQBindingContract.verified
			self.base = base
		}

		public init(clientId: AbstractTwoMLS.ClientID) throws(AbstractTwoMLS.SessionError) {
			do {
				self.init(base: try TwoMlsPqPrincipal(clientId: clientId))
			} catch {
				throw AbstractTwoMLS.SessionError(pqError: error, at: .client)
			}
		}

		public func makeInvitation()
			throws(AbstractTwoMLS.SessionError) -> PQInvitation.Persisted
		{
			// The client captures a combiner key package into self-contained mint
			// bytes; it keeps no key-package private material. Last-resort
			// (reusable) — a single-use invitation's `InvitationSpent` is unreachable here.
			try mapPQErrors(.client) {
				PQInvitationArchive(bytes: try base.generateInvitation(lastResort: true))
			}
		}

		public static func parseKeyPackageSuite(
			encoded: Data
		) -> AbstractTwoMLS.RawSuites? {
			// An opaque combiner blob reports its PQ half's suite; fall back to a bare
			// MLS key package message. Returns nil when the bytes are neither — callers
			// distinguish "unparseable" from a real suite without a magic 0 sentinel.
			if let pair = try? decodeCombinerKeyPackage(bytes: encoded) {
				return try? parseMlsKeyPackage(bytes: pair.pq).cipherSuite.value()
			}
			return try? parseMlsKeyPackage(bytes: encoded).cipherSuite.value()
		}

		public static var supportedSuites: [AbstractTwoMLS.RawSuites] {
			// 0x0003 = X25519+ChaCha20Poly1305 (classical), 0xFDEA = ML-KEM-768 (pq)
			[0x0003, 0xFDEA]
		}

		public func reply(
			keyPackageMessage: Data
		) throws(AbstractTwoMLS.SessionError) -> (
			sendGroup: PQSession,
			welcomeMessage: Data,
			myKeyPackage: Data
		) {
			return try mapPQErrors(.client) {
			let pair = try decodeCombinerKeyPackage(bytes: keyPackageMessage)
			// `appBinding: nil` — unbound (v15's AppBinding); threading a real
			// relationship binding through the abstract surface is its own follow-up.
			let session = try TwoMlsPqSession.initiate(
				client: base, theirKeyPackage: pair, appBinding: nil)
			// `welcomeMessage` is the PLAINTEXT APQWelcome (contract 15): the app binds
			// it — together with `myKeyPackage` — into its signed identity envelope
			// (AnchorWelcome) and hands the result back via `createTwoMLSGroup`, which
			// attaches it as the session's establishment-self-sufficient app payload.
			// The crate re-staples that payload on the wire envelope of the initial
			// frame AND of every pre-establishment app message, so any single frame
			// establishes the acceptor.
			guard let welcome = session.initialWelcome() else {
				throw AbstractTwoMLS.SessionError(
					code: .internalError,
					detail: "PQClient.reply — initiate produced no welcome")
			}
			// The return-group key package uses the retaining generate path: this live
			// session joins the acceptor's return welcome through its own client store
			// (an invitation-held key package would be purged from the client).
			let myKeyPackage = encodeCombinerKeyPackage(
				keyPackage: try base.generateCombinerKeyPackage()
			)
			return (PQSession(session), welcome, myKeyPackage)
			}
		}

		public func createTwoMLSGroup(
			remoteAgentId: AbstractTwoMLS.ClientID,
			mySendGroup: PQSession,
			theirKeyPackageMessage: Data,
			appWelcome: Data
		) throws(AbstractTwoMLS.SessionError) -> (
			PQSession, encryptedCombinedWelcome: Data
		) {
			return try mapPQErrors(.client) {
			// Bind the published key package to the remote identity the app is
			// addressing before anything is attached.
			let pair = try decodeCombinerKeyPackage(bytes: theirKeyPackageMessage)
			guard try parseCombinerKeyPackage(kp: pair).clientId.bytes == remoteAgentId
			else {
				throw AbstractTwoMLS.SessionError(
					code: .identityMismatch,
					detail: "key package credential != addressed remote id")
			}
			// Attach the app welcome as the session's establishment-self-sufficient
			// payload (it carries the plaintext welcome + return key package `reply`
			// handed out, inside the app's signed identity envelope). The crate
			// composes and HPKE-seals the §A.1 envelope itself (to the KP′ it retained
			// at initiate) — the attach also regenerates the parked initial frame,
			// and every pre-establishment `encrypt` re-staples the same payload.
			// CAPTURE ORDERING: persist-capture the session AFTER this call — the
			// attached payload rides the archive, and a capture taken between `reply`
			// and here restores a replier whose re-staples carry no identity envelope.
			try mySendGroup.base.setInitialAppPayload(payload: appWelcome)
			guard let envelope = mySendGroup.base.pendingOutbound() else {
				throw AbstractTwoMLS.SessionError(
					code: .internalError,
					detail: "createTwoMLSGroup — no parked envelope after attach")
			}
			return (mySendGroup, encryptedCombinedWelcome: envelope)
			}
		}
	}
}

// MARK: - §A.1 envelope outer frame

/// The crate's §A.1 envelope (contract 15): `[tag][u32-LE kem-len][kem_output]
/// [ciphertext…]` (ciphertext runs to the end), `tag` read via the exported
/// `initialEnvelopeTag()` — never hardcoded (the `pqFrameKind` convention). Produced
/// entirely by the crate (initiate / the attach setters / pre-establishment encrypt);
/// split HERE — rather than opened via `openInitial` — so `hpkeOpen`'s two inputs stay
/// separate and the raw plaintext remains available for the forward-routing path
/// (`forwarded(headerDecrypted:)` re-parses it).
private func decodeEnvelopeFrame(
	_ data: Data
) throws(AbstractTwoMLS.SessionError) -> (kemOutput: Data, ciphertext: Data) {
	var rest = data[...]
	guard rest.popFirst() == initialEnvelopeTag(), rest.count >= 4 else {
		throw AbstractTwoMLS.SessionError(
			code: .malformedFrame, detail: "§A.1 envelope outer frame")
	}
	let kemLength = Int(
		rest.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
	)
	rest = rest.dropFirst(4)
	guard rest.count >= kemLength else {
		throw AbstractTwoMLS.SessionError(
			code: .malformedFrame, detail: "§A.1 envelope outer frame")
	}
	return (Data(rest.prefix(kemLength)), Data(rest.dropFirst(kemLength)))
}
