//
//  PQSession.swift
//  TwoMLSPQ
//
//  Created by Mark @ Germ on 6/23/26.
//
//  Conforms the TwoMLSPQ UniFFI types to the abstract protocol surface.
//
//  The abstraction speaks `Data`/`TypedDigest` while TwoMLSPQ wraps identity
//  bytes in single-field structs (`ClientId`, …), and several abstract members
//  collide with the generated methods only on return type — so the conformances
//  are thin adapter types at TwoMLSPQ's top level rather than
//  extensions on the generated classes. The generated module stays pristine.
//
//  Status (TwoMLSPQ v0.5.0 binding, contract 19 — see the ladder above
//  `expectedBindingContract` for the v17/v18/v19 deltas):
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
import TwoMLSPQBinding

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
// v17: burned by an interim build of the v18 work; never shipped.
// v18: every round ends in a stapled bind. Side-band frames are RETAINED for re-send —
//     new pqPendingOutbound(sealing:) peeks the sealed frame without consuming it
//     (.fresh re-seals per hand-out; .stable holds the base still for chunking), and the
//     new DuplicateSideBand error classifies a re-sent frame for a step already taken as
//     a discardable duplicate. A BIND IS THE STAPLE, not a frame: pqRatchetBind /
//     pqBootstrapBind LOSE their app parameter and OWE the classical half, which rides
//     the binder's next classical COMMIT as the message-frame staple (draft-02 §7
//     APQPrivateMessage) — so binds arrive via processIncoming, and pqRatchetApply /
//     pqBootstrapApply are DELETED. A.5 reshaped to the same three-leg shape:
//     Upd' → Commit' → stapled ACK; the counter-Upd' is gone, pqRekeyApply is
//     initiator-only and returns Void, and one A.5 round re-keys ONE group (turn
//     alternation covers the other). PqFrameKind loses ratchetBind/bootstrapBind and
//     gains bootstrapWelcome. New pqReceiveBroken() query pairs with the new
//     BindApplyFailed (peer's bind staple failed after the round's secret was consumed —
//     receiving is poisoned until a restore) and BindDischargeFailed (our own owed bind
//     failed mid-commit — permanently broken, route to re-establishment).
// v19: evidence-gating — a classical commit no longer requires an app-approved proposal.
//     A round commits when it folds an approved Upd (unchanged) OR when it owes a bind
//     and is LICENSED by a peer offer built against our current epoch (proof the peer
//     applied our previous commit). Host-visible: didCommit can be true with NO
//     queueProposal, and committedRemoteClientId is nil on such a round (a proposal-less
//     commit canonicalizes nothing of the peer's).
//     PERSISTED STATE (both rungs, stated per the ladder's own rule): wire tags were
//     renumbered, so an in-flight v0.4.x frame fails to classify under v0.5.0 — a loud
//     unopenable/misrouted discard, never a misparse; retention means live peers re-send.
//     Session/invitation archives follow the crate's pre-release hard cut: a v0.4.1 blob
//     fails CLOSED as ArchiveInvalid (.discardArtifact) and the session/invitation must be
//     regenerated — availability loss only, no stale-PQ splice.
//   - v20 (TwoMLSPQ 0.6.0): the establishment return key package is CLASSICAL-only and the
//     A.4 bootstrap KP is pre-committed, hash-bound. `receive`/`accept` take the bare
//     classical return KP plus a required 32-byte `bootstrapKpCommitment` (SHA-256 of the
//     initiator's PQ keyPackage, carried in the host's SIGNED establishment payload);
//     `initiate` pre-commits that KP (`bootstrapKpCommitment()` exposes the hash) and
//     `pqBootstrapRespond` rejects a KP′ hashing to anything else (new `BootstrapKpMismatch`
//     error). `setInitialReturnKeyPackage` takes classical bytes. Archive layout changed
//     (pre-release hard cut, as v0.5.0).
// v21 (TwoMLSPQ 0.7.0): the §A.1 envelope drops its OUTER tag — the blob is now the raw
//     `[u32-LE kem-len][kem_output][ciphertext]`, and discrimination moved INSIDE to the
//     HPKE plaintext's authenticated leading tag. `decodeInitialPlaintext` / `openInitial`
//     now return `OpenedInitial` (`.establishment(frame:)` / `.bootstrapKp(frame:)`);
//     `initialEnvelopeTag()` is retired (route by transport channel, not first byte).
//     `decodeEnvelopeFrame` no longer reads a tag. (The parallel `pqBootstrapEnvelope` is
//     wired at v23 below; through v22 only establishment envelopes rode the header channel.)
// v22 (TwoMLSPQ 0.7.0): one declared TwoMLS suite drives every crypto choice, and the §A.1
//     seal binds it via an UNTRANSMITTED AAD. Both sides derive `[framingVersion][suite
//     pair]` locally, so the split-open path must pass `envelopeFramingAad()` to `hpkeOpen`
//     or the AEAD tag fails. No new FFI types — `TwoMlsSuite` is crate-internal.
// v23 (consolidated repo): the parallel A.4 delivery is now ADOPTED end to end. An initiator
//     ships its pre-committed KP′ as a §A.1 bootstrap envelope via `bootstrapEnvelope()`
//     (alongside the establishment reply; `begin(.finishBootstrap)` stays valid + idempotent).
//     The acceptor's `decodeHeader` dispatches `OpenedInitial.bootstrapKp` — resolving the
//     owed session through the invitation's new `bootstrapKpGroupId(kpFrame:)` (a
//     `H(KP′)->group` table populated at `receive`) — into the EXISTING `.forward` disposition,
//     and `forwarded` answers it with `pqBootstrapRespond`, failing open (respond errors are
//     swallowed — the parallel envelope is best-effort, the side-band path is authoritative;
//     `DuplicateSideBand` when the side-band won the race is the common one). The parked
//     `Welcome'` rides the acceptor's next `pendingSideBand` hand-out. Invitation archive layout
//     changed (INVITATION_VERSION 1→2, pre-release hard cut) — a stale blob fails to decode.
private let expectedBindingContract: UInt64 = 23

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
private final class PQSinkAdapter: TwoMLSPQBinding.ArchiveSink {
	private let wrapped: any PersistenceSink

	init(_ wrapped: any PersistenceSink) {
		self.wrapped = wrapped
	}

	func persist(seq: UInt64, kind: TwoMLSPQBinding.BlobKind, archive: Data) {
		wrapped.persist(
			seq: seq, slot: PersistedSlot(kind), bytes: archive)
	}
}

extension PersistedSlot {
	fileprivate init(_ kind: TwoMLSPQBinding.BlobKind) {
		switch kind {
		case .core: self = .core
		case .checkpoint: self = .checkpoint
		}
	}
}

extension PrincipalState {
	init(_ base: TwoMLSPQBinding.PrincipalState) {
		switch base {
		case .sync(let clientId):
			self = .sync(clientId.bytes)
		case .pending(let old, let new):
			self = .pending(old: old.bytes, new: new.bytes)
		}
	}
}

extension TwoMLSPQBinding.ClientId {
	var clientID: ClientID { bytes }
}

extension ClientID {
	var pqClientId: TwoMLSPQBinding.ClientId { .init(bytes: self) }
}

// MARK: - Result adapters


public struct PQEncryptResult {
	public let cipherText: Data
	public let sender: ClientID
	public let recipient: ClientID
	public let epochs: APQEpochs
	public let dependsOnSeq: UInt64

	init(_ base: TwoMLSPQBinding.EncryptResult) {
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

public struct PQPrepareEncryptResult {
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
	public let commitedRemoteClientId: ClientID?
	public let didCommit: Bool

	init(_ base: TwoMLSPQBinding.PrepareEncryptResult) throws {
		proposalMessage = base.proposalMessage
		proposalHash = try liftDigest(base.proposalHash)
		commitedRemoteClientId = base.committedRemoteClientId?.bytes
		didCommit = base.didCommit
	}
}

public struct PQSenderMessage: Sendable {
	public let appMessageData: Data
	public let senderClientId: ClientID
	public let epoch: UInt64

	init(_ base: TwoMLSPQBinding.MlsSenderMessage) {
		appMessageData = base.appMessageData
		senderClientId = base.senderClientId.bytes
		epoch = base.epoch
	}
}

public struct PQQueuedRemoteProposal: Sendable {
	public let digest: TypedDigest
	public let sender: ClientID
	public let proposing: ClientID
	public let context: TypedDigest

	init(_ base: TwoMLSPQBinding.QueuedRemoteProposal) throws {
		digest = try liftDigest(base.digest)
		sender = base.sender.bytes
		proposing = base.proposing.bytes
		context = try liftDigest(base.context)
	}
}

public struct PQCommitResult: Sendable {
	public let newSender: ClientID?
	public let newRecipient: ClientID

	init(_ base: TwoMLSPQBinding.CommitResult) {
		newSender = base.newSender?.bytes
		newRecipient = base.newRecipient.bytes
	}
}

public struct PQDecryptResult: Sendable {
	public let applicationMessage: PQSenderMessage?
	public let proposal: PQQueuedRemoteProposal?
	public let remoteCommit: PQCommitResult?

	init(_ base: TwoMLSPQBinding.DecryptResult) throws {
		applicationMessage = base.applicationMessage.map(PQSenderMessage.init)
		proposal = try base.proposal.map(PQQueuedRemoteProposal.init)
		remoteCommit = base.remoteCommit.map(PQCommitResult.init)
	}
}

// MARK: - Session


/// Adapter wrapping a `TwoMLSPQBinding.TwoMlsPqSession`.
public struct PQSession {
	let base: TwoMLSPQBinding.TwoMlsPqSession

	init(_ base: TwoMLSPQBinding.TwoMlsPqSession) {
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

	public init(persisted: Persisted) throws(SessionError) {
		// PQ trees come from the checkpoint; identity/classical/meta from
		// whichever slot has the higher stateSeq; fails closed
		// (`.archiveInvalid`) on a PQ-epoch manifest mismatch. The restored
		// session has NO sink — installSink immediately, before use.
		let restored: TwoMlsPqSession
		do {
			restored = try TwoMlsPqSession.restore(
				core: persisted.core.map { TwoMLSPQBinding.Archive(bytes: $0) },
				checkpoint: TwoMLSPQBinding.Archive(bytes: persisted.checkpoint))
		} catch {
			throw SessionError(pqError: error, at: .restore)
		}
		self.init(restored)
	}

	public func installSink(
		_ sink: any PersistenceSink
	) throws(SessionError) {
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

	public var myPrincipalState: PrincipalState {
		.init(base.myPrincipalState())
	}

	public var theirPrincipalState: PrincipalState {
		.init(base.theirPrincipalState())
	}

	public var queuedRemoteSuccessor: ClientID? {
		base.queuedRemoteSuccessor()?.bytes
	}

	public var sendRendezvous: RendezvousID? {
		get throws(SessionError) {
			try mapPQErrors(.pqOperation) { try base.sendRendezvous()?.bytes }
		}
	}

	// MARK: Encrypt / decrypt

	public func prepareToEncrypt(
		proposing: ClientID?
	) throws(SessionError) -> PQPrepareEncryptResult? {
		try mapPQErrors(.prepareToEncrypt) {
			try PQPrepareEncryptResult(
				base.prepareToEncrypt(proposing: proposing?.pqClientId))
		}
	}

	public func encrypt(
		appMessage: Data
	) throws(SessionError) -> PQEncryptResult {
		try mapPQErrors(.encrypt) {
			PQEncryptResult(try base.encrypt(appMessage: appMessage))
		}
	}

	public func processIncoming(
		ciphertext: Data
	) throws(SessionError) -> PQDecryptResult? {
		// `.misroutedFrame` if a PQ side-band frame lands here (route it to
		// `ingest`); `.decryptionFailed` is transient (retry); `.epochDesync`
		// means re-establish. After a `.retryLater` failure, reconcile identity
		// via `theirPrincipalState` — a staple may have applied.
		try mapPQErrors(.processIncoming) {
			try base.processIncoming(ciphertext: ciphertext)
				.map(PQDecryptResult.init)
		}
	}

	public func queueProposal(
		digest: TypedDigest
	) throws(SessionError) {
		try mapPQErrors(.pqOperation) {
			try base.queueProposal(digest: digest.digest)
		}
	}

	public func forwarded(
		headerDecrypted: Data
	) throws(SessionError) -> PQSenderMessage? {
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
			let opened = try? decodeInitialPlaintext(plaintext: headerDecrypted)
			// Part 3: `decodeHeader` resolved a parallel A.4 bootstrap KP′ to this
			// session and routed it here. Stand up our send group's deferred PQ half
			// around it; the Welcome' parks in the side-band slot and rides our next
			// `pendingSideBand(sealing:)` hand-out (no PQInbound — the parked reply is
			// drained by the ordinary re-send path, not `advance`). There is no app
			// message to deliver. FAIL OPEN like the establishment branch above: this
			// parallel envelope is a best-effort optimization, and the side-band
			// `pqBootstrapBegin`/`ingest` path is the AUTHORITATIVE A.4 carrier that
			// surfaces a genuine failure — so `DuplicateSideBand` (the common case: the
			// side-band already answered), a frame the app mis-routed here, and an
			// unrecoverable round are all swallowed rather than misgraded as fatal.
			if case .bootstrapKp(let kpFrame)? = opened {
				try? base.pqBootstrapRespond(kpMsg: kpFrame)
				return nil
			}
			guard case .establishment(let frame)? = opened,
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
	public var receiveGroupId: GroupID? {
		base.receiveGroupId()?.classical.bytes
	}

	public func shouldListenOn() throws(SessionError) -> (
		GroupID, [UInt64: RendezvousID]
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
		rotating: ClientID?
	) throws(SessionError) -> PQOutbound {
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
				throw SessionError(
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

	public func bootstrapEnvelope() throws(SessionError) -> Data? {
		// Initiator-only, pre-establishment. The crate returns `SessionNotReady`
		// when there is no pre-committed KP to ship (an acceptor, or a session past
		// the cutover) — map that to "nothing to ship" rather than an error; a real
		// seal failure still surfaces. The first call registers the A.4 round and
		// consumes the KP, re-calls re-seal the same frame, so calling it repeatedly
		// (or keeping `begin(.finishBootstrap)` too) is safe.
		do {
			return try base.pqBootstrapEnvelope()
		} catch TwoMLSPQBinding.TwoMlsPqError.SessionNotReady {
			return nil
		} catch {
			throw SessionError(pqError: error, at: .pqOperation)
		}
	}

	public func advance(
		after inbound: PQInbound
	) -> PQOutbound? {
		base.pqTakePendingOutbound().map {
			PQOutbound(kind: inbound.kind, payload: $0)
		}
	}

	public func ingest(
		_ message: Data
	) throws(SessionError) -> PQInbound {
		return try mapPQErrors(.ingest) {
		// Frames leave the peer sealed (header encryption, contract v7): the leading
		// tag is no longer in the clear, so classify by removing the outer seal and
		// reading the routing `kind` rather than switching on `message.first`. Hand
		// the receivers the OPENED frame — the binding documents them as taking it,
		// and passing the sealed blob (which they also tolerate) re-runs the whole
		// trial-decrypt window per frame for nothing.
		guard let opened = try base.openIncoming(blob: message) else {
			// No header key opened it (M2a). One alone may be a stranger's
			// garbage or a desync-gap frame; treat a RUN of these on a live
			// session as a re-establish signal (count at the call site).
			throw SessionError(
				code: .unopenableFrame,
				detail: "no receive-window key opens this blob; "
					+ "a run of these is a re-establish signal")
		}
		guard case let .pqSideBand(kind) = opened.kind else {
			// A message-path frame reached the side-band entry point (M2b).
			throw SessionError(
				code: .misroutedFrame,
				detail: "message-path frame at the PQ side-band entry — "
					+ "route to processIncoming")
		}
		// v18: binds are NOT side-band frames — a round's closing bind rides the
		// binder's next classical COMMIT as the message-frame staple, so it
		// arrives through `processIncoming` like any other message frame. This
		// switch only ever sees the six side-band kinds, in lifecycle order.
		switch kind {
		case .bootstrapKeyPackage:
			// A.4 leg 1 (we respond): stand up our send group's deferred PQ
			// half around the initiator's KP'; the Welcome' parks for `advance`.
			try base.pqBootstrapRespond(kpMsg: opened.frame)
			return PQInbound(
				kind: .finishBootstrap, advancedGroup: .ours,
				newEpochs: epochs, rotatedCredential: nil)
		case .bootstrapWelcome:
			// A.4 leg 2 (we initiated): join the peer's new PQ group, commit
			// our own send-PQ pathlessly, and OWE the classical half — the bind
			// rides our next classical commit as the staple. `epochs` now reads
			// pq+1 with classical unchanged; the pair evens out when the bind
			// lands.
			try base.pqBootstrapBind(welcomeMsg: opened.frame)
			return PQInbound(
				kind: .finishBootstrap, advancedGroup: .ours,
				newEpochs: epochs, rotatedCredential: nil, owesBind: true)
		case .ratchetEphemeralKey:
			// A.3 (we respond): seal a fresh secret to the EK; the CT parks.
			try base.pqRatchetRespond(ekMsg: opened.frame)
			return PQInbound(
				kind: .ratchet, advancedGroup: .theirs,
				newEpochs: nil, rotatedCredential: nil)
		case .ratchetCiphertext:
			// A.3 (we initiated): open the sealed secret, commit our send-PQ,
			// OWE the classical half. The round's app message travels on the
			// committing round's own message frame — there is no app to pass.
			try base.pqRatchetBind(ctMsg: opened.frame)
			return PQInbound(
				kind: .ratchet, advancedGroup: .ours,
				newEpochs: epochs, rotatedCredential: nil, owesBind: true)
		case .rekeyUpdate:
			// A.5 (we respond): commit the initiator's Upd' on our send-PQ —
			// the round's ONE updatePath commit, which also catches our own
			// leaf up. Commit' parks for `advance`. A credential handoff
			// announces the initiator's (already Phase 8-rotated) agent id in
			// the Upd' — by the time this returns, the initiator's leaf in our
			// send-PQ has moved to that agent's key.
			let rotated = try base.pqRekeyRespond(updMsg: opened.frame)
			return PQInbound(
				kind: .rekey, advancedGroup: .ours,
				newEpochs: epochs, rotatedCredential: rotated?.bytes)
		case .rekeyCommit:
			// A.5 (we initiated): apply the responder's Commit' to our recv
			// mirror. One A.5 round re-keys ONE group — the turn alternation
			// brings our own group's round next. Our stapled ACK (the round's
			// closing bind) is owed internally and rides our next classical
			// commit; nothing parks for `advance`.
			try base.pqRekeyApply(msg: opened.frame)
			return PQInbound(
				kind: .rekey, advancedGroup: .theirs,
				newEpochs: epochs, rotatedCredential: nil, owesBind: true)
		}
		}
	}

	/// The retained side-band frame, sealed, WITHOUT consuming it — the
	/// re-send path. Retention (v18) keeps the current round's outbound
	/// available until the peer's answer proves it landed, so a driver may
	/// hand this out on every send. `.fresh` re-seals per call (re-sends are
	/// unlinkable on the wire); `.stable` repeats the bytes while the frame
	/// is unchanged, which chunking requires — but see the liveness bound on
	/// `SideBandSealing`: a `.stable` pass over the pre-A.4 `BOOTSTRAP_KP`
	/// must finish inside the peer's classical header window. Advances no
	/// protocol state: nothing to persist. Returns nil while a bind is OWED
	/// — an owed bind is not a side-band frame (it rides the next classical
	/// commit); see `PQInbound.owesBind`.
	public func pendingSideBand(sealing: SideBandSealing) -> Data? {
		// Exhaustive, not `== .fresh ? :` — a future sealing mode must fail
		// compilation here rather than silently lower to `.stable` (the
		// same tripwire convention as the error map and PersistedSlot).
		let ffi: TwoMLSPQBinding.SideBandSealing
		switch sealing {
		case .fresh: ffi = .fresh
		case .stable: ffi = .stable
		}
		return base.pqPendingOutbound(sealing: ffi)
	}

	/// Whether receiving is poisoned: a peer bind staple failed to apply
	/// after the round's secret was consumed, so every further
	/// `processIncoming` refuses with `.bindApplyFailed` while SENDING is
	/// unaffected. Not reachable from an honest peer; healed by restoring
	/// the last persisted state. A query rather than only an error, because
	/// the urgency depends on the session's role — receive-critical treats
	/// it as fatal, send-mostly can defer.
	public var isReceiveBroken: Bool {
		base.pqReceiveBroken()
	}
}


// MARK: - Invitation (stub)


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

public struct PQInvitation {
	public typealias Client = PQClient
	public typealias Session = PQSession
	public typealias Persisted = PQInvitationArchive

	let base: TwoMLSPQBinding.TwoMlsPqInvitation

	init(base: TwoMLSPQBinding.TwoMlsPqInvitation) {
		_ = TwoMLSPQBindingContract.verified
		self.base = base
	}

	// MARK: Archivable (push)

	public init(persisted: PQInvitationArchive) throws(SessionError) {
		do {
			self.init(base: try TwoMlsPqInvitation.restore(archive: persisted.bytes))
		} catch {
			throw SessionError(pqError: error, at: .restore)
		}
	}

	/// Monolithic object: the sink receives only `.checkpoint` blobs (one
	/// per successful `receive`, plus the install-time baseline).
	public func installSink(
		_ sink: any PersistenceSink
	) throws(SessionError) {
		try mapPQErrors(.installSink) {
			try base.installSink(sink: PQSinkAdapter(sink))
		}
	}

	/// Bumps once per successful `receive`.
	public var stateSeq: UInt64 {
		base.stateSeq()
	}

	// MARK: Invitation

	public init(clientId: ClientID) throws(SessionError) {
		// Fresh invitation: mint a client for this identity and capture a combiner
		// key package into a self-contained archive. Last-resort (reusable), so a
		// single-use invitation's `InvitationSpent` never surfaces here.
		do {
			let archive = try TwoMlsPqPrincipal(clientId: clientId)
				.generateInvitation(lastResort: true)
			self.init(base: try TwoMlsPqInvitation.restore(archive: archive))
		} catch {
			throw SessionError(pqError: error, at: .invitation)
		}
	}

	public var clientId: ClientID {
		base.clientId().bytes
	}

	public var encodedKeyPackage: Data {
		// The combiner's two key packages travel as one opaque blob; only TwoMLSPQ
		// reads the halves back out (decodeCombinerKeyPackage).
		encodeCombinerKeyPackage(keyPackage: base.combinerKeyPackage())
	}

	public func decodeHeader(
		ciphertext: Data
	) throws(SessionError) -> HeaderDecryptResult {
		return try mapPQErrors(.decodeHeader) {
		// Split the crate's §A.1 envelope, strip the HPKE layer with this
		// invitation's key-package init key (info defaults to this ClientId,
		// matching the crate's seal), and parse the four optional sections.
		let (kemOutput, sealed) = try decodeEnvelopeFrame(ciphertext)
		let decrypted = try base.hpkeOpen(
			kemOutput: kemOutput,
			ciphertext: sealed,
			info: nil,
			// Contract 22: the §A.1 seal binds the declared suite via an
			// untransmitted AAD. Both sides derive the same bytes locally —
			// `[framingVersion][suite pair]` — so we pass `envelopeFramingAad()`
			// here or the AEAD tag fails as an opaque decryption error.
			aad: envelopeFramingAad()
		)
		// Contract 21: `decodeInitialPlaintext` returns `OpenedInitial`, dispatching
		// on the plaintext's inner tag — the establishment reply and the Part 3
		// parallel A.4 bootstrap KP′ share the outer §A.1 shape.
		let opened = try decodeInitialPlaintext(plaintext: decrypted)
		// Part 3: the initiator shipped its pre-committed KP′ as a §A.1 bootstrap
		// envelope IN PARALLEL with the reply. It carries no session id, but the
		// invitation pinned `H(KP′) -> spawned group` at `receive`, so it self-routes:
		// resolve the owed session and hand the frame through the SAME `.forward` path
		// the establishment replay uses — the spawned session's `forwarded` answers
		// A.4 via `pqBootstrapRespond`. A frame that resolves to nothing is early (no
		// session owes it yet) or bogus.
		if case .bootstrapKp(let kpFrame) = opened {
			guard let group = base.bootstrapKpGroupId(kpFrame: kpFrame) else {
				throw SessionError(
					code: .malformedFrame,
					detail: "§A.1 bootstrap-KP envelope resolves to no pinned session")
			}
			return .forward(
				groupId: try DataIdentifier(
					prefix: .bits256, checkedData: group.bytes),
				// The envelope PLAINTEXT: `forwarded(headerDecrypted:)` re-parses it
				// to the verbatim `[0x13][KP′]` frame and answers A.4.
				mlsMessageData: decrypted)
		}
		guard case .establishment(let frame) = opened else {
			// `OpenedInitial` has only the two cases; this stays exhaustive so a new
			// variant is a compile-visible decision, not a silent misroute.
			throw SessionError(
				code: .malformedFrame,
				detail: "§A.1 envelope: unrecognized initial variant")
		}
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
			throw SessionError(
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
			throw SessionError(
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
		bootstrapKpCommitment: Data,
		remoteClientId: ClientID,
		welcomeToken: WelcomeToken,
		stapledMessage: Data?,
		newClientId: ClientID
	) throws(SessionError) -> (PQSession, stapled: PQSenderMessage?) {
		return try mapPQErrors(.receive) {
		// Validate the dedicated principal id BEFORE any invitation state is
		// claimed: `stageRotation` (below) throws `.invalidClientId` on an empty
		// id, but by then `base.receive` has consumed the welcome — the session
		// would be orphaned and a retry refused as `.duplicateWelcome`. Same
		// error identity, fixed ordering.
		guard !newClientId.isEmpty else {
			throw SessionError(
				code: .invalidClientId,
				detail: "dedicated principal id must be non-empty")
		}

		// v20: `remoteKeyPackage` is the initiator's CLASSICAL return key package (a
		// bare MLS KeyPackage message), not a combiner blob — its PQ half now travels
		// in A.4, hash-bound to `bootstrapKpCommitment`.
		// Bind the key package to the authenticated identity from the validated
		// welcome. The crate's own RemoteIdentityMismatch (via base.receive) maps to
		// the SAME `.identityMismatch` — one code, both origins.
		let parsed = try parseMlsKeyPackage(bytes: remoteKeyPackage)
		guard parsed.clientId.bytes == remoteClientId else {
			throw SessionError(
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
				theirClassicalKeyPackage: remoteKeyPackage,
				bootstrapKpCommitment: bootstrapKpCommitment,
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

// A session is a single-driver state machine — see the PQRatchet doc. This
// unavailable conformance makes the non-Sendability explicit and blocks a
// consumer from retroactively re-adding it; the containing type (typically an
// actor owning the session) asserts its own Sendable story instead.
@available(*, unavailable)
extension PQSession: Sendable {}

// MARK: - Client (stub)


public struct PQClient {
	public typealias Invitation = PQInvitation

	let base: TwoMLSPQBinding.TwoMlsPqPrincipal

	init(base: TwoMLSPQBinding.TwoMlsPqPrincipal) {
		_ = TwoMLSPQBindingContract.verified
		self.base = base
	}

	public init(clientId: ClientID) throws(SessionError) {
		do {
			self.init(base: try TwoMlsPqPrincipal(clientId: clientId))
		} catch {
			throw SessionError(pqError: error, at: .client)
		}
	}

	public func makeInvitation()
		throws(SessionError) -> PQInvitation.Persisted
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
	) -> RawSuites? {
		// An opaque combiner blob reports its PQ half's suite; fall back to a bare
		// MLS key package message. Returns nil when the bytes are neither — callers
		// distinguish "unparseable" from a real suite without a magic 0 sentinel.
		if let pair = try? decodeCombinerKeyPackage(bytes: encoded) {
			return try? parseMlsKeyPackage(bytes: pair.pq).cipherSuite.value()
		}
		return try? parseMlsKeyPackage(bytes: encoded).cipherSuite.value()
	}

	public static var supportedSuites: [RawSuites] {
		// 0x0003 = X25519+ChaCha20Poly1305 (classical), 0xFDEA = ML-KEM-768 (pq)
		[0x0003, 0xFDEA]
	}

	public func reply(
		keyPackageMessage: Data
	) throws(SessionError) -> (
		sendGroup: PQSession,
		welcomeMessage: Data,
		myKeyPackage: Data,
		bootstrapKpCommitment: Data
	) {
		return try mapPQErrors(.client) {
		let pair = try decodeCombinerKeyPackage(bytes: keyPackageMessage)
		// `appBinding: nil` — unbound (v15's AppBinding); threading a real
		// relationship binding through the abstract surface is its own follow-up.
		let session = try TwoMlsPqSession.initiate(
			client: base, theirKeyPackage: pair, appBinding: nil)
		// `welcomeMessage` is the PLAINTEXT APQWelcome (contract 15): the app binds
		// it — together with `myKeyPackage` and `bootstrapKpCommitment` — into its
		// signed identity envelope (AnchorWelcome) and hands the result back via
		// `createTwoMLSGroup`, which attaches it as the session's
		// establishment-self-sufficient app payload. The crate re-staples that
		// payload on the wire envelope of the initial frame AND of every
		// pre-establishment app message, so any single frame establishes the
		// acceptor.
		guard let welcome = session.initialWelcome() else {
			throw SessionError(
				code: .internalError,
				detail: "PQClient.reply — initiate produced no welcome")
		}
		// The return-group key package is CLASSICAL-only (§A.1: the acceptor's send
		// group starts classical-only; our PQ key package travels in A.4). The
		// retaining generate path parks its private half in this live session's own
		// client store so the return-welcome join can resolve it (an invitation-held
		// key package would be purged from the client).
		let myKeyPackage = try base.generateKeyPackage(suite: .x25519Chacha())
		// The pre-committed A.4 bootstrap KP's hash, minted at `initiate` — Some on
		// a fresh initiating session (consumed only at `pqBootstrapBegin`).
		guard let commitment = session.bootstrapKpCommitment() else {
			throw SessionError(
				code: .internalError,
				detail: "PQClient.reply — initiate produced no bootstrap commitment")
		}
		return (PQSession(session), welcome, myKeyPackage, commitment)
		}
	}

	public func createTwoMLSGroup(
		remoteAgentId: ClientID,
		mySendGroup: PQSession,
		theirKeyPackageMessage: Data,
		appWelcome: Data
	) throws(SessionError) -> (
		PQSession, encryptedCombinedWelcome: Data
	) {
		return try mapPQErrors(.client) {
		// Bind the published key package to the remote identity the app is
		// addressing before anything is attached.
		let pair = try decodeCombinerKeyPackage(bytes: theirKeyPackageMessage)
		guard try parseCombinerKeyPackage(kp: pair).clientId.bytes == remoteAgentId
		else {
			throw SessionError(
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
			throw SessionError(
				code: .internalError,
				detail: "createTwoMLSGroup — no parked envelope after attach")
		}
		return (mySendGroup, encryptedCombinedWelcome: envelope)
		}
	}
}

// MARK: - §A.1 envelope outer frame

/// The crate's §A.1 envelope (contract 21): the raw HPKE blob `[u32-LE kem-len]
/// [kem_output][ciphertext…]` (ciphertext runs to the end) — NO outer tag. Contract 21
/// dropped it so the establishment reply and a parallel bootstrap-KP frame share one
/// indistinguishable shape; discrimination moved INSIDE, to the HPKE plaintext's
/// authenticated leading tag (`decodeInitialPlaintext` -> `OpenedInitial`). Produced
/// entirely by the crate (initiate / the attach setters / pre-establishment encrypt);
/// split HERE — rather than opened via `openInitial` — so `hpkeOpen`'s two inputs stay
/// separate and the raw plaintext remains available for the forward-routing path
/// (`forwarded(headerDecrypted:)` re-parses it).
private func decodeEnvelopeFrame(
	_ data: Data
) throws(SessionError) -> (kemOutput: Data, ciphertext: Data) {
	var rest = data[...]
	guard rest.count >= 4 else {
		throw SessionError(
			code: .malformedFrame, detail: "§A.1 envelope outer frame")
	}
	let kemLength = Int(
		rest.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
	)
	rest = rest.dropFirst(4)
	guard rest.count >= kemLength else {
		throw SessionError(
			code: .malformedFrame, detail: "§A.1 envelope outer frame")
	}
	return (Data(rest.prefix(kemLength)), Data(rest.dropFirst(kemLength)))
}
