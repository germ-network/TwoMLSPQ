//
//  AbstractTwoMLS.swift
//  CoreAppLogic
//
//  Created by Mark @ Germ on 6/2/26.
//

import CommProtocol
import Foundation

public protocol Archivable {
	associatedtype Archive: Codable, Sendable

	init(archive: Archive) throws
	var archive: Archive { get throws }
}

//abstracts the TwoMLS API surface PersistedTwoMLS depends on, so different
//implementations (classical to PQ) can be subbed in
extension AbstractTwoMLS {
	public protocol Session: Archivable {
		// `Session` is intentionally decoupled from `Invitation`: a session comes from
		// an invitation but never needs to name its type, and binding it here forced
		// every backend's session to expose a *generic* invitation — conflicting with
		// app-side invitation roles (anchor/card) that wrap `Invitation` independently.
		// The forward link remains: `Invitation` still names its `Session`
		// (see AbstractTwoMLS+Client.swift).

		var proposalContext: TypedDigest? { get }
		//this is an exported secret with width 32 bytes
		var sendRendezvous: RendezvousID? { get throws }

		/// This side's credential state — the TRUTH surface (see `PrincipalState`).
		var myPrincipalState: PrincipalState { get }
		/// The peer's credential state — the TRUTH surface. Reconcile identity
		/// here after any `processIncoming` failure of the retriable class: the
		/// frame's staple may have applied (moving the peer's principal) before
		/// the app message failed, and the one-shot `remoteCommit` event will not
		/// fire again on the retry.
		var theirPrincipalState: PrincipalState { get }
		/// The remote credential the app has approved (`queueProposal`) for the
		/// next commit — the running tally. Latest-wins; cleared when the send
		/// epoch advances. `nil` when nothing is tallied, and always `nil` for
		/// backends without an approval tally.
		var queuedRemoteSuccessor: ClientID? { get }

		associatedtype PrepareEncryptResult: PrepareEncryptResultProtocol
		func prepareToEncrypt(
			proposing: ClientID?
		) throws -> PrepareEncryptResult?
		associatedtype EncryptResult: EncryptResultProtocol
		func encrypt(appMessage: Data) throws -> EncryptResult
		func processIncoming(ciphertext: Data) throws -> DecryptResult?
		func queueProposal(digest: TypedDigest) throws
		func forwarded(headerDecrypted: Data) throws -> MLSSenderMessage?
		//resolve if this is the receive group or the session id
		func shouldListenOn() throws -> (GroupID, [UInt64: RendezvousID])

		//the concrete types are defined in the implementations so we avoid
		//redefining them
		associatedtype MLSSenderMessage: MLSSenderMessageProtocol
		associatedtype DecryptResult: DecryptResultProtocol
		where DecryptResult.SenderMessage == MLSSenderMessage

	}

	public protocol PrepareEncryptResultProtocol {
		var proposalHash: TypedDigest { get }
		var commitedRemoteClientId: ClientID? { get }
		var didCommit: Bool { get }
	}

	public protocol EncryptResultProtocol {
		var cipherText: Data { get }
		var sender: ClientID { get }
		var recipient: ClientID { get }
		//the APQ epoch pair (pq_epoch / t_epoch), see AbstractTwoMLS+PQRatchet.swift
		var epochs: APQEpochs { get }
	}

	//pass the sender client identity along with the appmessage
	public protocol MLSSenderMessageProtocol: Sendable {
		var appMessageData: Data { get }
		var senderClientId: ClientID { get }
		var epoch: UInt64 { get }
	}

	public protocol DecryptResultProtocol: Sendable {
		associatedtype SenderMessage: MLSSenderMessageProtocol
		associatedtype QueuedRemoteProposal: QueuedRemoteProposalProtocol
		associatedtype CommitResult: CommitResultProtocol

		var applicationMessage: SenderMessage? { get }
		var proposal: QueuedRemoteProposal? { get }
		var remoteCommit: CommitResult? { get }
	}

	public protocol QueuedRemoteProposalProtocol: Sendable {
		var digest: TypedDigest { get }
		var sender: ClientID { get }
		var proposing: ClientID { get }
		var context: TypedDigest { get }
	}

	/// Rotation outcomes surfaced by a commit — HINTS, not truth. These fire
	/// once, on the frame where the transition applied; if that frame's app
	/// message fails after the staple applied, the event is lost (the retry's
	/// staple is an idempotent skip). `myPrincipalState` / `theirPrincipalState`
	/// are the truth — reconcile there, never from missed events.
	public protocol CommitResultProtocol: Sendable {
		var newSender: ClientID? { get }
		var newRecipient: ClientID { get }
	}

	/// Credential state for one send direction. `.pending` means a candidate is
	/// staged/proposed but the peer's approval + commit has not yet
	/// canonicalized it.
	///
	/// STATE IS TRUTH, EVENTS ARE HINTS: `remoteCommit.newSender` /
	/// `.newRecipient` fire once, on the frame where the transition applied —
	/// and are LOST if that frame's app message fails after its staple applied.
	/// After a retriable `processIncoming` failure, reconcile identity from
	/// `theirPrincipalState`, not from missed events.
	public enum PrincipalState: Sendable, Equatable, Hashable {
		case sync(ClientID)
		case pending(old: ClientID, new: ClientID)
	}
}

extension AbstractTwoMLS.Session {
	/// Default for backends without an approval tally (e.g. the deprecated
	/// classical backend): honestly tally-less. Backends with a tally override.
	public var queuedRemoteSuccessor: AbstractTwoMLS.ClientID? { nil }
}
