//
//  AbstractTwoMLS+Client.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/22/26.
//
//  Declares the AbstractTwoMLS namespace and the Client / Invitation
//  entry-point protocols.
//

import CommProtocol
import Foundation

public enum AbstractTwoMLS {
	public typealias ClientID = Data
	public typealias GroupID = Data

	public typealias RawSuites = UInt16

	//should be 32 bytes
	public typealias RendezvousID = Data

	/// The per-credential entry point: a factory for `Invitation`s and sessions.
	///
	/// Terminology bridge. This is the single 1:1 entity that **CommProtocol** calls an
	/// **Agent** (delegated from its `Identity` / `Anchor`) and that the **TwoMLSPQ** backend
	/// exposes as a **`TwoMlsPqPrincipal`**. AbstractTwoMLS abstracts over the backend and
	/// historically named this protocol `Client`; the concept is the agent / principal, 1:1
	/// with the MLS Basic Credential — i.e. `Agent ↔ Principal`. TwoMLSPQ stays
	/// CommProtocol-agnostic and never says "agent"; CommProtocol never says "principal";
	/// this layer is where the two vocabularies meet.
	public protocol Client {
		associatedtype Invitation: AbstractTwoMLS.Invitation where Invitation.Client == Self

		init(clientId: ClientID) throws

		/// Mint artifact: bytes that restore a fresh invitation via
		/// `Invitation.init(persisted:)`. Minting is the one pull that survives
		/// the push-persistence model — the object doesn't exist yet.
		func makeInvitation() throws -> Invitation.Persisted

		//nil when `encoded` is not a parseable (combiner or bare MLS) key package
		static func parseKeyPackageSuite(encoded: Data) -> RawSuites?

		static var supportedSuites: [RawSuites] { get }

		//two-step reply: step one sets up a send group from a remote keyPackage.
		//Returns the live session plus the PLAINTEXT welcome and this side's
		//published key package for the return group — the two establishment
		//artifacts the app binds into its signed identity envelope (the
		//`appWelcome` handed back in step two). The welcome publishes key
		//material: installSink on the session AFTER step two (the attach), and
		//gate frame transmission on `dependsOnSeq`/`stateSeq` durability as usual
		//(the install-time baseline carries everything both steps did).
		func reply(keyPackageMessage: Data) throws -> (
			sendGroup: Invitation.Session,
			welcomeMessage: Data,
			myKeyPackage: Data
		)

		//step two: attach the identity envelope (`appWelcome`, self-sufficient —
		//it carries step one's welcome + key package inside) to the session and
		//return the sealed initial frame. The backend composes and seals the
		//frame itself; the same envelope rides every pre-establishment send the
		//session makes (§A.1: the replier sends app messages immediately), so any
		//single frame establishes the acceptor. CAPTURE ORDERING: persist-capture
		//the session AFTER this step — the attached envelope rides the archive.
		func createTwoMLSGroup(
			remoteAgentId: ClientID,
			mySendGroup: Invitation.Session,
			//bind the addressed remote to the published key package before attach
			theirKeyPackageMessage: Data,
			appWelcome: Data
		) throws -> (
			Invitation.Session,
			encryptedCombinedWelcome: Data
		)
	}

	//object backing one keyPackage
	public protocol Invitation: Archivable {
		associatedtype Client: AbstractTwoMLS.Client where Client.Invitation == Self
		associatedtype Session: AbstractTwoMLS.Session

		init(clientId: ClientID) throws
		var clientId: ClientID { get }
		var encodedKeyPackage: Data { get }

		//two-step receive
		//the invitation object recalls the used groupIds
		func decodeHeader(ciphertext: Data) throws -> HeaderDecryptResult

		//Unifies the card and anchor receive flows: after validating the decoded
		//AppWelcome/AnchorWelcome, the app passes back the remote's published key
		//package and authenticated client id extracted from it; the conformance
		//binds the two — the key package's credential must match the authenticated
		//identity. `remoteKeyPackage` is opaque to the abstraction (the PQ combiner
		//encodes both halves). Returns the live session with NO sink installed —
		//installSink immediately (the baseline snapshot captures everything
		//receive did, including the staged dedicated principal) before driving it.
		//`stapled` is the sender's early-delivered app message opened during the
		//join (from `HeaderDecryptResult.stapledPrivateMessage`), as the SAME
		//typed sender message `processIncoming` yields — the decrypt consumes its
		//ratchet generation, so the caller must deliver it (it cannot be
		//recovered from a re-delivered frame). Fail-open: an undecryptable staple
		//returns nil and the session still establishes (the peer re-staples its
		//CURRENT message until its first commit, so only that frame's copy drops).
		func receive(
			sendGroupWelcome: Data,
			remoteKeyPackage: Data,
			remoteClientId: ClientID,
			welcomeToken: WelcomeToken,
			stapledMessage: Data?,
			newClientId: ClientID
		) throws -> (Session, stapled: Session.MLSSenderMessage?)
	}

	public enum HeaderDecryptResult {
		//A frame whose welcome this invitation already turned into a session: an
		//exact re-delivery, or (PQ, §A.1) a LATER pre-establishment frame from
		//the same sender carrying a fresh stapled message. `mlsMessageData` is
		//the backend-opaque decrypted payload — hand it verbatim to the spawned
		//session's `forwarded(headerDecrypted:)`, which acknowledges the replay
		//and returns any newly-delivered stapled message.
		case forward(groupId: DataIdentifier, mlsMessageData: Data)
		case appWelcome(
			//opaque token for this welcome; pass it back verbatim to `receive`
			welcomeToken: WelcomeToken,
			appWelcome: Data,
			//the sender's early-delivered app message riding the establishment
			//frame (classical parity; PQ staples the sender's current message on
			//EVERY pre-establishment frame) — thread it into `receive`, which
			//opens it fail-open with the join
			stapledPrivateMessage: Data?
		)
	}
}
